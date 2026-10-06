package verifier

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"math/bits"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/gate"
)

const (
	settlementNodeAttested   = "node-attested"
	precisionRobust          = "robust"
	precisionBucketDependent = "bucket-dependent"
)

type options struct{ receipt []byte }

// Option changes one Verify call.
type Option func(*options)

// WithReceipt also checks a SignedReceipt of the decision. It is checked
// only for a decision with no failed check.
func WithReceipt(signed []byte) Option {
	return func(o *options) { o.receipt = bytes.Clone(signed) }
}

// run is the state of one verification.
type run struct {
	v     *Verifier
	ctx   context.Context
	h     commitment.Hash
	rep   Report
	c     *commitment.Commitment
	auth  *archive.AuthorizationRecord
	sa    *commitment.SignedAuthorization
	facts *AnchorFacts
}

// Verify checks the archived decision under h. The error is for operational
// failures (cancelled context, unreadable archive); a decision that does not
// verify is a Report with a failed check.
func (v *Verifier) Verify(ctx context.Context, h commitment.Hash, opts ...Option) (Report, error) {
	r, err := v.verify(ctx, h, opts)
	if err != nil {
		return Report{}, err
	}
	return r.rep, nil
}

func (r *run) pass(n CheckName) {
	r.rep.Checks = append(r.rep.Checks, Check{Name: n, Status: StatusPass})
}

func (r *run) fail(n CheckName, err error) {
	r.rep.Checks = append(r.rep.Checks, Check{Name: n, Status: StatusFail, Err: err})
}

func (r *run) unchecked(n CheckName, err error) {
	r.rep.Checks = append(r.rep.Checks, Check{Name: n, Status: StatusUnchecked, Err: err})
}

func (r *run) warn(format string, a ...any) {
	r.rep.Warnings = append(r.rep.Warnings, fmt.Sprintf(format, a...))
}

// soft reports an archive error that is a finding about the archive rather
// than a failure to read it.
func soft(err error) bool {
	return errors.Is(err, archive.ErrNotFound) || errors.Is(err, archive.ErrCorrupt)
}

func (v *Verifier) verify(ctx context.Context, h commitment.Hash, opts []Option) (*run, error) {
	var o options
	for _, opt := range opts {
		opt(&o)
	}
	r := &run{v: v, ctx: ctx, h: h}
	r.rep.CommitmentHash = h
	r.rep.Params = v.cfg.Params
	if err := r.alive(); err != nil {
		return nil, err
	}

	st, err := v.archive.State(ctx, h)
	if err != nil {
		if !soft(err) {
			return nil, fmt.Errorf("verifier: archive state: %w", err)
		}
		if !r.corruptAuthorization(ctx) {
			r.fail(CheckDecision, fmt.Errorf("%w: %w", ErrArchiveIncomplete, err))
			r.finish()
			return r, nil
		}
		// The decision reads; its Authorization record is what is damaged,
		// and the authorization step reports that under its own name.
		st = archive.DecisionState{State: archive.StateAuthorized}
	}
	r.rep.State = st.State
	if len(st.Rejections) > 0 {
		r.rep.Rejections = st.Rejections
	}
	if st.State == archive.StateAbsent {
		r.fail(CheckDecision, ErrDecisionNotFound)
		r.finish()
		return r, nil
	}

	dec, err := v.archive.Decision(ctx, h)
	if err != nil {
		if !soft(err) {
			return nil, fmt.Errorf("verifier: archive decision: %w", err)
		}
		r.fail(CheckDecision, fmt.Errorf("%w: %w", ErrArchiveIncomplete, err))
		r.finish()
		return r, nil
	}
	r.pass(CheckDecision)

	if !r.envelope(dec) {
		r.finish()
		return r, nil
	}
	r.action(dec)
	if st.State != archive.StateAuthorized {
		r.finish()
		return r, nil
	}

	for _, step := range []func() error{
		r.authorization,
		r.payload,
		r.anchorAndTrust,
	} {
		if err := r.alive(); err != nil {
			return nil, err
		}
		if err := step(); err != nil {
			return nil, err
		}
	}
	if o.receipt != nil && r.rep.AuthorizationVerified && !r.anyStatus(StatusFail) {
		r.receipt(o.receipt)
	}
	r.finish()
	return r, nil
}

// corruptAuthorization reports whether the decision record reads but its
// Authorization record is present and damaged.
func (r *run) corruptAuthorization(ctx context.Context) bool {
	if _, err := r.v.archive.Decision(ctx, r.h); err != nil {
		return false
	}
	_, err := r.v.archive.Authorization(ctx, r.h)
	return errors.Is(err, archive.ErrCorrupt)
}

func (r *run) alive() error {
	if err := r.ctx.Err(); err != nil {
		return fmt.Errorf("verifier: %w", err)
	}
	return nil
}

func (r *run) envelope(dec *archive.DecisionRecord) bool {
	bad := func(err error) bool {
		r.fail(CheckEnvelope, fmt.Errorf("%w: %w", ErrEnvelopeInvalid, err))
		return false
	}
	sc, err := commitment.DecodeSigned(dec.Envelope)
	if err != nil {
		return bad(err)
	}
	if err := commitment.ValidateStatic(&sc.Commitment, r.v.cfg.Params); err != nil {
		return bad(err)
	}
	got, err := commitment.Verify(sc)
	if err != nil {
		return bad(err)
	}
	for _, k := range r.v.cfg.GateKeys {
		if bytes.Equal(k, sc.Commitment.AgentPubKey) {
			return bad(errors.New("the agent key is a gate key"))
		}
	}
	if got != r.h {
		return bad(errors.New("envelope hashes to another commitment"))
	}
	r.c = &sc.Commitment
	r.rep.DA = r.c.PayloadRef.DA
	r.rep.Height = r.c.PayloadRef.Height
	r.rep.GateID = r.c.Scope.GateID
	r.rep.ActionType = r.c.Action.Type
	r.pass(CheckEnvelope)
	return true
}

func (r *run) action(dec *archive.DecisionRecord) {
	if err := commitment.CheckAction(r.c, dec.Action); err != nil {
		r.fail(CheckAction, fmt.Errorf("%w: %w", ErrActionInvalid, err))
		return
	}
	r.pass(CheckAction)
}

// authorization requires the record to decode, verify under a configured
// gate key and bind to this decision. Nothing is reported as authorized
// otherwise.
func (r *run) authorization() error {
	bad := func(sentinel, err error) error {
		r.fail(CheckAuthorization, fmt.Errorf("%w: %w", sentinel, err))
		return nil
	}
	rec, err := r.v.archive.Authorization(r.ctx, r.h)
	if err != nil {
		if !soft(err) {
			return fmt.Errorf("verifier: archive authorization: %w", err)
		}
		return bad(ErrAuthorizationInvalid, err)
	}
	sa, ah, err := commitment.DecodeSignedAuthorization(rec.SignedAuthorization)
	if err != nil {
		return bad(ErrAuthorizationInvalid, err)
	}
	msg := commitment.AuthorizationSigningMessage(ah)
	trusted := false
	for _, k := range r.v.cfg.GateKeys {
		if ed25519.Verify(k, msg, sa.Signature) {
			trusted = true
			break
		}
	}
	if !trusted {
		r.fail(CheckAuthorization, ErrGateKeyNotTrusted)
		return nil
	}
	a := &sa.Authorization
	var problem string
	switch {
	case a.Version != 0:
		problem = fmt.Sprintf("version %d", a.Version)
	case a.Path != commitment.PathDA && a.Path != commitment.PathArchive:
		problem = fmt.Sprintf("path %d", a.Path)
	case !bytes.Equal(a.CommitmentHash, r.h[:]):
		problem = "commitment hash is another decision's"
	case !bytes.Equal(a.ActionHash, r.c.Action.Hash):
		problem = "action hash differs from the decision's"
	case a.GateID != r.c.Scope.GateID:
		problem = "gate id differs from the decision's scope"
	case a.Expires == 0 || a.Expires > r.c.ValidUntil:
		problem = fmt.Sprintf("expires %d, decision valid until %d", a.Expires, r.c.ValidUntil)
	}
	if problem != "" {
		return bad(ErrAuthorizationInvalid, errors.New(problem))
	}
	r.auth, r.sa = rec, sa
	r.rep.AuthorizationVerified = true
	r.rep.Authorization = &AuthorizationInfo{Path: a.Path, Expires: a.Expires, AuthorizedAt: rec.AuthorizedAt}
	r.pass(CheckAuthorization)
	return nil
}

func (r *run) payload() error {
	ref := r.c.PayloadRef
	rec, err := r.v.archive.Payload(r.ctx, ref.DA, ref.Commitment)
	if err != nil {
		if !soft(err) {
			return fmt.Errorf("verifier: archive payload: %w", err)
		}
		r.fail(CheckPayload, fmt.Errorf("%w: %w", ErrArchiveIncomplete, err))
		return nil
	}
	if err := commitment.CheckPayload(r.c, rec.Blob); err != nil {
		r.fail(CheckPayload, fmt.Errorf("%w: %w", ErrPayloadInvalid, err))
		return nil
	}
	committer := r.v.committers[ref.DA]
	if committer == nil {
		r.fail(CheckPayload, fmt.Errorf("%w: %w: da %d", ErrPayloadInvalid, gate.ErrArchiveRecomputeUnsupported, ref.DA))
		return nil
	}
	if err := committer.Check(ref, rec.Blob); err != nil {
		r.fail(CheckPayload, fmt.Errorf("%w: %w", ErrPayloadInvalid, err))
		return nil
	}
	r.pass(CheckPayload)
	return nil
}

func (r *run) anchorAndTrust() error {
	ev, ok, err := r.anchor()
	if err != nil {
		return err
	}
	if !ok {
		r.rep.HeaderTrust.Status = TrustUnchecked
		r.unchecked(CheckHeaderTrust, errors.New("the anchor did not verify"))
		return nil
	}
	if err := commitment.CheckAnchorTime(r.c, r.facts.BlockTime, r.v.cfg.Params); err != nil {
		r.fail(CheckAnchorTime, err)
	} else {
		r.pass(CheckAnchorTime)
	}
	return r.headerTrust(ev)
}

// anchor runs the DA's anchor verifier and holds its facts to the rules that
// do not depend on the DA.
func (r *run) anchor() (*archive.EvidenceRecord, bool, error) {
	ref := r.c.PayloadRef
	bad := func(err error) (*archive.EvidenceRecord, bool, error) {
		r.fail(CheckAnchor, fmt.Errorf("%w: %w", ErrAnchorInvalid, err))
		return nil, false, nil
	}
	av := r.v.anchors[ref.DA]
	if av == nil {
		r.unchecked(CheckAnchor, fmt.Errorf("%w: da %d", ErrAnchorUnsupported, ref.DA))
		return nil, false, nil
	}
	ev, err := r.v.archive.Evidence(r.ctx, ref.DA, ref.Commitment)
	if err != nil {
		if !soft(err) {
			return nil, false, fmt.Errorf("verifier: archive evidence: %w", err)
		}
		r.fail(CheckAnchor, fmt.Errorf("%w: %w", ErrArchiveIncomplete, err))
		return nil, false, nil
	}
	if ev.Height != ref.Height {
		return bad(fmt.Errorf("evidence is for height %d, the decision names %d", ev.Height, ref.Height))
	}
	facts, err := av.VerifyAnchor(ref, ev)
	if errors.Is(err, ErrAnchorUnsupported) {
		r.unchecked(CheckAnchor, err)
		return nil, false, nil
	}
	if err != nil {
		return bad(err)
	}
	if facts.Settlement != "" && facts.Settlement != settlementNodeAttested {
		return bad(fmt.Errorf("settlement level %q is not one v0 reports", facts.Settlement))
	}
	if ref.DA == commitment.DAFibre {
		if facts.Settlement != settlementNodeAttested {
			return bad(errors.New("a da = 1 anchor must report the node-attested settlement"))
		}
		if p := facts.CertTokenPrecision; p != precisionRobust && p != precisionBucketDependent {
			return bad(fmt.Errorf("certificate token precision %q is neither %s nor %s", p, precisionRobust, precisionBucketDependent))
		}
	}
	for _, height := range r.neededHeights(ev) {
		if len(facts.HeaderHashes[height]) == 0 {
			return bad(fmt.Errorf("no header hash for height %d", height))
		}
	}
	if ref.DA == commitment.DAFibre {
		if ev.PromiseHeight == 0 {
			return bad(errors.New("evidence has no promise height"))
		}
		if facts.CertTotalPower <= 0 || facts.CertSignedPower < 0 || facts.CertSignedPower > facts.CertTotalPower {
			return bad(fmt.Errorf("certificate powers %d of %d", facts.CertSignedPower, facts.CertTotalPower))
		}
	}

	r.facts = &facts
	r.rep.BlockTime = facts.BlockTime
	r.rep.RetentionStart = facts.RetentionStart
	r.rep.Settlement = facts.Settlement
	if ref.DA == commitment.DAFibre {
		r.cert(facts)
	}
	r.pass(CheckAnchor)
	return ev, true, nil
}

func (r *run) cert(f AnchorFacts) {
	c := &CertReport{
		SignedPower:    f.CertSignedPower,
		TotalPower:     f.CertTotalPower,
		SignedShare:    float64(f.CertSignedPower) / float64(f.CertTotalPower),
		QuorumWarning:  atMostTwoThirds(f.CertSignedPower, f.CertTotalPower),
		TokenPrecision: f.CertTokenPrecision,
		ValsetHeader:   f.CertValsetHeader,
	}
	r.rep.Cert = c
	if c.QuorumWarning {
		r.warn("certificate: signed power %d of %d is not more than two thirds", c.SignedPower, c.TotalPower)
	}
	if c.TokenPrecision == precisionBucketDependent {
		r.warn("certificate: the verdict depends on token amounts inside a power bucket, which only the archive vouches for")
	}
}

// atMostTwoThirds is the warning predicate 3*signed <= 2*total, in 128-bit
// arithmetic so that large powers cannot overflow.
func atMostTwoThirds(signed, total int64) bool {
	sh, sl := bits.Mul64(uint64(signed), 3)
	th, tl := bits.Mul64(uint64(total), 2)
	return sh < th || sh == th && sl <= tl
}

func (r *run) neededHeights(ev *archive.EvidenceRecord) []uint64 {
	if r.c.PayloadRef.DA == commitment.DAFibre {
		return []uint64{ev.Height, ev.PromiseHeight}
	}
	return []uint64{ev.Height}
}

func (r *run) headerTrust(ev *archive.EvidenceRecord) error {
	ht := &r.rep.HeaderTrust
	if r.v.trust == nil {
		ht.Status = TrustUnchecked
		r.unchecked(CheckHeaderTrust, errors.New("no trusted header supplied"))
		return nil
	}
	heights := r.neededHeights(ev)
	ht.Hashes = make(map[uint64][]byte, len(heights))
	for _, height := range heights {
		ht.Hashes[height] = r.facts.HeaderHashes[height]
	}
	failTrust := func(err error) error {
		ht.Status = TrustFailed
		r.fail(CheckHeaderTrust, fmt.Errorf("%w: %w", ErrHeaderTrust, err))
		return nil
	}

	checked := true
	cross := ""
	for i, height := range heights {
		res, err := r.v.trust.Trusted(r.ctx, height, ht.Hashes[height])
		if cerr := r.ctx.Err(); cerr != nil {
			return fmt.Errorf("verifier: %w", cerr)
		}
		if i == 0 || res.CheckpointH != 0 {
			ht.CheckpointH, ht.CheckpointHash = res.CheckpointH, bytes.Clone(res.CheckpointHash)
		}
		if res.CrossCheck != "" {
			ht.CrossCheck = res.CrossCheck
		}
		if errors.Is(err, ErrTrustInput) {
			ht.Status = TrustUnchecked
			r.unchecked(CheckHeaderTrust, fmt.Errorf("height %d: %w", height, err))
			return nil
		}
		if err != nil {
			return failTrust(fmt.Errorf("height %d: %w", height, err))
		}
		if !res.Checked {
			checked = false
			continue
		}
		switch res.CrossCheck {
		case "mismatch":
			ht.CrossCheck = "mismatch"
			return failTrust(fmt.Errorf("height %d: cross-check mismatch", height))
		case "pass", "unavailable", "off":
			cross = worseCross(cross, res.CrossCheck)
		default:
			return failTrust(fmt.Errorf("height %d: unknown cross-check result %q", height, res.CrossCheck))
		}
	}
	ht.CrossCheck = cross
	if !checked {
		ht.Status = TrustUnchecked
		r.unchecked(CheckHeaderTrust, errors.New("header trust did not check the headers"))
		return nil
	}
	if cross == "unavailable" {
		r.warn("header trust: cross-check not done, no endpoint answered")
	}
	ht.Status = TrustValid
	r.pass(CheckHeaderTrust)
	return nil
}

// worseCross keeps the less assuring of two cross-check results.
func worseCross(a, b string) string {
	rank := map[string]int{"": 0, "pass": 1, "off": 2, "unavailable": 3}
	if rank[b] > rank[a] {
		return b
	}
	return a
}

func (r *run) receipt(signed []byte) {
	bad := func(err error) {
		r.fail(CheckReceipt, fmt.Errorf("%w: %w", ErrReceiptInvalid, err))
	}
	sr, _, err := commitment.VerifyReceipt(signed)
	if err != nil {
		bad(err)
		return
	}
	rc := &sr.Receipt
	switch {
	case !bytes.Equal(rc.CommitmentHash, r.h[:]):
		bad(errors.New("receipt is for another decision"))
		return
	case rc.GateID != r.c.Scope.GateID:
		bad(errors.New("receipt gate id differs from the decision's scope"))
		return
	}
	known := false
	for _, k := range r.v.cfg.GateKeys {
		if bytes.Equal(k, rc.GatePubKey) {
			known = true
			break
		}
	}
	if !known {
		bad(errors.New("receipt is signed by a key that is not a configured gate key"))
		return
	}
	r.rep.Receipt = &ReceiptInfo{RailRef: rc.RailRef, RecordedAt: rc.RecordedAt, GateAttested: true}
	r.pass(CheckReceipt)
}

// finish sets the verdict: any failed step invalidates; otherwise a decision
// that was not authorized says so; otherwise anything unchecked keeps it
// from being valid.
func (r *run) finish() {
	verdict := VerdictValid
	switch {
	case r.anyStatus(StatusFail):
		verdict = VerdictInvalid
	case r.rep.State != archive.StateAuthorized:
		verdict = VerdictNotAuthorized
	case r.anyStatus(StatusUnchecked), !r.allRequiredPassed():
		verdict = VerdictUnchecked
	}
	r.rep.Verdict = verdict
}

// allRequiredPassed holds only if every step a valid decision needs has run
// and passed, so a step that was never recorded cannot pass by omission.
func (r *run) allRequiredPassed() bool {
	for _, n := range []CheckName{
		CheckDecision, CheckEnvelope, CheckAction, CheckAuthorization,
		CheckPayload, CheckAnchor, CheckAnchorTime, CheckHeaderTrust,
	} {
		c, ok := r.rep.Check(n)
		if !ok || c.Status != StatusPass {
			return false
		}
	}
	return true
}

func (r *run) anyStatus(s Status) bool {
	for _, c := range r.rep.Checks {
		if c.Status == s {
			return true
		}
	}
	return false
}
