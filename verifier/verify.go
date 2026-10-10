package verifier

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"math/bits"
	"slices"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/gate"
	"github.com/vgonkivs/edicta/policy"
	"github.com/vgonkivs/edicta/sdk"
	"github.com/vgonkivs/edicta/sdk/payload"
)

const (
	settlementNodeAttested   = "node-attested"
	precisionRobust          = "robust"
	precisionBucketDependent = "bucket-dependent"
)

type options struct {
	receipt   []byte
	execution bool
}

// Option changes one Verify call.
type Option func(*options)

// WithReceipt also checks a SignedReceipt of the decision. It is checked
// only for a decision with no failed check.
func WithReceipt(signed []byte) Option {
	return func(o *options) { o.receipt = bytes.Clone(signed) }
}

// WithExecutionCheck also checks the rail transaction the receipt names.
// Once requested, a passing execution check is required for a valid verdict.
func WithExecutionCheck() Option { return func(o *options) { o.execution = true } }

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
	// authKey is the gate key the Authorization verified under.
	authKey ed25519.PublicKey

	// action and salt are what the action check matched; the execution
	// check uses these and never reads the record again.
	action, salt []byte
	// payloadSalt is the action salt of an opened payload, compared again
	// with a salt the reveal supplies after the payload check.
	payloadSalt []byte
	// sig is the agent signature of the verified envelope.
	sig []byte

	execRequested bool
	// checkpointH is the trusted header height a pending reference's
	// absence check learned; 0 when unknown.
	checkpointH uint64
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

// unchecked records a check that could not be decided, with its reason and
// the sources or checks it blames.
func (r *run) unchecked(n CheckName, reason Reason, err error, sources ...string) {
	if err == nil {
		err = errors.New(string(reason))
	}
	r.rep.Checks = append(r.rep.Checks, Check{Name: n, Status: StatusUnchecked, Err: err, Reason: reason, Sources: sources})
}

// archiveProblem records an archive record that is absent or damaged.
func (r *run) archiveProblem(n CheckName, unavailable Reason, err error) {
	reason := ReasonSourceCorrupt
	if errors.Is(err, archive.ErrNotFound) {
		reason = unavailable
	}
	r.unchecked(n, reason, fmt.Errorf("%w: %w", ErrArchiveIncomplete, err))
}

// corrupt records bytes that fail a check a genuine copy passes.
func (r *run) corrupt(n CheckName, sentinel, err error) {
	r.unchecked(n, ReasonSourceCorrupt, fmt.Errorf("%w: %w", sentinel, err))
}

// replaceCheck swaps the recorded check of that name for c.
func (r *run) replaceCheck(c Check) {
	for i := range r.rep.Checks {
		if r.rep.Checks[i].Name == c.Name {
			r.rep.Checks[i] = c
			return
		}
	}
	r.rep.Checks = append(r.rep.Checks, c)
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
	r := &run{v: v, ctx: ctx, h: h, execRequested: o.execution}
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
			r.archiveProblem(CheckDecision, ReasonDecisionUnavailable, err)
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
		r.unchecked(CheckDecision, ReasonDecisionUnavailable, ErrDecisionNotFound)
		r.finish()
		return r, nil
	}

	dec, err := v.archive.Decision(ctx, h)
	if err != nil {
		if !soft(err) {
			return nil, fmt.Errorf("verifier: archive decision: %w", err)
		}
		// No decision was read, so no state is known.
		r.rep.State, r.rep.Rejections = archive.StateAbsent, nil
		r.archiveProblem(CheckDecision, ReasonDecisionUnavailable, err)
		r.finish()
		return r, nil
	}
	r.pass(CheckDecision)

	if !r.envelope(dec) {
		r.finish()
		return r, nil
	}
	if err := r.checkAction(dec); err != nil {
		return nil, err
	}
	if st.State != archive.StateAuthorized {
		r.finish()
		return r, nil
	}

	for _, step := range []func() error{
		r.authorization,
		r.payload,
		r.anchorAndTrust,
		r.policy,
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
	if o.execution {
		if err := r.alive(); err != nil {
			return nil, err
		}
		r.execution()
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

// envelope runs stages D, S and G. A commitment that hashes to the reference
// and breaks one of them has the same bytes in every copy, so it fails. A copy
// whose bytes hash to something else, or whose signature (outside the hash)
// does not verify, is only a bad copy: unchecked.
func (r *run) envelope(dec *archive.DecisionRecord) bool {
	proven := func(err error) bool {
		r.fail(CheckEnvelope, fmt.Errorf("%w: %w", ErrEnvelopeInvalid, err))
		return false
	}
	corrupt := func(err error) bool {
		r.corrupt(CheckEnvelope, ErrEnvelopeInvalid, err)
		return false
	}
	hashesToRef := func(c *commitment.Commitment) bool {
		got, err := commitment.HashOf(c)
		return err == nil && got == r.h
	}
	sc, err := commitment.DecodeSigned(dec.Envelope)
	if err != nil {
		if raw, rerr := commitment.EnvelopeCommitment(dec.Envelope); rerr == nil &&
			commitment.HashCanonical(raw) == r.h {
			if _, derr := commitment.Decode(raw); derr != nil {
				return proven(derr)
			}
		}
		return corrupt(err)
	}
	if err := commitment.ValidateStatic(&sc.Commitment, r.v.cfg.Params); err != nil {
		if hashesToRef(&sc.Commitment) {
			return proven(err)
		}
		return corrupt(err)
	}
	if err := commitment.CheckPublicKey(sc.Commitment.AgentPubKey); err != nil {
		if hashesToRef(&sc.Commitment) {
			return proven(err)
		}
		return corrupt(err)
	}
	got, err := commitment.Verify(sc)
	if err != nil {
		return corrupt(err)
	}
	if got != r.h {
		return corrupt(errors.New("envelope hashes to another commitment"))
	}
	for _, k := range r.v.cfg.GateKeys {
		if bytes.Equal(k, sc.Commitment.AgentPubKey) {
			return proven(errors.New("the agent key is a gate key"))
		}
	}
	r.c, r.sig = &sc.Commitment, bytes.Clone(sc.Signature)
	r.rep.DA = r.c.PayloadRef.DA
	r.rep.Height = r.c.PayloadRef.Height
	r.rep.PayloadRef = r.c.PayloadRef
	r.rep.GateID = r.c.Scope.GateID
	r.rep.ActionType = r.c.Action.Type
	r.pass(CheckEnvelope)
	return true
}

// checkAction reads the action from the decision record. A public record
// holds the bytes and the salt; a private one holds neither: they are in the
// private blob of the action hash, which an auditor key opens.
func (r *run) checkAction(dec *archive.DecisionRecord) error {
	if dec.Form != archive.FormPublic {
		return r.checkPrivateAction()
	}
	if err := commitment.CheckAction(r.c, dec.Action, dec.ActionSalt); err != nil {
		r.corrupt(CheckAction, ErrActionInvalid, err)
		return nil
	}
	r.action, r.salt = bytes.Clone(dec.Action), bytes.Clone(dec.ActionSalt)
	r.rep.ActionSource = ActionSourceDecisionRecord
	r.pass(CheckAction)
	return nil
}

// authorization requires the record to decode, verify under a configured
// gate key and bind to this decision. Nothing is reported as authorized
// otherwise. A record that does not decode or verify is a bad copy
// (unchecked); a record the gate signed that contradicts the decision fails.
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
		// The state said the record is there, so a missing one is a copy
		// that disagrees with itself.
		r.corrupt(CheckAuthorization, ErrAuthorizationInvalid, err)
		return nil
	}
	sa, ah, err := commitment.DecodeSignedAuthorization(rec.SignedAuthorization)
	if err != nil {
		r.corrupt(CheckAuthorization, ErrAuthorizationInvalid, err)
		return nil
	}
	msg := commitment.AuthorizationSigningMessage(ah)
	trusted := false
	for _, k := range r.v.cfg.GateKeys {
		if ed25519.Verify(k, msg, sa.Signature) {
			trusted = true
			r.authKey = k
			break
		}
	}
	if !trusted {
		r.unchecked(CheckAuthorization, ReasonSourceCorrupt, ErrGateKeyNotTrusted)
		return nil
	}
	a := &sa.Authorization
	if !bytes.Equal(a.CommitmentHash, r.h[:]) {
		// Another decision's record under this key is a bad copy, not a
		// finding about this decision.
		r.corrupt(CheckAuthorization, ErrAuthorizationInvalid, errors.New("commitment hash is another decision's"))
		return nil
	}
	var problem string
	verr := commitment.ValidateAuthorization(a)
	switch {
	case verr != nil:
		problem = verr.Error()
	case (a.Mode == commitment.ModeFast) != r.c.PayloadRef.Pending():
		problem = fmt.Sprintf("mode %d does not match the reference form", a.Mode)
	case a.Mode == commitment.ModeFast && (a.AnchorDeadline <= r.c.PayloadRef.Height || a.AnchorDeadline-r.c.PayloadRef.Height > maxFastWindow):
		problem = fmt.Sprintf("anchor deadline %d outside (h0, h0 + %d]", a.AnchorDeadline, maxFastWindow)
	case a.Path != commitment.PathDA && a.Path != commitment.PathArchive:
		problem = fmt.Sprintf("path %d", a.Path)
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
	r.rep.Authorization = &AuthorizationInfo{Version: a.Version, Mode: a.Mode, Path: a.Path, Expires: a.Expires, AuthorizedAt: rec.AuthorizedAt}
	r.pass(CheckAuthorization)
	return nil
}

// maxFastWindow is the largest anchor window any gate configuration allows,
// in blocks after the reference height.
const maxFastWindow = 1000

func (r *run) payload() error {
	ref := r.c.PayloadRef
	rec, err := r.v.archive.Payload(r.ctx, ref.DA, ref.Commitment)
	if err != nil {
		if !soft(err) {
			return fmt.Errorf("verifier: archive payload: %w", err)
		}
		r.archiveProblem(CheckPayload, ReasonPayloadUnavailable, err)
		return nil
	}
	if err := commitment.CheckPayload(r.c, rec.Blob); err != nil {
		r.corrupt(CheckPayload, ErrPayloadInvalid, err)
		return nil
	}
	committer := r.v.committers[ref.DA]
	if committer == nil {
		r.unchecked(CheckPayload, ReasonDAUnsupported, fmt.Errorf("%w: %w: da %d", ErrPayloadInvalid, gate.ErrArchiveRecomputeUnsupported, ref.DA))
		return nil
	}
	if err := committer.Check(ref, rec.Blob); err != nil {
		r.corrupt(CheckPayload, ErrPayloadInvalid, err)
		return nil
	}
	o, err := r.openPayload(rec.Blob)
	if errors.Is(err, errEnvelopeEncode) {
		return fmt.Errorf("verifier: %w", err)
	}
	if err != nil {
		r.fail(CheckPayload, fmt.Errorf("%w: %w", ErrPayloadInvalid, err))
		return nil
	}
	r.pass(CheckPayload)
	if o != nil {
		r.payloadSalt = bytes.Clone(o.Payload.Action.Salt)
		r.compareSalt(r.payloadSalt)
	}
	return nil
}

// errEnvelopeEncode is a verifier fault, not a finding: the commitment
// decoded strictly and verified, so encoding it again cannot fail.
var errEnvelopeEncode = errors.New("re-encoding the verified envelope failed")

// openPayload opens the payload with the first configured recipient key
// that unwraps it. Without such a key nothing is opened and nil is returned:
// a payload this auditor cannot read is no finding. Once a key opens it, a
// plaintext hash mismatch or a payload action that differs from the
// committed one is the agent's own contradiction.
func (r *run) openPayload(raw []byte) (*sdk.Opened, error) {
	if len(r.v.cfg.PayloadKeys) == 0 {
		return nil, nil
	}
	env, err := commitment.EncodeSigned(&commitment.SignedCommitment{Commitment: *r.c, Signature: r.sig})
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errEnvelopeEncode, err)
	}
	for _, k := range r.v.cfg.PayloadKeys {
		o, err := sdk.OpenPayload(env, raw, k)
		switch {
		case err == nil:
			return o, nil
		case errors.Is(err, sdk.ErrPlaintextHashMismatch), errors.Is(err, sdk.ErrPayloadMismatch),
			errors.Is(err, payload.ErrMalformed), errors.Is(err, payload.ErrVersion):
			return nil, err
		}
	}
	return nil, nil
}

// compareSalt runs once the payload's action matched the commitment, and
// again after a reveal: the payload's salt and the archive copy's both hash
// the committed action, so a difference can only be a bad archive copy,
// never the agent's.
func (r *run) compareSalt(payloadSalt []byte) {
	if r.salt == nil || bytes.Equal(r.salt, payloadSalt) {
		return
	}
	src := archive.HashPath(archive.KindDecision, r.h)
	switch r.rep.ActionSource {
	case ActionSourcePrivateBlob:
		src, _ = archive.PrivateBlobPath(policy.PrivateAction, commitment.Hash(r.c.Action.Hash))
	case ActionSourceReveal:
		src = archive.HashPath(archive.KindReveal, r.h)
	}
	r.replaceCheck(Check{Name: CheckAction, Status: StatusUnchecked, Reason: ReasonSourceCorrupt,
		Sources: []string{src},
		Err:     fmt.Errorf("%w: the archive copy's action salt differs from the payload's", ErrActionInvalid)})
	r.action, r.salt = nil, nil
	r.rep.ActionSource = ""
}

func (r *run) anchorAndTrust() error {
	if r.c.PayloadRef.Pending() {
		return r.pendingAnchor()
	}
	ok, err := r.anchor()
	if err != nil {
		return err
	}
	if !ok {
		r.rep.HeaderTrust.Status = TrustUnchecked
		r.unchecked(CheckAnchorTime, ReasonBlocked, errors.New("the anchor did not verify"), string(CheckAnchor))
		r.unchecked(CheckHeaderTrust, ReasonBlocked, errors.New("the anchor did not verify"), string(CheckAnchor))
		return nil
	}
	if err := r.headerTrust(); err != nil {
		return err
	}
	r.anchorTime()
	return nil
}

// anchorTime holds the decision's issue time to the anchor block's time. The
// block time comes from an archived header, so it counts only once header
// trust tied that header to the chain; a time the verifier cannot trust never
// fails the decision. The check is listed before header trust.
func (r *run) anchorTime() {
	c := Check{Name: CheckAnchorTime, Status: StatusPass}
	if ht, ok := r.rep.Check(CheckHeaderTrust); !ok || ht.Status != StatusPass {
		c = Check{
			Name: CheckAnchorTime, Status: StatusUnchecked, Reason: ReasonBlocked,
			Err: errors.New("header trust did not pass, so the anchor block time is not trusted"), Sources: []string{string(CheckHeaderTrust)},
		}
	} else if err := commitment.CheckAnchorTime(r.c, r.facts.BlockTime, r.v.cfg.Params); err != nil {
		c = Check{Name: CheckAnchorTime, Status: StatusFail, Err: err}
	}
	for i, o := range r.rep.Checks {
		if o.Name == CheckHeaderTrust {
			r.rep.Checks = slices.Insert(r.rep.Checks, i, c)
			return
		}
	}
	r.rep.Checks = append(r.rep.Checks, c)
}

// anchor runs the DA's anchor verifier and holds its facts to the rules that
// do not depend on the DA.
func (r *run) anchor() (bool, error) {
	ref := r.c.PayloadRef
	av := r.v.anchors[ref.DA]
	if av == nil {
		r.unchecked(CheckAnchor, ReasonDAUnsupported, fmt.Errorf("%w: da %d", ErrAnchorUnsupported, ref.DA))
		return false, nil
	}
	ev, err := r.v.archive.Evidence(r.ctx, ref.DA, ref.Commitment)
	if err != nil {
		if !soft(err) {
			return false, fmt.Errorf("verifier: archive evidence: %w", err)
		}
		r.archiveProblem(CheckAnchor, ReasonEvidenceUnavailable, err)
		return false, nil
	}
	if ev.Height != ref.Height {
		r.corrupt(CheckAnchor, ErrAnchorInvalid, fmt.Errorf("evidence is for height %d, the decision names %d", ev.Height, ref.Height))
		return false, nil
	}
	facts, err := r.evidenceFacts(av, ref, ev)
	if errors.Is(err, ErrAnchorUnsupported) {
		r.unchecked(CheckAnchor, ReasonDAUnsupported, err)
		return false, nil
	}
	if err != nil {
		r.corrupt(CheckAnchor, ErrAnchorInvalid, err)
		return false, nil
	}
	r.adoptFacts(facts)
	r.pass(CheckAnchor)
	return true, nil
}

// evidenceFacts runs the anchor verifier on ev, read as the evidence at
// ref.Height, and holds its facts to the rules that do not depend on the DA.
// An error wrapping ErrAnchorUnsupported means the verifier declined the da;
// any other error is evidence that does not verify.
func (r *run) evidenceFacts(av AnchorVerifier, ref commitment.PayloadRef, ev *archive.EvidenceRecord) (AnchorFacts, error) {
	facts, err := av.VerifyAnchor(ref, ev)
	if err != nil {
		return AnchorFacts{}, err
	}
	if facts.Settlement != "" && facts.Settlement != settlementNodeAttested {
		return AnchorFacts{}, fmt.Errorf("settlement level %q is not reported", facts.Settlement)
	}
	if ref.DA == commitment.DAFibre {
		if facts.Settlement != settlementNodeAttested {
			return AnchorFacts{}, errors.New("a da = 1 anchor must report the node-attested settlement")
		}
		if p := facts.CertTokenPrecision; p != precisionRobust && p != precisionBucketDependent {
			return AnchorFacts{}, fmt.Errorf("certificate token precision %q is neither %s nor %s", p, precisionRobust, precisionBucketDependent)
		}
	}
	if len(facts.AnchorHeaderHash) == 0 {
		return AnchorFacts{}, fmt.Errorf("no header hash for height %d", ref.Height)
	}
	if ref.DA == commitment.DAFibre {
		if ev.PromiseHeight == 0 {
			return AnchorFacts{}, errors.New("evidence has no promise height")
		}
		if facts.PromiseHeight != ev.PromiseHeight {
			return AnchorFacts{}, fmt.Errorf("promise height %d, the evidence names %d", facts.PromiseHeight, ev.PromiseHeight)
		}
		if facts.PromiseHeight > ref.Height {
			return AnchorFacts{}, fmt.Errorf("promise height %d is above the anchor height %d", facts.PromiseHeight, ref.Height)
		}
		if len(facts.PromiseHeaderHash) == 0 {
			return AnchorFacts{}, fmt.Errorf("no header hash for height %d", facts.PromiseHeight)
		}
		if facts.PromiseHeight == ref.Height && !bytes.Equal(facts.PromiseHeaderHash, facts.AnchorHeaderHash) {
			return AnchorFacts{}, fmt.Errorf("two different headers at height %d", ref.Height)
		}
		if want, ok := uploadSize(r.c.PayloadSize); !ok || facts.PromiseBlobSize != want {
			return AnchorFacts{}, fmt.Errorf("promise blob size %d does not match the committed payload size %d", facts.PromiseBlobSize, r.c.PayloadSize)
		}
		if facts.ProofForm != 1 {
			return AnchorFacts{}, fmt.Errorf("anchor proof form %d", facts.ProofForm)
		}
		if facts.CandidatesEarlier < 0 {
			return AnchorFacts{}, fmt.Errorf("%d earlier candidates", facts.CandidatesEarlier)
		}
		if facts.CertTotalPower <= 0 || facts.CertSignedPower < 0 || facts.CertSignedPower > facts.CertTotalPower {
			return AnchorFacts{}, fmt.Errorf("certificate powers %d of %d", facts.CertSignedPower, facts.CertTotalPower)
		}
	}
	return facts, nil
}

// adoptFacts makes verified anchor facts the run's and reports them.
func (r *run) adoptFacts(facts AnchorFacts) {
	r.facts = &facts
	r.rep.BlockTime = facts.BlockTime
	r.rep.RetentionStart = facts.RetentionStart
	r.rep.Settlement = facts.Settlement
	if r.c.PayloadRef.DA == commitment.DAFibre {
		r.cert(facts)
		r.rep.AnchorProofForm = facts.ProofForm
		r.rep.AnchorCandidatesEarlier = facts.CandidatesEarlier
		if facts.CandidatesEarlier > 0 {
			r.warn("anchor: %d other promises for this blob are earlier; their result codes are not archived, so the retention start rests on the creation time the gate recorded", facts.CandidatesEarlier)
		}
	}
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

// UploadSize is the paid upload size of a blob: 4096 bytes times the row
// size, which is the encoded length (5-byte header included) in 4096-byte
// rows, rounded up to a multiple of 64 rows.
func UploadSize(payloadSize uint64) (uint64, bool) { return uploadSize(payloadSize) }

func uploadSize(payloadSize uint64) (uint64, bool) {
	const maxPayload = 1 << 27
	if payloadSize == 0 || payloadSize > maxPayload {
		return 0, false
	}
	row := (payloadSize + 5 + 4095) / 4096
	row = (row + 63) / 64 * 64
	return row * 4096, true
}

type headerAt struct {
	height uint64
	hash   []byte
}

func (r *run) neededHeaders() []headerAt {
	hs := []headerAt{{r.c.PayloadRef.Height, r.facts.AnchorHeaderHash}}
	if r.c.PayloadRef.DA == commitment.DAFibre {
		hs = append(hs, headerAt{r.facts.PromiseHeight, r.facts.PromiseHeaderHash})
	}
	return hs
}

func (r *run) headerTrust() error { return r.trustHeaders(r.neededHeaders()) }

// trustHeaders ties every header the anchor check relied on to the chain.
func (r *run) trustHeaders(headers []headerAt) error {
	if r.v.trust == nil {
		r.rep.HeaderTrust.Status = TrustUnchecked
		r.unchecked(CheckHeaderTrust, ReasonNoTrustedHeader, errors.New("no trusted header supplied"))
		return nil
	}
	t, err := r.tallyTrust(headers)
	if err != nil {
		return err
	}
	r.applyTrust(headers, t)
	return nil
}

// trustTally is what header trust said about a set of headers, before any
// of it is written to the report.
type trustTally struct {
	cpH       uint64
	cpHash    []byte
	lastCross string
	cross     string
	checked   bool
	problem   error
	// tied holds the heights whose hash header trust tied to the chain;
	// refused those whose hash the trusted chain does not have.
	tied    map[uint64]bool
	refused map[uint64]bool
}

// tallyTrust asks header trust about every header once. Only a cancelled
// context is an error.
func (r *run) tallyTrust(headers []headerAt) (trustTally, error) {
	t := trustTally{checked: true, tied: map[uint64]bool{}, refused: map[uint64]bool{}}
	note := func(err error) {
		// A disagreement between sources outranks the other problems: it is
		// the one the auditor must look at.
		if t.problem == nil || (!isDisagreement(t.problem) && isDisagreement(err)) {
			t.problem = err
		}
	}
	for i, h := range headers {
		height := h.height
		res, err := r.v.trust.Trusted(r.ctx, height, h.hash)
		if cerr := r.ctx.Err(); cerr != nil {
			return trustTally{}, fmt.Errorf("verifier: %w", cerr)
		}
		if i == 0 || res.CheckpointH != 0 {
			t.cpH, t.cpHash = res.CheckpointH, bytes.Clone(res.CheckpointHash)
		}
		if res.CrossCheck != "" {
			t.lastCross = res.CrossCheck
		}
		if err != nil {
			p := trustProblem(height, err)
			if reason, _, _ := ReasonOf(p); reason == ReasonChainMismatch {
				t.refused[height] = true
			}
			note(p)
			continue
		}
		if !res.Checked {
			t.checked = false
			note(Reasonf(ReasonNoTrustedHeader, nil, "%w: height %d was not checked", ErrHeaderTrust, height))
			continue
		}
		switch res.CrossCheck {
		case CrossMismatch:
			t.lastCross = CrossMismatch
			note(Reasonf(ReasonHeaderDisagreement, nil, "%w: height %d: %s", ErrHeaderTrust, height, DisagreementText))
		case CrossPass, CrossUnavailable, CrossOff:
			t.cross = worseCross(t.cross, res.CrossCheck)
			t.tied[height] = true
		default:
			note(Reasonf(ReasonHeaderSourceUnavailable, nil, "%w: height %d: unknown cross-check result %q", ErrHeaderTrust, height, res.CrossCheck))
		}
	}
	return t, nil
}

// applyTrust writes a tally to the header_trust check and report.
func (r *run) applyTrust(headers []headerAt, t trustTally) {
	ht := &r.rep.HeaderTrust
	ht.Hashes = make(map[uint64][]byte, len(headers))
	for _, h := range headers {
		ht.Hashes[h.height] = h.hash
	}
	ht.CheckpointH, ht.CheckpointHash, ht.CrossCheck = t.cpH, t.cpHash, t.lastCross
	if t.problem != nil {
		ht.Status = TrustUnchecked
		reason, srcs, _ := ReasonOf(t.problem)
		r.unchecked(CheckHeaderTrust, reason, t.problem, srcs...)
		return
	}
	ht.CrossCheck = t.cross
	if !t.checked {
		ht.Status = TrustUnchecked
		r.unchecked(CheckHeaderTrust, ReasonNoTrustedHeader, errors.New("header trust did not check the headers"))
		return
	}
	if t.cross == CrossUnavailable {
		r.warn("header trust: cross-check not done, no endpoint answered")
	}
	ht.Status = TrustValid
	r.pass(CheckHeaderTrust)
}

func isDisagreement(err error) bool {
	re, _, ok := ReasonOf(err)
	return ok && re == ReasonHeaderDisagreement
}

// trustProblem gives an error of header trust its reason. An error that
// carries none is classified by what it wraps: input trouble means no header
// source gave what was needed, and anything else means the header the
// decision names is not on the trusted chain.
func trustProblem(height uint64, err error) error {
	reason, srcs, ok := ReasonOf(err)
	if !ok {
		reason = ReasonChainMismatch
		if errors.Is(err, ErrTrustInput) {
			reason = ReasonHeaderSourceUnavailable
		}
	}
	return WithReason(reason, srcs, fmt.Errorf("%w: height %d: %w", ErrHeaderTrust, height, err))
}

// worseCross keeps the less assuring of two cross-check results.
func worseCross(a, b string) string {
	rank := map[string]int{"": 0, CrossPass: 1, CrossOff: 2, CrossUnavailable: 3}
	if rank[b] > rank[a] {
		return b
	}
	return a
}

// receipt checks the given receipt. A receipt that does not decode or verify
// is a bad file, and one that verifies but is not this decision's does not
// say anything about it: both are unchecked.
func (r *run) receipt(signed []byte) {
	mismatch := func(err error) {
		r.unchecked(CheckReceipt, ReasonReceiptMismatch, fmt.Errorf("%w: %w", ErrReceiptInvalid, err))
	}
	sr, _, err := commitment.VerifyReceipt(signed)
	if err != nil {
		r.corrupt(CheckReceipt, ErrReceiptInvalid, err)
		return
	}
	rc := &sr.Receipt
	switch {
	case !bytes.Equal(rc.CommitmentHash, r.h[:]):
		mismatch(errors.New("receipt is for another decision"))
		return
	case rc.GateID != r.c.Scope.GateID:
		mismatch(errors.New("receipt gate id differs from the decision's scope"))
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
		mismatch(errors.New("receipt is signed by a key that is not a configured gate key"))
		return
	}
	r.rep.Receipt = &ReceiptInfo{RailRef: rc.RailRef, RecordedAt: rc.RecordedAt, GateAttested: true}
	r.pass(CheckReceipt)
}

// finish sets the verdict: any failed step invalidates; otherwise a decision
// with no record says nothing; otherwise one that was not authorized says so;
// otherwise anything unchecked keeps it from being valid.
func (r *run) finish() {
	if _, ok := r.rep.Check(CheckExecution); r.execRequested && !ok {
		r.unchecked(CheckExecution, ReasonBlocked, errors.New("the decision did not get far enough to check the execution"), r.firstOther(CheckExecution))
	}
	if r.rep.GateIntegrity.Status == "" {
		r.rep.GateIntegrity.Status = IntegrityNotChecked
	}
	verdict := VerdictValid
	switch {
	case r.anyStatus(StatusFail):
		verdict = VerdictInvalid
	case r.rep.GateIntegrity.Status == IntegrityViolated:
		verdict = VerdictUnchecked
	case r.rep.State == archive.StateAbsent:
		verdict = VerdictUnchecked
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
	required := []CheckName{
		CheckDecision, CheckEnvelope, CheckAction, CheckAuthorization,
		CheckPayload, CheckAnchor, CheckAnchorTime, CheckHeaderTrust,
	}
	if r.execRequested {
		required = append(required, CheckExecution)
	}
	if r.v.cfg.RequirePolicy || r.policyRequired() {
		required = append(required, CheckPolicy)
	}
	for _, n := range required {
		c, ok := r.rep.Check(n)
		if !ok || c.Status != StatusPass {
			return false
		}
	}
	return true
}

// policyRequired holds when the signed data says a mandate applies: the
// agent named one (mandate_ref), or the gate authorized in fast mode, which
// needs the principal's consent.
func (r *run) policyRequired() bool {
	if r.c != nil && r.c.MandateRef != nil {
		return true
	}
	return r.sa != nil && r.sa.Authorization.Mode == commitment.ModeFast
}

// firstOther names the first check, other than skip, that did not pass, so
// that a blocked check can say what it waits for.
func (r *run) firstOther(skip CheckName) string {
	for _, c := range r.rep.Checks {
		if c.Name != skip && c.Status != StatusPass {
			return string(c.Name)
		}
	}
	return string(CheckAuthorization)
}

// passedAll reports whether every named check ran and passed.
func (r *run) passedAll(names ...CheckName) bool {
	for _, n := range names {
		if c, ok := r.rep.Check(n); !ok || c.Status != StatusPass {
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

// policy runs the policy check on the verified decision. It is skipped when
// the action did not verify, when the decision is not authorized, and when the archive holds no allow record and
// the auditor did not require one.
func (r *run) policy() error {
	if r.c == nil || r.rep.State != archive.StateAuthorized {
		return nil
	}
	// A private action without the key still lets the public part of the
	// policy check run: the allow, the links and the forks.
	if c, _ := r.rep.Check(CheckAction); r.action == nil && c.Reason != ReasonPolicyPrivate {
		return nil
	}
	in := policyInput{
		Hash: r.h, AgentPub: r.c.AgentPubKey, ActionType: r.c.Action.Type, Action: r.action,
		ActionHash: r.c.Action.Hash, ValidUntil: r.c.ValidUntil, GateID: r.c.Scope.GateID,
		MandateRef:    r.c.MandateRef,
		RequirePolicy: r.policyRequired(),
	}
	if r.sa != nil && r.sa.Authorization.Mode == commitment.ModeFast {
		in.FastMode, in.H0, in.AnchorDeadline = true, r.c.PayloadRef.Height, r.sa.Authorization.AnchorDeadline
	}
	if r.authKey != nil {
		in.GateKeys = []ed25519.PublicKey{r.authKey}
	} else {
		in.GateKeys = r.v.cfg.GateKeys
	}
	if ht, ok := r.rep.Check(CheckHeaderTrust); ok && ht.Status == StatusPass && r.facts != nil {
		in.TH, in.THVerified = r.facts.BlockTime, true
	}
	out, err := r.v.checkPolicy(r.ctx, in)
	if err != nil {
		return err
	}
	if !out.Ran {
		return nil
	}
	r.rep.Checks = append(r.rep.Checks, out.Check)
	r.rep.Policy = out.Info
	r.rep.GateIntegrity = out.Integrity
	return nil
}
