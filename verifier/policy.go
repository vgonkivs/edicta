package verifier

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/policy"
)

// ErrPolicyViolation wraps every failed policy check: verified data proves
// the allow broke the mandate.
var ErrPolicyViolation = errors.New("verifier: authorized in violation of the mandate")

// PolicyFailure is the error of a failed policy check. Rule is the sentinel
// name of the broken rule, or facts_mismatch, mandate_gate_id,
// anchor_time_mismatch or eval_time_mismatch.
type PolicyFailure struct {
	Rule string
	Err  error
}

func (e *PolicyFailure) Error() string {
	if e.Err == nil {
		return ErrPolicyViolation.Error() + ": " + e.Rule
	}
	return fmt.Sprintf("%s: %s: %v", ErrPolicyViolation, e.Rule, e.Err)
}

func (e *PolicyFailure) Unwrap() []error {
	if e.Err == nil {
		return []error{ErrPolicyViolation}
	}
	return []error{ErrPolicyViolation, e.Err}
}

// retentionHorizon is how far back the integrity walk goes by default.
const retentionHorizon = 32 * 24 * 3600

// policyInput is what the core checks verified about the decision, plus the
// anchor time when header trust passed.
type policyInput struct {
	Hash       commitment.Hash
	AgentPub   []byte
	ActionType string
	Action     []byte
	ActionHash []byte
	ValidUntil uint64
	GateID     string
	GateKeys   []ed25519.PublicKey
	TH         uint64
	THVerified bool
}

type policyOutcome struct {
	Ran       bool
	Check     Check
	Integrity GateIntegrity
	Info      *PolicyInfo
}

type srcStatus int

const (
	srcOK srcStatus = iota
	srcMissing
	srcCorrupt
)

type sourceProblem struct {
	missing bool
	err     error
}

type allowRec struct {
	sv   *policy.SignedVerdict
	hash commitment.Hash
	raw  []byte
}

type policyRun struct {
	v   *Verifier
	ctx context.Context
	in  policyInput
	rd  archive.PolicyReader

	mandates map[commitment.Hash]*policy.Mandate
	badMand  map[commitment.Hash]srcStatus

	fail      *PolicyFailure
	fastUnchk *Check
	walkUnchk *Check
	violation [][]byte
	violHash  []commitment.Hash
	info      *PolicyInfo
	stepOneOK bool
	held      []policy.Held
	heldRaw   map[commitment.Hash][]byte
}

// checkPolicy runs the policy check. The error is operational only.
func (v *Verifier) checkPolicy(ctx context.Context, in policyInput) (policyOutcome, error) {
	p := &policyRun{
		v: v, ctx: ctx, in: in,
		mandates: map[commitment.Hash]*policy.Mandate{}, badMand: map[commitment.Hash]srcStatus{},
		heldRaw: map[commitment.Hash][]byte{},
	}
	p.rd, _ = v.archive.(archive.PolicyReader)
	return p.run()
}

func (p *policyRun) unchecked(reason Reason, err error, sources ...string) *Check {
	if err == nil {
		err = errors.New(string(reason))
	}
	return &Check{Name: CheckPolicy, Status: StatusUnchecked, Err: err, Reason: reason, Sources: sources}
}

func (p *policyRun) setFast(c *Check) {
	if p.fastUnchk == nil {
		p.fastUnchk = c
	}
}

func (p *policyRun) setFail(rule string, err error) {
	if p.fail == nil {
		p.fail = &PolicyFailure{Rule: rule, Err: err}
	}
}

func (p *policyRun) violate(held ...[]byte) {
	if p.violation != nil {
		return
	}
	for _, raw := range held {
		_, h, err := policy.DecodeSignedVerdict(raw)
		if err != nil {
			continue
		}
		p.violation = append(p.violation, bytes.Clone(raw))
		p.violHash = append(p.violHash, h)
	}
}

func (p *policyRun) verifyUnder(raw []byte) (*policy.SignedVerdict, commitment.Hash, error) {
	var last error = policy.ErrVerdictSignature
	for _, k := range p.in.GateKeys {
		sv, h, err := policy.VerifyVerdict(raw, k)
		if err == nil {
			return sv, h, nil
		}
		last = err
		if !errors.Is(err, policy.ErrVerdictSignature) {
			break
		}
	}
	return nil, commitment.Hash{}, last
}

// loadAllow reads and verifies the policy_allow record of a commitment.
func (p *policyRun) loadAllow(h commitment.Hash) (*allowRec, srcStatus, error) {
	rec, err := p.rd.PolicyAllow(p.ctx, h)
	if err != nil {
		switch {
		case errors.Is(err, archive.ErrNotFound):
			return nil, srcMissing, nil
		case errors.Is(err, archive.ErrCorrupt):
			return nil, srcCorrupt, nil
		}
		return nil, 0, fmt.Errorf("verifier: archive policy allow: %w", err)
	}
	sv, vh, err := p.verifyUnder(rec.SignedVerdict)
	if err != nil || !bytes.Equal(sv.Verdict.CommitmentHash, h[:]) {
		return nil, srcCorrupt, nil
	}
	return &allowRec{sv: sv, hash: vh, raw: rec.SignedVerdict}, srcOK, nil
}

func (p *policyRun) loadMandate(h commitment.Hash) (*policy.Mandate, srcStatus, error) {
	if m, ok := p.mandates[h]; ok {
		return m, srcOK, nil
	}
	if st, ok := p.badMand[h]; ok {
		return nil, st, nil
	}
	remember := func(st srcStatus) (*policy.Mandate, srcStatus, error) {
		p.badMand[h] = st
		return nil, st, nil
	}
	rec, err := p.rd.Mandate(p.ctx, h)
	if err != nil {
		switch {
		case errors.Is(err, archive.ErrNotFound):
			return remember(srcMissing)
		case errors.Is(err, archive.ErrCorrupt):
			return remember(srcCorrupt)
		}
		return nil, 0, fmt.Errorf("verifier: archive mandate: %w", err)
	}
	sm, mh, err := policy.VerifyMandate(rec.SignedMandate)
	if err != nil || mh != h {
		return remember(srcCorrupt)
	}
	p.mandates[h] = &sm.Mandate
	return &sm.Mandate, srcOK, nil
}

func (p *policyRun) loadSet(root []byte) (policy.ClosedSet, srcStatus, error) {
	empty := policy.EmptyClosedSet()
	if eh, err := policy.HashClosedSet(&empty); err == nil && bytes.Equal(eh[:], root) {
		return empty, srcOK, nil
	}
	rec, err := p.rd.PolicyClosed(p.ctx, commitment.Hash(root))
	if err != nil {
		switch {
		case errors.Is(err, archive.ErrNotFound):
			return policy.ClosedSet{}, srcMissing, nil
		case errors.Is(err, archive.ErrCorrupt):
			return policy.ClosedSet{}, srcCorrupt, nil
		}
		return policy.ClosedSet{}, 0, fmt.Errorf("verifier: archive closed set: %w", err)
	}
	set, err := policy.DecodeClosedSet(rec.ClosedSet)
	if got := policy.HashClosedSetBytes(rec.ClosedSet); err != nil || !bytes.Equal(got[:], root) {
		return policy.ClosedSet{}, srcCorrupt, nil
	}
	return *set, srcOK, nil
}

func (p *policyRun) loadBucket(ref policy.ClosedRef) (policy.Bucket, srcStatus, error) {
	rec, err := p.rd.PolicyBucket(p.ctx, commitment.Hash(ref.Hash))
	if err != nil {
		switch {
		case errors.Is(err, archive.ErrNotFound):
			return policy.Bucket{}, srcMissing, nil
		case errors.Is(err, archive.ErrCorrupt):
			return policy.Bucket{}, srcCorrupt, nil
		}
		return policy.Bucket{}, 0, fmt.Errorf("verifier: archive bucket: %w", err)
	}
	b, err := policy.DecodeBucket(rec.Bucket)
	if got := policy.HashBucketBytes(rec.Bucket); err != nil || !bytes.Equal(got[:], ref.Hash) {
		return policy.Bucket{}, srcCorrupt, nil
	}
	return *b, srcOK, nil
}

func missingReason(st srcStatus) Reason {
	if st == srcMissing {
		return ReasonStateHistoryUnavailable
	}
	return ReasonSourceCorrupt
}

func (p *policyRun) run() (policyOutcome, error) {
	var out policyOutcome
	if p.rd == nil {
		if !p.v.cfg.RequirePolicy {
			return out, nil
		}
		return p.finish(p.unchecked(ReasonPolicyVerdictUnavailable, errors.New("the archive reads no policy records")))
	}
	allow, st, err := p.loadAllow(p.in.Hash)
	if err != nil {
		return out, err
	}
	switch {
	case st == srcMissing && !p.v.cfg.RequirePolicy:
		return out, nil
	case st == srcMissing:
		return p.finish(p.unchecked(ReasonPolicyVerdictUnavailable, errors.New("no policy_allow record for the decision")))
	case st == srcCorrupt:
		return p.finish(p.unchecked(ReasonSourceCorrupt, errors.New("the policy_allow record does not verify")))
	}
	p.stepOneOK = true
	v := &allow.sv.Verdict
	if !bytes.Equal(v.ActionHash, p.in.ActionHash) || !bytes.Equal(v.AgentPubKey, p.in.AgentPub) || v.GateID != p.in.GateID {
		p.violate(allow.raw)
	}

	m, err := p.fast(allow)
	if err != nil {
		return out, err
	}
	if err := p.integrity(allow, m); err != nil {
		return out, err
	}
	if err := p.denials(); err != nil {
		return out, err
	}
	return p.finish(nil)
}

// fast runs steps 2 to 6 of the fast check. It returns the mandate when it
// could be read.
func (p *policyRun) fast(allow *allowRec) (*policy.Mandate, error) {
	v := &allow.sv.Verdict

	m, st, err := p.loadMandate(commitment.Hash(v.MandateHash))
	if err != nil {
		return nil, err
	}
	if st != srcOK {
		reason := ReasonPolicyMandateUnavailable
		if st == srcCorrupt {
			reason = ReasonSourceCorrupt
		}
		p.setFast(p.unchecked(reason, errors.New("the mandate record does not read")))
		return nil, nil
	}
	p.fillInfo(allow, m)
	if !p.principalTrusted(m.Principal) {
		p.setFast(p.unchecked(ReasonPolicyPrincipalUntrusted, errors.New("the mandate's principal is not a trusted key")))
		return m, nil
	}
	if m.GateID != v.GateID {
		p.setFail("mandate_gate_id", fmt.Errorf("mandate for gate %q, verdict of gate %q", m.GateID, v.GateID))
		return m, nil
	}

	// Facts.
	x := p.v.extractors
	id, ok := x.ID(p.in.ActionType)
	if !ok || id != v.Extractor {
		p.setFast(p.unchecked(ReasonPolicyNoExtractor, fmt.Errorf("no extractor %q for %q", v.Extractor, p.in.ActionType)))
		return m, nil
	}
	_, got, xerr := x.Extract(p.in.ActionType, p.in.Action)
	if xerr != nil || !sameFacts(got, *v.Facts) {
		p.setFail("facts_mismatch", xerr)
		return m, nil
	}

	// Per-action rules on verified data.
	_, aerr := policy.Admit(m, x, policy.Decision{
		AgentPubKey: p.in.AgentPub, ActionType: p.in.ActionType, Action: p.in.Action, ValidUntil: p.in.ValidUntil,
	})
	if aerr != nil {
		rule := policy.ReasonOf(aerr)
		if rule == "" {
			rule = "facts_mismatch"
		}
		p.setFail(rule, aerr)
		return m, nil
	}
	if p.in.THVerified {
		switch {
		case v.AnchorTime != p.in.TH:
			p.setFail("anchor_time_mismatch", fmt.Errorf("verdict anchor_time %d, header time %d", v.AnchorTime, p.in.TH))
			return m, nil
		case p.in.TH < m.NotBefore:
			p.setFail(policy.ReasonOf(policy.ErrOutsideMandate), policy.ErrOutsideMandate)
			return m, nil
		}
	} else {
		p.setFast(p.unchecked(ReasonBlocked, errors.New("the anchor time is not verified"), string(CheckHeaderTrust)))
	}

	// Closed buckets and the evaluation on the signed state.
	led, ok, err := p.ledger(allow, m)
	if err != nil || !ok {
		return m, err
	}
	switch verr := policy.VerifyFast(m, v, led); {
	case verr == nil:
	case errors.Is(verr, policy.ErrEvalTime):
		p.setFail("eval_time_mismatch", verr)
	case errors.Is(verr, policy.ErrTransition):
		p.violate(allow.raw)
	default:
		p.setFail(policy.ReasonOf(verr), verr)
	}
	return m, nil
}

func (p *policyRun) principalTrusted(pub []byte) bool {
	for _, k := range p.v.cfg.PrincipalKeys {
		if bytes.Equal(k, pub) {
			return true
		}
	}
	return false
}

func sameFacts(a, b policy.Facts) bool {
	return a.Kind == b.Kind && a.Asset == b.Asset && a.Scale == b.Scale && a.Recipient == b.Recipient &&
		bytes.Equal(a.Amount, b.Amount)
}

// ledger fetches the closed set and the buckets the evaluation reads. ok is
// false when the fast check ended.
func (p *policyRun) ledger(allow *allowRec, m *policy.Mandate) (policy.Ledger, bool, error) {
	v := &allow.sv.Verdict
	set, st, err := p.loadSet(v.PrevState.ClosedRoot)
	if err != nil {
		return policy.Ledger{}, false, err
	}
	if st != srcOK {
		p.setFast(p.unchecked(missingReason(st), errors.New("the closed set of the signed state does not read")))
		return policy.Ledger{}, false, nil
	}
	lo := policy.MinBucketIndex(m, v)
	var closed []policy.Bucket
	for _, ref := range set.Buckets {
		if ref.Index < lo {
			continue
		}
		b, st, err := p.loadBucket(ref)
		if err != nil {
			return policy.Ledger{}, false, err
		}
		if st != srcOK {
			p.setFast(p.unchecked(missingReason(st), fmt.Errorf("closed bucket %d does not read", ref.Index)))
			return policy.Ledger{}, false, nil
		}
		closed = append(closed, b)
	}
	led, lerr := policy.NewLedger(*v.PrevState, closed, set)
	if lerr != nil {
		p.violate(allow.raw)
		return policy.Ledger{}, false, nil
	}
	return led, true, nil
}

func (p *policyRun) fillInfo(allow *allowRec, m *policy.Mandate) {
	v := &allow.sv.Verdict
	mh := commitment.Hash(v.MandateHash)
	info := &PolicyInfo{
		MandateHash: mh, MandateID: bytes.Clone(m.MandateID), Version: m.Version, Seq: v.PrevState.Seq,
		Principal: bytes.Clone(m.Principal), AnchorTime: v.AnchorTime, EvalTime: v.EvalTime,
		Facts: *v.Facts, ExtractorID: v.Extractor,
	}
	if h, ok := v.PrevStateHash(); ok {
		info.PrevStateHash = h
	}
	copy(info.NewStateHash[:], v.NewStateHash)
	p.info = info
	p.heldRaw[allow.hash] = allow.raw
}

func (p *policyRun) denials() error {
	if p.info == nil {
		return nil
	}
	for _, name := range policy.DenyReasons {
		_, err := p.rd.PolicyDeny(p.ctx, p.in.Hash, name)
		switch {
		case err == nil:
			if name == "ErrDecisionAge" {
				name += " (gate-attested)"
			}
			p.info.Denials = append(p.info.Denials, name)
		case soft(err):
		default:
			return fmt.Errorf("verifier: archive policy deny: %w", err)
		}
	}
	return nil
}

func (p *policyRun) finish(c *Check) (policyOutcome, error) {
	out := policyOutcome{Ran: true, Info: p.info}
	out.Integrity = GateIntegrity{Status: IntegrityNotChecked}
	switch {
	case p.violation != nil:
		out.Integrity = GateIntegrity{
			Status: IntegrityViolated, Reason: ReasonGateEquivocation, Evidence: p.violation, EvidenceHashes: p.violHash,
		}
	case p.stepOneOK && p.v.cfg.PolicyFull && p.walkUnchk != nil:
		out.Integrity = GateIntegrity{Status: IntegrityUnchecked, Reason: p.walkUnchk.Reason}
	case p.stepOneOK && p.v.cfg.PolicyFull:
		out.Integrity = GateIntegrity{Status: IntegrityOK}
	}
	switch {
	case c != nil:
		out.Check = *c
	case p.fail != nil:
		out.Check = Check{Name: CheckPolicy, Status: StatusFail, Err: p.fail}
	case p.violation != nil:
		out.Check = *p.unchecked(ReasonBlocked, errors.New("the gate contradicted itself"), "gate_integrity")
	case p.fastUnchk != nil:
		out.Check = *p.fastUnchk
	case p.walkUnchk != nil:
		out.Check = *p.walkUnchk
	default:
		out.Check = Check{Name: CheckPolicy, Status: StatusPass}
	}
	return out, nil
}

// integrity runs the walk and the fork search.
func (p *policyRun) integrity(allow *allowRec, m *policy.Mandate) error {
	if p.violation == nil && p.v.cfg.PolicyFull {
		if err := p.walk(allow, m); err != nil {
			return err
		}
	}
	if m != nil {
		cur := policy.Held{V: &allow.sv.Verdict, Hash: allow.hash, M: m}
		if len(p.held) == 0 {
			p.held = append(p.held, cur)
		}
	}
	if p.violation != nil {
		return nil
	}
	if p.v.cfg.PolicyFull {
		if err := p.successors(); err != nil {
			return err
		}
	}
	if err := p.addEvidence(); err != nil {
		return err
	}
	for i := range p.held {
		for j := i + 1; j < len(p.held); j++ {
			if policy.IsFork(p.held[i], p.held[j]) {
				p.violate(p.heldRaw[p.held[i].Hash], p.heldRaw[p.held[j].Hash])
				return nil
			}
		}
	}
	return nil
}

func (p *policyRun) walkStop(st srcStatus) {
	p.walkUnchk = p.unchecked(missingReason(st), errors.New("a record the walk needs does not read"))
}

func (p *policyRun) walk(allow *allowRec, m *policy.Mandate) error {
	if m == nil {
		p.walkUnchk = p.unchecked(ReasonStateHistoryUnavailable, errors.New("the mandate of the verdict does not read"))
		return nil
	}
	cur := policy.Held{V: &allow.sv.Verdict, Hash: allow.hash, M: m}
	p.held = []policy.Held{cur}
	target := cur.V
	for hops := 0; cur.V.PrevState.Seq > 0; hops++ {
		if d := p.v.cfg.PolicyDepth; d > 0 && hops >= d {
			break
		}
		if cur.V.PrevState.LastT+retentionHorizon < target.EvalTime {
			break
		}
		pa, st, err := p.loadAllow(commitment.Hash(cur.V.PrevCommitmentHash))
		if err != nil {
			return err
		}
		if st != srcOK {
			p.walkStop(st)
			return nil
		}
		pm, st, err := p.loadMandate(commitment.Hash(pa.sv.Verdict.MandateHash))
		if err != nil {
			return err
		}
		if st != srcOK {
			p.walkStop(st)
			return nil
		}
		set, st, err := p.loadSet(pa.sv.Verdict.PrevState.ClosedRoot)
		if err != nil {
			return err
		}
		if st != srcOK {
			p.walkStop(st)
			return nil
		}
		prev := policy.Held{V: &pa.sv.Verdict, Hash: pa.hash, M: pm}
		p.heldRaw[pa.hash] = pa.raw
		p.held = append(p.held, prev)
		if lerr := policy.CheckLink(prev, cur, set); lerr != nil {
			if errors.Is(lerr, policy.ErrTransition) {
				p.violate(pa.raw)
			} else {
				p.violate(pa.raw, p.heldRaw[cur.Hash])
			}
			return nil
		}
		cur = prev
	}
	return nil
}

// successors adds the verdicts the successor index points at. The index is a
// help only; every verdict it leads to is verified like any other.
func (p *policyRun) successors() error {
	walked := append([]policy.Held(nil), p.held...)
	for _, n := range walked {
		prevState, ok := n.V.PrevStateHash()
		if !ok {
			continue
		}
		key := policy.SuccessorKey(n.V.GateID, n.M.CounterKey(), prevState)
		rec, err := p.rd.PolicySuccessor(p.ctx, key)
		if err != nil {
			if soft(err) {
				continue
			}
			return fmt.Errorf("verifier: archive policy successor: %w", err)
		}
		if bytes.Equal(rec.CommitmentHash, n.V.CommitmentHash) {
			continue
		}
		other, st, err := p.loadAllow(commitment.Hash(rec.CommitmentHash))
		if err != nil {
			return err
		}
		if st != srcOK {
			continue
		}
		if err := p.hold(other); err != nil {
			return err
		}
	}
	return nil
}

func (p *policyRun) hold(a *allowRec) error {
	for _, h := range p.held {
		if h.Hash == a.hash {
			return nil
		}
	}
	m, st, err := p.loadMandate(commitment.Hash(a.sv.Verdict.MandateHash))
	if err != nil {
		return err
	}
	if st != srcOK {
		return nil
	}
	p.heldRaw[a.hash] = a.raw
	p.held = append(p.held, policy.Held{V: &a.sv.Verdict, Hash: a.hash, M: m})
	return nil
}

func (p *policyRun) addEvidence() error {
	for _, raw := range p.v.cfg.Evidence {
		sv, h, err := p.verifyUnder(raw)
		if err != nil || sv.Verdict.Outcome != policy.OutcomeAllow {
			continue
		}
		if err := p.hold(&allowRec{sv: sv, hash: h, raw: raw}); err != nil {
			return err
		}
	}
	return nil
}
