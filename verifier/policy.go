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

// DefaultMaxWalkSteps caps the walk, and with it the memory of the fork
// search, when the auditor sets no cap. A longer chain is not walked to
// genesis by default and its gate_integrity stays unchecked.
const DefaultMaxWalkSteps = 10000

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
	// MandateRef comes from the verified envelope.
	MandateRef []byte
	// RequirePolicy makes the check required for this decision whatever the
	// configuration: a fast-mode Authorization is valid only with the
	// mandate's consent, which only the allow record shows.
	RequirePolicy bool
	// FastMode is an Authorization with mode 2; H0 is the reference height
	// and AnchorDeadline the deadline it states.
	FastMode       bool
	H0             uint64
	AnchorDeadline uint64
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
	// srcUnsupported: the mandate decodes, but its principal scheme is not
	// one this verifier accepts, so its signature was not checked.
	srcUnsupported
	// srcPrivate: the record is a private blob no configured key opens.
	srcPrivate
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
	walkTrunc bool
	walkInfo  *WalkInfo
	violation [][]byte
	violHash  []commitment.Hash
	info      *PolicyInfo
	stepOneOK bool
	mandRef   MandateRefStatus
	held      []policy.Held
	heldRaw   map[commitment.Hash][]byte

	// Private mode. signed holds every held verdict as signed, for the fork
	// search that works without the key; ppViol is the target or walked
	// verdict whose PrivatePart breaks the presence rule.
	logicals map[commitment.Hash]logicalVerdict
	kids     map[commitment.Hash][]byte
	private  bool
	noKey    bool
	ppViol   []byte
	signed   []signedVerdict
	target   *policy.Verdict
}

type signedVerdict struct {
	v    *policy.Verdict
	hash commitment.Hash
}

// checkPolicy runs the policy check. The error is operational only.
func (v *Verifier) checkPolicy(ctx context.Context, in policyInput) (policyOutcome, error) {
	p := &policyRun{
		v: v, ctx: ctx, in: in,
		mandates: map[commitment.Hash]*policy.Mandate{}, badMand: map[commitment.Hash]srcStatus{},
		heldRaw: map[commitment.Hash][]byte{}, logicals: map[commitment.Hash]logicalVerdict{},
		kids: map[commitment.Hash][]byte{},
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
	var body []byte
	rec, err := p.rd.Mandate(p.ctx, h)
	switch {
	case err == nil:
		body = rec.SignedMandate
	case errors.Is(err, archive.ErrNotFound):
		// A private mandate is archived only sealed to its auditors.
		pt, kid, st, perr := p.v.readPrivate(p.ctx, policy.PrivateMandate, h, h, "")
		if perr != nil {
			return nil, 0, perr
		}
		if st != srcOK {
			return remember(st)
		}
		body = pt
		p.kids[h] = kid
	case errors.Is(err, archive.ErrCorrupt):
		return remember(srcCorrupt)
	default:
		return nil, 0, fmt.Errorf("verifier: archive mandate: %w", err)
	}
	dm, mh, err := policy.DecodeSignedMandate(body)
	if err != nil || mh != h {
		return remember(srcCorrupt)
	}
	scheme, err := dm.Mandate.Scheme()
	if err != nil {
		return remember(srcCorrupt)
	}
	if !p.v.cfg.principalSchemeAccepted(scheme) {
		return remember(srcUnsupported)
	}
	sm, _, err := policy.VerifyMandate(body)
	if err != nil {
		return remember(srcCorrupt)
	}
	p.mandates[h] = &sm.Mandate
	return &sm.Mandate, srcOK, nil
}

func (p *policyRun) loadSet(root []byte, m *policy.Mandate) (policy.ClosedSet, srcStatus, error) {
	empty := policy.EmptyClosedSet()
	if eh, err := policy.HashClosedSet(&empty); err == nil && bytes.Equal(eh[:], root) {
		return empty, srcOK, nil
	}
	if m != nil && len(m.Auditors) > 0 {
		pt, st, err := p.privateStruct(policy.PrivateClosedSet, root, m)
		if err != nil || st != srcOK {
			return policy.ClosedSet{}, st, err
		}
		set, err := policy.DecodeClosedSet(pt)
		if err != nil {
			return policy.ClosedSet{}, srcCorrupt, nil
		}
		return *set, srcOK, nil
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

func (p *policyRun) loadBucket(ref policy.ClosedRef, m *policy.Mandate) (policy.Bucket, srcStatus, error) {
	if m != nil && len(m.Auditors) > 0 {
		pt, st, err := p.privateStruct(policy.PrivateBucket, ref.Hash, m)
		if err != nil || st != srcOK {
			return policy.Bucket{}, st, err
		}
		b, err := policy.DecodeBucket(pt)
		if err != nil {
			return policy.Bucket{}, srcCorrupt, nil
		}
		return *b, srcOK, nil
	}
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
	switch st {
	case srcMissing:
		return ReasonStateHistoryUnavailable
	case srcUnsupported:
		return ReasonPrincipalSchemeUnsupported
	case srcPrivate:
		return ReasonPolicyPrivate
	}
	return ReasonSourceCorrupt
}

func (p *policyRun) run() (policyOutcome, error) {
	var out policyOutcome
	// An agent-signed mandate_ref says a mandate applies, so its verdict is
	// required whatever the auditor configured.
	required := p.v.cfg.RequirePolicy || p.in.RequirePolicy || p.in.MandateRef != nil
	if p.rd == nil {
		if !required {
			return out, nil
		}
		return p.finish(p.unchecked(ReasonPolicyVerdictUnavailable, errors.New("the archive reads no policy records")))
	}
	allow, st, err := p.loadAllow(p.in.Hash)
	if err != nil {
		return out, err
	}
	switch {
	case st == srcMissing && !required:
		return out, nil
	case st == srcMissing:
		return p.finish(p.unchecked(ReasonPolicyVerdictUnavailable, errors.New("no policy_allow record for the decision")))
	case st == srcCorrupt:
		return p.finish(p.unchecked(ReasonSourceCorrupt, errors.New("the policy_allow record does not verify")))
	}
	p.stepOneOK = true
	v := &allow.sv.Verdict
	p.target = v
	if !bytes.Equal(v.ActionHash, p.in.ActionHash) || !bytes.Equal(v.AgentPubKey, p.in.AgentPub) || v.GateID != p.in.GateID {
		p.violate(allow.raw)
	}
	m0, mst, err := p.loadMandate(commitment.Hash(v.MandateHash))
	if err != nil {
		return out, err
	}
	p.noKey = mst == srcPrivate
	p.private = p.noKey || (m0 != nil && len(m0.Auditors) > 0) || (m0 == nil && v.Private())
	if p.private {
		p.info = &PolicyInfo{MandateHash: commitment.Hash(v.MandateHash), Mode: PolicyModePrivate}
	}
	// Both sides are signed: the agent's mandate_ref and the gate's verdict.
	// An absent reference is the agent's omission, which the envelope alone
	// cannot turn into a finding about the gate.
	switch {
	case p.in.MandateRef == nil:
		p.mandRef = MandateRefAbsent
	case bytes.Equal(p.in.MandateRef, v.MandateHash):
		p.mandRef = MandateRefMatch
	default:
		p.mandRef = MandateRefMismatch
		p.setFail("mandate_ref_mismatch", fmt.Errorf("decision names mandate %x, allow is under %x", p.in.MandateRef, v.MandateHash))
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

// fast reads and verifies the allow, its mandate and its history, then
// evaluates it on the signed state. It returns the mandate when it
// could be read.
func (p *policyRun) fast(allow *allowRec) (*policy.Mandate, error) {
	v := &allow.sv.Verdict

	m, st, err := p.loadMandate(commitment.Hash(v.MandateHash))
	if err != nil {
		return nil, err
	}
	if st != srcOK {
		reason, msg := ReasonPolicyMandateUnavailable, "the mandate record does not read"
		switch st {
		case srcPrivate:
			// Without an auditor key only step 1 runs: the facts, the times,
			// the rules and the state are private.
			reason, msg = ReasonPolicyPrivate, "the mandate is private and no configured auditor key opens it"
		case srcCorrupt:
			reason = ReasonSourceCorrupt
		case srcUnsupported:
			reason, msg = ReasonPrincipalSchemeUnsupported, "the mandate's principal scheme is not in this verifier build"
		}
		p.setFast(p.unchecked(reason, errors.New(msg)))
		return nil, nil
	}
	p.fillInfo(allow, v, m)
	if !p.principalTrusted(m) {
		p.setFast(p.unchecked(ReasonPolicyPrincipalUntrusted, errors.New("the mandate's principal is not a trusted key")))
		return m, nil
	}
	if m.GateID != v.GateID {
		p.setFail("mandate_gate_id", fmt.Errorf("mandate for gate %q, verdict of gate %q", m.GateID, v.GateID))
		return m, nil
	}
	if v.Private() != (len(m.Auditors) > 0) {
		// The form follows the mandate; a gate that signs the other one
		// contradicts its own mandate.
		p.violate(allow.raw)
		return m, nil
	}
	if v.Private() {
		l, err := p.logical(v, m)
		if err != nil {
			return m, err
		}
		switch l.st {
		case logicalSource:
			reason := missingReason(l.src)
			p.setFast(p.unchecked(reason, errors.New("the PrivatePart of the verdict does not read")))
			return m, nil
		case logicalInconsistent:
			p.violate(allow.raw)
			return m, nil
		case logicalSelfInconsistent:
			// The gate signed contents it could not produce honestly. The
			// policy is still judged on what the verifier derives itself.
			p.ppViol = allow.raw
			d, chk := p.derive(l.v)
			if chk != nil {
				p.setFast(chk)
				return m, nil
			}
			v = d
		default:
			v = l.v
		}
		p.fillInfo(allow, v, m)
	}
	if p.in.Action == nil {
		p.setFast(p.unchecked(ReasonPolicyPrivate, errors.New("the action bytes are private")))
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
		Pending: p.in.FastMode,
	})
	if aerr != nil {
		rule := policy.ReasonOf(aerr)
		if rule == "" {
			rule = "facts_mismatch"
		}
		p.setFail(rule, aerr)
		return m, nil
	}
	// The gate clamps the window to the principal's bound; a longer one
	// means it signed a deadline the principal never accepted.
	if p.in.FastMode && (p.in.AnchorDeadline < p.in.H0 || p.in.AnchorDeadline-p.in.H0 > m.FastModeMaxDelay) {
		p.setFail("fast_mode_delay", fmt.Errorf("anchor deadline %d is more than %d blocks after h0 %d",
			p.in.AnchorDeadline, m.FastModeMaxDelay, p.in.H0))
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

	if v.PrevState == nil {
		// A self-inconsistent PrivatePart without the state read: steps 5
		// and 6 have no input.
		p.setFast(p.unchecked(ReasonBlocked, errors.New("the PrivatePart holds no prev_state"), "gate_integrity"))
		return m, nil
	}
	// Closed buckets and the evaluation on the signed state.
	led, ok, err := p.ledger(v, allow.raw, m)
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

func (p *policyRun) principalTrusted(m *policy.Mandate) bool {
	for _, k := range p.v.cfg.PrincipalKeys {
		if k.Pins(m) {
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
func (p *policyRun) ledger(v *policy.Verdict, raw []byte, m *policy.Mandate) (policy.Ledger, bool, error) {
	set, st, err := p.loadSet(v.PrevState.ClosedRoot, m)
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
		b, st, err := p.loadBucket(ref, m)
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
		p.violate(raw)
		return policy.Ledger{}, false, nil
	}
	return led, true, nil
}

func (p *policyRun) fillInfo(allow *allowRec, v *policy.Verdict, m *policy.Mandate) {
	mh := commitment.Hash(v.MandateHash)
	info := &PolicyInfo{
		MandateHash: mh, MandateID: bytes.Clone(m.MandateID), Version: m.Version,
		Principal: bytes.Clone(m.Principal), AnchorTime: v.AnchorTime, EvalTime: v.EvalTime,
		ExtractorID: v.Extractor, Mode: PolicyModePublic, AuditorKid: bytes.Clone(p.kids[mh]),
	}
	if len(m.Auditors) > 0 {
		info.Mode = PolicyModePrivate
	}
	if v.PrevState != nil {
		info.Seq = v.PrevState.Seq
	}
	if v.Facts != nil {
		info.Facts = *v.Facts
	}
	if h, ok := (policy.Held{V: v, M: m}).PrevStateHash(); ok {
		info.PrevStateHash = h
	}
	copy(info.NewStateHash[:], v.NewStateHash)
	p.info = info
	p.heldRaw[allow.hash] = allow.raw
}

func (p *policyRun) denials() error {
	// Private denies are keyed by their private_hash, which only an opened
	// PrivatePart names; a verifier may skip deny records.
	if p.info == nil || p.private {
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
	// A mismatch is reported only as the check's fail: the report names a
	// match or an absent reference, and no auditor key of a mandate the agent
	// did not commit to.
	if p.info != nil {
		if p.mandRef == MandateRefMismatch {
			p.info.AuditorKid = nil
		} else {
			p.info.MandateRef = p.mandRef
		}
	}
	out.Integrity = GateIntegrity{Status: IntegrityNotChecked}
	switch {
	case p.violation != nil:
		out.Integrity = GateIntegrity{
			Status: IntegrityViolated, Reason: ReasonGateEquivocation, Evidence: p.violation, EvidenceHashes: p.violHash,
		}
	case p.ppViol != nil:
		_, h, _ := policy.DecodeSignedVerdict(p.ppViol)
		out.Integrity = GateIntegrity{
			Status: IntegrityViolated, Reason: ReasonGateSignedInconsistentPrivatePart,
			Evidence: [][]byte{bytes.Clone(p.ppViol)}, EvidenceHashes: []commitment.Hash{h},
		}
	case p.stepOneOK && p.v.cfg.PolicyFull && p.walkUnchk != nil:
		out.Integrity = GateIntegrity{Status: IntegrityUnchecked, Reason: p.walkUnchk.Reason}
	case p.stepOneOK && p.v.cfg.PolicyFull && p.walkTrunc:
		out.Integrity = GateIntegrity{Status: IntegrityUnchecked, Reason: ReasonPolicyWalkTruncated}
	case p.stepOneOK && p.v.cfg.PolicyFull:
		out.Integrity = GateIntegrity{Status: IntegrityOK}
	}
	out.Integrity.Walk = p.walkInfo
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
		walk := p.walk
		if p.private {
			walk = p.walkPrivate
		}
		if err := walk(allow, m); err != nil {
			return err
		}
	}
	if len(p.signed) == 0 {
		p.signed = append(p.signed, signedVerdict{v: &allow.sv.Verdict, hash: allow.hash})
		p.heldRaw[allow.hash] = allow.raw
	}
	if m != nil && !p.private {
		cur := policy.Held{V: &allow.sv.Verdict, Hash: allow.hash, M: m}
		if len(p.held) == 0 {
			p.held = append(p.held, cur)
		}
	}
	if p.violation != nil {
		return nil
	}
	if p.v.cfg.PolicyFull && !p.noKey {
		if err := p.successors(); err != nil {
			return err
		}
	}
	if err := p.addEvidence(); err != nil {
		return err
	}
	if p.private {
		p.forkPrivate()
		return nil
	}
	p.findFork()
	return nil
}

// findFork indexes the held verdicts by gate, counter and previous sequence
// number; two commitments on one key are a fork.
func (p *policyRun) findFork() {
	type slot struct {
		gate string
		ctr  [32]byte
		seq  uint64
	}
	seen := make(map[slot]policy.Held, len(p.held))
	ctrs := map[*policy.Mandate][32]byte{}
	for _, h := range p.held {
		ck, ok := ctrs[h.M]
		if !ok {
			ck = h.M.CounterKey()
			ctrs[h.M] = ck
		}
		k := slot{h.V.GateID, ck, h.V.PrevState.Seq}
		if o, ok := seen[k]; ok && policy.IsFork(o, h) {
			p.violate(p.heldRaw[o.Hash], p.heldRaw[h.Hash])
			return
		}
		seen[k] = h
	}
}

func (p *policyRun) walkStop(st srcStatus) {
	p.walkUnchk = p.unchecked(missingReason(st), errors.New("a record the walk needs does not read"))
}

func (p *policyRun) walk(allow *allowRec, m *policy.Mandate) error {
	maxSteps := uint64(p.v.cfg.MaxWalkSteps)
	if maxSteps == 0 {
		maxSteps = DefaultMaxWalkSteps
	}
	toSeq := allow.sv.Verdict.PrevState.Seq
	info := &WalkInfo{MaxSteps: maxSteps, FromSeq: toSeq, ToSeq: toSeq, Total: toSeq + 1, End: WalkEndFinding}
	p.walkInfo = info
	if m == nil {
		p.walkUnchk = p.unchecked(ReasonStateHistoryUnavailable, errors.New("the mandate of the verdict does not read"))
		return nil
	}
	cur := policy.Held{V: &allow.sv.Verdict, Hash: allow.hash, M: m}
	p.held = []policy.Held{cur}
	scales := policy.NewScaleChain()
	for cur.V.PrevState.Seq > 0 {
		if info.Steps >= maxSteps {
			info.End = WalkEndMaxSteps
			p.walkTrunc = true
			return nil
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
		set, st, err := p.loadSet(pa.sv.Verdict.PrevState.ClosedRoot, pm)
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
		scales.Add(cur)
		if lerr := policy.CheckLink(prev, cur, set, scales); lerr != nil {
			var se *policy.ScaleError
			switch {
			case errors.As(lerr, &se):
				p.violate(pa.raw, p.heldRaw[se.With.Hash])
			case errors.Is(lerr, policy.ErrTransition):
				p.violate(pa.raw)
			default:
				p.violate(pa.raw, p.heldRaw[cur.Hash])
			}
			return nil
		}
		cur = prev
		info.Steps++
		info.FromSeq = cur.V.PrevState.Seq
	}
	info.End = WalkEndGenesis
	return nil
}

// successors adds the verdicts the successor index points at. The index is a
// help only; every verdict it leads to is verified like any other.
func (p *policyRun) successors() error {
	walked := append([]policy.Held(nil), p.held...)
	for _, n := range walked {
		prevState, ok := n.PrevStateHash()
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
	for _, s := range p.signed {
		if s.hash == a.hash {
			return nil
		}
	}
	m, st, err := p.loadMandate(commitment.Hash(a.sv.Verdict.MandateHash))
	if err != nil {
		return err
	}
	if st != srcOK && st != srcPrivate {
		return nil
	}
	p.heldRaw[a.hash] = a.raw
	p.signed = append(p.signed, signedVerdict{v: &a.sv.Verdict, hash: a.hash})
	if st == srcOK && !p.private {
		p.held = append(p.held, policy.Held{V: &a.sv.Verdict, Hash: a.hash, M: m})
	}
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
