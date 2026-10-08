package gate

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/gate/registry"
	"github.com/vgonkivs/edicta/policy"
)

// ErrPolicyStateConflict means the counter cell changed under the gate's
// compare-and-swap, or holds another mandate. Nothing was written; the
// request may be retried.
var ErrPolicyStateConflict = errors.New("gate: policy state changed concurrently")

// policyGate holds what the gate needs when a mandate is configured.
type policyGate struct {
	mandate     *policy.Mandate
	mandateHash commitment.Hash
	key         registry.StateKey
	state       registry.StateRegistry
	extractors  *policy.Extractors
	mu          chan struct{} // capacity 1; held from the cell read through ConsumeState
}

// setupPolicy validates the mandate against the dependencies and adopts it.
func (g *Gate) setupPolicy(ctx context.Context) error {
	bad := func(format string, a ...any) error {
		return fmt.Errorf("%w: %s", ErrInvalidConfig, fmt.Sprintf(format, a...))
	}
	sm, h, err := policy.VerifyMandate(g.cfg.Mandate)
	if err != nil {
		return fmt.Errorf("%w: mandate: %w", ErrInvalidConfig, err)
	}
	m := &sm.Mandate
	if m.GateID != g.cfg.Scope.GateID {
		return bad("mandate is bound to gate %q, this gate is %q", m.GateID, g.cfg.Scope.GateID)
	}
	if g.d.Extractors == nil {
		return bad("a mandate needs an extractor registry")
	}
	sr, ok := g.d.Registry.(registry.StateRegistry)
	if !ok {
		return bad("a mandate needs a registry with policy state")
	}
	for _, t := range g.cfg.Scope.ActionTypes {
		if !g.d.Extractors.Has(t) {
			return bad("action type %q has no extractor", t)
		}
	}
	var pk [32]byte
	copy(pk[:], m.Principal)
	if _, ok := g.gateKeys[pk]; ok {
		return fmt.Errorf("%w: principal key is a gate key", commitment.ErrKeyRole)
	}
	if _, ok := g.executors[pk]; ok {
		return fmt.Errorf("%w: principal key is an executor key", commitment.ErrKeyRole)
	}
	hk, hasKeys := g.d.Allowlist.(hasKey)
	if hasKeys && hk.HasKey(pk) {
		return fmt.Errorf("%w: principal key is an agent key", commitment.ErrKeyRole)
	}
	for i, a := range m.Agents {
		var ak [32]byte
		copy(ak[:], a)
		if _, ok := g.gateKeys[ak]; ok {
			return fmt.Errorf("%w: mandate agent %d is a gate key", commitment.ErrKeyRole, i)
		}
		if _, ok := g.executors[ak]; ok {
			return fmt.Errorf("%w: mandate agent %d is an executor key", commitment.ErrKeyRole, i)
		}
	}
	pg := &policyGate{mandate: m, mandateHash: h, key: registry.StateKey(m.CounterKey()), state: sr,
		extractors: g.d.Extractors, mu: make(chan struct{}, 1)}
	if err := g.adopt(ctx, pg); err != nil {
		return err
	}
	g.pol = pg
	return nil
}

// adopt applies the version rules to the stored counter cell.
func (g *Gate) adopt(ctx context.Context, pg *policyGate) error {
	m := pg.mandate
	cell, err := pg.state.State(ctx, pg.key)
	if err != nil {
		return fmt.Errorf("%w: policy cell: %w", ErrRegistryUnavailable, err)
	}
	write := func(expect commitment.Hash, c *policy.Counter) error {
		enc, err := policy.EncodeCounter(c)
		if err != nil {
			return fmt.Errorf("gate: encode counter: %w", err)
		}
		err = pg.state.UpdateState(ctx, registry.StateTx{Key: pg.key, Expect: expect, Next: registry.NewStateCell(enc)})
		if errors.Is(err, registry.ErrStateConflict) {
			return fmt.Errorf("%w: policy cell changed during adoption: %w", ErrInvalidConfig, err)
		}
		if err != nil {
			return fmt.Errorf("%w: policy cell: %w", ErrRegistryUnavailable, err)
		}
		return nil
	}
	if cell.Version == (commitment.Hash{}) {
		return write(commitment.Hash{}, policy.NewCounter(m, pg.mandateHash))
	}
	c, err := policy.DecodeCounter(cell.Value)
	if err != nil {
		return fmt.Errorf("%w: policy cell: %w", ErrRegistryUnavailable, err)
	}
	switch {
	case !bytes.Equal(c.MandateID, m.MandateID):
		return fmt.Errorf("%w: policy cell holds another mandate id", ErrRegistryUnavailable)
	case c.Version > m.Version:
		return fmt.Errorf("%w: mandate version %d is below the stored version %d", ErrInvalidConfig, m.Version, c.Version)
	case c.Version == m.Version:
		if !bytes.Equal(c.MandateHash, pg.mandateHash[:]) {
			return fmt.Errorf("%w: mandate version %d differs from the stored one", ErrInvalidConfig, m.Version)
		}
		return nil
	}
	next := *c
	if err := next.Adopt(m, pg.mandateHash); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidConfig, err)
	}
	return write(cell.Version, &next)
}

// lockPolicy takes the policy lock, giving up when ctx is done.
func (g *Gate) lockPolicy(ctx context.Context) error {
	select {
	case g.pol.mu <- struct{}{}:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("gate: %w", ctx.Err())
	}
}

func (g *Gate) unlockPolicy() { <-g.pol.mu }

// policyInput is what the verdict builders know about the request.
type policyInput struct {
	h          commitment.Hash
	actionHash commitment.Hash
	agent      []byte
	adm        policy.Admission
	anchorTime uint64
	decidedAt  uint64
}

func (g *Gate) baseVerdict(in policyInput, outcome uint64) policy.Verdict {
	return policy.Verdict{
		Format: 1, GateID: g.cfg.Scope.GateID, MandateHash: g.pol.mandateHash[:],
		CommitmentHash: in.h[:], ActionHash: in.actionHash[:], AgentPubKey: bytes.Clone(in.agent),
		Outcome: outcome, DecidedAt: in.decidedAt,
	}
}

// signVerdict encodes, signs and self-verifies a verdict. It returns the
// canonical SignedPolicyVerdict and the verdict hash.
func (g *Gate) signVerdict(ctx context.Context, v *policy.Verdict) ([]byte, commitment.Hash, error) {
	canon, err := policy.EncodeVerdict(v)
	if err != nil {
		return nil, commitment.Hash{}, fmt.Errorf("gate: encode verdict: %w", err)
	}
	h := policy.HashVerdict(canon)
	sig, err := g.sign(ctx, policy.VerdictSigningMessage(h))
	if err != nil {
		return nil, commitment.Hash{}, fmt.Errorf("gate: sign verdict: %w", err)
	}
	b, err := policy.EncodeSignedVerdict(&policy.SignedVerdict{Verdict: *v, Signature: sig})
	if err != nil {
		return nil, commitment.Hash{}, fmt.Errorf("gate: encode signed verdict: %w", err)
	}
	if _, _, err := policy.VerifyVerdict(b, g.signerPub); err != nil {
		return nil, commitment.Hash{}, fmt.Errorf("gate: verdict does not verify: %w", err)
	}
	return b, h, nil
}

// denyVerdict signs the deny verdict for reason. The optional parts follow
// from what the stage had learned.
func (g *Gate) denyVerdict(ctx context.Context, in policyInput, reason error, prev *policy.State, evalTime uint64) ([]byte, error) {
	v := g.baseVerdict(in, policy.OutcomeDeny)
	name := policy.ReasonOf(reason)
	v.Reason = name
	v.Extractor = in.adm.ExtractorID
	if in.adm.Facts.Asset != "" {
		f := in.adm.Facts
		v.Facts = &f
	}
	v.AnchorTime = in.anchorTime
	v.EvalTime = evalTime
	v.PrevState = prev
	if name == "ErrDecisionAge" {
		v.GateClock = 1
	}
	b, _, err := g.signVerdict(ctx, &v)
	return b, err
}

// admitPolicy runs the per-action rules. A deny is returned unsigned (denied
// is true); the caller signs it once it knows the request is not a retry.
func (g *Gate) admitPolicy(c *commitment.Commitment, action []byte, in *policyInput) (denied bool, err error) {
	adm, derr := policy.Admit(g.pol.mandate, g.pol.extractors, policy.Decision{
		AgentPubKey: c.AgentPubKey, ActionType: c.Action.Type, Action: action, ValidUntil: c.ValidUntil,
	})
	in.adm = adm
	switch {
	case derr == nil:
		return false, nil
	case errors.Is(derr, policy.ErrDenied):
		return true, derr
	}
	return false, fmt.Errorf("gate: policy admission: %w", derr)
}

// policyDecision is the outcome of the stateful evaluation for an allow.
type policyDecision struct {
	verdict     []byte
	verdictHash commitment.Hash
	tx          registry.StateTx
	// closedBucket and closedSet are set when the allow closed an hour.
	closedBucket []byte
	closedSet    []byte
}

// evaluatePolicy runs the stateful policy rules and, on allow, signs the allow verdict and
// builds the cell transaction. On allow the policy lock is held; the caller
// releases it. On a deny or an error it is already released.
func (g *Gate) evaluatePolicy(ctx context.Context, p commitment.Params, c *commitment.Commitment, in *policyInput, now2 uint64) (dec *policyDecision, verdict []byte, err error) {
	in.decidedAt = now2
	age := uint64(0)
	if now2 > in.anchorTime {
		age = now2 - in.anchorTime
	}
	maxAge := g.pol.mandate.MaxDecisionAge
	if maxAge == 0 {
		maxAge = p.MaxTTL(c.PayloadRef.DA)
	}
	if age > maxAge {
		b, serr := g.denyVerdict(ctx, *in, policy.ErrDecisionAge, nil, 0)
		if serr != nil {
			return nil, nil, serr
		}
		return nil, b, policy.ErrDecisionAge
	}

	if err := g.lockPolicy(ctx); err != nil {
		return nil, nil, err
	}
	held := true
	defer func() {
		if held {
			g.unlockPolicy()
		}
	}()
	cell, err := g.pol.state.State(ctx, g.pol.key)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: policy cell: %w", ErrRegistryUnavailable, err)
	}
	if cell.Version == (commitment.Hash{}) {
		return nil, nil, fmt.Errorf("%w: policy cell is missing", ErrRegistryUnavailable)
	}
	ctr, err := policy.DecodeCounter(cell.Value)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: policy cell: %w", ErrRegistryUnavailable, err)
	}
	if !bytes.Equal(ctr.MandateHash, g.pol.mandateHash[:]) {
		return nil, nil, fmt.Errorf("%w: the cell holds another mandate version", ErrPolicyStateConflict)
	}
	prev := ctr.Ledger.State
	step, eerr := policy.Evaluate(g.pol.mandate, ctr.Ledger, in.adm, in.anchorTime)
	if eerr != nil {
		if !errors.Is(eerr, policy.ErrDenied) {
			return nil, nil, fmt.Errorf("%w: policy evaluation: %w", ErrRegistryUnavailable, eerr)
		}
		evalTime := uint64(0)
		if policy.ReasonOf(eerr) != "ErrOutsideMandate" {
			evalTime = policy.EvalTime(prev, in.anchorTime)
		}
		b, serr := g.denyVerdict(ctx, *in, eerr, &prev, evalTime)
		if serr != nil {
			return nil, nil, serr
		}
		return nil, b, eerr
	}

	v := g.baseVerdict(*in, policy.OutcomeAllow)
	f := in.adm.Facts
	v.Extractor, v.Facts, v.AnchorTime, v.EvalTime = in.adm.ExtractorID, &f, in.anchorTime, step.EvalTime
	v.PrevState, v.NewStateHash = &prev, step.NewHash[:]
	if prev.Seq >= 1 {
		v.PrevCommitmentHash, v.PrevVerdictHash = bytes.Clone(ctr.HeadCommitment), bytes.Clone(ctr.HeadVerdict)
	}
	vb, vh, err := g.signVerdict(ctx, &v)
	if err != nil {
		return nil, nil, err
	}
	next := *ctr
	next.Ledger = step.Next
	next.HeadCommitment, next.HeadVerdict = bytes.Clone(in.h[:]), bytes.Clone(vh[:])
	enc, err := policy.EncodeCounter(&next)
	if err != nil {
		return nil, nil, fmt.Errorf("gate: encode counter: %w", err)
	}
	dec = &policyDecision{
		verdict: vb, verdictHash: vh,
		tx: registry.StateTx{Key: g.pol.key, Expect: cell.Version, Next: registry.NewStateCell(enc)},
	}
	if step.ClosedBucket != nil {
		if dec.closedBucket, err = policy.EncodeBucket(step.ClosedBucket); err != nil {
			return nil, nil, fmt.Errorf("gate: encode closed bucket: %w", err)
		}
		if dec.closedSet, err = policy.EncodeClosedSet(step.ClosedSet); err != nil {
			return nil, nil, fmt.Errorf("gate: encode closed set: %w", err)
		}
	}
	held = false
	return dec, nil, nil
}
