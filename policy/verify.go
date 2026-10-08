package policy

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/vgonkivs/edicta/commitment"
)

// Findings of the verifier checks on gate-signed data.
var (
	// ErrEvalTime: eval_time is not max(anchor_time, last_t) of the signed state.
	ErrEvalTime = errors.New("policy: eval_time differs from max(anchor_time, last_t)")
	// ErrTransition: the signed state and delta do not produce new_state_hash,
	// so the verdict contradicts itself.
	ErrTransition = errors.New("policy: the signed transition does not produce new_state_hash")
	// ErrUnlinked: two consecutive verdicts of one counter do not link.
	ErrUnlinked = errors.New("policy: consecutive verdicts do not link")
	// ErrChainMandate: the mandates of two linked verdicts break the rules of
	// one chain (principal, mandate_id, gate_id, version, scale).
	ErrChainMandate = errors.New("policy: mandates of one chain disagree")
)

// Held is an allow verdict with its hash and the mandate it names.
type Held struct {
	V    *Verdict
	Hash commitment.Hash
	M    *Mandate
}

// MinBucketIndex is the lowest closed bucket index the evaluation of an allow
// can read: k(eval_time) minus the longest window of the asset's periods and
// the count limits.
func MinBucketIndex(m *Mandate, v *Verdict) uint64 {
	var w uint64
	if i := m.AssetRuleFor(v.Facts.Asset); i >= 0 {
		for _, p := range m.Assets[i].Periods {
			w = max(w, p.Hours)
		}
	}
	for _, c := range m.CountLimits {
		w = max(w, c.Hours)
	}
	k := v.EvalTime / BucketSeconds
	if k < w {
		return 0
	}
	return k - w
}

// VerifyFast evaluates an allow verdict on the ledger it signed. The result
// is nil, ErrEvalTime, a deny sentinel (the signed state contradicts the
// allow) or ErrTransition.
func VerifyFast(m *Mandate, v *Verdict, l Ledger) error {
	if v.Outcome != OutcomeAllow || v.Facts == nil || v.PrevState == nil {
		return badVerdict("not an allow")
	}
	if v.EvalTime != EvalTime(l.State, v.AnchorTime) {
		return fmt.Errorf("%w: %d, expected %d", ErrEvalTime, v.EvalTime, EvalTime(l.State, v.AnchorTime))
	}
	adm := Admission{ExtractorID: v.Extractor, Facts: *v.Facts, Asset: m.AssetRuleFor(v.Facts.Asset)}
	step, err := Evaluate(m, l, adm, v.AnchorTime)
	if err != nil {
		if ReasonOf(err) != "" {
			return err
		}
		return fmt.Errorf("%w: %w", ErrTransition, err)
	}
	if !bytes.Equal(step.NewHash[:], v.NewStateHash) {
		return ErrTransition
	}
	return nil
}

// CheckLink checks one hop of a chain: prev is the allow n names as its
// predecessor, prevSet the closed set of prev's own state. The first failing
// rule wins: the verdict link, the state link, the sequence, the mandates,
// and prev's own transition.
func CheckLink(prev, next Held, prevSet ClosedSet) error {
	p, n := prev.V, next.V
	if !bytes.Equal(prev.Hash[:], n.PrevVerdictHash) || !bytes.Equal(p.CommitmentHash, n.PrevCommitmentHash) {
		return fmt.Errorf("%w: prev_verdict_hash", ErrUnlinked)
	}
	nPrev, ok := n.PrevStateHash()
	if !ok || !bytes.Equal(nPrev[:], p.NewStateHash) {
		return fmt.Errorf("%w: new_state_hash differs from the next prev_state_hash", ErrUnlinked)
	}
	if p.PrevState.Seq+1 != n.PrevState.Seq {
		return fmt.Errorf("%w: seq %d then %d", ErrUnlinked, p.PrevState.Seq, n.PrevState.Seq)
	}
	if err := checkChainMandates(prev, next); err != nil {
		return err
	}
	l, err := NewLedger(*p.PrevState, nil, prevSet)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrTransition, err)
	}
	d, _ := p.Delta()
	step, err := Apply(l, d)
	if err != nil || !bytes.Equal(step.NewHash[:], p.NewStateHash) {
		return fmt.Errorf("%w: transition of the earlier verdict", ErrTransition)
	}
	return nil
}

func checkChainMandates(prev, next Held) error {
	pm, nm := prev.M, next.M
	switch {
	case !bytes.Equal(pm.Principal, nm.Principal), !bytes.Equal(pm.MandateID, nm.MandateID):
		return fmt.Errorf("%w: principal or mandate_id changed", ErrChainMandate)
	case prev.V.GateID != next.V.GateID, pm.GateID != nm.GateID:
		return fmt.Errorf("%w: gate_id changed", ErrChainMandate)
	case pm.Version > nm.Version:
		return fmt.Errorf("%w: version %d then %d", ErrChainMandate, pm.Version, nm.Version)
	}
	for _, a := range pm.Assets {
		if i := nm.AssetRuleFor(a.Asset); i >= 0 && nm.Assets[i].Scale != a.Scale {
			return fmt.Errorf("%w: scale of %s changed", ErrChainMandate, a.Asset)
		}
	}
	return nil
}

// IsFork reports whether two allows fork one counter: the same gate, the
// same counter key and the same prev_state.seq with different commitments.
func IsFork(a, b Held) bool {
	if a.V.GateID != b.V.GateID || bytes.Equal(a.V.CommitmentHash, b.V.CommitmentHash) {
		return false
	}
	if a.V.PrevState.Seq != b.V.PrevState.Seq {
		return false
	}
	return a.M.CounterKey() == b.M.CounterKey()
}
