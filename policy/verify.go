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
	// one chain (principal, mandate_id, gate_id, version, asset scale).
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

// ScaleError is the finding of a scale that changed along a chain: the
// earlier verdict's mandate and With's mandate list Asset at different
// scales. It matches ErrChainMandate.
type ScaleError struct {
	Asset string
	With  Held
}

func (e *ScaleError) Error() string {
	return fmt.Sprintf("%s: scale of %s changed", ErrChainMandate, e.Asset)
}

func (e *ScaleError) Is(t error) bool { return t == ErrChainMandate }

// ScaleChain tracks, during a walk from the newest verdict back, the scale
// each asset has in the mandates of the verdicts already walked. Walking
// stops at the first disagreement, so every walked mandate agrees and the
// nearest verdict that lists an asset stands for all of them.
type ScaleChain struct{ nearest map[string]scaleRef }

type scaleRef struct {
	scale uint64
	held  Held
}

func NewScaleChain() *ScaleChain { return &ScaleChain{nearest: map[string]scaleRef{}} }

// Add records the assets of h's mandate; h is nearer to the next verdict
// checked than any verdict added before it.
func (c *ScaleChain) Add(h Held) {
	for _, a := range h.M.Assets {
		c.nearest[a.Asset] = scaleRef{scale: a.Scale, held: h}
	}
}

// Check reports the nearest walked verdict whose mandate lists an asset of
// p's mandate at another scale.
func (c *ScaleChain) Check(p Held) error {
	for _, a := range p.M.Assets {
		if r, ok := c.nearest[a.Asset]; ok && r.scale != a.Scale {
			return &ScaleError{Asset: a.Asset, With: r.held}
		}
	}
	return nil
}

// CheckLink checks one hop of a chain: prev is the allow n names as its
// predecessor, prevSet the closed set of prev's own state, later the scales
// of the verdicts walked so far (nil skips the scale rule). The first failing
// rule wins: the verdict link, the state link, the sequence, the mandates,
// and prev's own transition. A scale finding is a *ScaleError.
func CheckLink(prev, next Held, prevSet ClosedSet, later *ScaleChain) error {
	p, n := prev.V, next.V
	if !bytes.Equal(prev.Hash[:], n.PrevVerdictHash) || !bytes.Equal(p.CommitmentHash, n.PrevCommitmentHash) {
		return fmt.Errorf("%w: prev_verdict_hash", ErrUnlinked)
	}
	nPrev, ok := next.PrevStateHash()
	if !ok || !bytes.Equal(nPrev[:], p.NewStateHash) {
		return fmt.Errorf("%w: new_state_hash differs from the next prev_state_hash", ErrUnlinked)
	}
	if p.PrevState.Seq+1 != n.PrevState.Seq {
		return fmt.Errorf("%w: seq %d then %d", ErrUnlinked, p.PrevState.Seq, n.PrevState.Seq)
	}
	if err := checkChainMandates(prev, next); err != nil {
		return err
	}
	if later != nil {
		if err := later.Check(prev); err != nil {
			return err
		}
	}
	l, err := NewLedger(*p.PrevState, nil, prevSet)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrTransition, err)
	}
	d, _ := p.Delta()
	step, err := Apply(l, d)
	if err != nil {
		return fmt.Errorf("%w: transition of the earlier verdict", ErrTransition)
	}
	nh, err := NewStateHasher(prev.M).StateHash(&step.Next.State)
	if err != nil || !bytes.Equal(nh[:], p.NewStateHash) {
		return fmt.Errorf("%w: transition of the earlier verdict", ErrTransition)
	}
	return nil
}

// PrevStateHash is prev_state_hash of a held verdict: key 20 of a private
// form, else the hash of prev_state under the hasher of its mandate, so that
// a merged private verdict compares blinded hashes.
func (h Held) PrevStateHash() (commitment.Hash, bool) {
	if h.V.PrivateHash != nil || h.M == nil {
		return h.V.PrevStateHash()
	}
	if h.V.PrevState == nil {
		return commitment.Hash{}, false
	}
	ph, err := NewStateHasher(h.M).StateHash(h.V.PrevState)
	return ph, err == nil
}

// IsHashFork is the fork rule without the auditor key: two allows of one
// gate under one mandate_hash that read the same prev_state_hash and differ
// in commitment.
func IsHashFork(a, b *Verdict) bool {
	if a.GateID != b.GateID || !bytes.Equal(a.MandateHash, b.MandateHash) || bytes.Equal(a.CommitmentHash, b.CommitmentHash) {
		return false
	}
	ah, aok := a.PrevStateHash()
	bh, bok := b.PrevStateHash()
	return aok && bok && ah == bh
}

func checkChainMandates(prev, next Held) error {
	pm, nm := prev.M, next.M
	switch {
	case pm.SigType != nm.SigType, !bytes.Equal(pm.Principal, nm.Principal), !bytes.Equal(pm.MandateID, nm.MandateID):
		return fmt.Errorf("%w: principal or mandate_id changed", ErrChainMandate)
	case prev.V.GateID != next.V.GateID, pm.GateID != nm.GateID:
		return fmt.Errorf("%w: gate_id changed", ErrChainMandate)
	case pm.Version > nm.Version:
		return fmt.Errorf("%w: version %d then %d", ErrChainMandate, pm.Version, nm.Version)
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
