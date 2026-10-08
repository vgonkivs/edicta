package policy

import (
	"bytes"
	"fmt"
	"math/big"
	"slices"

	"github.com/vgonkivs/edicta/commitment"
)

// Decision is what the gate verified about a request before the policy runs.
type Decision struct {
	AgentPubKey []byte
	ActionType  string
	Action      []byte
	ValidUntil  uint64
}

// Admission is the result of the per-action rules.
type Admission struct {
	ExtractorID string
	Facts       Facts
	Asset       int // index of the asset rule in the mandate
}

// Delta is the effect of one allowed action on the state.
type Delta struct {
	Asset  string
	Scale  uint64
	Amount []byte
	TH     uint64
}

// Step is the result of an allowed transition.
type Step struct {
	Next         Ledger
	NewHash      commitment.Hash
	EvalTime     uint64
	ClosedBucket *Bucket    // set when this step closed an hour
	ClosedSet    *ClosedSet // set when this step closed an hour
}

// Admit runs the per-action rules (P1 to P8). On a deny the Admission holds
// what was learned so far (the extractor ID, the facts).
func Admit(m *Mandate, x *Extractors, d Decision) (Admission, error) {
	var a Admission
	if !m.Covers(d.AgentPubKey) {
		return a, ErrAgentNotCovered
	}
	if !x.Has(d.ActionType) {
		return a, ErrNoExtractor
	}
	id, f, err := x.Extract(d.ActionType, d.Action)
	a.ExtractorID = id
	if err != nil {
		return a, err
	}
	a.Facts = f
	if d.ValidUntil > m.NotAfter {
		return a, ErrOutsideMandate
	}
	if len(m.Kinds) > 0 && !slices.Contains(m.Kinds, f.Kind) {
		return a, ErrKindNotAllowed
	}
	a.Asset = m.AssetRuleFor(f.Asset)
	if a.Asset < 0 || m.Assets[a.Asset].Scale != f.Scale {
		return a, ErrAssetNotAllowed
	}
	r := &m.Assets[a.Asset]
	if r.Recipients != nil && (f.Recipient == "" || !slices.Contains(r.Recipients, f.Recipient)) {
		return a, ErrRecipientNotAllowed
	}
	if r.PerActionMax != nil && CompareAmount(f.Amount, r.PerActionMax) > 0 {
		return a, ErrAmountAboveMax
	}
	return a, nil
}

// EvalTime is the attribution time T_eff of an action anchored at tH.
func EvalTime(s State, tH uint64) uint64 {
	if s.Seq == 0 {
		return tH
	}
	return max(tH, s.LastT)
}

func satAdd(a, b uint64) uint64 {
	if s := a + b; s >= a {
		return s
	}
	return ^uint64(0)
}

func windowLo(t, hours uint64) uint64 {
	if t < BucketSeconds*hours {
		return 0
	}
	return (t - BucketSeconds*hours + 1) / BucketSeconds
}

// roll returns a copy of the ledger positioned at bucket k. When an hour
// closes, the closed bucket and the new closed set come back too; the
// returned state's closed_root is not updated until the set is hashed.
func roll(l Ledger, k uint64) (Ledger, *Bucket, *ClosedSet) {
	out := Ledger{State: l.State, Set: l.Set, Closed: l.Closed}
	if l.State.Seq == 0 {
		out.State.Open = &Bucket{Format: 1, Index: k}
		return out, nil, nil
	}
	open := *l.State.Open
	if k <= open.Index {
		return out, nil, nil
	}
	hash, _ := HashBucket(&open)
	cutoff := uint64(0)
	if k > MaxClosed {
		cutoff = k - MaxClosed
	}
	refs := make([]ClosedRef, 0, len(l.Set.Buckets)+1)
	for _, r := range l.Set.Buckets {
		if r.Index >= cutoff {
			refs = append(refs, r)
		}
	}
	refs = append(refs, ClosedRef{Index: open.Index, Hash: hash[:]})
	set := ClosedSet{Format: 1, Buckets: refs}
	closed := make([]Bucket, 0, len(l.Closed)+1)
	for _, b := range l.Closed {
		if b.Index >= cutoff {
			closed = append(closed, b)
		}
	}
	closed = append(closed, open)
	out.Set, out.Closed = set, closed
	out.State.Open = &Bucket{Format: 1, Index: k}
	return out, &open, &set
}

// window sums amounts of (asset, scale) and counts over the buckets from lo
// to the open bucket of a rolled ledger.
func window(l *Ledger, lo uint64, asset string, scale uint64, wantSum bool) (*big.Int, uint64, error) {
	sum := new(big.Int)
	var count uint64
	add := func(b *Bucket) {
		count = satAdd(count, b.Count)
		if !wantSum {
			return
		}
		for _, s := range b.Sums {
			if s.Asset == asset && s.Scale == scale {
				sum.Add(sum, amountBig(s.Sum))
			}
		}
	}
	for _, r := range l.Set.Buckets {
		if r.Index < lo {
			continue
		}
		i := slices.IndexFunc(l.Closed, func(b Bucket) bool { return b.Index == r.Index })
		if i < 0 {
			return nil, 0, fmt.Errorf("%w: %w: bucket %d", ErrStateInvalid, errMissingBucket, r.Index)
		}
		add(&l.Closed[i])
	}
	if o := l.State.Open; o != nil && o.Index >= lo {
		add(o)
	}
	return sum, count, nil
}

// Evaluate runs the rules over the ledger (P10 to P14) and, on allow,
// returns the transition. Denies change nothing.
func Evaluate(m *Mandate, l Ledger, a Admission, tH uint64) (Step, error) {
	if a.Asset < 0 || a.Asset >= len(m.Assets) {
		return Step{}, ErrAssetNotAllowed
	}
	r := &m.Assets[a.Asset]
	if r.Asset != a.Facts.Asset || r.Scale != a.Facts.Scale {
		return Step{}, ErrAssetNotAllowed
	}
	if tH < m.NotBefore {
		return Step{}, ErrOutsideMandate
	}
	s := &l.State
	if m.MinSpacing > 0 && s.Seq >= 1 && tH < satAdd(s.LastTH, m.MinSpacing) {
		return Step{}, ErrMinSpacing
	}
	tEff := EvalTime(l.State, tH)
	rl, _, _ := roll(l, tEff/BucketSeconds)
	amount := amountBig(a.Facts.Amount)
	for _, p := range r.Periods {
		sum, _, err := window(&rl, windowLo(tEff, p.Hours), r.Asset, r.Scale, true)
		if err != nil {
			return Step{}, err
		}
		if sum.Add(sum, amount).Cmp(amountBig(p.Max)) > 0 {
			return Step{}, ErrPeriodLimit
		}
	}
	for _, c := range m.CountLimits {
		_, n, err := window(&rl, windowLo(tEff, c.Hours), "", 0, false)
		if err != nil {
			return Step{}, err
		}
		if satAdd(n, 1) > c.MaxCount {
			return Step{}, ErrCountLimit
		}
	}
	return Apply(l, Delta{Asset: r.Asset, Scale: r.Scale, Amount: a.Facts.Amount, TH: tH})
}

var maxSum = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))

// Apply is the allow transition alone. It checks no limit; it refuses only
// when a capacity bound would break (ErrHistoryFull) so that a state stays
// encodable.
func Apply(l Ledger, d Delta) (Step, error) {
	if err := checkAmount(d.Amount); err != nil {
		return Step{}, fmt.Errorf("%w: %w", ErrFactsInvalid, err)
	}
	tEff := EvalTime(l.State, d.TH)
	rl, closedB, closedSet := roll(l, tEff/BucketSeconds)
	open := Bucket{Format: 1, Index: rl.State.Open.Index, Count: rl.State.Open.Count, Sums: slices.Clone(rl.State.Open.Sums)}
	i, found := slices.BinarySearchFunc(open.Sums, Sum{Asset: d.Asset, Scale: d.Scale}, func(a, b Sum) int {
		return cmpPair(a.Asset, a.Scale, b.Asset, b.Scale)
	})
	total := amountBig(d.Amount)
	if found {
		total.Add(total, amountBig(open.Sums[i].Sum))
	}
	switch {
	case total.Cmp(maxSum) > 0:
		return Step{}, &HistoryFullError{Cause: "sum"}
	case open.Count >= maxInt:
		return Step{}, &HistoryFullError{Cause: "count"}
	case !found && len(open.Sums) >= MaxPairs:
		return Step{}, &HistoryFullError{Cause: "pairs"}
	case l.State.Seq >= maxInt:
		return Step{}, &HistoryFullError{Cause: "seq"}
	}
	enc := total.Bytes()
	if len(enc) == 0 {
		enc = []byte{0}
	}
	if found {
		open.Sums[i].Sum = enc
	} else {
		open.Sums = slices.Insert(open.Sums, i, Sum{Asset: d.Asset, Scale: d.Scale, Sum: enc})
	}
	open.Count++
	next := State{Format: 1, Seq: l.State.Seq + 1, LastT: tEff, LastTH: d.TH, ClosedRoot: l.State.ClosedRoot, Open: &open}
	if closedSet != nil {
		root, err := HashClosedSet(closedSet)
		if err != nil {
			return Step{}, err
		}
		next.ClosedRoot = root[:]
	}
	h, err := HashState(&next)
	if err != nil {
		return Step{}, err
	}
	step := Step{Next: Ledger{State: next, Set: rl.Set, Closed: rl.Closed}, NewHash: h, EvalTime: tEff, ClosedBucket: closedB, ClosedSet: closedSet}
	return step, nil
}

// SameBytes reports whether two hashes held as slices are equal.
func SameBytes(a, b []byte) bool { return bytes.Equal(a, b) }
