package absence

import (
	"fmt"
	"math"
)

// Window is the verdict over [h0, deadline]. Absent only when every height is
// proven absent; Present names the first height that shows the anchor;
// otherwise Unproven names the first height not proven.
type Window struct {
	Result        Result
	AnchorHeight  uint64 // Present only
	FirstUnproven uint64 // Unproven only
	Heights       []Outcome
}

// VerifyWindow checks every height of [h0, deadline] with the record recs
// holds for it. A missing record leaves its height unproven. The error is for
// invalid arguments only; a bad proof is an Unproven height.
func VerifyWindow(q Query, h0, deadline uint64, recs map[uint64]Record, trusted TrustedHashes) (Window, error) {
	if err := q.ValidateBasic(); err != nil {
		return Window{}, err
	}
	if h0 == 0 || deadline < h0 || deadline-h0 > MaxWindow || deadline > math.MaxInt64 {
		return Window{}, fmt.Errorf("%w: [%d, %d]", ErrWindow, h0, deadline)
	}
	w := Window{Heights: make([]Outcome, 0, deadline-h0+1)}
	for h := h0; h <= deadline; h++ {
		rec, ok := recs[h]
		if !ok {
			w.Heights = append(w.Heights, unproven(h, RuleNoProof, ErrNoProof, "height %d", h))
			continue
		}
		w.Heights = append(w.Heights, VerifyHeight(rec, q, h, trusted))
	}
	for _, o := range w.Heights {
		if o.Result == Present {
			w.Result, w.AnchorHeight = Present, o.Height
			return w, nil
		}
	}
	for _, o := range w.Heights {
		if o.Result != Absent {
			w.Result, w.FirstUnproven = Unproven, o.Height
			return w, nil
		}
	}
	w.Result = Absent
	return w, nil
}
