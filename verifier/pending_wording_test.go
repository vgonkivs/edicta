package verifier_test

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/verifier"
)

// The anchor_pending text names the bound that is missing: a checkpoint
// below H names H, since reaching H is enough for evidence that verifies;
// a checkpoint in [H, D) with evidence the trust does not tie names the
// deadline, since only the absence window can decide then.
func TestPendingDiagnosticNamesTheMissingBound(t *testing.T) {
	for _, k := range pendingKinds {
		t.Run(k.name+", checkpoint below H", func(t *testing.T) {
			r, _ := pendingRig(t, k.parts(t), verifier.AbsenceWindow{})
			d := r.p.c.PayloadRef.Height + fastWindow
			r.deps.Trust = cpTrust{r.trust, r.p.ev.Height - 1}
			rep := r.verify(t)
			c := unchecked(t, rep, verifier.CheckAnchor, verifier.ReasonAnchorPending)
			require.ErrorIs(t, c.Err, verifier.ErrAnchorInvalid)
			assert.Contains(t, c.Err.Error(), fmt.Sprintf("the trusted header %d is below the anchor height %d", r.p.ev.Height-1, r.p.ev.Height))
			assert.Contains(t, c.Err.Error(), fmt.Sprintf("without usable evidence the window needs %d", d))
		})
		t.Run(k.name+", checkpoint in [H, D), evidence not tied", func(t *testing.T) {
			r, _ := pendingRig(t, k.parts(t), verifier.AbsenceWindow{})
			d := r.p.c.PayloadRef.Height + fastWindow
			r.trust.res.Checked = false
			r.deps.Trust = cpTrust{r.trust, d - 1}
			rep := r.verify(t)
			c := unchecked(t, rep, verifier.CheckAnchor, verifier.ReasonAnchorPending)
			require.ErrorIs(t, c.Err, verifier.ErrAnchorInvalid)
			assert.Contains(t, c.Err.Error(), fmt.Sprintf("evidence at height %d is not tied to the trusted chain, and the trusted header %d is below the deadline %d",
				r.p.ev.Height, d-1, d))
		})
	}
}
