package verifier_test

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/verifier"
)

// The deadline bound holds for every header trust kind: one with a
// Checkpointer, one that names its checkpoint only in its results, and one
// that names none. Only a checkpoint at or above D lets in-window evidence
// pass; the outcome below D is unchecked, never pass.
func TestPendingEvidenceDeadlineBoundEveryTrustKind(t *testing.T) {
	for _, k := range pendingKinds {
		t.Run(k.name+", checkpoint below H: nothing is tied", func(t *testing.T) {
			r, _ := pendingRig(t, k.parts(t), verifier.AbsenceWindow{})
			r.deps.Trust = cpTrust{r.trust, r.p.ev.Height - 1}
			rep := r.verify(t)
			c := unchecked(t, rep, verifier.CheckAnchor, verifier.ReasonAnchorPending)
			assert.NotContains(t, c.Err.Error(), "evidence ties")
			assert.Empty(t, r.trust.asked)
		})
		t.Run(k.name+", checkpoint in [H, D) only in the results", func(t *testing.T) {
			r, fp := pendingRig(t, k.parts(t), verifier.AbsenceWindow{})
			d := r.p.c.PayloadRef.Height + fastWindow
			r.trust.res.CheckpointH = d - 1
			rep := r.verify(t)
			c := unchecked(t, rep, verifier.CheckAnchor, verifier.ReasonAnchorPending)
			require.ErrorIs(t, c.Err, verifier.ErrAnchorInvalid)
			assert.Contains(t, c.Err.Error(), fmt.Sprintf("evidence ties at %d; verdict needs a checkpoint >= D (height %d)", r.p.ev.Height, d))
			unchecked(t, rep, verifier.CheckHeaderTrust, verifier.ReasonBlocked)
			unchecked(t, rep, verifier.CheckAnchorTime, verifier.ReasonBlocked)
			assert.Equal(t, d-1, rep.HeaderTrust.CheckpointH)
			assert.Contains(t, rep.HeaderTrust.Hashes, r.p.ev.Height)
			assert.Equal(t, verifier.VerdictUnchecked, rep.Verdict)
			assert.Zero(t, fp.asked)
		})
		t.Run(k.name+", checkpoint unknown", func(t *testing.T) {
			r, _ := pendingRig(t, k.parts(t), verifier.AbsenceWindow{})
			r.trust.res.CheckpointH = 0
			rep := r.verify(t)
			c := unchecked(t, rep, verifier.CheckAnchor, verifier.ReasonBlocked)
			assert.Equal(t, []string{string(verifier.CheckHeaderTrust)}, c.Sources)
			unchecked(t, rep, verifier.CheckHeaderTrust, verifier.ReasonNoTrustedHeader)
			unchecked(t, rep, verifier.CheckAnchorTime, verifier.ReasonBlocked)
			assert.Equal(t, verifier.VerdictUnchecked, rep.Verdict)
		})
		t.Run(k.name+", the lower of two checkpoint answers counts", func(t *testing.T) {
			r, _ := pendingRig(t, k.parts(t), verifier.AbsenceWindow{})
			d := r.p.c.PayloadRef.Height + fastWindow
			r.trust.res.CheckpointH = d - 1
			r.deps.Trust = cpTrust{r.trust, d + 50}
			rep := r.verify(t)
			unchecked(t, rep, verifier.CheckAnchor, verifier.ReasonAnchorPending)
		})
		t.Run(k.name+", checkpoint at D only in the results passes", func(t *testing.T) {
			r, _ := pendingRig(t, k.parts(t), verifier.AbsenceWindow{})
			r.trust.res.CheckpointH = r.p.c.PayloadRef.Height + fastWindow
			rep := r.verify(t)
			passed(t, rep, verifier.CheckAnchor)
			assert.Equal(t, r.p.ev.Height, rep.Fast.AnchorHeight)
		})
	}
}
