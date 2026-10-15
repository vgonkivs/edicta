package verifier_test

import (
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/verifier"
)

// The presence bound holds for every header trust kind: one with a
// Checkpointer, one that names its checkpoint only in its results, and one
// that names none. Only a checkpoint at or above the evidence height H lets
// in-window evidence pass; below H the outcome is unchecked, never pass.
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
		t.Run(k.name+", checkpoint below H only in the results", func(t *testing.T) {
			r, fp := pendingRig(t, k.parts(t), verifier.AbsenceWindow{})
			d := r.p.c.PayloadRef.Height + fastWindow
			r.trust.res.CheckpointH = r.p.ev.Height - 1
			rep := r.verify(t)
			c := unchecked(t, rep, verifier.CheckAnchor, verifier.ReasonAnchorPending)
			require.ErrorIs(t, c.Err, verifier.ErrAnchorInvalid)
			assert.Contains(t, c.Err.Error(), fmt.Sprintf("evidence ties at %d; verdict needs a checkpoint >= D (height %d)", r.p.ev.Height, d))
			unchecked(t, rep, verifier.CheckHeaderTrust, verifier.ReasonBlocked)
			unchecked(t, rep, verifier.CheckAnchorTime, verifier.ReasonBlocked)
			assert.Equal(t, r.p.ev.Height-1, rep.HeaderTrust.CheckpointH)
			assert.Contains(t, rep.HeaderTrust.Hashes, r.p.ev.Height)
			assert.Zero(t, rep.Fast.AnchorHeight)
			assert.Equal(t, verifier.VerdictUnchecked, rep.Verdict)
			assert.Zero(t, fp.asked)
		})
		for name, below := range map[string]uint64{"at H": fastWindow - 1, "in (H, D)": 1} {
			t.Run(k.name+", checkpoint "+name+" only in the results passes", func(t *testing.T) {
				r, fp := pendingRig(t, k.parts(t), verifier.AbsenceWindow{Result: verifier.AbsenceAbsent})
				d := r.p.c.PayloadRef.Height + fastWindow
				r.trust.res.CheckpointH = d - below
				withRefHeader(r, fp)
				require.GreaterOrEqual(t, r.trust.res.CheckpointH, r.p.ev.Height)
				rep := r.verify(t)
				passed(t, rep, verifier.CheckAnchor)
				passed(t, rep, verifier.CheckHeaderTrust)
				passed(t, rep, verifier.CheckAnchorTime)
				assert.Equal(t, r.p.ev.Height, rep.Fast.AnchorHeight)
				assert.Equal(t, verifier.PublicationAnchored, rep.Fast.Publication)
				assert.Equal(t, d-below, rep.HeaderTrust.CheckpointH)
				assert.Zero(t, fp.asked, "presence does not read the absence proofs")
				for _, w := range rep.Warnings {
					assert.NotContains(t, w, "evidence ties")
				}
			})
		}
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
			r.trust.res.CheckpointH = r.p.ev.Height - 1
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

// withRefHeader gives a da = 2 rig the header at h0 that T_ref is read from,
// on the trusted chain; da = 1 reads it from the promise in the evidence.
func withRefHeader(r *rig, fp *fakePending) {
	if r.p.da != commitment.DACelestiaBlob {
		return
	}
	h0 := r.p.c.PayloadRef.Height
	hh := sha256.Sum256([]byte("header at h0"))
	r.trust.hashes[h0] = hh[:]
	fp.header = verifier.ChainHeader{Hash: hh[:], Time: blockTime}
}
