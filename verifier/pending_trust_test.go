package verifier_test

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/verifier"
)

// pendingKinds are the two da of a pending reference.
var pendingKinds = []struct {
	name  string
	parts func(testing.TB) *parts
}{{"fibre", newFibreParts}, {"blob", newParts}}

// In-window evidence whose header the trusted chain refuses is evidence that
// does not verify: the absence proofs decide, so a gate cannot turn a proven
// absence into unchecked by writing forged evidence.
func TestPendingForgedInWindowEvidenceFallsToAbsence(t *testing.T) {
	absent := verifier.AbsenceWindow{Result: verifier.AbsenceAbsent, Heights: fastWindow + 1, Bytes: 10, ChainID: "c"}
	for _, k := range pendingKinds {
		t.Run(k.name+", evidence header refused", func(t *testing.T) {
			p := pendingParts(t, k.parts(t))
			r := newRigWith(t, p, absent)
			delete(r.trust.hashes, p.ev.Height)
			rep := r.verify(t)
			c := failed(t, rep, verifier.CheckAnchor)
			require.ErrorIs(t, c.Err, verifier.ErrAnchorAbsent)
			assert.Equal(t, verifier.VerdictInvalid, rep.Verdict)
			assert.Zero(t, rep.Fast.AnchorHeight, "refused evidence is not reported as the anchor")
			assert.Equal(t, verifier.PublicationFailed, rep.Fast.Publication)
			assert.NotEmpty(t, rep.Warnings)
		})
	}
	t.Run("fibre, promise header at h0 refused", func(t *testing.T) {
		p := pendingParts(t, newFibreParts(t))
		r := newRigWith(t, p, absent)
		delete(r.trust.hashes, p.c.PayloadRef.Height)
		rep := r.verify(t)
		c := failed(t, rep, verifier.CheckAnchor)
		require.ErrorIs(t, c.Err, verifier.ErrAnchorAbsent)
		assert.Equal(t, verifier.VerdictInvalid, rep.Verdict)
	})
	t.Run("refused evidence and a window not proven stays unchecked", func(t *testing.T) {
		p := pendingParts(t, newParts(t))
		h0 := p.c.PayloadRef.Height
		r := newRigWith(t, p, verifier.AbsenceWindow{Result: verifier.AbsenceUnproven, FirstUnproven: h0, Cause: errors.New("no proof")})
		delete(r.trust.hashes, p.ev.Height)
		rep := r.verify(t)
		unchecked(t, rep, verifier.CheckAnchor, verifier.ReasonAbsenceUnproven)
		assert.Zero(t, rep.Fast.AnchorHeight)
	})
}

// A trust problem other than a refused hash says nothing against the
// evidence: the anchor is blocked on header trust and the absence proofs are
// not read.
func TestPendingInWindowEvidenceBlockedOnTrust(t *testing.T) {
	for _, k := range pendingKinds {
		t.Run(k.name+", source unavailable", func(t *testing.T) {
			r, fp := pendingRig(t, k.parts(t), verifier.AbsenceWindow{Result: verifier.AbsenceAbsent})
			r.trust.err = verifier.WithReason(verifier.ReasonHeaderSourceUnavailable, []string{"rpc.example"}, errors.New("down"))
			rep := r.verify(t)
			c := unchecked(t, rep, verifier.CheckAnchor, verifier.ReasonBlocked)
			assert.Equal(t, []string{string(verifier.CheckHeaderTrust)}, c.Sources)
			unchecked(t, rep, verifier.CheckHeaderTrust, verifier.ReasonHeaderSourceUnavailable)
			unchecked(t, rep, verifier.CheckAnchorTime, verifier.ReasonBlocked)
			assert.Zero(t, fp.asked)
			assert.Equal(t, verifier.VerdictUnchecked, rep.Verdict)
		})
		t.Run(k.name+", headers not checked", func(t *testing.T) {
			r, fp := pendingRig(t, k.parts(t), verifier.AbsenceWindow{Result: verifier.AbsenceAbsent})
			r.trust.res.Checked = false
			rep := r.verify(t)
			unchecked(t, rep, verifier.CheckAnchor, verifier.ReasonBlocked)
			unchecked(t, rep, verifier.CheckHeaderTrust, verifier.ReasonNoTrustedHeader)
			assert.Zero(t, fp.asked)
		})
	}
}

// In-window evidence counts only once header trust reaches the deadline,
// so that every height of the window hangs from one trusted chain.
func TestPendingInWindowEvidenceNeedsCheckpointAtDeadline(t *testing.T) {
	for _, k := range pendingKinds {
		t.Run(k.name+", checkpoint below the deadline", func(t *testing.T) {
			r, fp := pendingRig(t, k.parts(t), verifier.AbsenceWindow{Result: verifier.AbsenceAbsent})
			d := r.p.c.PayloadRef.Height + fastWindow
			r.deps.Trust = cpTrust{r.trust, d - 1}
			rep := r.verify(t)
			c := unchecked(t, rep, verifier.CheckAnchor, verifier.ReasonAnchorPending)
			require.ErrorIs(t, c.Err, verifier.ErrAnchorInvalid)
			unchecked(t, rep, verifier.CheckAnchorTime, verifier.ReasonBlocked)
			unchecked(t, rep, verifier.CheckHeaderTrust, verifier.ReasonBlocked)
			assert.Equal(t, verifier.TrustUnchecked, rep.HeaderTrust.Status)
			assert.Zero(t, rep.Fast.AnchorHeight)
			assert.Zero(t, fp.asked)
			assert.Empty(t, r.trust.asked, "no header is tied before the checkpoint reaches the deadline")
			assert.Equal(t, verifier.VerdictUnchecked, rep.Verdict)
		})
	}
	t.Run("fibre, checkpoint at the deadline passes", func(t *testing.T) {
		r, _ := pendingRig(t, newFibreParts(t), verifier.AbsenceWindow{})
		r.deps.Trust = cpTrust{r.trust, r.p.c.PayloadRef.Height + fastWindow}
		rep := r.verify(t)
		passed(t, rep, verifier.CheckAnchor)
		passed(t, rep, verifier.CheckHeaderTrust)
		assert.Equal(t, r.p.ev.Height, rep.Fast.AnchorHeight)
		assert.Equal(t, verifier.PublicationAnchored, rep.Fast.Publication)
	})
	t.Run("fibre, header trust asked once per header", func(t *testing.T) {
		r, _ := pendingRig(t, newFibreParts(t), verifier.AbsenceWindow{})
		rep := r.verify(t)
		passed(t, rep, verifier.CheckAnchor)
		h0 := r.p.c.PayloadRef.Height
		assert.ElementsMatch(t, []uint64{r.p.ev.Height, h0}, r.trust.asked)
	})
}

// Evidence below h0 is source_corrupt before its facts are checked, for both
// da: a PFF cannot precede its reference height, and the absence proofs are
// not read.
func TestPendingEvidenceBelowH0BothDA(t *testing.T) {
	for _, k := range pendingKinds {
		t.Run(k.name, func(t *testing.T) {
			p := pendingParts(t, k.parts(t))
			p.ev.Height = p.c.PayloadRef.Height - 1
			r, fp := newRig(t, p), &fakePending{window: verifier.AbsenceWindow{Result: verifier.AbsenceAbsent}}
			r.deps.Pending = fp
			rep := r.verify(t)
			c := unchecked(t, rep, verifier.CheckAnchor, verifier.ReasonSourceCorrupt)
			require.ErrorIs(t, c.Err, verifier.ErrAnchorInvalid)
			assert.Contains(t, c.Err.Error(), "below h0")
			unchecked(t, rep, verifier.CheckAnchorTime, verifier.ReasonBlocked)
			unchecked(t, rep, verifier.CheckHeaderTrust, verifier.ReasonBlocked)
			assert.Zero(t, fp.asked)
			assert.Equal(t, verifier.VerdictUnchecked, rep.Verdict)
		})
	}
}
