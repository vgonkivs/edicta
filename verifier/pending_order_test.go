package verifier_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/verifier"
)

// A checkpoint in [H, D) keeps anchor_pending whatever header trust says
// about the evidence: a source error or an unchecked header must not turn
// the reason into blocked.
func TestPendingCheckpointInWindowTrustFailureStaysPending(t *testing.T) {
	for _, k := range pendingKinds {
		for _, tc := range []struct {
			name       string
			breakTrust func(r *rig)
		}{
			{"source unavailable", func(r *rig) {
				r.trust.err = verifier.WithReason(verifier.ReasonHeaderSourceUnavailable, []string{"rpc.example"}, errors.New("down"))
			}},
			{"headers not checked", func(r *rig) { r.trust.res.Checked = false }},
		} {
			t.Run(k.name+", "+tc.name, func(t *testing.T) {
				r, fp := pendingRig(t, k.parts(t), verifier.AbsenceWindow{Result: verifier.AbsenceAbsent})
				d := r.p.c.PayloadRef.Height + fastWindow
				tc.breakTrust(r)
				r.deps.Trust = cpTrust{r.trust, d - 1}
				rep := r.verify(t)
				c := unchecked(t, rep, verifier.CheckAnchor, verifier.ReasonAnchorPending)
				require.ErrorIs(t, c.Err, verifier.ErrAnchorInvalid)
				unchecked(t, rep, verifier.CheckHeaderTrust, verifier.ReasonBlocked)
				unchecked(t, rep, verifier.CheckAnchorTime, verifier.ReasonBlocked)
				assert.Equal(t, verifier.TrustUnchecked, rep.HeaderTrust.Status)
				assert.Zero(t, rep.Fast.AnchorHeight)
				assert.Equal(t, verifier.PublicationUnknown, rep.Fast.Publication)
				assert.NotEmpty(t, rep.Warnings, "the tie problem stays visible as a warning")
				assert.Zero(t, fp.asked)
				assert.Equal(t, verifier.VerdictUnchecked, rep.Verdict)
			})
		}
	}
	t.Run("checkpoint at the deadline keeps blocked on header trust", func(t *testing.T) {
		r, _ := pendingRig(t, newParts(t), verifier.AbsenceWindow{Result: verifier.AbsenceAbsent})
		r.trust.res.Checked = false
		r.deps.Trust = cpTrust{r.trust, r.p.c.PayloadRef.Height + fastWindow}
		rep := r.verify(t)
		unchecked(t, rep, verifier.CheckAnchor, verifier.ReasonBlocked)
		unchecked(t, rep, verifier.CheckHeaderTrust, verifier.ReasonNoTrustedHeader)
	})
}

// A header trust that names its checkpoint only in its results is learned
// while the absence proofs are tied. With that checkpoint below D the
// anchor_pending row decides before anchor_unpaid and absence_unproven; only
// a height present with code 0 decides before it.
func TestPendingAbsenceCheckpointFromResultsDecidesPendingFirst(t *testing.T) {
	for _, tc := range []struct {
		name   string
		window func(h0 uint64) verifier.AbsenceWindow
		want   verifier.Reason
	}{
		{"present unpaid", func(h0 uint64) verifier.AbsenceWindow {
			return verifier.AbsenceWindow{Result: verifier.AbsencePresentUnpaid, UnpaidHeight: h0 + 1}
		}, verifier.ReasonAnchorPending},
		{"not proven", func(h0 uint64) verifier.AbsenceWindow {
			return verifier.AbsenceWindow{Result: verifier.AbsenceUnproven, FirstUnproven: h0 + 2, Cause: errors.New("no proof")}
		}, verifier.ReasonAnchorPending},
		{"present with code 0", func(h0 uint64) verifier.AbsenceWindow {
			return verifier.AbsenceWindow{Result: verifier.AbsencePresent, AnchorHeight: h0 + 1}
		}, verifier.ReasonEvidenceUnavailable},
	} {
		for _, k := range pendingKinds {
			t.Run(k.name+", "+tc.name, func(t *testing.T) {
				p := pendingParts(t, k.parts(t))
				h0 := p.c.PayloadRef.Height
				r := newRig(t, p)
				withoutEvidence(r)
				r.trust.res.CheckpointH = h0 + fastWindow - 1
				r.trust.hashes[h0] = []byte("h0 header hash")
				fp := &fakePending{window: tc.window(h0), confirm: map[uint64][]byte{h0: r.trust.hashes[h0]}}
				r.deps.Pending = fp
				rep := r.verify(t)
				unchecked(t, rep, verifier.CheckAnchor, tc.want)
				assert.Equal(t, 1, fp.asked)
				assert.Equal(t, verifier.VerdictUnchecked, rep.Verdict)
			})
		}
	}
}

// Evidence whose header the chain refuses falls to the absence rows; a
// checkpoint below D that the refusing trust named in its results makes the
// reference anchor_pending before any absence proof is read.
func TestPendingRefusedEvidenceNotesCheckpointFromResults(t *testing.T) {
	for _, k := range pendingKinds {
		t.Run(k.name, func(t *testing.T) {
			r, fp := pendingRig(t, k.parts(t), verifier.AbsenceWindow{Result: verifier.AbsencePresentUnpaid})
			d := r.p.c.PayloadRef.Height + fastWindow
			delete(r.trust.hashes, r.p.ev.Height)
			r.deps.Trust = refusingTrust{r.trust, d - 1}
			rep := r.verify(t)
			unchecked(t, rep, verifier.CheckAnchor, verifier.ReasonAnchorPending)
			assert.Zero(t, fp.asked)
			assert.NotEmpty(t, rep.Warnings)
		})
	}
}

// refusingTrust names its checkpoint in its results, refusals included.
type refusingTrust struct {
	*fakeTrust
	cp uint64
}

func (f refusingTrust) Trusted(ctx context.Context, height uint64, hash []byte) (verifier.TrustResult, error) {
	res, err := f.fakeTrust.Trusted(ctx, height, hash)
	res.CheckpointH = f.cp
	return res, err
}
