package verifier_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/verifier"
)

func TestDA1PromiseAndAnchorHeights(t *testing.T) {
	anchorHash := sha256.Sum256(goodHeader())
	same := func(ev *archive.EvidenceRecord) uint64 { return ev.Height }
	above := func(ev *archive.EvidenceRecord) uint64 { return ev.Height + 1 }
	tests := []struct {
		name string
		// evidence names the promise height; nil keeps the archived one.
		evidence func(ev *archive.EvidenceRecord) uint64
		// reported is the promise height the anchor verifier returns.
		reported func(ev *archive.EvidenceRecord) uint64
		hash     []byte
		valid    bool
	}{
		{"promise below the anchor", nil, nil, nil, true},
		{"promise above the anchor", above, nil, nil, false},
		{"equal heights, equal hashes", same, nil, anchorHash[:], true},
		{"equal heights, different hashes", same, nil, []byte("forged anchor header hash"), false},
		{"promise height differs from the evidence", nil, func(ev *archive.EvidenceRecord) uint64 { return ev.PromiseHeight - 1 }, nil, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := newFibreParts(t)
			if tc.evidence != nil {
				p.ev.PromiseHeight = tc.evidence(p.ev)
			}
			r := newRig(t, p)
			r.anchor.promiseHeight = tc.reported
			r.anchor.promiseHash = tc.hash
			r.trust.hashes[p.ev.Height] = anchorHash[:]
			if tc.hash != nil {
				r.trust.hashes[p.ev.PromiseHeight] = tc.hash
			}
			rep := r.verify(t)
			if tc.valid {
				assert.Equal(t, verifier.VerdictValid, rep.Verdict)
				return
			}
			assert.Equal(t, verifier.VerdictUnchecked, rep.Verdict, "an anchor the copy cannot back is a source problem")
			requireOnly(t, unchecked(t, rep, verifier.CheckAnchor, verifier.ReasonSourceCorrupt).Err, verifier.ErrAnchorInvalid)
		})
	}
}

func TestDA1PromiseBlobSizeMustMatchThePayloadSize(t *testing.T) {
	r := newRig(t, newFibreParts(t))
	want := uploadSize(r.p.c.PayloadSize)
	for name, size := range map[string]uint64{"one row more": want + 4096, "zero": 0, "payload size itself": r.p.c.PayloadSize} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t, newFibreParts(t))
			r.anchor.blobSize = &size
			rep := r.verify(t)
			assert.Equal(t, verifier.VerdictUnchecked, rep.Verdict)
			requireOnly(t, unchecked(t, rep, verifier.CheckAnchor, verifier.ReasonSourceCorrupt).Err, verifier.ErrAnchorInvalid)
		})
	}
	rep := newRig(t, newFibreParts(t)).verify(t)
	assert.Equal(t, verifier.VerdictValid, rep.Verdict)
}

// A problem on a later header does not stop the loop, and the first one is
// the one reported.
func TestHeaderTrustLoopGoesOnAfterAProblem(t *testing.T) {
	r := newRig(t, newFibreParts(t))
	calls := 0
	r.deps.Trust = trustFunc(func(_ context.Context, _ uint64, _ []byte) (verifier.TrustResult, error) {
		calls++
		if calls == 1 {
			return verifier.TrustResult{}, verifier.ErrTrustInput
		}
		return verifier.TrustResult{}, errors.New("hash is not on the trusted chain")
	})
	rep := r.verify(t)
	assert.Equal(t, 2, calls, "the loop goes on after a missing input")
	assert.Equal(t, verifier.VerdictUnchecked, rep.Verdict)
	assert.Equal(t, verifier.TrustUnchecked, rep.HeaderTrust.Status)
	requireOnly(t, unchecked(t, rep, verifier.CheckHeaderTrust, verifier.ReasonHeaderSourceUnavailable).Err, verifier.ErrHeaderTrust)
}

// A disagreement between sources outranks the other problems.
func TestHeaderTrustDisagreementOutranksOtherProblems(t *testing.T) {
	r := newRig(t, newFibreParts(t))
	calls := 0
	r.deps.Trust = trustFunc(func(_ context.Context, _ uint64, _ []byte) (verifier.TrustResult, error) {
		calls++
		if calls == 1 {
			return verifier.TrustResult{}, verifier.ErrTrustInput
		}
		return verifier.TrustResult{}, verifier.WithReason(verifier.ReasonHeaderDisagreement, nil, errors.New("sources differ"))
	})
	rep := r.verify(t)
	unchecked(t, rep, verifier.CheckHeaderTrust, verifier.ReasonHeaderDisagreement)
	assert.Equal(t, verifier.VerdictUnchecked, rep.Verdict)
}

func TestHeaderTrustMissingInputOnEveryHeaderIsUnchecked(t *testing.T) {
	r := newRig(t, newFibreParts(t))
	r.deps.Trust = trustFunc(func(context.Context, uint64, []byte) (verifier.TrustResult, error) {
		return verifier.TrustResult{}, verifier.ErrTrustInput
	})
	rep := r.verify(t)
	assert.Equal(t, verifier.VerdictUnchecked, rep.Verdict)
	assert.Equal(t, verifier.TrustUnchecked, rep.HeaderTrust.Status)
}

func TestReplayPromiseCreationRules(t *testing.T) {
	const earlier = blockTime - 100
	tests := []struct {
		name       string
		creations  []uint64
		created    uint64
		path       commitment.PayloadPath
		consistent bool
	}{
		{"the archived candidate", nil, blockTime, commitment.PathDA, true},
		{"an earlier candidate", []uint64{earlier}, earlier, commitment.PathDA, true},
		{"an unrelated time", []uint64{earlier}, earlier - 7, commitment.PathDA, false},
		{"a later time than the archived one", []uint64{earlier}, blockTime + 1, commitment.PathDA, false},
		{"an earlier time no candidate has", nil, earlier, commitment.PathDA, false},
		{"absent time on the archive path", nil, 0, commitment.PathArchive, true},
		{"absent time on the DA path", nil, 0, commitment.PathDA, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := newFibreParts(t)
			p.k2.PromiseCreated = tc.created
			p.auth = signAuth(t, gateKey(t), p.hash, p.c, tc.path, authExpires)
			r := newRig(t, p)
			r.anchor.proofForm = 1
			r.anchor.creations = tc.creations
			r.anchor.earlier = len(tc.creations)

			rr := replay(t, r)
			require.True(t, rr.K2.Replayable)
			assert.Equal(t, tc.consistent, rr.K2.Consistent, "%v", rr.K2.Err)
			switch {
			case !tc.consistent:
				require.ErrorIs(t, rr.K2.Err, verifier.ErrGateInconsistent)
				assert.Equal(t, verifier.VerdictUnchecked, rr.Report.Verdict, "the K2 inputs are unsigned: a gate error and an altered record look the same")
				unchecked(t, rr.Report, verifier.CheckRetention, verifier.ReasonReplayInconsistent)
			default:
				assert.Equal(t, verifier.VerdictValid, rr.Report.Verdict)
			}
		})
	}
}
