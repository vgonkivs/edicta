package verifier_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/verifier"
)

func TestDA1CompleteArchive(t *testing.T) {
	p := newFibreParts(t)
	r := newRig(t, p)
	rep := r.verify(t)

	assert.Equal(t, verifier.VerdictValid, rep.Verdict)
	assert.Equal(t, commitment.DAFibre, rep.DA)
	assert.True(t, rep.AuthorizationVerified)
	assert.Equal(t, "node-attested", rep.Settlement)
	require.NotNil(t, rep.Cert)
	assert.Equal(t, int64(3), rep.Cert.SignedPower)
	assert.Equal(t, int64(4), rep.Cert.TotalPower)
	assert.InDelta(t, 0.75, rep.Cert.SignedShare, 1e-9)
	assert.False(t, rep.Cert.QuorumWarning)
	assert.Equal(t, "robust", rep.Cert.TokenPrecision)
	assert.Equal(t, "next_validators_hash@promise", rep.Cert.ValsetHeader)
	assert.ElementsMatch(t, []uint64{p.ev.Height, p.ev.PromiseHeight}, r.trust.asked,
		"both the anchor header and the promise header go through header trust")
	passed(t, rep, verifier.CheckAnchor)
	passed(t, rep, verifier.CheckHeaderTrust)
}

func TestDA1QuorumWarning(t *testing.T) {
	tests := []struct {
		name          string
		signed, total int64
		warn          bool
	}{
		{"exactly two thirds", 2, 3, true},
		{"floor threshold, still at most two thirds", 4, 6, true},
		{"just above two thirds", 3, 4, false},
		{"every validator signed", 1 << 62, 1 << 62, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := newRig(t, newFibreParts(t))
			r.anchor.signed, r.anchor.total = tc.signed, tc.total
			rep := r.verify(t)
			require.NotNil(t, rep.Cert)
			assert.Equal(t, tc.warn, rep.Cert.QuorumWarning)
			assert.Equal(t, verifier.VerdictValid, rep.Verdict, "the warning never changes the verdict")
			if tc.warn {
				assert.NotEmpty(t, rep.Warnings)
			}
		})
	}
}

func TestDA1BucketDependentPrecisionIsAWarning(t *testing.T) {
	r := newRig(t, newFibreParts(t))
	r.anchor.precision = "bucket-dependent"
	rep := r.verify(t)
	assert.Equal(t, verifier.VerdictValid, rep.Verdict)
	require.NotNil(t, rep.Cert)
	assert.Equal(t, "bucket-dependent", rep.Cert.TokenPrecision)
	assert.NotEmpty(t, rep.Warnings)
}

func TestDA1PromiseHeaderTamperedIsAHeaderTrustProblem(t *testing.T) {
	r := newRig(t, newFibreParts(t))
	r.trust.hashes[r.p.ev.PromiseHeight] = []byte("another hash")
	rep := r.verify(t)
	c := unchecked(t, rep, verifier.CheckHeaderTrust, verifier.ReasonChainMismatch)
	requireOnly(t, c.Err, verifier.ErrHeaderTrust)
	assert.Equal(t, verifier.VerdictUnchecked, rep.Verdict)
}

func TestDA1ReplayUsesFibreInputs(t *testing.T) {
	r := newRig(t, newFibreParts(t))
	rr, err := r.verifier(t).Replay(t.Context(), r.p.hash)
	require.NoError(t, err)
	require.True(t, rr.K2.Replayable)
	assert.Equal(t, uint64(14400), rr.K2.R)
	assert.Equal(t, blockTime, rr.K2.Start)
	assert.Equal(t, commitment.PathDA, rr.K2.Route)
	assert.True(t, rr.K2.Consistent)
}

func TestDA1PayloadMissingIsIncomplete(t *testing.T) {
	p := newFibreParts(t)
	p.blob = nil
	rep := newRig(t, p).verify(t)
	c := unchecked(t, rep, verifier.CheckPayload, verifier.ReasonPayloadUnavailable)
	requireOnly(t, c.Err, verifier.ErrArchiveIncomplete)
	require.ErrorIs(t, c.Err, archive.ErrNotFound)
}

func TestDA1ProofFormAndEarlierCandidatesReachTheReport(t *testing.T) {
	tests := []struct {
		name         string
		form, early  int
		wantVerdict  verifier.Verdict
		wantWarnings int
	}{
		{"form 1, no earlier candidate", 1, 0, verifier.VerdictValid, 0},
		{"form 1, earlier candidates", 1, 3, verifier.VerdictValid, 1},
		{"form 0 is refused", 0, 0, verifier.VerdictUnchecked, 0},
		{"unknown form", 2, 0, verifier.VerdictUnchecked, 0},
		{"negative count", 1, -1, verifier.VerdictUnchecked, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := newRig(t, newFibreParts(t))
			r.anchor.proofForm, r.anchor.earlier = tc.form, tc.early
			rep := r.verify(t)
			assert.Equal(t, tc.wantVerdict, rep.Verdict)
			if tc.wantVerdict == verifier.VerdictUnchecked {
				requireOnly(t, unchecked(t, rep, verifier.CheckAnchor, verifier.ReasonSourceCorrupt).Err, verifier.ErrAnchorInvalid)
				assert.Zero(t, rep.AnchorProofForm, "nothing of a refused anchor is reported")
				assert.Zero(t, rep.AnchorCandidatesEarlier)
				return
			}
			assert.Equal(t, tc.form, rep.AnchorProofForm)
			assert.Equal(t, tc.early, rep.AnchorCandidatesEarlier)
			assert.Len(t, rep.Warnings, tc.wantWarnings)
		})
	}
}

func TestDA2ReportHasNoProofFormFields(t *testing.T) {
	r := newRig(t, newParts(t))
	r.anchor.proofForm, r.anchor.earlier = 1, 4
	rep := r.verify(t)
	assert.Equal(t, verifier.VerdictValid, rep.Verdict)
	assert.Zero(t, rep.AnchorProofForm)
	assert.Zero(t, rep.AnchorCandidatesEarlier)
}
