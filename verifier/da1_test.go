package verifier_test

import (
	"os"
	"path/filepath"
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
	r.anchor.precision = "robust"
	rep := r.verify(t)

	assert.Equal(t, verifier.VerdictValid, rep.Verdict)
	assert.Equal(t, commitment.DAFibre, rep.DA)
	assert.True(t, rep.Authorized)
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

func TestDA1PromiseHeaderTamperedIsAHeaderTrustFailure(t *testing.T) {
	r := newRig(t, newFibreParts(t))
	r.trust.hashes[r.p.ev.PromiseHeight] = []byte("another hash")
	rep := r.verify(t)
	c := failed(t, rep, verifier.CheckHeaderTrust)
	requireOnly(t, c.Err, verifier.ErrHeaderTrust)
}

func TestDA1ReplayUsesFibreInputs(t *testing.T) {
	r := newRig(t, newFibreParts(t))
	rr, err := r.verifier(t).Replay(t.Context(), r.p.hash)
	require.NoError(t, err)
	require.True(t, rr.K2.Replayable)
	assert.Equal(t, uint64(14400), rr.K2.R)
	assert.Equal(t, blockTime-10, rr.K2.Start, "start is min(T_H, promise creation)")
	assert.Equal(t, commitment.PathDA, rr.K2.Route)
	assert.True(t, rr.K2.Consistent)
}

func TestDA1PayloadMissingIsIncomplete(t *testing.T) {
	p := newFibreParts(t)
	p.blob = nil
	rep := newRig(t, p).verify(t)
	c := failed(t, rep, verifier.CheckPayload)
	requireOnly(t, c.Err, verifier.ErrArchiveIncomplete)
	require.ErrorIs(t, c.Err, archive.ErrNotFound)
}

// The real da = 1 anchor verifier arrives with the form-1 anchor proof
// (namespace data and the data availability header).
func TestDA1RealAnchorVectors(t *testing.T) {
	path := filepath.Join("..", "spec", "vectors", "da", "fibre_anchor.json")
	if _, err := os.Stat(path); err != nil {
		t.Skip("needs 017: spec/vectors/da/fibre_anchor.json and the form-1 anchor verifier are not merged yet")
	}
	t.Skip("needs 017: enable once the form-1 AnchorVerifier lands in celestia/; fibre_anchor.json drives it with fibre_cert.json")
}
