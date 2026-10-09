package commitment_test

import (
	"crypto/sha256"
	"math"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/commitment"
)

func TestParamsValidate(t *testing.T) {
	const max = uint64(math.MaxInt64)
	tests := []struct {
		name string
		p    commitment.Params
		bad  bool
	}{
		{"default", commitment.DefaultParams(), false},
		{"minimum", commitment.Params{FibreRetentionS: 1, BlobRetentionS: 1, SkewS: 0}, false},
		{"maximum", commitment.Params{FibreRetentionS: max, BlobRetentionS: max, SkewS: 300}, false},
		{"fibre retention zero", commitment.Params{FibreRetentionS: 0, BlobRetentionS: 14400, SkewS: 30}, true},
		{"blob retention zero", commitment.Params{FibreRetentionS: 14400, BlobRetentionS: 0, SkewS: 30}, true},
		{"fibre retention above 2^63-1", commitment.Params{FibreRetentionS: max + 1, BlobRetentionS: 14400, SkewS: 30}, true},
		{"blob retention above 2^63-1", commitment.Params{FibreRetentionS: 14400, BlobRetentionS: max + 1, SkewS: 30}, true},
		{"skew 301", commitment.Params{FibreRetentionS: 14400, BlobRetentionS: 14400, SkewS: 301}, true},
		{"zero value", commitment.Params{}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.p.Validate()
			if tt.bad {
				assertSentinel(t, err, "ErrInvalidParams")
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestDefaultParams(t *testing.T) {
	want := commitment.Params{FibreRetentionS: 14400, BlobRetentionS: 14400, SkewS: 30}
	got := commitment.DefaultParams()
	require.Equal(t, want, got)
}

func TestMaxTTL(t *testing.T) {
	tests := []struct {
		name string
		p    commitment.Params
		da   commitment.DA
		want uint64
	}{
		{"fibre default capped at 1h", commitment.DefaultParams(), commitment.DAFibre, 3600},
		{"blob default capped at 1h", commitment.DefaultParams(), commitment.DACelestiaBlob, 3600},
		{"fibre 600 gives 150", commitment.Params{FibreRetentionS: 600, BlobRetentionS: 14400, SkewS: 30}, commitment.DAFibre, 150},
		{"fibre 601 floors to 150", commitment.Params{FibreRetentionS: 601, BlobRetentionS: 14400, SkewS: 30}, commitment.DAFibre, 150},
		{"fibre 603 floors to 150", commitment.Params{FibreRetentionS: 603, BlobRetentionS: 14400, SkewS: 30}, commitment.DAFibre, 150},
		{"fibre 3 floors to 0", commitment.Params{FibreRetentionS: 3, BlobRetentionS: 14400, SkewS: 30}, commitment.DAFibre, 0},
		{"fibre exactly at the cap boundary", commitment.Params{FibreRetentionS: 14400, BlobRetentionS: 1, SkewS: 30}, commitment.DAFibre, 3600},
		{"fibre just under the cap", commitment.Params{FibreRetentionS: 14399, BlobRetentionS: 1, SkewS: 30}, commitment.DAFibre, 3599},
		{"blob uses blob retention", commitment.Params{FibreRetentionS: 14400, BlobRetentionS: 800, SkewS: 30}, commitment.DACelestiaBlob, 200},
		{"fibre ignores blob retention", commitment.Params{FibreRetentionS: 14400, BlobRetentionS: 800, SkewS: 30}, commitment.DAFibre, 3600},
		{"huge retention does not overflow", commitment.Params{FibreRetentionS: math.MaxInt64, BlobRetentionS: 1, SkewS: 0}, commitment.DAFibre, 3600},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.p.MaxTTL(tt.da)
			require.Equal(t, tt.want, got)
		})
	}
}

// ErrInvalidParams has no vector. Params.Validate runs first in the pipeline,
// before any byte of the input is parsed.
func TestVerifyForGateRejectsInvalidParamsFirst(t *testing.T) {
	vf := loadValid(t)
	vc := validCaseByID(t, vf, "minimal_lmt")
	gate := toGate(t, vf.Gate)
	now := u64(t, vc.Now)
	bad := commitment.Params{FibreRetentionS: 0, BlobRetentionS: 14400, SkewS: 30}

	tests := []struct {
		name string
		env  []byte
	}{
		{"valid envelope", mustHex(t, vc.EnvelopeHex)},
		{"garbage envelope", []byte{0xff, 0xff}},
		{"nil envelope", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := commitment.VerifyForGate(tt.env, now, gate, bad)
			assertSentinel(t, err, "ErrInvalidParams")
		})
	}
}

func TestConstantsAndTags(t *testing.T) {
	assert.Equalf(t, "edicta/v1/decision-commitment", commitment.TagCommitment, "TagCommitment = %q", commitment.TagCommitment)
	assert.Equalf(t, "edicta/v1/sig", commitment.TagSig, "TagSig = %q", commitment.TagSig)
	assert.Equalf(t, "edicta/v1/receipt", commitment.TagReceipt, "TagReceipt = %q", commitment.TagReceipt)
	assert.EqualValuesf(t, 2176, commitment.MaxSignedSize, "size limits: %d %d %d", commitment.MaxSignedSize, commitment.MaxCommitmentSize, commitment.MaxPayloadSize)
	assert.EqualValuesf(t, 2048, commitment.MaxCommitmentSize, "size limits: %d %d %d", commitment.MaxSignedSize, commitment.MaxCommitmentSize, commitment.MaxPayloadSize)
	assert.EqualValues(t, 1<<27, commitment.MaxPayloadSize, "payload size limit")
	assert.Equal(t, "edicta/v1/action", commitment.TagAction)
	assert.Equal(t, "edicta/v1/authorization", commitment.TagAuthorization)
	assert.Equal(t, "edicta/v1/authorization-sig", commitment.TagAuthorizationSig)
	assert.EqualValues(t, 65536, commitment.MaxActionSize)
	assert.EqualValues(t, 128, commitment.MaxActionTypeSize)
	assert.EqualValues(t, 256, commitment.MaxAuthorizationSize)
	assert.EqualValuesf(t, 1, commitment.DAFibre, "DA enum: %d %d", commitment.DAFibre, commitment.DACelestiaBlob)
	assert.EqualValuesf(t, 2, commitment.DACelestiaBlob, "DA enum: %d %d", commitment.DAFibre, commitment.DACelestiaBlob)
}

// The preimages are rebuilt here byte by byte from the layout definition,
// independently of the vector files.
func TestHashAndSigningMessageLayout(t *testing.T) {
	canon := []byte{0xa0, 0x01, 0x02}
	pre := append([]byte{0x1d}, "edicta/v1/decision-commitment"...)
	pre = append(pre, canon...)
	want := sha256.Sum256(pre)
	got := commitment.HashCanonical(canon)
	require.EqualValues(t, want, [32]byte(got))

	msg := commitment.SigningMessage(got)
	wantMsg := append([]byte{0x0d}, "edicta/v1/sig"...)
	wantMsg = append(wantMsg, got[:]...)
	require.Len(t, msg, 46)
	require.Equal(t, string(wantMsg), string(msg))
}
