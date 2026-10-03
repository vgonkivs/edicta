package commitment_test

import (
	"crypto/sha256"
	"math"
	"testing"

	"github.com/vgonkivs/prior/commitment"
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
			} else if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestDefaultParams(t *testing.T) {
	want := commitment.Params{FibreRetentionS: 14400, BlobRetentionS: 14400, SkewS: 30}
	if got := commitment.DefaultParams(); got != want {
		t.Fatalf("DefaultParams %+v, want %+v", got, want)
	}
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
			if got := tt.p.MaxTTL(tt.da); got != tt.want {
				t.Fatalf("MaxTTL = %d, want %d", got, tt.want)
			}
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
	if commitment.TagCommitment != "prior/v0/decision-commitment" {
		t.Errorf("TagCommitment = %q", commitment.TagCommitment)
	}
	if commitment.TagSig != "prior/v0/sig" {
		t.Errorf("TagSig = %q", commitment.TagSig)
	}
	if commitment.TagReceipt != "prior/v0/receipt" {
		t.Errorf("TagReceipt = %q", commitment.TagReceipt)
	}
	if commitment.MaxSignedSize != 2176 || commitment.MaxCommitmentSize != 2048 || commitment.MaxPayloadSize != 1<<27 {
		t.Errorf("size limits: %d %d %d", commitment.MaxSignedSize, commitment.MaxCommitmentSize, commitment.MaxPayloadSize)
	}
	if commitment.QtyScale != 10_000 || commitment.MoneyScale != 100_000_000 {
		t.Errorf("scales: %d %d", commitment.QtyScale, commitment.MoneyScale)
	}
	if commitment.DAFibre != 1 || commitment.DACelestiaBlob != 2 {
		t.Errorf("DA enum: %d %d", commitment.DAFibre, commitment.DACelestiaBlob)
	}
}

// The preimages are rebuilt here byte by byte from the layout definition,
// independently of the vector files.
func TestHashAndSigningMessageLayout(t *testing.T) {
	canon := []byte{0xa0, 0x01, 0x02}
	pre := append([]byte{0x1c}, "prior/v0/decision-commitment"...)
	pre = append(pre, canon...)
	want := sha256.Sum256(pre)
	got := commitment.HashCanonical(canon)
	if [32]byte(got) != want {
		t.Fatalf("HashCanonical = %x, want %x", got[:], want)
	}

	msg := commitment.SigningMessage(got)
	wantMsg := append([]byte{0x0c}, "prior/v0/sig"...)
	wantMsg = append(wantMsg, got[:]...)
	if len(msg) != 45 || string(msg) != string(wantMsg) {
		t.Fatalf("SigningMessage = %x, want %x", msg, wantMsg)
	}
}
