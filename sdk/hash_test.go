package sdk_test

import (
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/sdk/blob"
	"github.com/vgonkivs/edicta/test/gatefix"
)

type hashCase struct {
	ID                string `json:"id"`
	BlobHex           string `json:"blob_hex"`
	PayloadSize       string `json:"payload_size"`
	CiphertextHashHex string `json:"ciphertext_hash_hex"`
	SaltHex           string `json:"salt_hex"`
	PlaintextHex      string `json:"plaintext_hex"`
	PlaintextHashHex  string `json:"plaintext_hash_hex"`
}

func hashCases(t testing.TB) map[string]hashCase {
	var f struct {
		Cases []hashCase `json:"cases"`
	}
	gatefix.ReadVector(t, "payload.json", &f)
	out := map[string]hashCase{}
	for _, c := range f.Cases {
		out[c.ID] = c
	}
	return out
}

// ciphertext_hash = SHA-256 of the whole blob and payload_size = its length;
// the pre-existing blob conforms to the blob layout.
func TestCiphertextHashVector(t *testing.T) {
	c, ok := hashCases(t)["ciphertext_hash_small_blob"]
	require.True(t, ok)
	raw := gatefix.MustHex(t, c.BlobHex)
	sum := sha256.Sum256(raw)
	assert.Equal(t, gatefix.MustHex(t, c.CiphertextHashHex), sum[:])
	assert.EqualValues(t, gatefix.U64(t, c.PayloadSize), len(raw))
	b, err := blob.Decode(raw)
	require.NoError(t, err, "the existing payload blob follows the strict layout")
	enc, err := blob.Encode(b)
	require.NoError(t, err)
	assert.Equal(t, raw, enc)
}

// plaintext_hash = SHA-256(salt || plaintext), no domain tag.
func TestPlaintextHashVector(t *testing.T) {
	c, ok := hashCases(t)["plaintext_hash_basic"]
	require.True(t, ok)
	salt, pt := gatefix.MustHex(t, c.SaltHex), gatefix.MustHex(t, c.PlaintextHex)
	require.Len(t, salt, 32)
	want := gatefix.MustHex(t, c.PlaintextHashHex)

	sum := sha256.Sum256(append(append([]byte{}, salt...), pt...))
	assert.Equal(t, want, sum[:])
	var s [32]byte
	copy(s[:], salt)
	h := commitment.PlaintextHash(s, pt)
	assert.Equal(t, want, h[:])
}

// What the builder signs is what the spec defines, checked from the outside:
// the blob that was published, the bytes the recipient decrypts.
func TestBuilderHashesMatchTheSpecDefinitions(t *testing.T) {
	r := newRig(t)
	b := r.builder()
	s, err := b.Seal(bg, r.payload())
	require.NoError(t, err)
	pub, err := b.Publish(bg, s)
	require.NoError(t, err)
	res, err := b.Finalize(bg, s, pub)
	require.NoError(t, err)

	published := r.rec.lastBlob(t)
	sum := sha256.Sum256(published)
	assert.Equal(t, sum[:], res.Commitment.CiphertextHash, "ciphertext_hash = SHA-256(published blob)")
	assert.EqualValues(t, len(published), res.Commitment.PayloadSize, "payload_size = len(published blob)")
	assert.Equal(t, commitment.Hash(sum), s.CiphertextHash())

	k := r.vec.Key(t, "auditor-1")
	salt, pt, err := blob.Open(published, k.OpenKey(true))
	require.NoError(t, err)
	assert.Equal(t, encoded(t, r.payload()), pt, "the plaintext is the canonical encoding of the payload")
	aead := append(append([]byte{}, salt[:]...), pt...) // exactly what the AEAD returned
	ph := sha256.Sum256(aead)
	assert.Equal(t, ph[:], res.Commitment.PlaintextHash, "plaintext_hash = SHA-256(salt || plaintext)")
	assert.Equal(t, commitment.Hash(ph), s.PlaintextHash())
	assert.Equal(t, commitment.PlaintextHash(salt, pt), s.PlaintextHash())
}

// The hashes cover the blob only: the DA framing around it does not change
// them, and the blob a Fibre or celestia_blob reader gets back is the same
// bytes.
func TestHashesIgnoreDAFraming(t *testing.T) {
	res := newRig(t).commit()
	framed := append([]byte{0x03, 0, 0, 0, 1}, res.Blob...) // illustrative framing
	err := commitment.CheckPayload(&res.Commitment, framed)
	require.Error(t, err, "framed bytes are not the committed payload")
	require.NoError(t, commitment.CheckPayload(&res.Commitment, res.Blob))
}

func TestSealedExposesTheHashesTheCommitmentCarries(t *testing.T) {
	r := newRig(t)
	b := r.builder()
	s, err := b.Seal(bg, r.payload())
	require.NoError(t, err)
	assert.NotEqual(t, commitment.Hash{}, s.CiphertextHash())
	assert.NotEqual(t, commitment.Hash{}, s.PlaintextHash())
	assert.NotEqual(t, s.CiphertextHash(), s.PlaintextHash())
}
