package blob_test

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/sdk/blob"
	"github.com/vgonkivs/edicta/test/sdkfix"
)

func requireOnly(t *testing.T, err, want error) {
	t.Helper()
	sdkfix.RequireOnly(t, err, want, sdkfix.BlobSentinels())
}

func TestConstants(t *testing.T) {
	assert.EqualValues(t, 1, blob.Version)
	assert.Equal(t, 1, blob.MinRecipients)
	assert.Equal(t, 16, blob.MaxRecipients)
	assert.Equal(t, 32, blob.MaxKIDSize)
	assert.Equal(t, 32, blob.EncSize)
	assert.Equal(t, 48, blob.WrappedDEKSize)
	assert.Equal(t, 12, blob.NonceSize)
	assert.Equal(t, 32, blob.SaltSize)
	assert.Equal(t, 49, blob.MinCiphertextSize)
	assert.EqualValues(t, commitment.MaxPayloadSize, blob.MaxDecodeSize)
	assert.EqualValues(t, commitment.MaxPayloadSize-5, blob.MaxSealSize)
	assert.Equal(t, "edicta/v1/payload", blob.TagPayloadAEAD)
	assert.Equal(t, "edicta/v1/payload-dek", blob.TagPayloadDEK)
}

func newKey(t *testing.T, kid string) (blob.Recipient, *ecdh.PrivateKey) {
	t.Helper()
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	return blob.Recipient{KID: []byte(kid), PublicKey: k.PublicKey()}, k
}

func recipients(t *testing.T, n int) ([]blob.Recipient, []*ecdh.PrivateKey) {
	t.Helper()
	var rs []blob.Recipient
	var ks []*ecdh.PrivateKey
	for i := range n {
		r, k := newKey(t, fmt.Sprintf("rcpt-%02d", i))
		rs = append(rs, r)
		ks = append(ks, k)
	}
	return rs, ks
}

// seal seals and returns the salt Seal drew.
func seal(t testing.TB, pt []byte, rs []blob.Recipient) ([]byte, [blob.SaltSize]byte) {
	t.Helper()
	raw, salt, err := blob.Seal(pt, rs)
	require.NoError(t, err)
	return raw, salt
}

// Seal then Open for every recipient, by kid and by trying every entry.
func TestRoundTrip(t *testing.T) {
	pt := []byte("a decision, canonical CBOR in real use")
	for _, n := range []int{1, 2, 16} {
		t.Run(fmt.Sprintf("%d recipients", n), func(t *testing.T) {
			rs, ks := recipients(t, n)
			raw, salt := seal(t, pt, rs)

			b, err := blob.Decode(raw)
			require.NoError(t, err)
			require.Len(t, b.Recipients, n)
			assert.EqualValues(t, 1, b.Version)
			assert.Len(t, b.Ciphertext, blob.SaltSize+len(pt)+16)
			enc, err := blob.Encode(b)
			require.NoError(t, err)
			require.Equal(t, raw, enc, "Encode(Decode(x)) must be x")

			for i := range rs {
				for _, withKID := range []bool{true, false} {
					k := sdkfix.OpenKeyOf(t, nil, ks[i])
					if withKID {
						k.KID = rs[i].KID
					}
					s, got, err := blob.Open(raw, k)
					require.NoErrorf(t, err, "recipient %d kid %v", i, withKID)
					assert.Equal(t, salt, s)
					assert.Equal(t, pt, got)
				}
			}
		})
	}
}

func TestSealIsRandomised(t *testing.T) {
	rs, ks := recipients(t, 1)
	a, saltA := seal(t, []byte("same input"), rs)
	b, saltB := seal(t, []byte("same input"), rs)
	require.NotEqual(t, a, b, "fresh DEK, nonce and ephemeral key per blob")
	require.NotEqual(t, saltA, saltB, "a fresh salt per blob")
	da, err := blob.Decode(a)
	require.NoError(t, err)
	db, err := blob.Decode(b)
	require.NoError(t, err)
	assert.NotEqual(t, da.AEADNonce, db.AEADNonce)
	assert.NotEqual(t, da.Ciphertext, db.Ciphertext, "a fresh DEK changes the ciphertext")
	assert.NotEqual(t, da.Recipients[0].Enc, db.Recipients[0].Enc)
	_, p, err := blob.Open(a, sdkfix.OpenKeyOf(t, nil, ks[0]))
	require.NoError(t, err)
	assert.Equal(t, []byte("same input"), p)
}

func TestSealKeepsProducerOrder(t *testing.T) {
	rs, _ := recipients(t, 3)
	rs[0], rs[2] = rs[2], rs[0]
	raw, _ := seal(t, []byte("x"), rs)
	b, err := blob.Decode(raw)
	require.NoError(t, err)
	for i := range rs {
		assert.Equal(t, rs[i].KID, b.Recipients[i].KID)
	}
}

func TestSealDoesNotKeepInputs(t *testing.T) {
	rs, _ := recipients(t, 1)
	pt := []byte("plaintext stays with the caller")
	keep := bytes.Clone(pt)
	seal(t, pt, rs)
	assert.Equal(t, keep, pt, "Seal must not modify the plaintext")
}

func TestSealRejects(t *testing.T) {
	good, _ := recipients(t, 17)
	p256, err := ecdh.P256().GenerateKey(rand.Reader)
	require.NoError(t, err)

	tests := []struct {
		name string
		pt   []byte
		rs   []blob.Recipient
		want error // nil: any error
	}{
		{"no recipients", []byte("x"), nil, blob.ErrRecipients},
		{"empty recipient list", []byte("x"), []blob.Recipient{}, blob.ErrRecipients},
		{"17 recipients", []byte("x"), good, blob.ErrRecipients},
		{"duplicate kid", []byte("x"),
			[]blob.Recipient{good[0], {KID: good[0].KID, PublicKey: good[1].PublicKey}}, blob.ErrDuplicateKID},
		{"empty kid", []byte("x"), []blob.Recipient{{KID: nil, PublicKey: good[0].PublicKey}}, nil},
		{"kid of 33 bytes", []byte("x"),
			[]blob.Recipient{{KID: bytes.Repeat([]byte{1}, 33), PublicKey: good[0].PublicKey}}, nil},
		{"nil public key", []byte("x"), []blob.Recipient{{KID: []byte("k")}}, blob.ErrRecipientKey},
		{"P-256 public key", []byte("x"),
			[]blob.Recipient{{KID: []byte("k"), PublicKey: p256.PublicKey()}}, blob.ErrRecipientKey},
		{"empty plaintext", nil, good[:1], nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw, salt, err := blob.Seal(tt.pt, tt.rs)
			require.Error(t, err)
			assert.Nil(t, raw)
			assert.Equal(t, [blob.SaltSize]byte{}, salt)
			if tt.want != nil {
				requireOnly(t, err, tt.want)
			}
		})
	}
}

func TestSealKIDBounds(t *testing.T) {
	r, k := newKey(t, "x")
	for _, n := range []int{1, 32} {
		t.Run(fmt.Sprintf("kid of %d bytes", n), func(t *testing.T) {
			kid := bytes.Repeat([]byte{0xab}, n)
			raw, _ := seal(t, []byte("x"), []blob.Recipient{{KID: kid, PublicKey: r.PublicKey}})
			_, _, err := blob.Open(raw, sdkfix.OpenKeyOf(t, kid, k))
			require.NoError(t, err)
		})
	}
}

func TestSealTooLarge(t *testing.T) {
	if testing.Short() {
		t.Skip("allocates 128 MiB")
	}
	rs, _ := recipients(t, 1)
	_, _, err := blob.Seal(make([]byte, blob.MaxSealSize), rs)
	requireOnly(t, err, blob.ErrTooLarge)
}

func TestDecodeTooLarge(t *testing.T) {
	if testing.Short() {
		t.Skip("allocates 128 MiB")
	}
	_, err := blob.Decode(make([]byte, blob.MaxDecodeSize+1))
	requireOnly(t, err, blob.ErrTooLarge)
}

func sealed(t *testing.T, n int) ([]byte, []*ecdh.PrivateKey, []blob.Recipient) {
	t.Helper()
	rs, ks := recipients(t, n)
	raw, _ := seal(t, []byte("the committed decision"), rs)
	return raw, ks, rs
}

func TestOpenWrongKey(t *testing.T) {
	raw, _, rs := sealed(t, 2)
	_, stranger := newKey(t, "stranger")
	tests := []struct {
		name string
		key  blob.RecipientKey
		want error
	}{
		{"known kid, wrong key", sdkfix.OpenKeyOf(t, rs[0].KID, stranger), blob.ErrUnwrap},
		{"no kid, wrong key", sdkfix.OpenKeyOf(t, nil, stranger), blob.ErrUnwrap},
		{"unknown kid", sdkfix.OpenKeyOf(t, []byte("nobody"), stranger), blob.ErrNoRecipient},
		{"zero-value key", blob.RecipientKey{KID: rs[0].KID}, blob.ErrRecipientKey},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, pt, err := blob.Open(raw, tt.key)
			requireOnly(t, err, tt.want)
			assert.Equal(t, [blob.SaltSize]byte{}, s)
			assert.Nil(t, pt)
		})
	}
	t.Run("the constructor refuses a key that is not X25519", func(t *testing.T) {
		p256, err := ecdh.P256().GenerateKey(rand.Reader)
		require.NoError(t, err)
		_, err = blob.NewRecipientKey(p256)
		requireOnly(t, err, blob.ErrRecipientKey)
		_, err = blob.NewRecipientKey(nil)
		requireOnly(t, err, blob.ErrRecipientKey)
	})
}

// Other recipients' entries are not bound to a recipient's AEAD, so a flip
// there leaves that recipient's result unchanged. A flip anywhere else must
// fail. The commitment's ciphertext_hash is what binds the whole blob.
func TestEveryByteFlipFailsOrChangesNothingForTheReader(t *testing.T) {
	raw, ks, rs := sealed(t, 2)
	wantSalt, want, err := blob.Open(raw, sdkfix.OpenKeyOf(t, rs[0].KID, ks[0]))
	require.NoError(t, err)

	failed := 0
	for i := range raw {
		mut := bytes.Clone(raw)
		mut[i] ^= 0x01
		s, pt, err := blob.Open(mut, sdkfix.OpenKeyOf(t, rs[0].KID, ks[0]))
		if err != nil {
			failed++
			assert.Nil(t, pt)
			continue
		}
		require.Equalf(t, want, pt, "byte %d flipped, a different plaintext was accepted", i)
		require.Equal(t, wantSalt, s)
	}
	assert.Greater(t, failed, len(raw)/2, "most single-byte flips must be rejected")
}

func TestOpenDoesNotModifyInput(t *testing.T) {
	raw, ks, rs := sealed(t, 1)
	keep := bytes.Clone(raw)
	_, _, err := blob.Open(raw, sdkfix.OpenKeyOf(t, rs[0].KID, ks[0]))
	require.NoError(t, err)
	assert.Equal(t, keep, raw)
}

// Decode and Encode agree on every proper prefix and every extension.
func TestDecodeTruncationsAndExtensions(t *testing.T) {
	raw, _, _ := sealed(t, 2)
	for n := range raw {
		_, err := blob.Decode(raw[:n])
		requireOnly(t, err, blob.ErrMalformed)
	}
	for _, tail := range [][]byte{{0x00}, {0xff}, raw[:1]} {
		_, err := blob.Decode(append(bytes.Clone(raw), tail...))
		requireOnly(t, err, blob.ErrMalformed)
	}
}

func entry(kid string, fill byte) blob.Entry {
	e := blob.Entry{KID: []byte(kid)}
	for i := range e.Enc {
		e.Enc[i] = fill
	}
	for i := range e.WrappedDEK {
		e.WrappedDEK[i] = fill
	}
	return e
}

func TestEncodeRejects(t *testing.T) {
	ok := func() *blob.Blob {
		return &blob.Blob{Version: blob.Version, Recipients: []blob.Entry{entry("a", 1)}, Ciphertext: make([]byte, blob.MinCiphertextSize)}
	}
	many := func(n int) []blob.Entry {
		var es []blob.Entry
		for i := range n {
			es = append(es, entry(fmt.Sprintf("k%02d", i), byte(i)))
		}
		return es
	}
	tests := []struct {
		name string
		mod  func(b *blob.Blob)
		want error
	}{
		{"version 0", func(b *blob.Blob) { b.Version = 0 }, blob.ErrVersion},
		{"version 2", func(b *blob.Blob) { b.Version = 2 }, blob.ErrVersion},
		{"no recipients", func(b *blob.Blob) { b.Recipients = nil }, blob.ErrRecipients},
		{"17 recipients", func(b *blob.Blob) { b.Recipients = many(17) }, blob.ErrRecipients},
		{"duplicate kid", func(b *blob.Blob) { b.Recipients = []blob.Entry{entry("a", 1), entry("a", 2)} }, blob.ErrDuplicateKID},
		{"empty kid", func(b *blob.Blob) { b.Recipients[0].KID = nil }, blob.ErrMalformed},
		{"kid of 33 bytes", func(b *blob.Blob) { b.Recipients[0].KID = bytes.Repeat([]byte{1}, 33) }, blob.ErrMalformed},
		{"ciphertext of 48 bytes", func(b *blob.Blob) { b.Ciphertext = make([]byte, 48) }, blob.ErrMalformed},
		{"nil ciphertext", func(b *blob.Blob) { b.Ciphertext = nil }, blob.ErrMalformed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := ok()
			tt.mod(b)
			out, err := blob.Encode(b)
			requireOnly(t, err, tt.want)
			assert.Nil(t, out)
		})
	}
	t.Run("sixteen recipients and the minimum ciphertext", func(t *testing.T) {
		b := ok()
		b.Recipients = many(16)
		raw, err := blob.Encode(b)
		require.NoError(t, err)
		d, err := blob.Decode(raw)
		require.NoError(t, err)
		assert.Len(t, d.Recipients, 16)
	})
	t.Run("nil blob", func(t *testing.T) {
		_, err := blob.Encode(nil)
		require.Error(t, err)
	})
}

// Each recipient adds 89 bytes plus the kid (one more for a kid of 24 bytes or
// longer), not the payload size.
func TestSizePerRecipient(t *testing.T) {
	pt := bytes.Repeat([]byte{7}, 1000)
	sizeFor := func(n int) int {
		rs, _ := recipients(t, n) // kids are 7 bytes
		raw, _ := seal(t, pt, rs)
		return len(raw)
	}
	assert.Equal(t, 89+len("rcpt-00"), sizeFor(2)-sizeFor(1))
	assert.Equal(t, 15*(89+len("rcpt-00")), sizeFor(16)-sizeFor(1))
}

// ciphertext_hash is the hash of the whole blob and nothing else.
func TestCiphertextHashCoversTheWholeBlob(t *testing.T) {
	raw, _, _ := sealed(t, 2)
	whole := sha256.Sum256(raw)
	b, err := blob.Decode(raw)
	require.NoError(t, err)
	assert.NotEqual(t, whole, sha256.Sum256(b.Ciphertext))
	reenc, err := blob.Encode(b)
	require.NoError(t, err)
	assert.Equal(t, whole, sha256.Sum256(reenc))
}

// The salt is drawn inside Seal: the exported function takes no salt, returns
// the one it drew, and every blob gets a different one.
func TestSealDrawsItsOwnSalt(t *testing.T) {
	st := reflect.TypeOf(blob.Seal)
	require.Equal(t, 2, st.NumIn(), "plaintext and recipients only")
	assert.Equal(t, reflect.TypeOf([]byte(nil)), st.In(0))
	assert.Equal(t, reflect.TypeOf([]blob.Recipient(nil)), st.In(1))
	require.Equal(t, 3, st.NumOut())
	assert.Equal(t, reflect.TypeOf([blob.SaltSize]byte{}), st.Out(1))

	rs, ks := recipients(t, 1)
	seen := map[[blob.SaltSize]byte]bool{}
	for range 64 {
		raw, salt := seal(t, []byte("buy"), rs)
		assert.NotEqual(t, [blob.SaltSize]byte{}, salt)
		seen[salt] = true
		s, _, err := blob.Open(raw, sdkfix.OpenKeyOf(t, nil, ks[0]))
		require.NoError(t, err)
		assert.Equal(t, salt, s, "the returned salt is the one inside the blob")
	}
	assert.Len(t, seen, 64, "no salt repeats")
}

// An empty, non-nil kid means "try every entry", like nil.
func TestOpenEmptyKIDTriesEveryEntry(t *testing.T) {
	raw, ks, _ := sealed(t, 3)
	for _, kid := range [][]byte{nil, {}} {
		s, pt, err := blob.Open(raw, sdkfix.OpenKeyOf(t, kid, ks[2]))
		require.NoErrorf(t, err, "kid %#v", kid)
		assert.Equal(t, []byte("the committed decision"), pt)
		assert.NotEqual(t, [blob.SaltSize]byte{}, s)
	}
}

// No key material is printable through any verb, including when the key is an
// unexported field of another struct or copied by value.
func TestRecipientKeyIsNotPrintable(t *testing.T) {
	rs, ks := recipients(t, 1)
	_ = rs
	k := sdkfix.OpenKeyOf(t, []byte("k"), ks[0])
	copyOfK := k
	type holder struct{ key blob.RecipientKey }
	type ptrHolder struct{ key *blob.RecipientKey }
	type nested struct{ h holder }
	for name, v := range map[string]any{
		"value":            k,
		"copy":             copyOfK,
		"pointer":          &k,
		"unexported field": holder{key: k},
		"pointer field":    ptrHolder{key: &k},
		"nested":           nested{h: holder{key: k}},
		"slice":            []blob.RecipientKey{k},
		"map":              map[string]blob.RecipientKey{"a": k},
		"array":            [1]blob.RecipientKey{k},
	} {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d", "%t", "%p", "%10v", "%-10s", "%08.3f"} {
			out := fmt.Sprintf(verb, v)
			secret := ks[0].Bytes()
			assert.NotContainsf(t, out, hex.EncodeToString(secret), "%s %s: hex", name, verb)
			assert.NotContainsf(t, out, fmt.Sprint(secret), "%s %s: decimal bytes", name, verb)
			assert.NotContainsf(t, out, string(secret), "%s %s: raw bytes", name, verb)
		}
	}
}
