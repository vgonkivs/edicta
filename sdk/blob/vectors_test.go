package blob_test

import (
	"crypto/ecdh"
	"crypto/hpke"
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/sdk/blob"
	"github.com/vgonkivs/edicta/test/sdkfix"
)

// The suite constants of the vector file and of the package agree.
func TestSuiteConstants(t *testing.T) {
	v := sdkfix.Load(t)
	assert.Equal(t, append([]byte{0x15}, blob.TagPayloadDEK...), v.HPKEInfo)
	assert.Equal(t, append([]byte{0x11}, blob.TagPayloadAEAD...), v.PayloadAAD)
	assert.Len(t, v.HPKEInfo, 22)
	assert.Len(t, v.PayloadAAD, 18)
}

// RFC 9180 Appendix A.2.1 opens with the stdlib suite the blob uses
// (DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20-Poly1305), pinning the
// three identifiers.
func TestHPKEKnownAnswer(t *testing.T) {
	v := sdkfix.Load(t)
	k := v.KAT
	require.Equal(t, 0, k.Mode)
	kem := hpke.DHKEM(ecdh.X25519())
	kdf, aead := hpke.HKDFSHA256(), hpke.ChaCha20Poly1305()
	require.EqualValues(t, 0x0020, kem.ID())
	require.EqualValues(t, 0x0001, kdf.ID())
	require.EqualValues(t, 0x0003, aead.ID())
	require.Equal(t, 0x0020, k.KEMID)
	require.Equal(t, 0x0001, k.KDFID)
	require.Equal(t, 0x0003, k.AEADID)

	sk, err := kem.NewPrivateKey(k.SkR)
	require.NoError(t, err)
	r, err := hpke.NewRecipient(k.Enc, sk, kdf, aead, k.Info)
	require.NoError(t, err)
	pt, err := r.Open(k.AAD, k.CT)
	require.NoError(t, err)
	assert.Equal(t, k.PT, pt)
}

func TestVectorCases(t *testing.T) {
	v := sdkfix.Load(t)
	for _, c := range v.Cases {
		t.Run(c.ID, func(t *testing.T) {
			b, err := blob.Decode(c.Blob)
			require.NoError(t, err)
			assert.EqualValues(t, 0, b.Version)
			require.Len(t, b.Recipients, len(c.Recipients))
			for i, r := range c.Recipients {
				assert.Equal(t, r.KID, b.Recipients[i].KID)
				assert.Equal(t, r.Enc, b.Recipients[i].Enc[:])
				assert.Equal(t, r.Wrapped, b.Recipients[i].WrappedDEK[:])
			}
			assert.Equal(t, c.Nonce, b.AEADNonce[:])
			assert.Equal(t, c.Ciphertext, b.Ciphertext)

			enc, err := blob.Encode(b)
			require.NoError(t, err)
			assert.Equal(t, c.Blob, enc, "Encode(Decode(x)) == x")

			var built blob.Blob
			copy(built.AEADNonce[:], c.Nonce)
			built.Ciphertext = c.Ciphertext
			for _, r := range c.Recipients {
				e := blob.Entry{KID: r.KID}
				copy(e.Enc[:], r.Enc)
				copy(e.WrappedDEK[:], r.Wrapped)
				built.Recipients = append(built.Recipients, e)
			}
			enc, err = blob.Encode(&built)
			require.NoError(t, err)
			assert.Equal(t, c.Blob, enc, "Encode from the seal trace components")

			assert.Equal(t, [32]byte(c.CiphertextHash), sha256.Sum256(c.Blob))
			assert.EqualValues(t, c.PayloadSize, len(c.Blob))

			for _, r := range c.Recipients {
				k := v.Key(t, r.Key)
				for _, withKID := range []bool{true, false} {
					salt, pt, err := blob.Open(c.Blob, k.OpenKey(withKID))
					require.NoErrorf(t, err, "recipient %s kid %v", r.Key, withKID)
					assert.Equal(t, c.Salt, salt)
					assert.Equal(t, c.Plaintext, pt)
					assert.Equal(t, c.PlaintextHash, commitment.PlaintextHash(salt, pt))
				}
			}
		})
	}
}

// A recipient that is not in the blob is told so only when it names a kid.
func TestVectorCasesOtherKeysFail(t *testing.T) {
	v := sdkfix.Load(t)
	c := v.Cases[0]
	stranger := v.Key(t, "counterparty-1")
	_, _, err := blob.Open(c.Blob, stranger.OpenKey(false))
	requireOnly(t, err, blob.ErrUnwrap)
	_, _, err = blob.Open(c.Blob, stranger.OpenKey(true))
	requireOnly(t, err, blob.ErrNoRecipient)
}

func TestVectorDecodeRejects(t *testing.T) {
	v := sdkfix.Load(t)
	n := 0
	for _, r := range v.Rejects {
		if r.Stage != "decode" {
			continue
		}
		n++
		t.Run(r.ID, func(t *testing.T) {
			want, ok := sdkfix.Sentinel(r.Expect)
			require.Truef(t, ok, "unknown sentinel %s", r.Expect)
			b, err := blob.Decode(r.Blob)
			requireOnly(t, err, want)
			assert.Nil(t, b)
		})
	}
	require.Equal(t, 21, n)
}

func TestVectorOpenRejects(t *testing.T) {
	v := sdkfix.Load(t)
	n := 0
	for _, r := range v.Rejects {
		if r.Stage != "open" {
			continue
		}
		n++
		t.Run(r.ID, func(t *testing.T) {
			want, ok := sdkfix.Sentinel(r.Expect)
			require.Truef(t, ok, "unknown sentinel %s", r.Expect)
			k := v.Key(t, r.Key)
			rk := sdkfix.OpenKeyOf(t, r.KID, k.Priv)
			salt, pt, err := blob.Open(r.Blob, rk)
			requireOnly(t, err, want)
			assert.Equal(t, [32]byte{}, salt)
			assert.Nil(t, pt)
		})
	}
	require.Equal(t, 19, n)
}

// Plaintext-stage vectors are well-formed blobs: the blob layer opens them and
// says nothing about the payload. This is why Open is documented as not bound
// to any commitment.
func TestVectorPlaintextRejectsOpenAtTheBlobLayer(t *testing.T) {
	v := sdkfix.Load(t)
	n := 0
	for _, r := range v.Rejects {
		if r.Stage != "plaintext" {
			continue
		}
		n++
		t.Run(r.ID, func(t *testing.T) {
			k := v.Key(t, r.Key)
			_, pt, err := blob.Open(r.Blob, sdkfix.OpenKeyOf(t, r.KID, k.Priv))
			require.NoError(t, err)
			assert.NotEmpty(t, pt)
		})
	}
	require.Equal(t, 24, n)
}

// Both recipients of the two-DEK blob open it without any blob-level error,
// and they get different bytes: only the plaintext_hash comparison can tell.
func TestTwoDEKBlobOpensForBothAtTheBlobLayer(t *testing.T) {
	v := sdkfix.Load(t)
	var r sdkfix.Reject
	for _, x := range v.Rejects {
		if x.ID == "pb_key_commitment_two_deks" {
			r = x
		}
	}
	require.NotEmpty(t, r.ID, "vector missing")
	honest := v.Key(t, r.HonestKey)
	hSalt, hPT, err := blob.Open(r.Blob, sdkfix.OpenKeyOf(t, r.HonestKID, honest.Priv))
	require.NoError(t, err)
	assert.Equal(t, r.PlaintextHash, hashOf(hSalt, hPT), "the honest recipient gets the committed bytes")

	auditor := v.Key(t, r.Key)
	aSalt, aPT, err := blob.Open(r.Blob, sdkfix.OpenKeyOf(t, r.KID, auditor.Priv))
	require.NoError(t, err, "the AEAD accepts the second DEK too")
	assert.NotEqual(t, r.PlaintextHash, hashOf(aSalt, aPT))
	assert.Equal(t, r.AuditorAEADPT, append(aSalt[:], aPT...))
}

func hashOf(salt [32]byte, pt []byte) []byte {
	h := commitment.PlaintextHash(salt, pt)
	return h[:]
}
