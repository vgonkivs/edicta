package sdk_test

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/sdk"
	"github.com/vgonkivs/edicta/sdk/blob"
	"github.com/vgonkivs/edicta/sdk/payload"
	"github.com/vgonkivs/edicta/test/gatefix"
	"github.com/vgonkivs/edicta/test/sdkfix"
)

var _ func(envelope, blobBytes []byte, k blob.RecipientKey) (*sdk.Opened, error) = sdk.OpenPayload

func encoded(t testing.TB, p *payload.Payload) []byte {
	t.Helper()
	b, err := payload.Encode(p)
	require.NoError(t, err)
	return b
}

// Build, seal, publish, sign, then every recipient opens the same decision.
func TestRoundTripEveryRecipient(t *testing.T) {
	for _, names := range [][]string{
		{"gate-paper-1"},
		{"gate-paper-1", "auditor-1"},
		{"gate-paper-1", "auditor-1", "counterparty-1", "rcpt-04", "rcpt-05", "rcpt-06", "rcpt-07", "rcpt-08",
			"rcpt-09", "rcpt-10", "rcpt-11", "rcpt-12", "rcpt-13", "rcpt-14", "rcpt-15", "rcpt-16"},
	} {
		t.Run(fmt.Sprintf("%d recipients", len(names)), func(t *testing.T) {
			r := newRig(t)
			r.cfg.Recipients = r.vec.Recipients(t, names...)
			res := r.commit()
			want := encoded(t, withSalt(r.payload(), res.ActionSalt))
			for _, n := range names {
				k := r.vec.Key(t, n)
				for _, withKID := range []bool{true, false} {
					o, err := sdk.OpenPayload(res.Envelope, res.Blob, k.OpenKey(withKID))
					require.NoErrorf(t, err, "%s kid %v", n, withKID)
					assert.Equal(t, res.CommitmentHash, o.CommitmentHash)
					assert.Equal(t, res.Commitment, o.Commitment)
					assert.Equal(t, want, encoded(t, o.Payload), "the recipient reads the decision that was committed")
					assert.Equal(t, res.Action, o.Payload.Action.Data, "the recipient reads the exact action bytes")
					assert.Equal(t, res.ActionSalt, o.Payload.Action.Salt, "the payload carries the salt of the committed hash")
					assert.NoError(t, commitment.CheckAction(&o.Commitment, o.Payload.Action.Data, o.Payload.Action.Salt), "the opened action matches the committed hash")
				}
			}
		})
	}
}

func TestOpenPayloadWrongKey(t *testing.T) {
	r := newRig(t)
	res := r.commit()
	stranger, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	k := r.vec.Key(t, "gate-paper-1")

	o, err := sdk.OpenPayload(res.Envelope, res.Blob, sdkfix.OpenKeyOf(t, nil, stranger))
	require.ErrorIs(t, err, blob.ErrUnwrap)
	assert.Nil(t, o)
	_, err = sdk.OpenPayload(res.Envelope, res.Blob, sdkfix.OpenKeyOf(t, k.KID, stranger))
	require.ErrorIs(t, err, blob.ErrUnwrap)
	_, err = sdk.OpenPayload(res.Envelope, res.Blob, sdkfix.OpenKeyOf(t, []byte("nobody"), stranger))
	require.ErrorIs(t, err, blob.ErrNoRecipient)
}

// A flipped byte anywhere in the blob is a hash mismatch against the
// commitment, before any decryption.
func TestOpenPayloadDetectsEveryTamperedBlobByte(t *testing.T) {
	r := newRig(t)
	res := r.commit()
	k := r.vec.Key(t, "gate-paper-1").OpenKey(true)
	for i := range res.Blob {
		mut := bytes.Clone(res.Blob)
		mut[i] ^= 0x80
		o, err := sdk.OpenPayload(res.Envelope, mut, k)
		require.ErrorIsf(t, err, commitment.ErrPayloadHashMismatch, "byte %d", i)
		require.Nil(t, o)
	}
}

func TestOpenPayloadBlobSizeAndEnvelope(t *testing.T) {
	r := newRig(t)
	res := r.commit()
	k := r.vec.Key(t, "gate-paper-1").OpenKey(true)

	t.Run("blob truncated", func(t *testing.T) {
		_, err := sdk.OpenPayload(res.Envelope, res.Blob[:len(res.Blob)-1], k)
		require.ErrorIs(t, err, commitment.ErrPayloadSizeMismatch)
	})
	t.Run("blob extended", func(t *testing.T) {
		_, err := sdk.OpenPayload(res.Envelope, append(bytes.Clone(res.Blob), 0), k)
		require.ErrorIs(t, err, commitment.ErrPayloadSizeMismatch)
	})
	t.Run("no blob", func(t *testing.T) {
		_, err := sdk.OpenPayload(res.Envelope, nil, k)
		require.ErrorIs(t, err, commitment.ErrPayloadSizeMismatch)
	})
	t.Run("another blob of the same decision", func(t *testing.T) {
		again := r.commit()
		require.NotEqual(t, res.Blob, again.Blob)
		_, err := sdk.OpenPayload(res.Envelope, again.Blob, k)
		require.Error(t, err)
		require.True(t, isAny(err, commitment.ErrPayloadHashMismatch, commitment.ErrPayloadSizeMismatch))
	})
	t.Run("every flipped envelope byte is refused", func(t *testing.T) {
		for i := range res.Envelope {
			mut := bytes.Clone(res.Envelope)
			mut[i] ^= 0x01
			o, err := sdk.OpenPayload(mut, res.Blob, k)
			require.Errorf(t, err, "envelope byte %d", i)
			require.Nil(t, o)
		}
	})
	t.Run("garbage and empty envelopes", func(t *testing.T) {
		for _, env := range [][]byte{nil, {}, {0xa0}, []byte("not cbor")} {
			o, err := sdk.OpenPayload(env, res.Blob, k)
			require.Error(t, err)
			assert.Nil(t, o)
		}
	})
	t.Run("envelope signed by a key other than the one it names", func(t *testing.T) {
		s, err := commitment.DecodeSigned(res.Envelope)
		require.NoError(t, err)
		other := ed25519.Sign(gatefix.Key(t, "agent2"), commitment.SigningMessage(res.CommitmentHash))
		forged, err := commitment.EncodeSigned(&commitment.SignedCommitment{Commitment: s.Commitment, Signature: other})
		require.NoError(t, err)
		o, err := sdk.OpenPayload(forged, res.Blob, k)
		require.ErrorIs(t, err, commitment.ErrSignatureInvalid)
		assert.Nil(t, o)
	})
}
