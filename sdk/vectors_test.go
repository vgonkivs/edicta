package sdk_test

import (
	"crypto/sha256"
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

// pkgSentinel resolves the sentinel names of the vector file, including the
// sdk ones.
func pkgSentinel(t testing.TB, name string) error {
	t.Helper()
	switch name {
	case "sdk.ErrPlaintextHashMismatch":
		return sdk.ErrPlaintextHashMismatch
	case "sdk.ErrPayloadMismatch":
		return sdk.ErrPayloadMismatch
	}
	e, ok := sdkfix.Sentinel(name)
	require.Truef(t, ok, "unknown sentinel %s", name)
	return e
}

// vectorGate also allows the second action type that one reject vector commits
// to, so the fixture envelope stays a valid commitment.
var vectorGate = commitment.GateScope{
	GateID:      gatefix.GateID,
	ActionTypes: []string{gatefix.ActionType, "application/octet-stream"},
}

var openOutcomes = []error{payload.ErrMalformed, payload.ErrVersion, sdk.ErrPlaintextHashMismatch, sdk.ErrPayloadMismatch}

// Every valid vector opens for every recipient with the full pipeline, and the
// payload it yields is the one in the file.
func TestOpenPayloadValidVectors(t *testing.T) {
	v := sdkfix.Load(t)
	for _, c := range v.Cases {
		t.Run(c.ID, func(t *testing.T) {
			for _, rc := range c.Recipients {
				k := v.Key(t, rc.Key)
				o, err := sdk.OpenPayload(c.Envelope, c.Blob, k.OpenKey(true))
				require.NoError(t, err)
				assert.Equal(t, c.CommitmentHash, o.CommitmentHash)
				back, err := payload.Encode(o.Payload)
				require.NoError(t, err)
				assert.Equal(t, c.Plaintext, back)
			}
		})
	}
}

// The plaintext-stage rejects. The envelope is a real signed commitment bound
// to the blob, carrying the vector's plaintext_hash, action and constraints, so
// only the rule under test can fail.
func TestOpenPayloadPlaintextVectors(t *testing.T) {
	v := sdkfix.Load(t)
	n := 0
	for _, r := range v.Rejects {
		if r.Stage != "plaintext" {
			continue
		}
		n++
		t.Run(r.ID, func(t *testing.T) {
			want := pkgSentinel(t, r.Expect)
			env := v.EnvelopeFor(t, r.Blob, r.PlaintextHash, r.ActionType, r.ActionHash)
			_, _, err := commitment.VerifyForGate(env, 1791000060, vectorGate, params)
			require.NoError(t, err, "the fixture envelope must be a valid commitment")

			k := v.Key(t, r.Key)
			o, err := sdk.OpenPayload(env, r.Blob, blobKey(k, r.KID))
			require.Error(t, err)
			require.ErrorIs(t, err, want)
			for _, other := range openOutcomes {
				if other != want {
					require.NotErrorIs(t, err, other)
				}
			}
			assert.Nil(t, o)
		})
	}
	require.Equal(t, 24, n)
}

func blobKey(k sdkfix.Key, kid []byte) blob.RecipientKey {
	rk := k.OpenKey(false)
	rk.KID = kid
	return rk
}

// One ciphertext, two DEKs, two plaintexts. The auditor's AEAD check passes
// and the bytes are well-formed enough to start parsing; only the comparison
// with plaintext_hash, made before parsing, rejects them. The honest
// recipient is unaffected.
func TestTwoDEKBlobIsRejectedByThePlaintextHash(t *testing.T) {
	v := sdkfix.Load(t)
	var r sdkfix.Reject
	for _, x := range v.Rejects {
		if x.ID == "pb_key_commitment_two_deks" {
			r = x
		}
	}
	require.NotEmpty(t, r.ID)
	env := v.EnvelopeFor(t, r.Blob, r.PlaintextHash, r.ActionType, r.ActionHash)

	t.Run("honest recipient reads the committed decision", func(t *testing.T) {
		k := v.Key(t, r.HonestKey)
		o, err := sdk.OpenPayload(env, r.Blob, blobKey(k, r.HonestKID))
		require.NoError(t, err)
		require.NotNil(t, o.Payload)
	})
	t.Run("second recipient is told the hash differs, not that the payload is malformed", func(t *testing.T) {
		k := v.Key(t, r.Key)
		o, err := sdk.OpenPayload(env, r.Blob, blobKey(k, r.KID))
		require.ErrorIs(t, err, sdk.ErrPlaintextHashMismatch)
		require.NotErrorIs(t, err, payload.ErrMalformed, "parsing must not run before the hash check")
		require.NotErrorIs(t, err, payload.ErrVersion)
		require.NotErrorIs(t, err, sdk.ErrPayloadMismatch)
		assert.Nil(t, o)
	})
	t.Run("the second recipient's bytes really do hash differently", func(t *testing.T) {
		h := sha256.Sum256(r.AuditorAEADPT)
		assert.NotEqual(t, r.PlaintextHash, h[:])
	})
}

// The hash is checked before parsing for every vector whose payload is also
// broken: an unsalted or other-salted hash wins over any parse problem.
func TestPlaintextHashIsCheckedBeforeParsing(t *testing.T) {
	v := sdkfix.Load(t)
	var r sdkfix.Reject
	for _, x := range v.Rejects {
		if x.ID == "pb_payload_unsorted_keys" {
			r = x
		}
	}
	require.NotEmpty(t, r.ID)
	wrong := append([]byte{}, r.PlaintextHash...)
	wrong[0] ^= 1
	env := v.EnvelopeFor(t, r.Blob, wrong, r.ActionType, r.ActionHash)
	_, err := sdk.OpenPayload(env, r.Blob, blobKey(v.Key(t, r.Key), r.KID))
	require.ErrorIs(t, err, sdk.ErrPlaintextHashMismatch)
	require.NotErrorIs(t, err, payload.ErrMalformed)
}
