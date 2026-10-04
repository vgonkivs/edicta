package sdk_test

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/sdk"
	"github.com/vgonkivs/edicta/test/gatefix"
	"github.com/vgonkivs/edicta/test/sdkfix"
)

var verbs = []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d", "%t", "%08.3f", "%10v", "%-10s"}

func requireNoSecret(t *testing.T, what string, v any, secrets ...[]byte) {
	t.Helper()
	var outs []string
	for _, verb := range verbs {
		outs = append(outs, fmt.Sprintf(verb, v), fmt.Sprintf(verb, &v))
	}
	var buf bytes.Buffer
	slog.New(slog.NewTextHandler(&buf, nil)).Info("x", "v", v)
	slog.New(slog.NewJSONHandler(&buf, nil)).Info("x", "v", v)
	outs = append(outs, buf.String(), fmt.Sprint(v), fmt.Sprintln(v))
	for _, out := range outs {
		for _, s := range secrets {
			require.NotEmptyf(t, s, "%s: empty secret in the test", what)
			assert.NotContainsf(t, out, string(s), "%s leaks raw key bytes", what)
			assert.NotContainsf(t, out, sdkfix.HexOf(s), "%s leaks hex key bytes", what)
			assert.NotContainsf(t, out, fmt.Sprint(s), "%s leaks decimal key bytes", what)
		}
	}
}

// Every type that holds a private key stays silent under every fmt verb and
// every log handler, by value and by pointer.
func TestKeyHoldersNeverPrintKeys(t *testing.T) {
	priv := gatefix.Key(t, "agent1")
	signer, err := sdk.NewEd25519Signer(bytes.Clone(priv))
	require.NoError(t, err)
	secrets := [][]byte{priv.Seed(), priv}

	t.Run("Ed25519Signer", func(t *testing.T) { requireNoSecret(t, "signer", signer, secrets...) })

	r := newRig(t)
	k := r.vec.Key(t, "gate-paper-1")
	rk := sdkfix.OpenKeyOf(t, k.KID, k.Priv)
	t.Run("RecipientKey", func(t *testing.T) { requireNoSecret(t, "recipient key", rk, k.Priv.Bytes()) })
	t.Run("RecipientKey by pointer", func(t *testing.T) { requireNoSecret(t, "recipient key", &rk, k.Priv.Bytes()) })

	b, err := sdk.New(r.cfg, sdk.Deps{Publisher: r.rec, Signer: signer, Clock: r.clock, Chain: r.chain})
	require.NoError(t, err)
	t.Run("Builder", func(t *testing.T) { requireNoSecret(t, "builder", b, secrets...) })
	t.Run("Deps", func(t *testing.T) {
		requireNoSecret(t, "deps", sdk.Deps{Publisher: r.rec, Signer: signer, Clock: r.clock}, secrets...)
	})

	s, err := b.Seal(bg, r.payload())
	require.NoError(t, err)
	c0 := r.vec.Case0(t)
	t.Run("Sealed", func(t *testing.T) { requireNoSecret(t, "sealed", s, c0.Salt[:], c0.DEK) })

	t.Run("a closed signer", func(t *testing.T) {
		require.NoError(t, signer.Close())
		requireNoSecret(t, "closed signer", signer, secrets...)
	})
}

// The opener checks the commitment against the default chain parameters, not
// the gate's, because replay happens long after signing.
func TestOpenPayloadUsesDefaultParams(t *testing.T) {
	v := sdkfix.Load(t)
	c0 := v.Case0(t)
	k := v.Key(t, "gate-paper-1").OpenKey(true)
	resign := func(ttl uint64) []byte {
		s, err := commitment.DecodeSigned(c0.Envelope)
		require.NoError(t, err)
		c := gatefix.Clone(&s.Commitment)
		c.ValidUntil = c.IssuedAt + ttl
		env, _ := gatefix.Sign(t, "agent1", c)
		return env
	}
	short := commitment.Params{FibreRetentionS: 4800, BlobRetentionS: 4800, SkewS: 30} // maximum ttl 1200

	t.Run("a ttl that a gate with short retention refuses still opens", func(t *testing.T) {
		env := resign(2000)
		_, _, err := commitment.VerifyForGate(env, 1791000060, scope, short)
		require.ErrorIs(t, err, commitment.ErrTTLTooLong, "the gate with short retention would refuse it")
		o, err := sdk.OpenPayload(env, c0.Blob, k)
		require.NoError(t, err)
		assert.NotNil(t, o.Payload)
	})
	t.Run("a ttl above every chain's cap is refused", func(t *testing.T) {
		o, err := sdk.OpenPayload(resign(3601), c0.Blob, k)
		require.ErrorIs(t, err, commitment.ErrTTLTooLong)
		assert.Nil(t, o)
	})
	t.Run("an expired commitment still opens", func(t *testing.T) {
		o, err := sdk.OpenPayload(c0.Envelope, c0.Blob, k)
		require.NoError(t, err)
		assert.NotNil(t, o)
	})
}

// A failed Finalize may be retried, but two attempts never yield two
// commitments with one nonce, and at most one attempt succeeds.
func TestFinalizeRetrySemantics(t *testing.T) {
	t.Run("signature lost after signing: the retry has the same nonce", func(t *testing.T) {
		r := newRig(t)
		var leakedHash commitment.Hash
		var leakedSig []byte
		r.signer.override = func(h commitment.Hash) ([]byte, error) {
			sig, err := r.signer.inner.SignCommitment(bg, h)
			require.NoError(t, err)
			if leakedSig == nil {
				leakedHash, leakedSig = h, sig
				return nil, errors.New("kms timeout after signing")
			}
			return sig, nil
		}
		b := r.builder()
		s, err := b.Seal(bg, r.payload())
		require.NoError(t, err)
		pub, err := b.Publish(bg, s)
		require.NoError(t, err)

		res, err := b.Finalize(bg, s, pub)
		require.Error(t, err)
		assert.Nil(t, res)

		res, err = b.Finalize(bg, s, pub)
		require.NoError(t, err, "a failed attempt does not consume the sealed payload")
		assert.Equal(t, leakedHash, res.CommitmentHash, "same clock, same nonce: the retry is the same commitment")
		assert.True(t, ed25519.Verify(res.Commitment.AgentPubKey, commitment.SigningMessage(res.CommitmentHash), leakedSig),
			"the leaked signature is a signature over the retry's commitment, not over another order")

		_, err = b.Finalize(bg, s, pub)
		require.ErrorIs(t, err, sdk.ErrAlreadyFinalized)
		assert.Equal(t, 2, r.signer.calls())
	})
	t.Run("failure before signing never calls the signer", func(t *testing.T) {
		r := newRig(t)
		r.rec.other = []byte("other")
		b := r.builder()
		s, err := b.Seal(bg, r.payload())
		require.NoError(t, err)
		pub, err := b.Publish(bg, s)
		require.NoError(t, err)
		for range 3 {
			_, err = b.Finalize(bg, s, pub)
			require.ErrorIs(t, err, sdk.ErrDACommitmentMismatch)
		}
		assert.Zero(t, r.signer.calls())
	})
	t.Run("concurrent Finalize of one sealed payload", func(t *testing.T) {
		r := newRig(t)
		b := r.builder()
		s, err := b.Seal(bg, r.payload())
		require.NoError(t, err)
		pub, err := b.Publish(bg, s)
		require.NoError(t, err)
		const n = 16
		var wg sync.WaitGroup
		var mu sync.Mutex
		var ok int
		for range n {
			wg.Add(1)
			go func() {
				defer wg.Done()
				res, err := b.Finalize(bg, s, pub)
				mu.Lock()
				defer mu.Unlock()
				if err == nil {
					ok++
					assert.NotNil(t, res)
				} else {
					assert.ErrorIs(t, err, sdk.ErrAlreadyFinalized)
				}
			}()
		}
		wg.Wait()
		assert.Equal(t, 1, ok)
		assert.Equal(t, 1, r.signer.calls(), "one signature for one payload")
	})
	t.Run("two Sealed from one payload never share a nonce or a blob", func(t *testing.T) {
		r := newRig(t)
		b := r.builder()
		p := r.payload()
		s1, err := b.Seal(bg, p)
		require.NoError(t, err)
		s2, err := b.Seal(bg, p)
		require.NoError(t, err)
		assert.NotEqual(t, s1.Blob(), s2.Blob())
		pub1, err := b.Publish(bg, s1)
		require.NoError(t, err)
		pub2, err := b.Publish(bg, s2)
		require.NoError(t, err)
		r1, err := b.Finalize(bg, s1, pub1)
		require.NoError(t, err)
		r2, err := b.Finalize(bg, s2, pub2)
		require.NoError(t, err)
		assert.NotEqual(t, r1.Commitment.Nonce, r2.Commitment.Nonce)
	})
	t.Run("a Published for another blob is refused", func(t *testing.T) {
		r := newRig(t)
		b := r.builder()
		s1, err := b.Seal(bg, r.payload())
		require.NoError(t, err)
		s2, err := b.Seal(bg, r.payload())
		require.NoError(t, err)
		pub2, err := b.Publish(bg, s2)
		require.NoError(t, err)
		res, err := b.Finalize(bg, s1, pub2)
		require.ErrorIs(t, err, sdk.ErrDACommitmentMismatch)
		assert.Nil(t, res)
		assert.Zero(t, r.signer.calls())
	})
}
