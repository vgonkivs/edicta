package verifier_test

import (
	"crypto/ed25519"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/test/gatefix"
	"github.com/vgonkivs/edicta/verifier"
)

const railRef = gatefix.RailRef

func signReceipt(t testing.TB, key ed25519.PrivateKey, p *parts, mod func(*commitment.Receipt)) []byte {
	t.Helper()
	ek := gatefix.ExecutorKey(t, "executor1")
	req, err := commitment.RecordRequestMessage(p.hash, gatefix.GateID, railRef)
	require.NoError(t, err)
	r := commitment.Receipt{
		CommitmentHash:    append([]byte(nil), p.hash[:]...),
		GateID:            gatefix.GateID,
		GatePubKey:        key.Public().(ed25519.PublicKey),
		RailRef:           railRef,
		RecordedAt:        authorizedAt + 5,
		ExecutorPubKey:    ek.Public().(ed25519.PublicKey),
		ExecutorSignature: ed25519.Sign(ek, req),
	}
	if mod != nil {
		mod(&r)
	}
	canon, err := commitment.EncodeReceipt(&r)
	require.NoError(t, err)
	h := commitment.HashReceipt(canon)
	b, err := commitment.EncodeSignedReceipt(&commitment.SignedReceipt{
		Receipt:   r,
		Signature: ed25519.Sign(key, commitment.ReceiptSigningMessage(h)),
	})
	require.NoError(t, err)
	return b
}

func validReceipt(t testing.TB, p *parts) []byte { return signReceipt(t, gateKey(t), p, nil) }

func TestReceipt(t *testing.T) {
	t.Run("absent receipt adds no check", func(t *testing.T) {
		rep := newRig(t, newParts(t)).verify(t)
		_, ok := rep.Check(verifier.CheckReceipt)
		assert.False(t, ok)
		assert.Nil(t, rep.Receipt)
	})
	t.Run("valid receipt is an attestation, not proof of execution", func(t *testing.T) {
		p := newParts(t)
		rep := newRig(t, p).verify(t, verifier.WithReceipt(validReceipt(t, p)))
		passed(t, rep, verifier.CheckReceipt)
		require.NotNil(t, rep.Receipt)
		assert.Equal(t, railRef, rep.Receipt.RailRef)
		assert.Equal(t, authorizedAt+5, rep.Receipt.RecordedAt)
		assert.True(t, rep.Receipt.GateAttested)
		assert.False(t, rep.Receipt.ProvenExecution)
		assert.Equal(t, verifier.VerdictValid, rep.Verdict)
	})
	tests := []struct {
		name string
		make func(t *testing.T, p *parts) []byte
	}{
		{"tampered signature", func(t *testing.T, p *parts) []byte {
			b := validReceipt(t, p)
			b[len(b)-1] ^= 1
			return b
		}},
		{"signed by a key that is not a gate key", func(t *testing.T, p *parts) []byte {
			return signReceipt(t, gatefix.Key(t, "agent2"), p, nil)
		}},
		{"receipt of another commitment", func(t *testing.T, p *parts) []byte {
			return signReceipt(t, gateKey(t), p, func(r *commitment.Receipt) { r.CommitmentHash[0] ^= 1 })
		}},
		{"garbage", func(*testing.T, *parts) []byte { return []byte{0xa0} }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := newParts(t)
			rep := newRig(t, p).verify(t, verifier.WithReceipt(tc.make(t, p)))
			c := failed(t, rep, verifier.CheckReceipt)
			requireOnly(t, c.Err, verifier.ErrReceiptInvalid)
			assert.Equal(t, verifier.VerdictInvalid, rep.Verdict)
			assert.True(t, rep.Authorized, "a bad receipt does not undo the authorization")
			assert.Nil(t, rep.Receipt)
		})
	}
}
