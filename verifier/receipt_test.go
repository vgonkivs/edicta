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
		Version:           commitment.Version,
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

// reSignRequest makes the executor's record request match the receipt as it
// was changed, so that the receipt still verifies and only differs from the
// decision.
func reSignRequest(t testing.TB, r *commitment.Receipt) {
	t.Helper()
	var h commitment.Hash
	copy(h[:], r.CommitmentHash)
	req, err := commitment.RecordRequestMessage(h, r.GateID, r.RailRef)
	require.NoError(t, err)
	r.ExecutorSignature = ed25519.Sign(gatefix.ExecutorKey(t, "executor1"), req)
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
		name   string
		make   func(t *testing.T, p *parts) []byte
		reason verifier.Reason
	}{
		{"tampered signature", func(t *testing.T, p *parts) []byte {
			b := validReceipt(t, p)
			b[len(b)-1] ^= 1
			return b
		}, verifier.ReasonSourceCorrupt},
		{"signed by a key that is not a gate key", func(t *testing.T, p *parts) []byte {
			return signReceipt(t, gatefix.Key(t, "agent2"), p, nil)
		}, verifier.ReasonReceiptMismatch},
		{"receipt of another commitment", func(t *testing.T, p *parts) []byte {
			return signReceipt(t, gateKey(t), p, func(r *commitment.Receipt) {
				r.CommitmentHash[0] ^= 1
				reSignRequest(t, r)
			})
		}, verifier.ReasonReceiptMismatch},
		{"receipt of another gate", func(t *testing.T, p *parts) []byte {
			return signReceipt(t, gateKey(t), p, func(r *commitment.Receipt) {
				r.GateID = "gate2"
				reSignRequest(t, r)
			})
		}, verifier.ReasonReceiptMismatch},
		{"garbage", func(*testing.T, *parts) []byte { return []byte{0xa0} }, verifier.ReasonSourceCorrupt},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := newParts(t)
			rep := newRig(t, p).verify(t, verifier.WithReceipt(tc.make(t, p)))
			c, ok := rep.Check(verifier.CheckReceipt)
			require.True(t, ok)
			assert.Equal(t, verifier.StatusUnchecked, c.Status, "a receipt file is a source: it is never the reason for invalid")
			assert.Equal(t, tc.reason, c.Reason)
			requireOnly(t, c.Err, verifier.ErrReceiptInvalid)
			assert.Equal(t, verifier.VerdictUnchecked, rep.Verdict)
			assert.True(t, rep.AuthorizationVerified, "a bad receipt does not undo the authorization")
			assert.Nil(t, rep.Receipt)
		})
	}
}
