package commitment_test

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/commitment"
)

func TestValidVectors(t *testing.T) {
	vf := loadValid(t)
	require.NotEmpty(t, vf.Cases, "no valid vectors loaded")
	agent1 := loadKey(t, "agent1")

	for _, vc := range vf.Cases {
		t.Run(vc.ID, func(t *testing.T) {
			require.Equalf(t, "agent1", vc.Signer, "unexpected signer %q", vc.Signer)
			c := toCommitment(t, vc.Input)
			params := toParams(t, vf.Params)
			if vc.Params != nil {
				params = toParams(t, *vc.Params)
			}
			gate := toGate(t, vf.Gate)
			if vc.Gate != nil {
				gate = toGate(t, *vc.Gate)
			}
			now := u64(t, vc.Now)
			wantCanon := mustHex(t, vc.CommitmentCBORHex)
			wantHash := mustHex(t, vc.CommitmentHashHex)
			wantSig := mustHex(t, vc.SignatureHex)
			wantEnv := mustHex(t, vc.EnvelopeHex)

			t.Run("encode", func(t *testing.T) {
				got, err := commitment.Encode(c)
				require.NoError(t, err, "Encode")
				require.Equalf(t, hex.EncodeToString(wantCanon), hex.EncodeToString(got), "canonical bytes differ\n got %x\nwant %x", got, wantCanon)
			})

			t.Run("decode round trip", func(t *testing.T) {
				got, err := commitment.Decode(wantCanon)
				require.NoError(t, err, "Decode")
				require.Equalf(t, c, got, "Decode result differs from vector input\n got %+v\nwant %+v", got, c)
				again, err := commitment.Encode(got)
				require.NoError(t, err, "re-encode differs: err=")
				require.Equalf(t, hex.EncodeToString(wantCanon), hex.EncodeToString(again), "re-encode differs: err=%v", err)
			})

			t.Run("hash", func(t *testing.T) {
				h, err := commitment.HashOf(c)
				require.NoError(t, err, "HashOf")
				require.Equal(t, hex.EncodeToString(wantHash), hex.EncodeToString(h[:]))
				hc := commitment.HashCanonical(wantCanon)
				require.Equal(t, hex.EncodeToString(wantHash), hex.EncodeToString(hc[:]))
				msg := commitment.SigningMessage(commitment.Hash(wantHash))
				require.Equal(t, vc.SignedMessageHex, hex.EncodeToString(msg))
			})

			t.Run("sign", func(t *testing.T) {
				require.Equal(t, hex.EncodeToString(agent1.Public().(ed25519.PublicKey)), hex.EncodeToString(c.AgentPubKey), "vector agent_pubkey is not the agent1 key")
				s, h, err := commitment.Sign(agent1, c)
				require.NoError(t, err, "Sign")
				require.Equal(t, hex.EncodeToString(wantSig), hex.EncodeToString(s.Signature))
				require.Equal(t, hex.EncodeToString(wantHash), hex.EncodeToString(h[:]))
			})

			t.Run("envelope round trip", func(t *testing.T) {
				s, err := commitment.DecodeSigned(wantEnv)
				require.NoError(t, err, "DecodeSigned")
				require.Equal(t, c, &s.Commitment, "DecodeSigned commitment differs from vector input")
				require.Equal(t, hex.EncodeToString(wantSig), hex.EncodeToString(s.Signature))
				enc, err := commitment.EncodeSigned(s)
				require.NoError(t, err, "EncodeSigned")
				require.Equalf(t, hex.EncodeToString(wantEnv), hex.EncodeToString(enc), "envelope differs\n got %x\nwant %x", enc, wantEnv)
			})

			t.Run("verify", func(t *testing.T) {
				s, err := commitment.DecodeSigned(wantEnv)
				require.NoError(t, err, "DecodeSigned")
				h, err := commitment.Verify(s)
				require.NoError(t, err, "Verify")
				require.Equal(t, hex.EncodeToString(wantHash), hex.EncodeToString(h[:]))
			})

			t.Run("action hash", func(t *testing.T) {
				action, salt := actionBytes(t, vc.actionSpec), actionSalt(t, vc.actionSpec)
				h, err := commitment.ActionHash(vc.ActionType, salt, action)
				require.NoError(t, err, "ActionHash")
				require.Equal(t, vc.ActionHashHex, hex.EncodeToString(h[:]))
				require.Equal(t, vc.ActionType, c.Action.Type)
				require.Equal(t, vc.ActionHashHex, hex.EncodeToString(c.Action.Hash))

				prefix := mustHex(t, vc.PrefixHex)
				require.Equal(t, append(append([]byte{byte(len(commitment.TagAction))}, commitment.TagAction...), byte(len(vc.ActionType))), prefix[:len(commitment.TagAction)+2], "preimage prefix head")
				require.Equal(t, vc.ActionType, string(prefix[len(commitment.TagAction)+2:]), "preimage prefix type")
				sum := sha256.New()
				sum.Write(prefix)
				sum.Write(salt)
				sum.Write(action)
				require.Equal(t, vc.ActionHashHex, hex.EncodeToString(sum.Sum(nil)), "independent action hash")
			})

			t.Run("pipeline", func(t *testing.T) {
				s, h, err := commitment.VerifyForGate(wantEnv, now, gate, params)
				require.NoError(t, err, "VerifyForGate")
				require.Equal(t, hex.EncodeToString(wantHash), hex.EncodeToString(h[:]), "VerifyForGate result differs from vector")
				require.Equal(t, c, &s.Commitment, "VerifyForGate result differs from vector")
				err = commitment.CheckAction(&s.Commitment, actionBytes(t, vc.actionSpec), actionSalt(t, vc.actionSpec))
				require.NoError(t, err, "CheckAction")
				require.Equal(t, vc.Pending, s.Commitment.PayloadRef.Pending())
			})
		})
	}
}

func TestValidVectorsPinRequiredCases(t *testing.T) {
	vf := loadValid(t)
	have := map[string]bool{}
	for _, c := range vf.Cases {
		have[c.ID] = true
	}
	for _, id := range []string{
		"minimal_lmt", "ttl_exactly_max", "fibre_small_payload", "blob_large_payload",
		"issued_at_within_skew", "int_head_widths", "max_int_values", "ttl_max_at_601s_retention",
		"action_type_128_chars", "action_one_byte", "action_max_size", "action_json_bytes",
		"v1_minimal_included_fibre", "v1_minimal_included_blob", "v1_pending_fibre", "v1_pending_blob",
		"v1_mandate_ref", "v1_maximal",
	} {
		assert.Truef(t, have[id], "valid vector %q missing", id)
	}
}

func TestVerifyDetectsTamperedCommitment(t *testing.T) {
	vf := loadValid(t)
	vc := validCaseByID(t, vf, "minimal_lmt")
	signed := func() *commitment.SignedCommitment {
		s, err := commitment.DecodeSigned(mustHex(t, vc.EnvelopeHex))
		require.NoError(t, err, "DecodeSigned")
		return s
	}
	tests := []struct {
		name   string
		mutate func(s *commitment.SignedCommitment)
	}{
		{"nonce", func(s *commitment.SignedCommitment) { s.Commitment.Nonce[0] ^= 1 }},
		{"action hash", func(s *commitment.SignedCommitment) { s.Commitment.Action.Hash[0] ^= 1 }},
		{"action type", func(s *commitment.SignedCommitment) { s.Commitment.Action.Type = "application/json" }},
		{"gate id", func(s *commitment.SignedCommitment) { s.Commitment.Scope.GateID = "gate-paper-2" }},
		{"valid_until", func(s *commitment.SignedCommitment) { s.Commitment.ValidUntil++ }},
		{"ciphertext_hash", func(s *commitment.SignedCommitment) { s.Commitment.CiphertextHash[31] ^= 1 }},
		{"signature", func(s *commitment.SignedCommitment) { s.Signature[0] ^= 1 }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := signed()
			tt.mutate(s)
			_, err := commitment.Verify(s)
			assertSentinel(t, err, "ErrSignatureInvalid")
		})
	}
}

// Every single-bit change of a signed envelope must fail the stateless gate
// checks: no byte of the envelope is free.
func TestEveryBitFlipOfAnEnvelopeIsRejected(t *testing.T) {
	vf := loadValid(t)
	vc := validCaseByID(t, vf, "minimal_lmt")
	good := mustHex(t, vc.EnvelopeHex)
	g, p, now := toGate(t, vf.Gate), toParams(t, vf.Params), u64(t, vc.Now)
	_, _, err := commitment.VerifyForGate(good, now, g, p)
	require.NoError(t, err)
	for i := range good {
		for bit := 0; bit < 8; bit++ {
			b := append([]byte(nil), good...)
			b[i] ^= 1 << bit
			_, _, err := commitment.VerifyForGate(b, now, g, p)
			require.Errorf(t, err, "flip of byte %d bit %d accepted", i, bit)
		}
	}
}
