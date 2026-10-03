package commitment_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"reflect"
	"testing"

	"github.com/vgonkivs/prior/commitment"
)

func TestValidVectors(t *testing.T) {
	vf := loadValid(t)
	if len(vf.Cases) == 0 {
		t.Fatal("no valid vectors loaded")
	}
	agent1 := loadKey(t, "agent1")

	for _, vc := range vf.Cases {
		t.Run(vc.ID, func(t *testing.T) {
			if vc.Signer != "agent1" {
				t.Fatalf("unexpected signer %q", vc.Signer)
			}
			c := toCommitment(t, vc.Input)
			params := toParams(t, vf.Params)
			if vc.Params != nil {
				params = toParams(t, *vc.Params)
			}
			gate := toGate(t, vf.Gate)
			now := u64(t, vc.Now)
			wantCanon := mustHex(t, vc.CommitmentCBORHex)
			wantHash := mustHex(t, vc.CommitmentHashHex)
			wantSig := mustHex(t, vc.SignatureHex)
			wantEnv := mustHex(t, vc.EnvelopeHex)

			t.Run("encode", func(t *testing.T) {
				got, err := commitment.Encode(c)
				if err != nil {
					t.Fatalf("Encode: %v", err)
				}
				if !bytes.Equal(got, wantCanon) {
					t.Fatalf("canonical bytes differ\n got %x\nwant %x", got, wantCanon)
				}
			})

			t.Run("decode round trip", func(t *testing.T) {
				got, err := commitment.Decode(wantCanon)
				if err != nil {
					t.Fatalf("Decode: %v", err)
				}
				if !reflect.DeepEqual(got, c) {
					t.Fatalf("Decode result differs from vector input\n got %+v\nwant %+v", got, c)
				}
				again, err := commitment.Encode(got)
				if err != nil || !bytes.Equal(again, wantCanon) {
					t.Fatalf("re-encode differs: err=%v", err)
				}
			})

			t.Run("hash", func(t *testing.T) {
				h, err := commitment.HashOf(c)
				if err != nil {
					t.Fatalf("HashOf: %v", err)
				}
				if !bytes.Equal(h[:], wantHash) {
					t.Fatalf("hash %x, want %x", h[:], wantHash)
				}
				if hc := commitment.HashCanonical(wantCanon); !bytes.Equal(hc[:], wantHash) {
					t.Fatalf("HashCanonical %x, want %x", hc[:], wantHash)
				}
				msg := commitment.SigningMessage(commitment.Hash(wantHash))
				if hex.EncodeToString(msg) != vc.SignedMessageHex {
					t.Fatalf("signing message %x, want %s", msg, vc.SignedMessageHex)
				}
			})

			t.Run("sign", func(t *testing.T) {
				if !bytes.Equal(c.AgentPubKey, agent1.Public().(ed25519.PublicKey)) {
					t.Fatal("vector agent_pubkey is not the agent1 key")
				}
				s, h, err := commitment.Sign(agent1, c)
				if err != nil {
					t.Fatalf("Sign: %v", err)
				}
				if !bytes.Equal(s.Signature, wantSig) {
					t.Fatalf("signature %x, want %x", s.Signature, wantSig)
				}
				if !bytes.Equal(h[:], wantHash) {
					t.Fatalf("Sign hash %x, want %x", h[:], wantHash)
				}
			})

			t.Run("envelope round trip", func(t *testing.T) {
				s, err := commitment.DecodeSigned(wantEnv)
				if err != nil {
					t.Fatalf("DecodeSigned: %v", err)
				}
				if !reflect.DeepEqual(&s.Commitment, c) {
					t.Fatal("DecodeSigned commitment differs from vector input")
				}
				if !bytes.Equal(s.Signature, wantSig) {
					t.Fatalf("signature %x, want %x", s.Signature, wantSig)
				}
				enc, err := commitment.EncodeSigned(s)
				if err != nil {
					t.Fatalf("EncodeSigned: %v", err)
				}
				if !bytes.Equal(enc, wantEnv) {
					t.Fatalf("envelope differs\n got %x\nwant %x", enc, wantEnv)
				}
			})

			t.Run("verify", func(t *testing.T) {
				s, err := commitment.DecodeSigned(wantEnv)
				if err != nil {
					t.Fatalf("DecodeSigned: %v", err)
				}
				h, err := commitment.Verify(s)
				if err != nil {
					t.Fatalf("Verify: %v", err)
				}
				if !bytes.Equal(h[:], wantHash) {
					t.Fatalf("Verify hash %x, want %x", h[:], wantHash)
				}
			})

			t.Run("pipeline", func(t *testing.T) {
				s, h, err := commitment.VerifyForGate(wantEnv, now, gate, params)
				if err != nil {
					t.Fatalf("VerifyForGate: %v", err)
				}
				if !bytes.Equal(h[:], wantHash) || !reflect.DeepEqual(&s.Commitment, c) {
					t.Fatal("VerifyForGate result differs from vector")
				}
				if err := commitment.CheckAction(&s.Commitment, toOrder(t, vc.Request)); err != nil {
					t.Fatalf("CheckAction: %v", err)
				}
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
		"minimal_lmt", "full_ibkr_order", "sell_with_bound", "notional_exact_equal",
		"ttl_exactly_max", "deadline_eq_valid_until", "fibre_small_payload",
		"blob_large_payload", "issued_at_within_skew", "symbol_ignored_in_action_match",
		"int_head_widths", "max_int_values", "ttl_max_at_601s_retention",
	} {
		if !have[id] {
			t.Errorf("valid vector %q missing", id)
		}
	}
}

func TestVerifyDetectsTamperedCommitment(t *testing.T) {
	vf := loadValid(t)
	vc := validCaseByID(t, vf, "minimal_lmt")
	signed := func() *commitment.SignedCommitment {
		s, err := commitment.DecodeSigned(mustHex(t, vc.EnvelopeHex))
		if err != nil {
			t.Fatalf("DecodeSigned: %v", err)
		}
		return s
	}
	tests := []struct {
		name   string
		mutate func(s *commitment.SignedCommitment)
	}{
		{"nonce", func(s *commitment.SignedCommitment) { s.Commitment.Nonce[0] ^= 1 }},
		{"qty", func(s *commitment.SignedCommitment) { s.Commitment.Action.IBKROrder.Qty++ }},
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
