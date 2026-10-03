package commitment_test

import (
	"bytes"
	"testing"

	"github.com/vgonkivs/prior/commitment"
)

// signerField is key 5 of payload_ref (CBOR uint 5) followed by the bstr head
// and the 20 signer bytes of the minimal_lmt vector.
func signerField(t *testing.T) []byte {
	c, _, _ := baseCommitment(t)
	if len(c.PayloadRef.Signer) != 20 {
		t.Fatalf("vector signer length %d", len(c.PayloadRef.Signer))
	}
	return append([]byte{0x05, 0x54}, c.PayloadRef.Signer...)
}

func TestSignerWireEdges(t *testing.T) {
	good := signedEnv(t, nil)
	field := signerField(t)
	if bytes.Count(good, field) != 1 {
		t.Fatalf("signer field found %d times", bytes.Count(good, field))
	}
	tests := []struct {
		name string
		repl []byte
		want string
	}{
		{"empty bstr", []byte{0x05, 0x40}, "ErrFieldSize"},
		{"21 bytes", append([]byte{0x05, 0x55}, make([]byte, 21)...), "ErrFieldSize"},
		{"uint instead of bstr", []byte{0x05, 0x14}, "ErrWrongType"},
		{"array instead of bstr", []byte{0x05, 0x80}, "ErrWrongType"},
		{"key removed", nil, "ErrMissingField"},
	}
	g, p := edgeGate(t)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := bytes.Replace(good, field, tt.repl, 1)
			if tt.repl == nil {
				// payload_ref map header a5 -> a4
				i := bytes.Index(good, field)
				j := bytes.LastIndex(good[:i], []byte{0xa5})
				env = append(append([]byte{}, good[:j]...), 0xa4)
				env = append(env, good[j+1:i]...)
				env = append(env, good[i+len(field):]...)
			}
			_, err := commitment.DecodeSigned(env)
			assertSentinel(t, err, tt.want)
			_, _, err = commitment.VerifyForGate(env, edgeNow, g, p)
			assertSentinel(t, err, tt.want)
		})
	}
}

// Any 20 bytes are a legal signer; v0 ties it to nothing (spec 10.5).
func TestSignerValuesAccepted(t *testing.T) {
	g, p := edgeGate(t)
	for name, v := range map[string][]byte{
		"all zero": make([]byte, 20),
		"all ff":   bytes.Repeat([]byte{0xff}, 20),
	} {
		t.Run(name, func(t *testing.T) {
			env := signedEnv(t, func(c *commitment.Commitment) { c.PayloadRef.Signer = v })
			s, _, err := commitment.VerifyForGate(env, edgeNow, g, p)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(s.Commitment.PayloadRef.Signer, v) {
				t.Fatal("signer did not round-trip")
			}
		})
	}
}

// The signer is covered by the hash and the signature.
func TestSignerIsBound(t *testing.T) {
	c, _, _ := baseCommitment(t)
	h1, err := commitment.HashOf(c)
	if err != nil {
		t.Fatal(err)
	}
	s, _, err := commitment.Sign(loadKey(t, "agent1"), c)
	if err != nil {
		t.Fatal(err)
	}
	d := *c
	d.PayloadRef.Signer = append([]byte{}, c.PayloadRef.Signer...)
	d.PayloadRef.Signer[19] ^= 1
	h2, err := commitment.HashOf(&d)
	if err != nil {
		t.Fatal(err)
	}
	if h1 == h2 {
		t.Fatal("signer does not affect the commitment hash")
	}
	assertSentinel(t, verifyErr(&commitment.SignedCommitment{Commitment: d, Signature: s.Signature}), "ErrSignatureInvalid")
}

// A fibre commitment carries no key 5, and a decoded one has a nil signer.
func TestFibreCommitmentsHaveNoSigner(t *testing.T) {
	vf := loadValid(t)
	n := 0
	for _, vc := range vf.Cases {
		if vc.Input.PayloadRef.DA != "1" {
			continue
		}
		n++
		c, err := commitment.Decode(mustHex(t, vc.CommitmentCBORHex))
		if err != nil {
			t.Fatalf("%s: %v", vc.ID, err)
		}
		if c.PayloadRef.Signer != nil {
			t.Fatalf("%s: signer %x on a fibre commitment", vc.ID, c.PayloadRef.Signer)
		}
	}
	if n == 0 {
		t.Fatal("no fibre valid vectors")
	}
}
