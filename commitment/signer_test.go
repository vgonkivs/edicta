package commitment_test

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/prior/commitment"
)

// signerField is key 5 of payload_ref (CBOR uint 5) followed by the bstr head
// and the 20 signer bytes of the minimal_lmt vector.
func signerField(t *testing.T) []byte {
	c, _, _ := baseCommitment(t)
	require.Lenf(t, c.PayloadRef.Signer, 20, "vector signer length %d", len(c.PayloadRef.Signer))
	return append([]byte{0x05, 0x54}, c.PayloadRef.Signer...)
}

func TestSignerWireEdges(t *testing.T) {
	good := signedEnv(t, nil)
	field := signerField(t)
	require.EqualValuesf(t, 1, bytes.Count(good, field), "signer field found %d times", bytes.Count(good, field))
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

// Any 20 bytes are a legal signer; v0 ties it to nothing.
func TestSignerValuesAccepted(t *testing.T) {
	g, p := edgeGate(t)
	for name, v := range map[string][]byte{
		"all zero": make([]byte, 20),
		"all ff":   bytes.Repeat([]byte{0xff}, 20),
	} {
		t.Run(name, func(t *testing.T) {
			env := signedEnv(t, func(c *commitment.Commitment) { c.PayloadRef.Signer = v })
			s, _, err := commitment.VerifyForGate(env, edgeNow, g, p)
			require.NoError(t, err)
			require.Equal(t, hex.EncodeToString(v), hex.EncodeToString(s.Commitment.PayloadRef.Signer), "signer did not round-trip")
		})
	}
}

// The signer is covered by the hash and the signature.
func TestSignerIsBound(t *testing.T) {
	c, _, _ := baseCommitment(t)
	h1, err := commitment.HashOf(c)
	require.NoError(t, err)
	s, _, err := commitment.Sign(loadKey(t, "agent1"), c)
	require.NoError(t, err)
	d := *c
	d.PayloadRef.Signer = append([]byte{}, c.PayloadRef.Signer...)
	d.PayloadRef.Signer[19] ^= 1
	h2, err := commitment.HashOf(&d)
	require.NoError(t, err)
	require.NotEqual(t, h2, h1, "signer does not affect the commitment hash")
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
		require.NoErrorf(t, err, "%s", vc.ID)
		require.Nilf(t, c.PayloadRef.Signer, "%s: signer %x on a fibre commitment", vc.ID, c.PayloadRef.Signer)
	}
	require.NotEqual(t, 0, n, "no fibre valid vectors")
}
