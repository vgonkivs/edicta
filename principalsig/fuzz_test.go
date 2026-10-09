package principalsig_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/principalsig"
)

func fuzzMessage(id []byte, version uint64, gate string) principalsig.EIP712Message {
	m := principalsig.EIP712Message{Version: version, GateID: gate, MandateHash: sha256.Sum256(id)}
	copy(m.MandateID[:], id)
	return m
}

// Verify must never panic, and must accept a fuzzed signature only when it is
// exactly the one the signer produced for these inputs (all three schemes are
// deterministic here).
func fuzzScheme(f *testing.F, scheme principalsig.Scheme) {
	sk := sha256.Sum256([]byte("fuzz principal"))
	var s principalsig.Signer
	switch scheme {
	case principalsig.Ed25519:
		s = principalsig.NewEd25519Signer(ed25519.NewKeyFromSeed(sk[:]))
	default:
		var err error
		s, err = principalsig.NewSecp256k1Signer(scheme, sk[:], "celestia")
		require.NoError(f, err)
	}
	m := fuzzMessage([]byte("seed"), 1, "gate")
	d := principalsig.ADR036Data([]byte("text\n"), m.MandateHash)
	sig, err := s.Sign(m, d)
	require.NoError(f, err)
	f.Add(s.Principal(), "celestia", []byte("seed"), uint64(1), "gate", []byte("text\n"), sig)
	f.Add(s.Principal(), "cosmos", []byte("seed"), uint64(2), "gate", []byte(""), append(bytes.Clone(sig), 0))
	f.Fuzz(func(t *testing.T, principal []byte, hrp string, id []byte, version uint64, gate string, text, sig []byte) {
		m := fuzzMessage(id, version, gate)
		d := principalsig.ADR036Data(text, m.MandateHash)
		err := principalsig.Verify(scheme, principal, hrp, m, d, sig)
		if err != nil {
			return
		}
		if !bytes.Equal(principal, s.Principal()) {
			// Another key's valid signature cannot be forged by the fuzzer.
			require.Failf(t, "accepted a signature under an unknown principal", "%x", principal)
		}
		want, serr := s.Sign(m, d)
		require.NoError(t, serr)
		if scheme == principalsig.CosmosADR036 && hrp != "celestia" {
			require.Failf(t, "accepted under another hrp", "%q", hrp)
		}
		require.Equal(t, want, sig)
	})
}

func FuzzVerifyEd25519(f *testing.F) { fuzzScheme(f, principalsig.Ed25519) }
func FuzzVerifyADR036(f *testing.F)  { fuzzScheme(f, principalsig.CosmosADR036) }
func FuzzVerifyEIP712(f *testing.F)  { fuzzScheme(f, principalsig.EIP712) }
