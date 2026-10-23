// SPDX-License-Identifier: Apache-2.0

package evm_test

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/internal/evm"
	"github.com/vgonkivs/edicta/internal/testkit"
)

func readVector(t *testing.T, v any, elem ...string) {
	t.Helper()
	b, err := os.ReadFile(testkit.SpecPath(t, append([]string{"vectors"}, elem...)...))
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(b, v))
}

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
	require.NoError(t, err)
	return b
}

type escrowKeys struct {
	Keys map[string]struct {
		PrivateKeyHex string `json:"private_key_hex"`
		Address       string `json:"address"`
	} `json:"keys"`
}

func payer1(t *testing.T) (*secp256k1.PrivateKey, [20]byte) {
	t.Helper()
	var f escrowKeys
	readVector(t, &f, "profiles", "eden-escrow", "signed.json")
	k := f.Keys["payer1"]
	priv := secp256k1.PrivKeyFromBytes(unhex(t, k.PrivateKeyHex))
	return priv, [20]byte(unhex(t, k.Address))
}

// The payer key signs every escrow transaction sighash to the recorded
// r, s and y_parity: deterministic and low s, byte for byte.
func TestSignMatchesEscrowTransactionVectors(t *testing.T) {
	priv, addr := payer1(t)
	require.Equal(t, addr, evm.Address(priv.PubKey()))
	var f struct {
		Cases []struct {
			ID      string `json:"id"`
			Key     string `json:"key"`
			SigHash string `json:"sighash_hex"`
			YParity string `json:"y_parity"`
			R       string `json:"r_hex"`
			S       string `json:"s_hex"`
			Payer   string `json:"payer"`
		} `json:"cases"`
	}
	readVector(t, &f, "profiles", "eden-escrow", "signed.json")
	require.NotEmpty(t, f.Cases)
	for _, c := range f.Cases {
		require.Equal(t, "payer1", c.Key, c.ID)
		digest := [32]byte(unhex(t, c.SigHash))
		sig, err := evm.Sign(priv, digest)
		require.NoError(t, err, c.ID)
		assert.Equal(t, c.R+c.S, hex.EncodeToString(sig[:64]), c.ID)
		assert.Equal(t, c.YParity, string('0'+sig[64]), c.ID)
		got, err := evm.RecoverAddress(digest, sig)
		require.NoError(t, err, c.ID)
		assert.Equal(t, [20]byte(unhex(t, c.Payer)), got, c.ID)
	}
}

// The payment proof is personal_sign by the payer key, v = 27 + y_parity.
func TestPersonalSignMatchesPaymentSignatureVectors(t *testing.T) {
	priv, addr := payer1(t)
	var f struct {
		PaymentSignature struct {
			Cases []struct {
				Message   string `json:"message_hex"`
				Preimage  string `json:"preimage_hex"`
				Digest    string `json:"digest_hex"`
				Signature string `json:"signature_hex"`
			} `json:"cases"`
		} `json:"payment_signature"`
	}
	readVector(t, &f, "profiles", "eden-escrow", "x402.json")
	require.NotEmpty(t, f.PaymentSignature.Cases)
	for _, c := range f.PaymentSignature.Cases {
		m := [32]byte(unhex(t, c.Message))
		digest := evm.PersonalDigest32(m)
		assert.Equal(t, c.Digest, hex.EncodeToString(digest[:]))
		assert.Equal(t, evm.Keccak256(unhex(t, c.Preimage)), digest)
		sig, err := evm.Sign(priv, digest)
		require.NoError(t, err)
		want := unhex(t, c.Signature)
		require.Len(t, want, 65)
		assert.Equal(t, want[:64], sig[:64])
		assert.Equal(t, want[64], 27+sig[64])
		got, err := evm.RecoverAddress(digest, sig)
		require.NoError(t, err)
		assert.Equal(t, addr, got)
	}
}

// The principal's EIP-712 key: address, deterministic signature with
// v = 27 + y_parity, and recovery.
func TestSignMatchesPrincipalEIP712Vector(t *testing.T) {
	var f struct {
		Keys map[string]struct {
			Seed    string `json:"seed_hex"`
			Address string `json:"eth_address_hex"`
		} `json:"keys"`
		Case struct {
			Digest    string `json:"digest_hex"`
			Signature string `json:"signature_hex"`
		} `json:"case"`
	}
	readVector(t, &f, "principal", "eip712.json")
	for name, k := range f.Keys {
		priv := secp256k1.PrivKeyFromBytes(unhex(t, k.Seed))
		assert.Equal(t, [20]byte(unhex(t, k.Address)), evm.Address(priv.PubKey()), name)
	}
	priv := secp256k1.PrivKeyFromBytes(unhex(t, f.Keys["p1_secp"].Seed))
	digest := [32]byte(unhex(t, f.Case.Digest))
	sig, err := evm.Sign(priv, digest)
	require.NoError(t, err)
	want := unhex(t, f.Case.Signature)
	require.Len(t, want, 65)
	assert.Equal(t, want[:64], sig[:64])
	assert.Equal(t, want[64], 27+sig[64])
	got, err := evm.RecoverAddress(digest, sig)
	require.NoError(t, err)
	assert.Equal(t, evm.Address(priv.PubKey()), got)
}

// The examples of EIP-55.
func TestChecksumAddress(t *testing.T) {
	for _, a := range []string{
		"5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
		"fB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
		"dbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
		"D1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
	} {
		assert.Equal(t, a, evm.ChecksumAddress([20]byte(unhex(t, strings.ToLower(a)))))
	}
}

func TestRecoverAddressRefusesOverflowRecoveryIDs(t *testing.T) {
	priv, _ := payer1(t)
	sig, err := evm.Sign(priv, [32]byte{1})
	require.NoError(t, err)
	for _, y := range []byte{2, 3, 27, 28} {
		bad := sig
		bad[64] = y
		_, err := evm.RecoverAddress([32]byte{1}, bad)
		require.ErrorIs(t, err, evm.ErrRecover, y)
	}
}

// A high s recovers to the same key: refusing it is the caller's rule.
func TestRecoverAddressAcceptsTheHighSTwin(t *testing.T) {
	priv, addr := payer1(t)
	sig, err := evm.Sign(priv, [32]byte{2})
	require.NoError(t, err)
	var s secp256k1.ModNScalar
	require.False(t, s.SetByteSlice(sig[32:64]))
	s.Negate()
	b := s.Bytes()
	copy(sig[32:64], b[:])
	sig[64] ^= 1
	got, err := evm.RecoverAddress([32]byte{2}, sig)
	require.NoError(t, err)
	assert.Equal(t, addr, got)
}

func TestRecoverAddressRefusesZeroR(t *testing.T) {
	_, err := evm.RecoverAddress([32]byte{3}, [65]byte{63: 1})
	require.Error(t, err)
}
