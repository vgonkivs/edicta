// SPDX-License-Identifier: Apache-2.0

package evm_test

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/internal/evm"
)

func key(t *testing.T, scalar []byte) *secp256k1.PrivateKey {
	t.Helper()
	var s secp256k1.ModNScalar
	require.False(t, s.SetByteSlice(scalar))
	require.False(t, s.IsZero())
	return secp256k1.NewPrivateKey(&s)
}

func TestKeccak256OfNothing(t *testing.T) {
	got := evm.Keccak256()
	assert.Equal(t, "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470", hex.EncodeToString(got[:]))
	assert.Equal(t, got, evm.Keccak256(nil, []byte{}))
}

func TestAddressOfKeyOne(t *testing.T) {
	one := make([]byte, 32)
	one[31] = 1
	a := evm.Address(key(t, one).PubKey())
	assert.Equal(t, "7e5f4552091a69125d5dfcb7b8c2659029395bdf", hex.EncodeToString(a[:]))
}

func TestSignIsDeterministicLowSAndRecoversToTheAddress(t *testing.T) {
	for i := range 32 {
		seed := sha256.Sum256([]byte{'k', byte(i)})
		priv := key(t, seed[:])
		digest := sha256.Sum256([]byte{'d', byte(i)})

		sig, err := evm.Sign(priv, digest)
		require.NoError(t, err)
		again, err := evm.Sign(priv, digest)
		require.NoError(t, err)
		assert.Equal(t, sig, again)

		require.LessOrEqual(t, sig[64], byte(1))
		var s secp256k1.ModNScalar
		require.False(t, s.SetByteSlice(sig[32:64]))
		assert.False(t, s.IsOverHalfOrder())

		compact := append([]byte{27 + sig[64]}, sig[:64]...)
		pub, _, err := ecdsa.RecoverCompact(compact, digest[:])
		require.NoError(t, err)
		assert.Equal(t, evm.Address(priv.PubKey()), evm.Address(pub))
	}
}

func TestSignWithoutAKey(t *testing.T) {
	_, err := evm.Sign(nil, [32]byte{})
	require.ErrorIs(t, err, evm.ErrSignature)
}
