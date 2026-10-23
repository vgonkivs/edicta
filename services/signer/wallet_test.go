// SPDX-License-Identifier: Apache-2.0

package signer_test

import (
	"context"
	"crypto/sha256"
	"math/big"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"golang.org/x/crypto/sha3"

	"github.com/vgonkivs/edicta/services/signer"
)

// The file wallet's signature is checked against the key without the
// helpers it signs with: the public key recovered with the secp256k1 library
// is the wallet's key, the address is the Keccak-256 tail of that key, s is
// the low one, and one digest always gives one signature.
func TestKeyWalletSignatureRecoversToItsKey(t *testing.T) {
	ctx := context.Background()
	halfN := new(big.Int).Rsh(secp256k1.S256().N, 1)
	for i := range 64 {
		scalar := sha256.Sum256([]byte{'w', byte(i)})
		w, err := signer.NewKeyWallet(scalar[:])
		require.NoError(t, err)
		var s secp256k1.ModNScalar
		s.SetByteSlice(scalar[:])
		priv := secp256k1.NewPrivateKey(&s)

		h := sha3.NewLegacyKeccak256()
		h.Write(priv.PubKey().SerializeUncompressed()[1:])
		addr, err := w.Address(ctx)
		require.NoError(t, err)
		assert.Equal(t, h.Sum(nil)[12:], addr[:])

		digest := sha256.Sum256([]byte{'m', byte(i)})
		got, err := w.SignDigest(ctx, digest)
		require.NoError(t, err)
		again, err := w.SignDigest(ctx, digest)
		require.NoError(t, err)
		assert.Equal(t, got, again)

		require.LessOrEqual(t, got[64], byte(1))
		assert.LessOrEqual(t, new(big.Int).SetBytes(got[32:64]).Cmp(halfN), 0, "s must be the low one")
		compact := append([]byte{27 + got[64]}, got[:64]...)
		pub, _, err := ecdsa.RecoverCompact(compact, digest[:])
		require.NoError(t, err)
		assert.True(t, pub.IsEqual(priv.PubKey()))
	}
}
