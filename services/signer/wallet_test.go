// SPDX-License-Identifier: Apache-2.0

package signer_test

import (
	"context"
	"crypto/sha256"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/plugins/edenescrow"
	"github.com/vgonkivs/edicta/services/signer"
	"github.com/vgonkivs/edicta/services/signer/eden"
)

// The file wallet signs exactly as the Eden escrow profile does: the same
// address, the same r || s || y_parity, and the profile reads it back as
// the same signature.
func TestKeyWalletSignsAsTheProfile(t *testing.T) {
	ctx := context.Background()
	for i := range 64 {
		scalar := sha256.Sum256([]byte{'w', byte(i)})
		w, err := signer.NewKeyWallet(scalar[:])
		require.NoError(t, err)
		var s secp256k1.ModNScalar
		s.SetByteSlice(scalar[:])
		priv := secp256k1.NewPrivateKey(&s)

		addr, err := w.Address(ctx)
		require.NoError(t, err)
		assert.Equal(t, edenescrow.Address(priv.PubKey()), addr)

		digest := sha256.Sum256([]byte{'m', byte(i)})
		got, err := w.SignDigest(ctx, digest)
		require.NoError(t, err)
		want, err := edenescrow.Sign(priv, digest)
		require.NoError(t, err)
		assert.Equal(t, want, eden.UnpackSig(got))
		assert.Equal(t, want.R[:], got[:32])
		assert.Equal(t, want.S[:], got[32:64])
		assert.Equal(t, want.YParity, got[64])
	}
}
