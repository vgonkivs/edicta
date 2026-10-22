// SPDX-License-Identifier: Apache-2.0

package edenescrow

import (
	"bytes"
	"errors"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/engine/policy"
)

func TestTransactionAttacksAreRefused(t *testing.T) {
	a, b := f14(t)
	it := f14Items(t)

	t.Run("bytes after the transaction list", func(t *testing.T) {
		tx := append(append([]byte(nil), a.unsigned...), 0x00)
		_, err := DecodeTxAction(cborMap(cborUint(1), cborUint(1), cborUint(2), cborBstr(tx),
			cborUint(3), cborTstr(a.Resource), cborUint(4), cborBstr(a.RequirementsHash[:])))
		require.ErrorIs(t, err, ErrMalformed)
		assert.Equal(t, "ET2", ruleOf(t, err))
	})
	t.Run("bytes after the action", func(t *testing.T) {
		_, err := DecodeTxAction(append(append([]byte(nil), b...), 0x00))
		require.ErrorIs(t, err, ErrMalformed)
	})
	t.Run("another escrow in to", func(t *testing.T) {
		other := rlpString(append([]byte{0x01}, make([]byte, 19)...))
		_, err := DecodeTxAction(withTx(t, replaced(it, 5, other)...))
		require.Error(t, err)
		assert.True(t, errors.Is(err, ErrUnknownDomain) || errors.Is(err, ErrMalformed))
	})
	t.Run("value of 33 bytes", func(t *testing.T) {
		big33 := rlpString(append([]byte{0x01}, make([]byte, 32)...))
		_, err := DecodeTxAction(withTx(t, replaced(it, 6, big33)...))
		require.ErrorIs(t, err, ErrMalformed)
		assert.Equal(t, "ET3", ruleOf(t, err))
	})
	t.Run("value that overflows with the fee bound is refused by the facts", func(t *testing.T) {
		max32 := rlpString(bytes.Repeat([]byte{0xff}, 32))
		x, err := DecodeTxAction(withTx(t, replaced(it, 6, max32)...))
		require.NoError(t, err)
		_, err = x.Facts()
		require.ErrorIs(t, err, policy.ErrFactsInvalid)
	})
	t.Run("a large value is never understated in the facts", func(t *testing.T) {
		huge := rlpString([]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
		x, err := DecodeTxAction(withTx(t, replaced(it, 6, huge)...))
		require.NoError(t, err)
		f, err := x.Facts()
		require.NoError(t, err)
		assert.GreaterOrEqual(t, new(big.Int).SetBytes(f.Amount).Cmp(new(big.Int).SetBytes(x.Value)), 0)
	})
	t.Run("zero value", func(t *testing.T) {
		_, err := DecodeTxAction(withTx(t, replaced(it, 6, []byte{0x80})...))
		require.ErrorIs(t, err, ErrMalformed)
		assert.Equal(t, "ET6", ruleOf(t, err))
	})
	t.Run("another chain id", func(t *testing.T) {
		_, err := DecodeTxAction(withTx(t, replaced(it, 0, []byte{0x82, 0x13, 0x37})...))
		require.ErrorIs(t, err, ErrUnknownDomain)
	})
}
