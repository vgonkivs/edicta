// SPDX-License-Identifier: Apache-2.0

package recorder

import (
	"errors"
	"fmt"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/celestia/node"
)

func TestGasPriceFloor(t *testing.T) {
	floor := big.NewRat(1, 500)
	reported := big.NewRat(1, 250)
	boom := errors.New("boom")

	t.Run("an unset price becomes the floor", func(t *testing.T) {
		got, floored, err := applyGasPriceFloor(floor)(nil, fmt.Errorf("wrapped: %w", node.ErrNoMinGasPrice))
		require.NoError(t, err)
		assert.True(t, floored)
		assert.Zero(t, got.Cmp(floor))
		got.SetInt64(7)
		assert.Zero(t, floor.Cmp(big.NewRat(1, 500)), "the floor is copied, not shared")
	})
	t.Run("a zero price becomes the floor", func(t *testing.T) {
		got, floored, err := applyGasPriceFloor(floor)(new(big.Rat), nil)
		require.NoError(t, err)
		assert.True(t, floored)
		assert.Zero(t, got.Cmp(floor))
	})
	t.Run("a price below the floor is raised to it", func(t *testing.T) {
		got, floored, err := applyGasPriceFloor(floor)(big.NewRat(1, 1_000_000), nil)
		require.NoError(t, err)
		assert.True(t, floored)
		assert.Zero(t, got.Cmp(floor))
	})
	t.Run("a price at or above the floor is used as is", func(t *testing.T) {
		got, floored, err := applyGasPriceFloor(floor)(reported, nil)
		require.NoError(t, err)
		assert.False(t, floored)
		assert.Zero(t, got.Cmp(reported))
		got, floored, err = applyGasPriceFloor(floor)(floor, nil)
		require.NoError(t, err)
		assert.False(t, floored)
		assert.Zero(t, got.Cmp(floor))
	})
	t.Run("other errors pass through", func(t *testing.T) {
		_, _, err := applyGasPriceFloor(floor)(nil, boom)
		require.ErrorIs(t, err, boom)
		_, _, err = applyGasPriceFloor(floor)(nil, fmt.Errorf("%w: garbage", node.ErrUnsupported))
		require.ErrorIs(t, err, node.ErrUnsupported)
	})
	t.Run("without a floor the node's answer stands", func(t *testing.T) {
		_, _, err := applyGasPriceFloor(nil)(nil, node.ErrNoMinGasPrice)
		require.ErrorIs(t, err, node.ErrNoMinGasPrice)
		require.ErrorIs(t, err, node.ErrUnsupported)
		got, floored, err := applyGasPriceFloor(nil)(big.NewRat(1, 1_000_000), nil)
		require.NoError(t, err)
		assert.False(t, floored)
		assert.Zero(t, got.Cmp(big.NewRat(1, 1_000_000)))
	})
}
