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
		got, err := applyGasPriceFloor(floor)(nil, fmt.Errorf("wrapped: %w", node.ErrNoMinGasPrice))
		require.NoError(t, err)
		assert.Zero(t, got.Cmp(floor))
		got.SetInt64(7)
		assert.Zero(t, floor.Cmp(big.NewRat(1, 500)), "the floor is copied, not shared")
	})
	t.Run("a reported price is used as is, above or below the floor", func(t *testing.T) {
		got, err := applyGasPriceFloor(floor)(reported, nil)
		require.NoError(t, err)
		assert.Zero(t, got.Cmp(reported))
		low := big.NewRat(1, 1_000_000)
		got, err = applyGasPriceFloor(floor)(low, nil)
		require.NoError(t, err)
		assert.Zero(t, got.Cmp(low))
	})
	t.Run("other errors pass through", func(t *testing.T) {
		_, err := applyGasPriceFloor(floor)(nil, boom)
		require.ErrorIs(t, err, boom)
		_, err = applyGasPriceFloor(floor)(nil, fmt.Errorf("%w: garbage", node.ErrUnsupported))
		require.ErrorIs(t, err, node.ErrUnsupported)
	})
	t.Run("without a floor an unset price is refused", func(t *testing.T) {
		_, err := applyGasPriceFloor(nil)(nil, node.ErrNoMinGasPrice)
		require.ErrorIs(t, err, node.ErrNoMinGasPrice)
		require.ErrorIs(t, err, node.ErrUnsupported)
	})
}
