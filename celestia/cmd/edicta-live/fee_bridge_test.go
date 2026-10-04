package main

import (
	"context"
	"errors"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/celestia/railtx"
)

// Assumed symbols (package main):
//   Config.FeeMargin string (decimal, no floats), flag --fee-margin; "" or "0" means
//     railtx.DefaultFeeMargin (6/5); malformed or negative is a config error.
//   railtx.GasPriceSource.MinGasPrice returns *big.Rat.
//   --fee default is 0, meaning "derive from the node's minimum_gas_price".
//   resolveFee(ctx context.Context, c Config, src railtx.GasPriceSource) (uint64, error):
//     c.Fee != 0 -> returned as is, src never asked; otherwise
//     railtx.DeriveFee(ctx, src, c.GasLimit, c.FeeMargin); a result above
//     c.MaxFee is an error wrapping railtx.ErrFeeAboveMax. An explicit
//     --gas-limit feeds the derivation.
//   parseFlags normalises --bridge-addr to a URL (node.BridgeURL with --bridge-tls);
//     a scheme that disagrees with --bridge-tls is a config error.

type price struct {
	p   *big.Rat
	err error
	n   int
}

func (p *price) MinGasPrice(context.Context) (*big.Rat, error) { p.n++; return p.p, p.err }

func TestFeeDefaultsToDerive(t *testing.T) {
	c, err := parse(t)
	require.NoError(t, err)
	assert.Zero(t, c.Fee)
	assert.Contains(t, []string{"", "1.2"}, c.FeeMargin)
}

func TestResolveFee(t *testing.T) {
	ctx := context.Background()
	t.Run("derived from the node price", func(t *testing.T) {
		c, err := parse(t, "--gas-limit", "123456")
		require.NoError(t, err)
		p := &price{p: big.NewRat(1, 250)}
		fee, err := resolveFee(ctx, c, p)
		require.NoError(t, err)
		assert.EqualValues(t, 593, fee)
		assert.Equal(t, 1, p.n)
	})
	t.Run("explicit gas limit feeds the derivation", func(t *testing.T) {
		c, err := parse(t, "--gas-limit", "250001", "--max-fee", "5000")
		require.NoError(t, err)
		fee, err := resolveFee(ctx, c, &price{p: big.NewRat(1, 250)})
		require.NoError(t, err)
		assert.EqualValues(t, 1201, fee)
	})
	t.Run("margin is configurable", func(t *testing.T) {
		c, err := parse(t, "--gas-limit", "123456", "--fee-margin", "2", "--max-fee", "5000")
		require.NoError(t, err)
		fee, err := resolveFee(ctx, c, &price{p: big.NewRat(1, 250)})
		require.NoError(t, err)
		assert.EqualValues(t, 988, fee)
	})
	t.Run("explicit fee overrides and the node is not asked", func(t *testing.T) {
		c, err := parse(t, "--fee", "777", "--max-fee", "1000")
		require.NoError(t, err)
		p := &price{err: errors.New("must not be called")}
		fee, err := resolveFee(ctx, c, p)
		require.NoError(t, err)
		assert.EqualValues(t, 777, fee)
		assert.Zero(t, p.n)
	})
	t.Run("derived fee above max-fee is refused", func(t *testing.T) {
		c, err := parse(t, "--gas-limit", "123456", "--max-fee", "500")
		require.NoError(t, err)
		_, err = resolveFee(ctx, c, &price{p: big.NewRat(1, 250)})
		require.ErrorIs(t, err, railtx.ErrFeeAboveMax)
	})
	t.Run("node error propagates", func(t *testing.T) {
		c, err := parse(t)
		require.NoError(t, err)
		boom := errors.New("node down")
		_, err = resolveFee(ctx, c, &price{err: boom})
		require.ErrorIs(t, err, boom)
	})
	t.Run("explicit fee above max-fee is a config error", func(t *testing.T) {
		_, err := parse(t, "--fee", "2000", "--max-fee", "1000")
		require.Error(t, err)
	})
	t.Run("exact: 0.004 x 150000 x 1.2 is 720", func(t *testing.T) {
		c, err := parse(t, "--gas-limit", "150000", "--max-fee", "5000")
		require.NoError(t, err)
		fee, err := resolveFee(ctx, c, &price{p: big.NewRat(1, 250)})
		require.NoError(t, err)
		assert.EqualValues(t, 720, fee)
	})
	t.Run("zero margin is the default", func(t *testing.T) {
		c, err := parse(t, "--gas-limit", "150000", "--fee-margin", "0", "--max-fee", "5000")
		require.NoError(t, err)
		fee, err := resolveFee(ctx, c, &price{p: big.NewRat(1, 250)})
		require.NoError(t, err)
		assert.EqualValues(t, 720, fee)
	})
	t.Run("bad margin", func(t *testing.T) {
		_, err := parse(t, "--fee-margin", "abc")
		require.Error(t, err)
		_, err = parse(t, "--fee-margin", "-1")
		require.Error(t, err)
	})
}

func TestBridgeAddrForms(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want string
		bad  bool
	}{
		{"host port with tls", []string{"--bridge-addr", "bn.example.invalid:26658"}, "https://bn.example.invalid:26658", false},
		{"host port plain", []string{"--bridge-addr", "bn.example.invalid:26658", "--bridge-tls=false"}, "http://bn.example.invalid:26658", false},
		{"https url with tls", []string{"--bridge-addr", "https://bn.example.invalid:26658"}, "https://bn.example.invalid:26658", false},
		{"http url plain", []string{"--bridge-addr", "http://bn.example.invalid:26658", "--bridge-tls=false"}, "http://bn.example.invalid:26658", false},
		{"http url with tls flag", []string{"--bridge-addr", "http://bn.example.invalid:26658"}, "", true},
		{"https url without tls flag", []string{"--bridge-addr", "https://bn.example.invalid:26658", "--bridge-tls=false"}, "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := parse(t, tc.args...)
			if tc.bad {
				require.ErrorIs(t, err, ErrConfig)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, c.BridgeAddr)
		})
	}
}
