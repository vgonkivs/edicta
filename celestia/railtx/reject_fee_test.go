package railtx_test

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/celestia/node"
	"github.com/vgonkivs/edicta/celestia/nodefake"
	"github.com/vgonkivs/edicta/celestia/railtx"
	"github.com/vgonkivs/edicta/celestia/secret"
	"github.com/vgonkivs/edicta/examples/tia-transfer/transfer"
)

// Assumed symbols:
//   railtx.ErrRejected: final; Broadcast maps node.ErrRejected to it (never to
//     ErrIndeterminate), keeping the node's code and log in the message. It
//     also satisfies errors.Is(err, transfer.ErrRejected) (assumed new sentinel
//     in the transfer package; railtx.ErrRejected may be that same value).
//   railtx.DefaultFeeMargin = big.NewRat(6, 5)
//   railtx.DeriveFee(ctx, src railtx.GasPriceSource, gasLimit uint64, margin *big.Rat) (uint64, error)
//     fee = ceil(gasLimit * minGasPrice * margin); nil or zero margin means DefaultFeeMargin; exact big.Rat math, no floats;
//     a result above MaxUint64 is an error, a negative margin or price is an error.
//   railtx.GasPriceSource interface { MinGasPrice(ctx context.Context) (*big.Rat, error) }
//     (satisfied by node.Consensus, which gains MinGasPrice).

type rejectingCons struct {
	*nodefake.Consensus
	bErr  error
	price *big.Rat
	pErr  error
}

func (c *rejectingCons) Broadcast(ctx context.Context, raw []byte) ([32]byte, error) {
	if c.bErr != nil {
		return [32]byte{}, c.bErr
	}
	return c.Consensus.Broadcast(ctx, raw)
}

func (c *rejectingCons) MinGasPrice(context.Context) (*big.Rat, error) { return c.price, c.pErr }

func TestBroadcastRejectionIsFinalWithCodeAndLog(t *testing.T) {
	f, _ := load(t)
	v := f.Signed[0]
	cons := &rejectingCons{Consensus: nodefake.NewConsensus(v.ChainID)}
	rail, err := railtx.New(railtx.Config{Consensus: cons, Reader: nodefake.NewChain(nil), GasLimit: 1, Fee: 1,
		Key: railKey(t, v)})
	require.NoError(t, err)

	cons.bErr = fmt.Errorf("%w: codespace %q code %d: %s", node.ErrRejected, "sdk", 13, "insufficient fee; got: 500utia required: 600utia")
	err = rail.Broadcast(bg, []byte("tx"))
	require.ErrorIs(t, err, railtx.ErrRejected)
	require.ErrorIs(t, err, transfer.ErrRejected)
	require.NotErrorIs(t, err, railtx.ErrIndeterminate)
	require.Contains(t, err.Error(), "code 13")
	require.Contains(t, err.Error(), "insufficient fee")

	cons.bErr = errors.New("connection reset")
	err = rail.Broadcast(bg, []byte("tx"))
	require.ErrorIs(t, err, railtx.ErrIndeterminate, "transient errors stay indeterminate")
	require.NotErrorIs(t, err, railtx.ErrRejected)

	cons.bErr = fmt.Errorf("%w: unavailable", node.ErrUnavailable)
	require.NotErrorIs(t, rail.Broadcast(bg, []byte("tx")), railtx.ErrRejected)
}

func TestDeriveFee(t *testing.T) {
	cons := func(p *big.Rat) *rejectingCons {
		return &rejectingCons{Consensus: nodefake.NewConsensus("c"), price: p}
	}
	require.Zero(t, railtx.DefaultFeeMargin.Cmp(big.NewRat(6, 5)))
	for _, tc := range []struct {
		name   string
		gas    uint64
		price  *big.Rat
		margin *big.Rat
		want   uint64
	}{
		{"exact 0.004 x 150000 x 1.2", 150000, rat("0.004"), nil, 720},
		{"explicit default margin", 150000, rat("0.004"), big.NewRat(6, 5), 720},
		{"uneven rounds up", 123456, rat("0.004"), nil, 593},
		{"explicit margin", 123456, rat("0.004"), rat("2"), 988},
		{"margin below one", 123456, rat("0.004"), rat("0.5"), 247},
		{"zero margin is default", 150000, rat("0.004"), rat("0"), 720},
		{"tiny price never zero", 1, rat("0.0000001"), nil, 1},
		{"node decimal string", 150000, rat("0.004000000000000000"), nil, 720},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := railtx.DeriveFee(bg, cons(tc.price), tc.gas, tc.margin)
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
	t.Run("node error", func(t *testing.T) {
		c := cons(rat("0.004"))
		c.pErr = node.ErrUnavailable
		_, err := railtx.DeriveFee(bg, c, 100, nil)
		require.ErrorIs(t, err, node.ErrUnavailable)
	})
	t.Run("zero gas", func(t *testing.T) {
		_, err := railtx.DeriveFee(bg, cons(rat("0.004")), 0, nil)
		require.Error(t, err)
	})
	t.Run("overflow is an error not a wrap", func(t *testing.T) {
		_, err := railtx.DeriveFee(bg, cons(rat("100000000000000000000")), 18446744073709551615, nil)
		require.Error(t, err)
	})
	t.Run("negative or nil price", func(t *testing.T) {
		_, err := railtx.DeriveFee(bg, cons(rat("-0.004")), 100, nil)
		require.Error(t, err)
		_, err = railtx.DeriveFee(bg, cons(nil), 100, nil)
		require.Error(t, err)
	})
	t.Run("negative margin", func(t *testing.T) {
		_, err := railtx.DeriveFee(bg, cons(rat("0.004")), 100, big.NewRat(-1, 1))
		require.Error(t, err)
	})
}

func TestDerivedFeeAboveMaxFeeIsRefusedAtSign(t *testing.T) {
	f, bodies := load(t)
	v := f.Signed[0]
	cons := &rejectingCons{Consensus: nodefake.NewConsensus(v.ChainID), price: rat("0.004")}
	fee, err := railtx.DeriveFee(bg, cons, 150001, nil)
	require.NoError(t, err)
	require.Equal(t, uint64(721), fee, "150001 * 0.004 * 1.2 = 720.0048")
	cons.Accounts[v.Key.Address] = node.AccountInfo{Number: num(t, v.Account), Sequence: num(t, v.Sequence)}
	rail, err := railtx.New(railtx.Config{Consensus: cons, Reader: nodefake.NewChain(nil), GasLimit: 150001, Fee: fee, Key: railKey(t, v)})
	require.NoError(t, err)
	_, err = rail.Sign(bg, bodies[v.BodyRef], v.ChainID, fee-1)
	require.ErrorIs(t, err, railtx.ErrFeeAboveMax)
}

func railKey(t *testing.T, v vec) railtx.KeySource {
	t.Helper()
	return railtx.KeyFromSecret(secret.New(unhex(t, v.Key.Priv)))
}

func rat(s string) *big.Rat {
	r, ok := new(big.Rat).SetString(s)
	if !ok {
		panic("bad rat " + s)
	}
	return r
}
