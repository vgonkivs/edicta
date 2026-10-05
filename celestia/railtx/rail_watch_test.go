package railtx_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/celestia/node"
	"github.com/vgonkivs/edicta/celestia/nodefake"
	"github.com/vgonkivs/edicta/celestia/railtx"
	"github.com/vgonkivs/edicta/celestia/secret"
	"github.com/vgonkivs/edicta/examples/tia-transfer/transfer"
)

func TestHeightReadsTheConsensusNodeNotTheBridge(t *testing.T) {
	f, _ := load(t)
	v := f.Signed[0]
	chain := nodefake.NewChain(nil)
	chain.AddHeader(node.Header{ChainID: v.ChainID, Height: 500})
	cons := nodefake.NewConsensus(v.ChainID)
	r, err := railtx.New(railtx.Config{
		Consensus: cons, Reader: chain,
		Key:      railtx.KeyFromSecret(secret.New(unhex(t, v.Key.Priv))),
		GasLimit: num(t, v.GasLimit), Fee: num(t, v.Fee.Amount),
	})
	require.NoError(t, err)

	_, err = r.Height(bg)
	require.ErrorIs(t, err, node.ErrUnavailable, "the bridge head does not stand in for the consensus node")

	cons.SetHeight(900)
	h, err := r.Height(bg)
	require.NoError(t, err)
	require.Equal(t, uint64(900), h, "the consensus height, not the bridge head 500")

	cons.Fail = errors.New("status node down")
	_, err = r.Height(bg)
	require.Error(t, err)
	cons.Fail = nil

	ctx, cancel := context.WithCancel(bg)
	cancel()
	_, err = r.Height(ctx)
	require.ErrorIs(t, err, context.Canceled)
}

func TestStatusCarriesTheAnsweringNodesHeight(t *testing.T) {
	f, _ := load(t)
	v := f.Signed[0]
	cons := nodefake.NewConsensus(v.ChainID)
	r := newRail(t, v, cons)
	cons.SetTx([32]byte{1}, node.TxStatus{Found: true, Height: 777, NodeHeight: 900})
	cons.SetTx([32]byte{2}, node.TxStatus{Found: false, NodeHeight: 1234})

	s, err := r.Status(bg, [32]byte{1})
	require.NoError(t, err)
	require.Equal(t, transfer.TxStatus{State: transfer.TxCommitted, Height: 777, NodeHeight: 900}, s)
	s, err = r.Status(bg, [32]byte{2})
	require.NoError(t, err)
	require.Equal(t, transfer.TxStatus{State: transfer.TxUnknown, NodeHeight: 1234}, s)
}

func TestStartupRefusesANodeWithoutTxIndex(t *testing.T) {
	f, _ := load(t)
	v := f.Signed[0]
	cons := nodefake.NewConsensus(v.ChainID)
	r := newRail(t, v, cons)
	require.NoError(t, r.CheckTxIndex(bg))

	cons.Fail = node.ErrTxIndexDisabled
	err := r.CheckTxIndex(bg)
	require.ErrorIs(t, err, railtx.ErrTxIndexDisabled)

	_, err = r.Status(bg, [32]byte{1})
	require.ErrorIs(t, err, railtx.ErrTxIndexDisabled, "never read as an unknown tx")
}
