package railtx_test

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/celestia/node"
	"github.com/vgonkivs/edicta/celestia/nodefake"
	"github.com/vgonkivs/edicta/celestia/railtx"
	"github.com/vgonkivs/edicta/examples/tia-transfer/transfer"
)

// The Rail reports it as indeterminate, so the executor keeps sending the same
// bytes; other node rejections stay final.
func TestBroadcastMempoolFullIsIndeterminateNotFinal(t *testing.T) {
	f, _ := load(t)
	v := f.Signed[0]
	cons := &rejectingCons{Consensus: nodefake.NewConsensus(v.ChainID)}
	rail, err := railtx.New(railtx.Config{Consensus: cons, Reader: nodefake.NewChain(nil), GasLimit: 1, Fee: 1,
		Key: railKey(t, v)})
	require.NoError(t, err)

	cons.bErr = fmt.Errorf("%w: codespace %q code %d: %s", node.ErrMempoolFull, "sdk", 20, "mempool is full")
	err = rail.Broadcast(bg, []byte("tx"))
	require.ErrorIs(t, err, railtx.ErrIndeterminate)
	require.NotErrorIs(t, err, railtx.ErrRejected)
	require.NotErrorIs(t, err, transfer.ErrRejected)
	require.Contains(t, err.Error(), "mempool is full")

	cons.bErr = fmt.Errorf("%w: codespace %q code %d: %s", node.ErrRejected, "sdk", 5, "insufficient funds")
	require.ErrorIs(t, rail.Broadcast(bg, []byte("tx")), railtx.ErrRejected, "other final codes stay final")
}
