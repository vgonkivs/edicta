package node

import (
	"testing"

	sdk "github.com/cosmos/cosmos-sdk/types"
	txtypes "github.com/cosmos/cosmos-sdk/types/tx"
	"github.com/stretchr/testify/require"
)

// ErrMempoolFull is wrapped by Broadcast for sdk code 20. It is transient, so never ErrRejected.

func TestBroadcastMempoolFullIsNotFinal(t *testing.T) {
	f := &fakeChain{broadcast: func(*txtypes.BroadcastTxRequest) (*txtypes.BroadcastTxResponse, error) {
		return &txtypes.BroadcastTxResponse{TxResponse: &sdk.TxResponse{Codespace: "sdk", Code: 20, RawLog: "mempool is full"}}, nil
	}}
	_, err := startFake(t, f, false, "").Broadcast(tctx(t), []byte("tx"))
	require.ErrorIs(t, err, ErrMempoolFull)
	require.NotErrorIs(t, err, ErrRejected, "the same bytes may be sent again")
	require.Contains(t, err.Error(), "mempool is full", "the node's log is kept")

	f.broadcast = func(*txtypes.BroadcastTxRequest) (*txtypes.BroadcastTxResponse, error) {
		return &txtypes.BroadcastTxResponse{TxResponse: &sdk.TxResponse{Codespace: "bank", Code: 20, RawLog: "other module"}}, nil
	}
	_, err = startFake(t, f, false, "").Broadcast(tctx(t), []byte("tx"))
	require.ErrorIs(t, err, ErrRejected, "code 20 of another codespace is not the mempool")
	require.NotErrorIs(t, err, ErrMempoolFull)
}
