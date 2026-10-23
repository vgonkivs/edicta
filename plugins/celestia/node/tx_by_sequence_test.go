package node

import (
	"context"
	"encoding/hex"
	"net"
	"strings"
	"testing"

	sdk "github.com/cosmos/cosmos-sdk/types"
	txtypes "github.com/cosmos/cosmos-sdk/types/tx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

type seqSvc struct {
	txtypes.UnimplementedServiceServer
	fn  func(*txtypes.GetTxsEventRequest) (*txtypes.GetTxsEventResponse, error)
	got *txtypes.GetTxsEventRequest
}

func (s *seqSvc) GetTxsEvent(_ context.Context, r *txtypes.GetTxsEventRequest) (*txtypes.GetTxsEventResponse, error) {
	s.got = r
	return s.fn(r)
}

func startSeq(t *testing.T, s *seqSvc) *ConsensusClient {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer()
	txtypes.RegisterServiceServer(srv, s)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	c := NewConsensusConn(conn)
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func TestTxBySequence(t *testing.T) {
	hash := strings.Repeat("ab", 32)
	t.Run("query and result", func(t *testing.T) {
		s := &seqSvc{fn: func(*txtypes.GetTxsEventRequest) (*txtypes.GetTxsEventResponse, error) {
			return &txtypes.GetTxsEventResponse{TxResponses: []*sdk.TxResponse{{Height: 77, TxHash: strings.ToUpper(hash)}, {Height: 0, TxHash: hash}}}, nil
		}}
		got, err := startSeq(t, s).TxBySequence(tctx(t), "celestia1abc", 9)
		require.NoError(t, err)
		assert.Equal(t, "tx.acc_seq='celestia1abc/9'", s.got.Query)
		require.Len(t, got, 1, "an entry without a block height is not committed")
		assert.EqualValues(t, 77, got[0].Height)
		assert.Equal(t, hash, hex.EncodeToString(got[0].Hash[:]))
	})
	t.Run("empty", func(t *testing.T) {
		s := &seqSvc{fn: func(*txtypes.GetTxsEventRequest) (*txtypes.GetTxsEventResponse, error) {
			return &txtypes.GetTxsEventResponse{}, nil
		}}
		got, err := startSeq(t, s).TxBySequence(tctx(t), "celestia1abc", 9)
		require.NoError(t, err)
		assert.Empty(t, got)
	})
	t.Run("bad hash is unavailable", func(t *testing.T) {
		s := &seqSvc{fn: func(*txtypes.GetTxsEventRequest) (*txtypes.GetTxsEventResponse, error) {
			return &txtypes.GetTxsEventResponse{TxResponses: []*sdk.TxResponse{{Height: 5, TxHash: "zz"}}}, nil
		}}
		_, err := startSeq(t, s).TxBySequence(tctx(t), "celestia1abc", 9)
		require.ErrorIs(t, err, ErrUnavailable)
	})
	t.Run("an address that could inject into the query is refused", func(t *testing.T) {
		s := &seqSvc{fn: func(*txtypes.GetTxsEventRequest) (*txtypes.GetTxsEventResponse, error) {
			assert.Fail(t, "must not be queried")
			return nil, nil
		}}
		_, err := startSeq(t, s).TxBySequence(tctx(t), "a' AND tx.height>0 AND x='", 9)
		require.Error(t, err)
	})
}
