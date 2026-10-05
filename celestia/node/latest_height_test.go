package node

import (
	"context"
	"net"
	"sync"
	"testing"

	"github.com/cosmos/cosmos-sdk/client/grpc/cmtservice"
	txtypes "github.com/cosmos/cosmos-sdk/types/tx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

func startFakeWith(t *testing.T, f *fakeChain, cmt cmtservice.ServiceServer) *ConsensusClient {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer()
	txtypes.RegisterServiceServer(srv, &txSvc{f: f})
	cmtservice.RegisterServiceServer(srv, cmt)
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

type lightCmtSvc struct {
	cmtservice.UnimplementedServiceServer
	mu         sync.Mutex
	height     int64
	valSetReqs []*cmtservice.GetLatestValidatorSetRequest
	blockCalls int
}

func (s *lightCmtSvc) GetLatestBlock(context.Context, *cmtservice.GetLatestBlockRequest) (*cmtservice.GetLatestBlockResponse, error) {
	s.mu.Lock()
	s.blockCalls++
	s.mu.Unlock()
	return nil, status.Error(codes.Internal, "the full block must not be downloaded")
}

func (s *lightCmtSvc) GetLatestValidatorSet(_ context.Context, r *cmtservice.GetLatestValidatorSetRequest) (*cmtservice.GetLatestValidatorSetResponse, error) {
	s.mu.Lock()
	s.valSetReqs = append(s.valSetReqs, r)
	s.mu.Unlock()
	return &cmtservice.GetLatestValidatorSetResponse{BlockHeight: s.height}, nil
}

func (s *lightCmtSvc) assertLight(t *testing.T) {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	assert.Zero(t, s.blockCalls, "GetLatestBlock was called")
	require.NotEmpty(t, s.valSetReqs, "no light height call")
	for _, r := range s.valSetReqs {
		require.NotNil(t, r.Pagination, "validator set request has no page limit")
		assert.GreaterOrEqual(t, r.Pagination.Limit, uint64(1))
		assert.LessOrEqual(t, r.Pagination.Limit, uint64(1), "request asks for more than one validator")
	}
}

func TestLatestHeightIsALightRead(t *testing.T) {
	f := &fakeChain{}
	cmt := &lightCmtSvc{height: 4242}
	c := startFakeWith(t, f, cmt)
	h, err := c.LatestHeight(tctx(t))
	require.NoError(t, err)
	assert.Equal(t, uint64(4242), h)
	cmt.assertLight(t)
}

func TestLatestHeightRejectsNonPositiveHeight(t *testing.T) {
	f := &fakeChain{}
	cmt := &lightCmtSvc{height: 0}
	c := startFakeWith(t, f, cmt)
	_, err := c.LatestHeight(tctx(t))
	require.ErrorIs(t, err, ErrUnavailable)
}

func TestTxNodeHeightIsALightRead(t *testing.T) {
	f := &fakeChain{getTx: func(*txtypes.GetTxRequest) (*txtypes.GetTxResponse, error) {
		return nil, status.Error(codes.NotFound, "tx not found")
	}}
	cmt := &lightCmtSvc{height: 777}
	c := startFakeWith(t, f, cmt)
	st, err := c.Tx(tctx(t), [32]byte{1})
	require.NoError(t, err)
	assert.False(t, st.Found)
	assert.Equal(t, uint64(777), st.NodeHeight)
	cmt.assertLight(t)
}
