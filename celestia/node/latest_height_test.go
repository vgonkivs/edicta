package node

import (
	"context"
	"net"
	"sync"
	"testing"

	"github.com/cosmos/cosmos-sdk/client/grpc/cmtservice"
	nodeservice "github.com/cosmos/cosmos-sdk/client/grpc/node"
	txtypes "github.com/cosmos/cosmos-sdk/types/tx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

func startFakeWith(t *testing.T, f *fakeChain, cmt *lightCmtSvc) *ConsensusClient {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer()
	txtypes.RegisterServiceServer(srv, &txSvc{f: f})
	cmtservice.RegisterServiceServer(srv, cmt)
	nodeservice.RegisterServiceServer(srv, &heightNodeSvc{cmt: cmt})
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
	statusReqs int
	blockCalls int
}

type heightNodeSvc struct {
	nodeservice.UnimplementedServiceServer
	cmt *lightCmtSvc
}

func (s *heightNodeSvc) Status(context.Context, *nodeservice.StatusRequest) (*nodeservice.StatusResponse, error) {
	s.cmt.mu.Lock()
	s.cmt.statusReqs++
	s.cmt.mu.Unlock()
	return &nodeservice.StatusResponse{Height: uint64(s.cmt.height)}, nil
}

func (s *lightCmtSvc) GetLatestBlock(context.Context, *cmtservice.GetLatestBlockRequest) (*cmtservice.GetLatestBlockResponse, error) {
	s.mu.Lock()
	s.blockCalls++
	s.mu.Unlock()
	return nil, status.Error(codes.Internal, "the full block must not be downloaded")
}

// The validator set height is one above the committed one on a caught-up node.
func (s *lightCmtSvc) GetLatestValidatorSet(context.Context, *cmtservice.GetLatestValidatorSetRequest) (*cmtservice.GetLatestValidatorSetResponse, error) {
	return &cmtservice.GetLatestValidatorSetResponse{BlockHeight: s.height + 1}, nil
}

func (s *lightCmtSvc) assertLight(t *testing.T) {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	assert.Zero(t, s.blockCalls, "GetLatestBlock was called")
	assert.NotZero(t, s.statusReqs, "the node service Status was not called")
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
