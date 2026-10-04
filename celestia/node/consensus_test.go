package node

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cosmos/cosmos-sdk/client/grpc/cmtservice"
	sdk "github.com/cosmos/cosmos-sdk/types"
	txtypes "github.com/cosmos/cosmos-sdk/types/tx"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	stakingtypes "github.com/cosmos/cosmos-sdk/x/staking/types"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	fibretypes "github.com/celestiaorg/celestia-app/v10/x/fibre/types"
	cmtp2p "github.com/cometbft/cometbft/proto/tendermint/p2p"
)

// fakeChain is a consensus node. Every service method is a hook so each test
// states exactly what the node answers.
type fakeChain struct {
	mu        sync.Mutex
	broadcast func(*txtypes.BroadcastTxRequest) (*txtypes.BroadcastTxResponse, error)
	getTx     func(*txtypes.GetTxRequest) (*txtypes.GetTxResponse, error)
	fibre     func() (*fibretypes.QueryParamsResponse, error)
	account   func(string) (*authtypes.QueryAccountInfoResponse, error)
	token     string
	lastReq   *txtypes.BroadcastTxRequest
}

type txSvc struct {
	txtypes.UnimplementedServiceServer
	f *fakeChain
}

func (s *txSvc) BroadcastTx(_ context.Context, r *txtypes.BroadcastTxRequest) (*txtypes.BroadcastTxResponse, error) {
	s.f.mu.Lock()
	s.f.lastReq = r
	s.f.mu.Unlock()
	return s.f.broadcast(r)
}
func (s *txSvc) GetTx(_ context.Context, r *txtypes.GetTxRequest) (*txtypes.GetTxResponse, error) {
	return s.f.getTx(r)
}

type cmtSvc struct {
	cmtservice.UnimplementedServiceServer
	f *fakeChain
}

func (s *cmtSvc) GetNodeInfo(ctx context.Context, _ *cmtservice.GetNodeInfoRequest) (*cmtservice.GetNodeInfoResponse, error) {
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if v := md.Get("x-token"); len(v) == 1 {
			s.f.mu.Lock()
			s.f.token = v[0]
			s.f.mu.Unlock()
		}
	}
	return &cmtservice.GetNodeInfoResponse{DefaultNodeInfo: &cmtp2p.DefaultNodeInfo{Network: "test-chain-1"}}, nil
}

type authSvc struct {
	authtypes.UnimplementedQueryServer
	f *fakeChain
}

func (s *authSvc) AccountInfo(_ context.Context, r *authtypes.QueryAccountInfoRequest) (*authtypes.QueryAccountInfoResponse, error) {
	return s.f.account(r.Address)
}
func (*authSvc) Bech32Prefix(context.Context, *authtypes.Bech32PrefixRequest) (*authtypes.Bech32PrefixResponse, error) {
	return &authtypes.Bech32PrefixResponse{Bech32Prefix: "celestia"}, nil
}

type stakingSvc struct{ stakingtypes.UnimplementedQueryServer }

func (*stakingSvc) Params(context.Context, *stakingtypes.QueryParamsRequest) (*stakingtypes.QueryParamsResponse, error) {
	return &stakingtypes.QueryParamsResponse{Params: stakingtypes.Params{BondDenom: "utia"}}, nil
}

type fibreSvc struct {
	fibretypes.UnimplementedQueryServer
	f *fakeChain
}

func (s *fibreSvc) Params(context.Context, *fibretypes.QueryParamsRequest) (*fibretypes.QueryParamsResponse, error) {
	return s.f.fibre()
}

func startFake(t *testing.T, f *fakeChain, withFibre bool, token string) *ConsensusClient {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer()
	txtypes.RegisterServiceServer(srv, &txSvc{f: f})
	cmtservice.RegisterServiceServer(srv, &cmtSvc{f: f})
	authtypes.RegisterQueryServer(srv, &authSvc{f: f})
	stakingtypes.RegisterQueryServer(srv, &stakingSvc{})
	if withFibre {
		fibretypes.RegisterQueryServer(srv, &fibreSvc{f: f})
	}
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	opts := []grpc.DialOption{
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	}
	if token != "" {
		opts = append(opts, grpc.WithChainUnaryInterceptor(tokenInterceptor(token)))
	}
	conn, err := grpc.NewClient("passthrough:///bufnet", opts...)
	require.NoError(t, err)
	c := NewConsensusConn(conn)
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func tctx(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func TestBroadcastRequestShapeAndHash(t *testing.T) {
	raw := []byte("signed-tx-raw-bytes")
	sum := sha256.Sum256(raw)
	f := &fakeChain{broadcast: func(*txtypes.BroadcastTxRequest) (*txtypes.BroadcastTxResponse, error) {
		return &txtypes.BroadcastTxResponse{TxResponse: &sdk.TxResponse{TxHash: strings.ToUpper(hex.EncodeToString(sum[:]))}}, nil
	}}
	c := startFake(t, f, false, "")
	h, err := c.Broadcast(tctx(t), raw)
	require.NoError(t, err)
	require.Equal(t, sum, h)
	require.Equal(t, raw, f.lastReq.TxBytes, "bytes must be sent unchanged")
	require.Equal(t, txtypes.BroadcastMode_BROADCAST_MODE_SYNC, f.lastReq.Mode)
}

func TestBroadcastRefusals(t *testing.T) {
	raw := []byte("tx")
	cases := []struct {
		name string
		resp *sdk.TxResponse
		err  error
		want error
	}{
		{"in mempool cache", &sdk.TxResponse{Codespace: "sdk", Code: 19, RawLog: "tx already in mempool"}, nil, ErrAlreadyInMempool},
		{"wrong sequence", &sdk.TxResponse{Codespace: "sdk", Code: 32, RawLog: "account sequence mismatch"}, nil, ErrSequenceMismatch},
		{"other code", &sdk.TxResponse{Codespace: "sdk", Code: 5, RawLog: "insufficient funds"}, nil, ErrRejected},
		{"same code other codespace", &sdk.TxResponse{Codespace: "bank", Code: 19}, nil, ErrRejected},
		{"hash of another tx", &sdk.TxResponse{TxHash: strings.Repeat("00", 32)}, nil, ErrUnavailable},
		{"sequence in grpc error", nil, status.Error(codes.Unknown, "rpc error: account sequence mismatch, expected 5"), ErrSequenceMismatch},
		{"node down", nil, status.Error(codes.Unavailable, "down"), ErrUnavailable},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeChain{broadcast: func(*txtypes.BroadcastTxRequest) (*txtypes.BroadcastTxResponse, error) {
				if tc.err != nil {
					return nil, tc.err
				}
				return &txtypes.BroadcastTxResponse{TxResponse: tc.resp}, nil
			}}
			c := startFake(t, f, false, "")
			_, err := c.Broadcast(tctx(t), raw)
			require.ErrorIs(t, err, tc.want)
		})
	}
}

func TestTxStatus(t *testing.T) {
	f := &fakeChain{getTx: func(r *txtypes.GetTxRequest) (*txtypes.GetTxResponse, error) {
		if r.Hash == strings.Repeat("AB", 32) {
			return &txtypes.GetTxResponse{TxResponse: &sdk.TxResponse{Height: 77, Code: 0}}, nil
		}
		return nil, status.Error(codes.NotFound, "tx not found")
	}}
	c := startFake(t, f, false, "")
	var h [32]byte
	for i := range h {
		h[i] = 0xab
	}
	st, err := c.Tx(tctx(t), h)
	require.NoError(t, err)
	require.Equal(t, TxStatus{Found: true, Height: 77}, st)
	st, err = c.Tx(tctx(t), [32]byte{1})
	require.NoError(t, err)
	require.False(t, st.Found)
}

func TestContextBeatsNotFound(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	f := &fakeChain{
		getTx: func(*txtypes.GetTxRequest) (*txtypes.GetTxResponse, error) {
			cancel()
			return nil, status.Error(codes.NotFound, "tx not found")
		},
		account: func(string) (*authtypes.QueryAccountInfoResponse, error) {
			cancel()
			return nil, status.Error(codes.NotFound, "account not found")
		},
	}
	c := startFake(t, f, false, "")
	_, err := c.Tx(ctx, [32]byte{})
	require.ErrorIs(t, err, ErrUnavailable)
	require.NotErrorIs(t, err, ErrNotFound)

	ctx2, cancel2 := context.WithCancel(context.Background())
	f.account = func(string) (*authtypes.QueryAccountInfoResponse, error) {
		cancel2()
		return nil, status.Error(codes.NotFound, "account not found")
	}
	_, err = c.Account(ctx2, "celestia1x")
	require.ErrorIs(t, err, ErrUnavailable)
	require.NotErrorIs(t, err, ErrNotFound)
}

func TestClassifyGRPC(t *testing.T) {
	bg := context.Background()
	require.NoError(t, classifyGRPC(bg, nil))
	require.ErrorIs(t, classifyGRPC(bg, status.Error(codes.NotFound, "x")), ErrNotFound)
	require.ErrorIs(t, classifyGRPC(bg, status.Error(codes.Unimplemented, "x")), ErrUnsupported)
	require.ErrorIs(t, classifyGRPC(bg, status.Error(codes.DeadlineExceeded, "x")), ErrUnavailable)
	require.ErrorIs(t, classifyGRPC(bg, errors.New("plain")), ErrUnavailable)
	done, cancel := context.WithCancel(bg)
	cancel()
	err := classifyGRPC(done, status.Error(codes.NotFound, "x"))
	require.ErrorIs(t, err, ErrUnavailable)
	require.NotErrorIs(t, err, ErrNotFound)
}

func TestAccountNetworkPrefixDenom(t *testing.T) {
	f := &fakeChain{account: func(a string) (*authtypes.QueryAccountInfoResponse, error) {
		if a == "missing" {
			return nil, status.Error(codes.NotFound, "no such account")
		}
		return &authtypes.QueryAccountInfoResponse{Info: &authtypes.BaseAccount{AccountNumber: 9, Sequence: 4}}, nil
	}}
	c := startFake(t, f, false, "")
	ctx := tctx(t)
	ai, err := c.Account(ctx, "celestia1abc")
	require.NoError(t, err)
	require.Equal(t, AccountInfo{Number: 9, Sequence: 4}, ai)
	_, err = c.Account(ctx, "missing")
	require.ErrorIs(t, err, ErrNotFound)
	n, err := c.Network(ctx)
	require.NoError(t, err)
	require.Equal(t, "test-chain-1", n)
	p, err := c.Bech32Prefix(ctx)
	require.NoError(t, err)
	require.Equal(t, "celestia", p)
	d, err := c.BondDenom(ctx)
	require.NoError(t, err)
	require.Equal(t, "utia", d)
	ids, err := c.ProviderChainIDs(ctx)
	require.NoError(t, err)
	require.Empty(t, ids)
}

func TestFibreParams(t *testing.T) {
	f := &fakeChain{fibre: func() (*fibretypes.QueryParamsResponse, error) {
		return &fibretypes.QueryParamsResponse{Params: fibretypes.Params{ShardRetention: 4 * time.Hour}}, nil
	}}
	c := startFake(t, f, true, "")
	p, err := c.FibreParams(tctx(t))
	require.NoError(t, err)
	require.Equal(t, FibreParams{RetentionS: 4 * 3600}, p)

	absent := startFake(t, &fakeChain{}, false, "")
	_, err = absent.FibreParams(tctx(t))
	require.ErrorIs(t, err, ErrNotFound, "no x/fibre service means absent")

	down := startFake(t, &fakeChain{fibre: func() (*fibretypes.QueryParamsResponse, error) {
		return nil, status.Error(codes.Unavailable, "down")
	}}, true, "")
	_, err = down.FibreParams(tctx(t))
	require.ErrorIs(t, err, ErrUnavailable)
	require.NotErrorIs(t, err, ErrNotFound)
}

func TestTokenSentAsXToken(t *testing.T) {
	f := &fakeChain{}
	c := startFake(t, f, false, "s3cret")
	_, err := c.Network(tctx(t))
	require.NoError(t, err)
	require.Equal(t, "s3cret", f.token)
}

func TestDialRefusals(t *testing.T) {
	_, err := DialGRPC(GRPCConfig{})
	require.Error(t, err)
	_, err = DialGRPC(GRPCConfig{Addr: "example.invalid:9090", Token: "x"})
	require.Error(t, err, "token over plain gRPC is refused")
	c, err := DialGRPC(GRPCConfig{Addr: "example.invalid:9090", Token: "x", TLS: true})
	require.NoError(t, err)
	require.NoError(t, c.Close())
	c, err = DialGRPC(GRPCConfig{Addr: "127.0.0.1:9090", Token: "x", AllowInsecureToken: true})
	require.NoError(t, err)
	require.NoError(t, c.Close())
}

// tokenInterceptor mirrors what DialGRPC installs, for the bufconn dialer.
func tokenInterceptor(tok string) grpc.UnaryClientInterceptor {
	return func(ctx context.Context, m string, req, rep any, cc *grpc.ClientConn, inv grpc.UnaryInvoker, o ...grpc.CallOption) error {
		return inv(metadata.AppendToOutgoingContext(ctx, "x-token", tok), m, req, rep, cc, o...)
	}
}
