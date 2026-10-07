package node

import (
	"context"
	"net"
	"strconv"
	"testing"

	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/test/bufconn"

	"github.com/vgonkivs/edicta/celestia/heightcheck"
)

type accountAtSvc struct {
	authtypes.UnimplementedQueryServer
	fn func(ctx context.Context, pinned uint64) (*authtypes.QueryAccountInfoResponse, error)
}

func (s *accountAtSvc) AccountInfo(ctx context.Context, _ *authtypes.QueryAccountInfoRequest) (*authtypes.QueryAccountInfoResponse, error) {
	var h uint64
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if v := md.Get(echoKey); len(v) == 1 {
			h, _ = strconv.ParseUint(v[0], 10, 64)
		}
	}
	return s.fn(ctx, h)
}

func startAccountAt(t *testing.T, fn func(context.Context, uint64) (*authtypes.QueryAccountInfoResponse, error)) *ConsensusClient {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer()
	authtypes.RegisterQueryServer(srv, &accountAtSvc{fn: fn})
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

func accountResp(seq uint64) *authtypes.QueryAccountInfoResponse {
	return &authtypes.QueryAccountInfoResponse{Info: &authtypes.BaseAccount{AccountNumber: 3, Sequence: seq}}
}

func TestAccountAtPinsAndRequiresTheEcho(t *testing.T) {
	const h = 4321
	t.Run("exact echo is used", func(t *testing.T) {
		var pinnedSeen uint64
		c := startAccountAt(t, func(ctx context.Context, p uint64) (*authtypes.QueryAccountInfoResponse, error) {
			pinnedSeen = p
			echo(ctx, p)
			return accountResp(9), nil
		})
		got, err := c.AccountAt(tctx(t), "addr", h)
		require.NoError(t, err)
		assert.Equal(t, AccountInfo{Number: 3, Sequence: 9}, got)
		assert.EqualValues(t, h, pinnedSeen)
	})
	t.Run("no echo is refused", func(t *testing.T) {
		c := startAccountAt(t, func(context.Context, uint64) (*authtypes.QueryAccountInfoResponse, error) {
			return accountResp(9), nil
		})
		_, err := c.AccountAt(tctx(t), "addr", h)
		require.ErrorIs(t, err, heightcheck.ErrHeightIgnored)
		assert.ErrorIs(t, err, ErrUnavailable)
	})
	t.Run("another height is refused", func(t *testing.T) {
		c := startAccountAt(t, func(ctx context.Context, p uint64) (*authtypes.QueryAccountInfoResponse, error) {
			echo(ctx, p-1)
			return accountResp(9), nil
		})
		_, err := c.AccountAt(tctx(t), "addr", h)
		require.ErrorIs(t, err, heightcheck.ErrHeightIgnored)
	})
	t.Run("height zero is refused before any call", func(t *testing.T) {
		c := startAccountAt(t, func(context.Context, uint64) (*authtypes.QueryAccountInfoResponse, error) {
			assert.Fail(t, "must not be queried")
			return nil, nil
		})
		_, err := c.AccountAt(tctx(t), "addr", 0)
		require.Error(t, err)
	})
	t.Run("missing account is not found", func(t *testing.T) {
		c := startAccountAt(t, func(ctx context.Context, p uint64) (*authtypes.QueryAccountInfoResponse, error) {
			echo(ctx, p)
			return &authtypes.QueryAccountInfoResponse{}, nil
		})
		_, err := c.AccountAt(tctx(t), "addr", h)
		require.ErrorIs(t, err, ErrNotFound)
	})
}
