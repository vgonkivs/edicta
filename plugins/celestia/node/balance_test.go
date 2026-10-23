package node

import (
	"context"
	"net"
	"testing"

	"cosmossdk.io/math"
	sdk "github.com/cosmos/cosmos-sdk/types"
	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

type bankSvc struct {
	banktypes.UnimplementedQueryServer
	answer func(*banktypes.QueryBalanceRequest) (*banktypes.QueryBalanceResponse, error)
	got    []*banktypes.QueryBalanceRequest
}

func (s *bankSvc) Balance(_ context.Context, r *banktypes.QueryBalanceRequest) (*banktypes.QueryBalanceResponse, error) {
	s.got = append(s.got, r)
	return s.answer(r)
}

func startBank(t *testing.T, s *bankSvc) *ConsensusClient {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer()
	banktypes.RegisterQueryServer(srv, s)
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

func TestBalance(t *testing.T) {
	big := math.NewIntFromUint64(1<<64 - 1)
	over := big.AddRaw(1)
	for _, tc := range []struct {
		name   string
		answer func(*banktypes.QueryBalanceRequest) (*banktypes.QueryBalanceResponse, error)
		want   uint64
		err    error
	}{
		{"amount", func(r *banktypes.QueryBalanceRequest) (*banktypes.QueryBalanceResponse, error) {
			return &banktypes.QueryBalanceResponse{Balance: &sdk.Coin{Denom: r.Denom, Amount: math.NewInt(61200)}}, nil
		}, 61200, nil},
		{"max uint64", func(r *banktypes.QueryBalanceRequest) (*banktypes.QueryBalanceResponse, error) {
			return &banktypes.QueryBalanceResponse{Balance: &sdk.Coin{Denom: r.Denom, Amount: big}}, nil
		}, 1<<64 - 1, nil},
		{"no coin means zero", func(*banktypes.QueryBalanceRequest) (*banktypes.QueryBalanceResponse, error) {
			return &banktypes.QueryBalanceResponse{}, nil
		}, 0, nil},
		{"overflow", func(r *banktypes.QueryBalanceRequest) (*banktypes.QueryBalanceResponse, error) {
			return &banktypes.QueryBalanceResponse{Balance: &sdk.Coin{Denom: r.Denom, Amount: over}}, nil
		}, 0, ErrUnsupported},
		{"negative", func(r *banktypes.QueryBalanceRequest) (*banktypes.QueryBalanceResponse, error) {
			return &banktypes.QueryBalanceResponse{Balance: &sdk.Coin{Denom: r.Denom, Amount: math.NewInt(-1)}}, nil
		}, 0, ErrUnsupported},
		{"other denom", func(*banktypes.QueryBalanceRequest) (*banktypes.QueryBalanceResponse, error) {
			return &banktypes.QueryBalanceResponse{Balance: &sdk.Coin{Denom: "uother", Amount: math.NewInt(5)}}, nil
		}, 0, ErrUnsupported},
		{"unavailable", func(*banktypes.QueryBalanceRequest) (*banktypes.QueryBalanceResponse, error) {
			return nil, status.Error(codes.Unavailable, "down")
		}, 0, ErrUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &bankSvc{answer: tc.answer}
			got, err := startBank(t, s).Balance(tctx(t), "celestia1abc", "utia")
			if tc.err != nil {
				require.ErrorIs(t, err, tc.err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
			require.Len(t, s.got, 1)
			assert.Equal(t, "celestia1abc", s.got[0].Address)
			assert.Equal(t, "utia", s.got[0].Denom)
		})
	}
}

func TestBalanceNeedsAddressAndDenom(t *testing.T) {
	s := &bankSvc{}
	c := startBank(t, s)
	_, err := c.Balance(tctx(t), "", "utia")
	require.Error(t, err)
	_, err = c.Balance(tctx(t), "celestia1abc", "")
	require.Error(t, err)
	assert.Empty(t, s.got)
}
