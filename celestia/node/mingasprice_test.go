package node

import (
	"context"
	"math/big"
	"net"
	"testing"

	nodeservice "github.com/cosmos/cosmos-sdk/client/grpc/node"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

type cfgSvc struct {
	nodeservice.UnimplementedServiceServer
	price string
}

func (s *cfgSvc) Config(context.Context, *nodeservice.ConfigRequest) (*nodeservice.ConfigResponse, error) {
	return &nodeservice.ConfigResponse{MinimumGasPrice: s.price}, nil
}

func minPriceClient(t *testing.T, price string) *ConsensusClient {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer()
	nodeservice.RegisterServiceServer(srv, &cfgSvc{price: price})
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

// Assumed symbol: (*ConsensusClient).MinGasPrice(ctx) (*big.Rat, error), exact, also a
// method of the Consensus interface: the node's minimum_gas_price in bond
// denom per gas unit, read from cosmos.base.node.v1.Service/Config.
func TestMinGasPrice(t *testing.T) {
	for _, tc := range []struct {
		price string
		want  string
		err   error
	}{
		{"0.004utia", "1/250", nil},
		{"0.004000000000000000utia", "1/250", nil},
		{"0.002000utia", "1/500", nil},
		{"1utia", "1", nil},
		{"0.1utia", "1/10", nil},
		{"", "0", ErrUnsupported},
		{"garbage", "0", ErrUnsupported},
		{"-1utia", "0", ErrUnsupported},
	} {
		t.Run(tc.price, func(t *testing.T) {
			got, err := minPriceClient(t, tc.price).MinGasPrice(tctx(t))
			if tc.err != nil {
				require.ErrorIs(t, err, tc.err)
				return
			}
			require.NoError(t, err)
			require.Zero(t, got.Cmp(mustRat(t, tc.want)), "got %s", got.RatString())
		})
	}
}

func mustRat(t *testing.T, s string) *big.Rat {
	t.Helper()
	r, ok := new(big.Rat).SetString(s)
	require.True(t, ok)
	return r
}
