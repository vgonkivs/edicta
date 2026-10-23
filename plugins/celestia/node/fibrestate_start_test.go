package node

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/celestiaorg/celestia-app/v10/fibre/state"
	"github.com/celestiaorg/celestia-node/api/client"
	coregrpc "github.com/cometbft/cometbft/rpc/grpc"
	"github.com/cosmos/cosmos-sdk/client/grpc/cmtservice"
	"github.com/cosmos/cosmos-sdk/crypto/keyring"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	"github.com/celestiaorg/celestia-app/v10/fibre/validator"
	fibretypes "github.com/celestiaorg/celestia-app/v10/x/fibre/types"
	valtypes "github.com/celestiaorg/celestia-app/v10/x/valaddr/types"
)

// In da = blob mode edictad must start against a chain that has no x/fibre
// and no x/valaddr, although the api/client starts the Fibre state client
// inside client.New. The state client built by the seam is the real
// fibreState over an in-memory consensus node that serves only the CometBFT
// service.

func TestFibreStateStartsOnAChainWithoutFibre(t *testing.T) {
	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer()
	cmtservice.RegisterServiceServer(srv, &cmtSvc{f: &fakeChain{}})
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	oldNew, oldDial := newClientFn, dialStateClient
	t.Cleanup(func() { newClientFn, dialStateClient = oldNew, oldDial })
	dialStateClient = func(GRPCConfig) (state.Client, error) {
		return &fibreState{
			conn: conn, blocks: coregrpc.NewBlockAPIClient(conn), query: fibretypes.NewQueryClient(conn),
			vals: valtypes.NewQueryClient(conn), hosts: map[string]validator.Host{},
		}, nil
	}
	errStop := errors.New("stop after the state client started")
	var startErr error
	var chainID string
	newClientFn = func(ctx context.Context, cfg client.Config, _ keyring.Keyring) (*client.Client, error) {
		sc, err := cfg.SubmitConfig.Fibre.StateClientFn() // what api/client does
		require.NoError(t, err)
		startErr = sc.Start(ctx)
		chainID = sc.ChainID()
		return nil, errStop
	}
	_, _, _, err = NewSigning(context.Background(), BridgeConfig{Addr: "http://bn.invalid:26658"},
		GRPCConfig{Addr: "127.0.0.1:9090"}, keyring.NewInMemory(nil), "k", "test-chain-1")
	require.ErrorContains(t, err, errStop.Error())
	require.NoError(t, startErr, "a chain without x/fibre (and x/valaddr) must not stop a da = blob start")
	assert.Equal(t, "test-chain-1", chainID)
}
