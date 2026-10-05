package node

import (
	"context"
	"errors"
	"testing"

	"github.com/cosmos/cosmos-sdk/crypto/keyring"
	"github.com/stretchr/testify/require"

	"github.com/celestiaorg/celestia-app/v10/fibre/state"
	"github.com/celestiaorg/celestia-node/api/client"
)

// NewSigning builds the Fibre state client through dialStateClient with the
// consensus connection's address, TLS flag and token.
func TestNewSigningFibreStateClientUsesConsensusTLSAndToken(t *testing.T) {
	for _, tc := range []struct {
		name string
		g    GRPCConfig
	}{
		{"tls with token", GRPCConfig{Addr: "grpc.example.invalid:9090", TLS: true, Token: "tok-1"}},
		{"plain no token", GRPCConfig{Addr: "127.0.0.1:9090"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var got client.Config
			errStop := errors.New("stop")
			oldNew, oldDial := newClientFn, dialStateClient
			t.Cleanup(func() { newClientFn, dialStateClient = oldNew, oldDial })
			newClientFn = func(_ context.Context, cfg client.Config, _ keyring.Keyring) (*client.Client, error) {
				got = cfg
				return nil, errStop
			}
			var dAddr, dTok string
			var dTLS bool
			dialStateClient = func(addr string, tls bool, token string) (state.Client, error) {
				dAddr, dTLS, dTok = addr, tls, token
				return nil, errStop
			}
			kr := keyring.NewInMemory(nil)
			_, _, _, err := NewSigning(context.Background(), BridgeConfig{Addr: "http://bn.invalid:26658"}, tc.g, kr, "k", "mocha-4")
			require.Error(t, err)

			require.NotNil(t, got.SubmitConfig.Fibre, "Fibre config must be set")
			require.NotNil(t, got.SubmitConfig.Fibre.StateClientFn, "StateClientFn must be set")
			_, err = got.SubmitConfig.Fibre.StateClientFn()
			require.ErrorIs(t, err, errStop)
			require.Equal(t, tc.g.Addr, dAddr)
			require.Equal(t, tc.g.TLS, dTLS)
			require.Equal(t, tc.g.Token, dTok)
			require.Equal(t, tc.g.TLS, got.SubmitConfig.CoreGRPCConfig.TLSEnabled)
		})
	}
}
