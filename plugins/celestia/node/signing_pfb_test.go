package node

import (
	"context"
	"errors"
	"testing"

	"github.com/cosmos/cosmos-sdk/crypto/keyring"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/celestiaorg/celestia-node/api/client"
	"github.com/celestiaorg/celestia-node/nodebuilder/p2p"
)

// The PayForBlob is signed with the local key and broadcast to the consensus
// gRPC endpoint. The bridge address is the read side only, so a bridge without
// state methods (a public, tokenless one) is enough.
func TestNewSigningSubmitsThroughConsensusGRPCWithTheLocalKey(t *testing.T) {
	var got client.Config
	var gotKR keyring.Keyring
	oldNew := newClientFn
	t.Cleanup(func() { newClientFn = oldNew })
	newClientFn = func(_ context.Context, cfg client.Config, kr keyring.Keyring) (*client.Client, error) {
		got, gotKR = cfg, kr
		return nil, errors.New("stop")
	}
	kr := keyring.NewInMemory(nil)
	g := GRPCConfig{Addr: "grpc.example.invalid:9090", TLS: true, Token: "tok"}
	b := BridgeConfig{Addr: "https://bridge.example.invalid", TLS: true}
	_, _, _, err := NewSigning(context.Background(), b, g, kr, "recorder", "mocha-5")
	require.Error(t, err)

	sub := got.SubmitConfig
	assert.Equal(t, "grpc.example.invalid:9090", sub.CoreGRPCConfig.Addr, "submissions go to the consensus node")
	assert.True(t, sub.CoreGRPCConfig.TLSEnabled)
	assert.Equal(t, "tok", sub.CoreGRPCConfig.AuthToken)
	assert.Equal(t, "recorder", sub.DefaultKeyName, "signed with the local keyring key")
	assert.Equal(t, p2p.Network("mocha-5"), sub.Network)
	assert.NotNil(t, gotKR, "the caller's keyring signs")
	assert.Equal(t, "https://bridge.example.invalid", got.ReadConfig.BridgeDAAddr, "the bridge is for reads")
	assert.Empty(t, got.ReadConfig.DAAuthToken, "no bridge token is needed")
}

// A client without the local submit side is refused instead of falling back to
// a bridge blob.Submit.
func TestSubmitterRefusesAClientWithoutALocalSubmitSide(t *testing.T) {
	_, err := newSubmitter(&client.Client{})
	require.Error(t, err)
	_, err = newSubmitter(nil)
	require.Error(t, err)
}
