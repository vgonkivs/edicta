package node

import (
	"context"
	"errors"

	"github.com/cosmos/cosmos-sdk/crypto/keyring"

	"github.com/celestiaorg/celestia-node/api/client"
	"github.com/celestiaorg/celestia-node/nodebuilder/p2p"
)

// BridgeConfig is a bridge node JSON-RPC endpoint.
type BridgeConfig struct {
	Addr  string
	Token string
	TLS   bool
}

// NewReadOnly connects to the bridge node only. Close the result.
func NewReadOnly(ctx context.Context, b BridgeConfig) (*client.ReadClient, Reader, error) {
	rc, err := client.NewReadClient(ctx, client.ReadConfig{BridgeDAAddr: b.Addr, DAAuthToken: b.Token, EnableDATLS: b.TLS})
	if err != nil {
		return nil, nil, wrapCtx(ctx, err)
	}
	r, err := NewReader(rc)
	if err != nil {
		_ = rc.Close()
		return nil, nil, err
	}
	return rc, r, nil
}

// NewSigning connects to the bridge node for reads and to the consensus gRPC
// endpoint for submissions, signing with key keyName of kr. network is the
// chain id the consensus node reports (ConsensusClient.Network). Close the result.
func NewSigning(ctx context.Context, b BridgeConfig, g GRPCConfig, kr keyring.Keyring, keyName, network string) (*client.Client, Reader, Submitter, error) {
	if kr == nil {
		return nil, nil, nil, errors.New("node: no keyring")
	}
	if network == "" {
		return nil, nil, nil, errors.New("node: no chain id; read it from the consensus node first")
	}
	c, err := client.New(ctx, client.Config{
		ReadConfig: client.ReadConfig{BridgeDAAddr: b.Addr, DAAuthToken: b.Token, EnableDATLS: b.TLS},
		SubmitConfig: client.SubmitConfig{
			DefaultKeyName: keyName,
			Network:        p2p.Network(network), // the core accessor refuses a node on another chain
			CoreGRPCConfig: client.CoreGRPCConfig{Addr: g.Addr, TLSEnabled: g.TLS, AuthToken: g.Token},
		},
	}, kr)
	if err != nil {
		return nil, nil, nil, wrapCtx(ctx, err)
	}
	r, err := NewReader(&c.ReadClient)
	if err != nil {
		_ = c.Close()
		return nil, nil, nil, err
	}
	s, err := NewSubmitter(c)
	if err != nil {
		_ = c.Close()
		return nil, nil, nil, err
	}
	return c, r, s, nil
}
