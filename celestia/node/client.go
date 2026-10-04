package node

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/cosmos/cosmos-sdk/crypto/keyring"

	appfibre "github.com/celestiaorg/celestia-app/v10/fibre"
	"github.com/celestiaorg/celestia-app/v10/fibre/state"
	"github.com/celestiaorg/celestia-node/api/client"
	"github.com/celestiaorg/celestia-node/nodebuilder/p2p"
)

// BridgeConfig is a bridge node JSON-RPC endpoint.
type BridgeConfig struct {
	Addr  string
	Token string
	TLS   bool
}

// newClientFn and dialStateClient are seams for tests.
var (
	newClientFn     = client.New
	dialStateClient = defaultDialStateClient
)

// BridgeURL turns addr into the URL the bridge client needs. A bare host:port
// gets http or https by tls; a URL must carry the scheme tls implies.
func BridgeURL(addr string, tls bool) (string, error) {
	want := "http"
	if tls {
		want = "https"
	}
	if addr == "" {
		return "", errors.New("node: no bridge address")
	}
	if !strings.Contains(addr, "://") {
		addr = want + "://" + addr
	}
	u, err := url.Parse(addr)
	if err != nil {
		return "", fmt.Errorf("node: bridge address: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("node: bridge address scheme %q, want http or https", u.Scheme)
	}
	if u.Scheme != want {
		return "", fmt.Errorf("node: bridge address scheme %q disagrees with tls=%t", u.Scheme, tls)
	}
	if u.Host == "" {
		return "", errors.New("node: bridge address has no host")
	}
	return addr, nil
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
	fibreCfg := appfibre.DefaultClientConfig()
	fibreCfg.StateClientFn = func() (state.Client, error) { return dialStateClient(g.Addr, g.TLS, g.Token) }
	c, err := newClientFn(ctx, client.Config{
		ReadConfig: client.ReadConfig{BridgeDAAddr: b.Addr, DAAuthToken: b.Token, EnableDATLS: b.TLS},
		SubmitConfig: client.SubmitConfig{
			DefaultKeyName: keyName,
			Network:        p2p.Network(network), // the core accessor refuses a node on another chain
			CoreGRPCConfig: client.CoreGRPCConfig{Addr: g.Addr, TLSEnabled: g.TLS, AuthToken: g.Token},
			Fibre:          &fibreCfg,
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
