// Package wire builds the edictad dependencies from a configuration, so the
// daemon and an in-process caller start with the same wiring.
package wire

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"

	"github.com/cosmos/cosmos-sdk/crypto/keyring"

	"github.com/vgonkivs/edicta/celestia/edictad"
	"github.com/vgonkivs/edicta/celestia/node"
	"github.com/vgonkivs/edicta/celestia/recorder"
	"github.com/vgonkivs/edicta/celestia/secret"
)

// Adapters builds every dependency edictad.Start needs for cfg. The returned
// function releases all connections and must be called once, after the daemon
// has shut down. On error nothing stays open and the function is a no-op.
func Adapters(ctx context.Context, cfg edictad.Config, log *slog.Logger) (edictad.Deps, func(), error) {
	rd, cons, sub, closeAll, err := adapters(ctx, cfg, log)
	if err != nil {
		return edictad.Deps{}, func() {}, err
	}
	deps := edictad.Deps{Reader: rd, Consensus: cons, Submitter: sub, Logger: log}
	if cfg.Network.DA == edictad.DAConfigFibre {
		fd, closeFibre, err := fibreWiring(ctx, cfg, rd, cons, log)
		if err != nil {
			closeAll()
			return edictad.Deps{}, func() {}, err
		}
		deps.Fibre = fd
		return deps, func() { closeFibre(); closeAll() }, nil
	}
	return deps, closeAll, nil
}

// consensusConn is the consensus client adapters needs.
type consensusConn interface {
	node.Consensus
	Close() error
}

// The seams let tests check the order of the startup steps without a network.
var (
	newConsensusFn = func(g node.GRPCConfig) (consensusConn, error) { return node.NewConsensus(g) }
	newReadOnlyFn  = func(ctx context.Context, b node.BridgeConfig) (io.Closer, node.Reader, error) {
		return node.NewReadOnly(ctx, b)
	}
	checkFn       = node.Check
	openKeyringFn = node.OpenKeyring
	newSigningFn  = func(ctx context.Context, b node.BridgeConfig, g node.GRPCConfig, kr keyring.Keyring,
		keyName, network string) (io.Closer, node.Reader, node.Submitter, error) {
		return node.NewSigning(ctx, b, g, kr, keyName, network)
	}
)

// adapters builds the real node adapters. The Recorder's keyring is its own:
// the executor signs with a different key in a different keyring, never here.
// closeAll releases every connection and is safe to call once.
func adapters(ctx context.Context, cfg edictad.Config, log *slog.Logger) (node.Reader, node.Consensus, recorder.Submitter, func(), error) {
	noop := func() {}
	b, g, err := endpointConfigs(cfg)
	if err != nil {
		return nil, nil, nil, noop, err
	}
	cons, err := newConsensusFn(g)
	if err != nil {
		return nil, nil, nil, noop, err
	}
	var closers []func()
	closeAll := func() {
		for i := len(closers) - 1; i >= 0; i-- {
			closers[i]()
		}
	}
	closers = append(closers, func() { _ = cons.Close() })

	rc, rd, err := newReadOnlyFn(ctx, b)
	if err != nil {
		closeAll()
		return nil, nil, nil, noop, err
	}
	closers = append(closers, func() { _ = rc.Close() })
	if !cfg.Recorder.Enabled || cfg.Network.DA == edictad.DAConfigFibre {
		// With da = fibre the signing client is built with the Fibre
		// dependencies, after the Fibre compatibility check.
		return rd, cons, nil, closeAll, nil
	}

	// The signing client starts the transaction and Fibre clients, so the
	// chain is vetted first and an unsupported one fails with a clear error.
	ns, err := hex.DecodeString(cfg.Recorder.Namespace)
	if err != nil {
		closeAll()
		return nil, nil, nil, noop, fmt.Errorf("recorder namespace: %w", err)
	}
	if _, err := checkFn(ctx, rd, cons, node.Expect{
		ChainID: cfg.Network.ChainID, MinAppVersion: cfg.Network.MinAppVersion,
		MaxAppVersion: cfg.Network.MaxAppVersion, Namespace: ns,
	}); err != nil {
		closeAll()
		return nil, nil, nil, noop, fmt.Errorf("compatibility check: %w", err)
	}
	pass, err := secret.FromFile(cfg.Recorder.PassphraseFile)
	if err != nil {
		closeAll()
		return nil, nil, nil, noop, fmt.Errorf("passphrase file: %w", err)
	}
	pb := pass.Reveal()
	kr, err := openKeyringFn(node.KeyringConfig{
		Dir: cfg.Recorder.KeyringDir, Name: cfg.Recorder.KeyName, Backend: cfg.Recorder.KeyringBackend,
		AllowTest: cfg.Recorder.AllowTestKeyring, Passphrase: pb, Logger: log,
	})
	clear(pb)
	pass.Zero()
	if err != nil {
		closeAll()
		return nil, nil, nil, noop, err
	}
	network, err := cons.Network(ctx)
	if err != nil {
		closeAll()
		return nil, nil, nil, noop, fmt.Errorf("consensus node: %w", err)
	}
	c, srd, sub, err := newSigningFn(ctx, b, g, kr, cfg.Recorder.KeyName, network)
	if err != nil {
		closeAll()
		return nil, nil, nil, noop, err
	}
	closers = append(closers, func() { _ = c.Close() })
	return srd, cons, recorder.NewLocalSubmitter(sub), closeAll, nil
}

// endpointConfigs reads the endpoint tokens and builds the bridge and the
// consensus connection settings.
func endpointConfigs(cfg edictad.Config) (b node.BridgeConfig, g node.GRPCConfig, err error) {
	bridgeTok, err := readToken(cfg.Network.Bridge.TokenFile)
	if err != nil {
		return b, g, fmt.Errorf("bridge token: %w", err)
	}
	consTok, err := readToken(cfg.Network.ConsensusGRPC.TokenFile)
	if err != nil {
		return b, g, fmt.Errorf("consensus token: %w", err)
	}
	b = node.BridgeConfig{Addr: cfg.Network.Bridge.Addr, Token: bridgeTok, TLS: cfg.Network.Bridge.TLS,
		AllowInsecureToken: loopbackAddr(cfg.Network.Bridge.Addr)}
	if err := b.ValidateBasic(); err != nil {
		return b, g, err
	}
	g = node.GRPCConfig{Addr: cfg.Network.ConsensusGRPC.Addr, TLS: cfg.Network.ConsensusGRPC.TLS, Token: consTok,
		AllowInsecureToken: loopbackAddr(cfg.Network.ConsensusGRPC.Addr)}
	return b, g, nil
}

func readToken(path string) (string, error) {
	if path == "" {
		return "", nil
	}
	s, err := secret.FromFile(path)
	if err != nil {
		return "", err
	}
	defer s.Zero()
	return s.RevealString(), nil
}

func loopbackAddr(addr string) bool { return node.LoopbackAddr(addr) }
