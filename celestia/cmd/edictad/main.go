// Command edictad is the gate and optional Recorder daemon.
package main

import (
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cosmos/cosmos-sdk/crypto/keyring"
	"github.com/pelletier/go-toml/v2"

	"github.com/vgonkivs/edicta/celestia/edictad"
	"github.com/vgonkivs/edicta/celestia/node"
	"github.com/vgonkivs/edicta/celestia/recorder"
	"github.com/vgonkivs/edicta/celestia/secret"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "edictad:", err)
		os.Exit(1)
	}
}

func run() error {
	path := flag.String("config", "", "path of the TOML configuration")
	printCfg := flag.Bool("print-config", false, "print the parsed configuration (paths only, no secrets) and exit")
	flag.Parse()
	if *path == "" {
		return errors.New("-config is required")
	}
	data, err := os.ReadFile(*path)
	if err != nil {
		return fmt.Errorf("reading config: %w", err)
	}
	cfg, err := edictad.ParseConfig(data)
	if err != nil {
		return err
	}
	if *printCfg {
		out, err := toml.Marshal(cfg)
		if err != nil {
			return err
		}
		_, err = os.Stdout.Write(out)
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	rd, cons, sub, closeAll, err := adapters(ctx, cfg, log)
	if err != nil {
		return err
	}
	defer closeAll()
	srv, err := edictad.Start(ctx, cfg, edictad.Deps{Reader: rd, Consensus: cons, Submitter: sub, Logger: log})
	if err != nil {
		return err
	}
	<-ctx.Done()
	sctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return srv.Shutdown(sctx)
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
	bridgeTok, err := readToken(cfg.Network.Bridge.TokenFile)
	if err != nil {
		return nil, nil, nil, noop, fmt.Errorf("bridge token: %w", err)
	}
	consTok, err := readToken(cfg.Network.ConsensusGRPC.TokenFile)
	if err != nil {
		return nil, nil, nil, noop, fmt.Errorf("consensus token: %w", err)
	}
	b := node.BridgeConfig{Addr: cfg.Network.Bridge.Addr, Token: bridgeTok, TLS: cfg.Network.Bridge.TLS,
		AllowInsecureToken: loopbackAddr(cfg.Network.Bridge.Addr)}
	if err := b.ValidateBasic(); err != nil {
		return nil, nil, nil, noop, err
	}
	g := node.GRPCConfig{Addr: cfg.Network.ConsensusGRPC.Addr, TLS: cfg.Network.ConsensusGRPC.TLS, Token: consTok,
		AllowInsecureToken: loopbackAddr(cfg.Network.ConsensusGRPC.Addr)}
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
	if !cfg.Recorder.Enabled {
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
