// SPDX-License-Identifier: Apache-2.0

package signerd

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/vgonkivs/edicta/api/edictaapi"
	"github.com/vgonkivs/edicta/celestia/keyfile"
	"github.com/vgonkivs/edicta/celestia/secret"
	"github.com/vgonkivs/edicta/plugins/edenescrow/edenexec"
	"github.com/vgonkivs/edicta/plugins/edenescrow/edenrpc"
	"github.com/vgonkivs/edicta/signer"
	"github.com/vgonkivs/edicta/signer/eden"
)

// Daemon is a started signer: the service passed its startup checks.
type Daemon struct {
	cfg   Config
	svc   *signer.Service
	api   http.Handler
	store *signer.BoltStore
	log   *slog.Logger
}

// Build reads the key files, opens the store and the RPC clients, and runs
// the startup checks (payer addresses, escrow code, payer code). Nothing is
// served yet.
func Build(ctx context.Context, cfg Config, log *slog.Logger) (_ *Daemon, err error) {
	if log == nil {
		log = slog.Default()
	}
	sc, err := cfg.SignerConfig()
	if err != nil {
		return nil, err
	}
	hc, err := cfg.HandlerConfig()
	if err != nil {
		return nil, err
	}
	opts := signer.HTTPOptions{AllowRemote: cfg.AllowRemote}
	if cfg.TokenFile != "" {
		token, err := secret.FromFile(cfg.TokenFile)
		if err != nil {
			return nil, fmt.Errorf("signerd: token_file: %w", err)
		}
		defer token.Zero()
		opts.Token = token.Reveal()
	}
	for i, cr := range cfg.Credentials {
		tok, err := secret.FromFile(cr.TokenFile)
		if err != nil {
			return nil, fmt.Errorf("signerd: credential %d: %w", i, err)
		}
		defer tok.Zero()
		agent, err := hexKey("agent_pubkey", cr.AgentPubKey)
		if err != nil {
			return nil, err
		}
		opts.Credentials = append(opts.Credentials, signer.Credential{Token: tok.Reveal(), Agent: agent})
	}

	wallets := map[uint64]signer.WalletBackend{}
	chains := map[uint64]eden.Chain{}
	settlers := map[uint64]eden.Settler{}
	relays := map[uint64]eden.Relay{}
	for _, ch := range cfg.Chains {
		k, err := keyfile.ReadSecp256k1(ch.PayerKeyFile, "payer")
		if err != nil {
			return nil, fmt.Errorf("signerd: chain %d: %w", ch.ChainID, err)
		}
		w, err := signer.NewKeyWallet(k)
		clear(k)
		if err != nil {
			return nil, fmt.Errorf("signerd: chain %d: %w", ch.ChainID, err)
		}
		wallets[ch.ChainID] = w

		class := edenexec.ClassPublicRPC
		if ch.OwnNode {
			class = edenexec.ClassOwnNode
		}
		own, err := rpcClient(ch.RPC, class, ch.ChainID)
		if err != nil {
			return nil, fmt.Errorf("signerd: chain %d: %w", ch.ChainID, err)
		}
		if len(ch.SettlementRPC) == 0 {
			log.Warn("signerd: one settlement source: a deposit not found is never final as not executed",
				"chain", ch.ChainID)
		}
		if ch.Broadcaster == eden.BroadcastRelay {
			r, err := eden.NewHoustonRelay(ch.relayConfig(cfg.Broadcast), nil)
			if err != nil {
				return nil, fmt.Errorf("signerd: chain %d: %w", ch.ChainID, err)
			}
			relays[ch.ChainID] = r
		}
		srcs := []edenexec.Source{own}
		for _, u := range ch.SettlementRPC {
			c, err := rpcClient(u, edenexec.ClassPublicRPC, ch.ChainID)
			if err != nil {
				return nil, fmt.Errorf("signerd: chain %d: %w", ch.ChainID, err)
			}
			srcs = append(srcs, c)
		}
		checker, err := edenexec.NewChecker(cfg.SettlementConfig(), srcs, nil)
		if err != nil {
			return nil, fmt.Errorf("signerd: chain %d: %w", ch.ChainID, err)
		}
		chains[ch.ChainID], settlers[ch.ChainID] = own, checker
	}
	h, err := eden.New(hc, eden.Deps{Chains: chains, Settlers: settlers, Relays: relays, Log: log})
	if err != nil {
		return nil, err
	}

	deps := signer.Deps{Wallets: wallets, Handlers: []signer.Handler{h}, Log: log}
	if r := cfg.Record; r != nil {
		seed, err := keyfile.ReadSeed(r.ExecutorKeyFile, "executor")
		if err != nil {
			return nil, fmt.Errorf("signerd: record: %w", err)
		}
		exec, err := signer.NewEd25519Executor(seed)
		if err != nil {
			return nil, err
		}
		gateToken := edictaapi.Secret{}
		if r.GateTokenFile != "" {
			t, err := secret.FromFile(r.GateTokenFile)
			if err != nil {
				return nil, fmt.Errorf("signerd: record.gate_token_file: %w", err)
			}
			gateToken = edictaapi.NewSecret(t.RevealString())
			t.Zero()
		}
		client, err := edictaapi.NewClient(r.GateURL, gateToken, nil, nil)
		if err != nil {
			return nil, fmt.Errorf("signerd: record: %w", err)
		}
		deps.Executor, deps.Recorder = exec, signer.GateRecorder{C: client}
	}

	store, err := signer.OpenBoltStore(cfg.StorePath)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			_ = store.Close()
		}
	}()
	deps.Store = store
	svc, err := signer.New(sc, deps)
	if err != nil {
		return nil, err
	}
	if err := svc.Start(ctx); err != nil {
		return nil, err
	}
	if cfg.AdminTokenFile != "" {
		admin, err := secret.FromFile(cfg.AdminTokenFile)
		if err != nil {
			return nil, fmt.Errorf("signerd: admin_token_file: %w", err)
		}
		opts.AdminToken = admin.Reveal()
		admin.Zero()
	}
	api, err := signer.NewHandler(svc, opts, log)
	if err != nil {
		return nil, err
	}
	return &Daemon{cfg: cfg, svc: svc, api: api, store: store, log: log}, nil
}

func rpcClient(src string, class edenexec.SourceClass, chainID uint64) (*edenrpc.Client, error) {
	op, u := edenrpc.SplitSource(src)
	rc := edenrpc.Config{URL: u, Class: class, ExpectChainID: chainID, Operator: op}
	rc.ApplyDefaults()
	return edenrpc.New(rc, nil)
}

// Serve listens on the configured address and runs the settlement worker
// until ctx ends. ready, if set, gets the bound address.
func (d *Daemon) Serve(ctx context.Context, ready func(net.Addr)) error {
	defer d.store.Close()
	if err := signer.CheckBind(d.cfg.Listen, d.cfg.AllowRemote); err != nil {
		return err
	}
	ln, err := net.Listen("tcp", d.cfg.Listen)
	if err != nil {
		return err
	}
	srv := &http.Server{
		Handler:           d.api,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	if ready != nil {
		ready(ln.Addr())
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	work := make(chan error, 1)
	go func() { work <- d.svc.Run(ctx) }()
	errc := make(chan error, 1)
	go func() {
		if d.cfg.TLSCertFile != "" {
			errc <- srv.ServeTLS(ln, d.cfg.TLSCertFile, d.cfg.TLSKeyFile)
			return
		}
		errc <- srv.Serve(ln)
	}()
	d.log.Info("edicta-signer: serving", "listen", ln.Addr().String())
	select {
	case err = <-errc:
		cancel()
	case <-ctx.Done():
		sctx, scancel := context.WithTimeout(context.Background(), 10*time.Second)
		_ = srv.Shutdown(sctx)
		scancel()
		<-errc
	}
	if werr := <-work; werr != nil && !errors.Is(werr, context.Canceled) && err == nil {
		err = werr
	}
	if errors.Is(err, http.ErrServerClosed) {
		err = nil
	}
	return err
}
