package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/cometbft/cometbft/light"
	"github.com/cometbft/cometbft/light/provider"
	lighthttp "github.com/cometbft/cometbft/light/provider/http"

	"github.com/vgonkivs/edicta/celestia/inclusion"
	"github.com/vgonkivs/edicta/celestia/node"
	"github.com/vgonkivs/edicta/celestia/railtx"
	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/edictaapi"
	"github.com/vgonkivs/edicta/examples/tia-transfer/agent"
	"github.com/vgonkivs/edicta/examples/tia-transfer/bankmsg"
	"github.com/vgonkivs/edicta/examples/tia-transfer/pricefeed"
	"github.com/vgonkivs/edicta/examples/tia-transfer/pricetrigger"
	"github.com/vgonkivs/edicta/examples/tia-transfer/transfer"
	"github.com/vgonkivs/edicta/sdk"
	"github.com/vgonkivs/edicta/sdk/blob"
)

// runEnv is what the process hands to a run.
type runEnv struct {
	Out   io.Writer // evidence
	Log   io.Writer // progress
	Stdin *os.File
	// Feed replaces the price source. Only the integration test sets it; the
	// command never does.
	Feed pricefeed.Feed
	// Collected receives each verified decision's evidence.
	Collected func(*Evidence)
}

func (e runEnv) logf(format string, a ...any) {
	if e.Log == nil {
		return
	}
	fmt.Fprintf(e.Log, "edicta-live: "+format+"\n", a...)
}

// ErrNoDecision means the run ended before the price moved enough.
var ErrNoDecision = errors.New("no decision was made")

// live runs the demo. It returns an error on any failure, after printing the
// evidence of every decision that completed.
func live(ctx context.Context, cfg Config, env runEnv) (err error) {
	ctx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()
	logf := env.logf

	// secrets
	agentKey, err := readSeed(cfg.AgentKeyFile, "agent")
	if err != nil {
		return err
	}
	var execSign ed25519.PrivateKey
	if cfg.ExecEd25519File != "" {
		if execSign, err = readSeed(cfg.ExecEd25519File, "executor"); err != nil {
			return err
		}
	}
	pass, err := passphrase(cfg, env.Stdin, env.Log)
	if err != nil {
		return err
	}
	defer pass.Zero()
	apiTok, err := readToken(cfg.APITokenFile)
	if err != nil {
		return fmt.Errorf("api token: %w", err)
	}
	recTok := apiTok
	if cfg.RecordTokenFile != "" {
		if recTok, err = readToken(cfg.RecordTokenFile); err != nil {
			return fmt.Errorf("record token: %w", err)
		}
	}
	bridgeTok, err := readToken(cfg.BridgeTokenFile)
	if err != nil {
		return fmt.Errorf("bridge token: %w", err)
	}
	grpcTok, err := readToken(cfg.GRPCTokenFile)
	if err != nil {
		return fmt.Errorf("consensus token: %w", err)
	}

	recipients := make([]blob.Recipient, 0, len(cfg.Recipients)+1)
	for _, r := range cfg.Recipients {
		rc, err := parseRecipient(r)
		if err != nil {
			return cfgErr("--recipient: %v", err)
		}
		recipients = append(recipients, rc)
	}
	if cfg.GenRecipient != "" {
		rc, err := genRecipient(cfg.GenRecipient)
		if err != nil {
			return err
		}
		logf("created recipient key file %s (keep it: it opens the published payload); kid=%s", cfg.GenRecipient, rc.KID)
		recipients = append(recipients, rc)
	}

	// chain access
	rc, rd, err := node.NewReadOnly(ctx, node.BridgeConfig{Addr: cfg.BridgeAddr, Token: bridgeTok, TLS: cfg.BridgeTLS})
	if err != nil {
		return fmt.Errorf("bridge node: %w", err)
	}
	defer func() { _ = rc.Close() }()
	cons, err := node.NewConsensus(node.GRPCConfig{
		Addr: cfg.GRPCAddr, TLS: cfg.GRPCTLS, Token: grpcTok, AllowInsecureToken: loopbackAddr(cfg.GRPCAddr),
	})
	if err != nil {
		return fmt.Errorf("consensus node: %w", err)
	}
	defer func() { _ = cons.Close() }()

	head, err := node.Check(ctx, rd, cons, node.Expect{
		ChainID: cfg.ChainID, MinAppVersion: cfg.MinAppVersion, MaxAppVersion: cfg.MaxAppVersion,
	})
	if err != nil {
		return fmt.Errorf("compatibility check: %w", err)
	}
	logf("chain %s, app version %d, head %d", head.ChainID, head.AppVersion, head.Height)

	// edictad
	probe, err := edictaapi.NewClient(cfg.APIURL, edictaapi.NewSecret(apiTok), nil, nil)
	if err != nil {
		return err
	}
	hl, err := probe.Health(ctx)
	if err != nil {
		return fmt.Errorf("edictad health: %w", err)
	}
	pins, err := checkHealth(cfg, hl, head.ChainID)
	if err != nil {
		return err
	}
	if !pins.keyPinned {
		logf("WARNING: gate public key learned from edictad, not pinned; pass --gate-pubkey")
	}
	pub, err := edictaapi.NewClient(cfg.APIURL, edictaapi.NewSecret(apiTok), newPublishSigner(cfg.AgentID, agentKey), nil,
		edictaapi.WithGateID(hl.GateID), edictaapi.WithRetry(3, nil))
	if err != nil {
		return err
	}
	recClient, err := edictaapi.NewClient(cfg.APIURL, edictaapi.NewSecret(recTok), nil, nil)
	if err != nil {
		return err
	}

	// executor rail, with its own chain key
	rail, err := railtx.New(railtx.Config{
		Consensus: cons, Reader: rd,
		Key:      railtx.KeyFromKeyring(cfg.ExecKeyringDir, cfg.ExecKeyName, pass),
		GasLimit: cfg.GasLimit, Fee: cfg.Fee,
	})
	if err != nil {
		return fmt.Errorf("executor key: %w", err)
	}
	pass.Zero()
	dom, err := rail.Domain(ctx)
	if err != nil {
		return fmt.Errorf("executor domain: %w", err)
	}
	if dom.ChainID != head.ChainID {
		return fmt.Errorf("consensus node chain %q differs from bridge node chain %q", dom.ChainID, head.ChainID)
	}
	if err := checkAccounts(dom, hl.RecorderSigner); err != nil {
		return err
	}
	logf("executor account %s (denom %s)", dom.Sender, dom.Denom)

	// inclusion verifier
	verifier, trust, level, closeVerifier, err := buildVerifier(ctx, cfg, head.ChainID, rd)
	if err != nil {
		return err
	}
	defer closeVerifier()
	logf("inclusion check: %s", level)

	scfg := sdk.DefaultConfig()
	scfg.AgentID = cfg.AgentID
	scfg.Scope = commitment.Scope{GateID: hl.GateID}
	scfg.Recipients = recipients
	scfg.SkewS = cfg.SkewS
	scfg.SubmitterTrust = trust
	scfg.ExpectNamespace = hl.Namespace
	scfg.ExpectSigners = [][]byte{hl.RecorderSigner}
	if cfg.PublishWait > 0 {
		scfg.MaxPublishWait = cfg.PublishWait
	}
	signer, err := sdk.NewEd25519Signer(agentKey)
	if err != nil {
		return fmt.Errorf("agent key: %w", err)
	}
	builder, err := sdk.New(scfg, sdk.Deps{Publisher: pub, Signer: signer, Clock: wallClock{}, Inclusion: verifier})
	if err != nil {
		return err
	}

	store := transfer.NewMemStore()
	exec, err := transfer.NewExecutor(transfer.Config{
		GatePubKey: ed25519.PublicKey(pins.gateKey), GateID: hl.GateID, SkewS: cfg.SkewS,
		MaxAmount: max(cfg.UpAmount, cfg.DownAmount), MaxFee: cfg.MaxFee,
		Destinations: []string{cfg.UpAddr, cfg.DownAddr}, RebroadcastEvery: cfg.Rebroadcast,
		SignKey: execSign,
	}, dom, rail, store, wallClock{})
	if err != nil {
		return fmt.Errorf("executor: %w", err)
	}

	act := &actor{
		cfg: cfg, log: logf, out: env.Out, collected: env.Collected,
		builder: builder, api: pub, rec: recClient, exec: exec, store: store, rail: rail, dom: dom,
		gateID: hl.GateID, gateKey: pins.gateKey, keyPinned: pins.keyPinned, level: level,
		execPub: execPubKey(execSign), recorderSigner: hl.RecorderSigner,
	}

	feed := env.Feed
	if feed == nil {
		if feed, err = newFeed(cfg); err != nil {
			return err
		}
	}
	ag, err := agent.New(agent.Config{
		StrategyID: cfg.StrategyID, ChainID: dom.ChainID, HRP: dom.HRP, Sender: dom.Sender,
		Up:          pricetrigger.Branch{Name: "up", ToAddress: cfg.UpAddr, Amount: cfg.UpAmount, Denom: dom.Denom},
		Down:        pricetrigger.Branch{Name: "down", ToAddress: cfg.DownAddr, Amount: cfg.DownAmount, Denom: dom.Denom},
		ThresholdBP: cfg.ThresholdBP, Reason: cfg.Reason,
	}, loggingFeed{inner: feed, logf: logf}, act, wallClock{})
	if err != nil {
		return fmt.Errorf("agent: %w", err)
	}
	return loop(ctx, cfg, ag, logf)
}

// loop polls until MaxDecisions decisions completed, a decision failed, or
// the time ran out.
func loop(ctx context.Context, cfg Config, ag *agent.Agent, logf func(string, ...any)) error {
	logf("watching %s %s every %s; threshold %d bp; stop after %d decision(s); dry-run=%t",
		cfg.PriceAsset, cfg.PriceQuote, cfg.PollInterval, cfg.ThresholdBP, cfg.MaxDecisions, cfg.DryRun)
	done, feedFails := 0, 0
	for done < cfg.MaxDecisions {
		acted, err := ag.Step(ctx)
		var fatal *decisionError
		switch {
		case errors.As(err, &fatal):
			return fatal.err
		case err != nil && ctx.Err() != nil:
			return fmt.Errorf("%w: %w", ErrNoDecision, ctx.Err())
		case err != nil:
			feedFails++
			if feedFails >= 5 {
				return fmt.Errorf("price feed failed %d times in a row: %w", feedFails, err)
			}
		default:
			feedFails = 0
		}
		if acted {
			done++
			continue
		}
		if done >= cfg.MaxDecisions {
			break
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("%w: ran out of time (%s) before the price moved %d bp from the baseline; lower --threshold-bp or raise --timeout: %w",
				ErrNoDecision, cfg.Timeout, cfg.ThresholdBP, ctx.Err())
		case <-time.After(cfg.PollInterval):
		}
	}
	return nil
}

func execPubKey(k ed25519.PrivateKey) []byte {
	if k == nil {
		return nil
	}
	return bytes.Clone(k.Public().(ed25519.PublicKey))
}

type wallClock struct{}

func (wallClock) Now() time.Time                         { return time.Now() }
func (wallClock) After(d time.Duration) <-chan time.Time { return time.After(d) }

// gatePins is what the run trusts about the gate.
type gatePins struct {
	gateKey   []byte
	keyPinned bool
}

// checkHealth cross-checks edictad's health answer against the chain and the
// pins. The answer is information: a pin always wins.
func checkHealth(cfg Config, h edictaapi.HealthInfo, chainID string) (gatePins, error) {
	switch {
	case h.Status != 1:
		return gatePins{}, fmt.Errorf("edictad reports status %d, not ok", h.Status)
	case h.ChainID != chainID:
		return gatePins{}, fmt.Errorf("edictad is on chain %q, the node is on %q", h.ChainID, chainID)
	case len(h.RecorderSigner) != 20 || len(h.Namespace) != 29:
		return gatePins{}, errors.New("edictad has no Recorder enabled; it cannot publish")
	}
	want := uint64(commitment.DACelestiaBlob)
	if cfg.DA == "fibre" {
		want = uint64(commitment.DAFibre)
	}
	if len(h.AllowedDA) != 1 || h.AllowedDA[0] != want {
		return gatePins{}, fmt.Errorf("edictad runs data availability %v, this run is configured for %q", h.AllowedDA, cfg.DA)
	}
	p := gatePins{gateKey: bytes.Clone(h.GatePubKey)}
	if cfg.GateID != "" && cfg.GateID != h.GateID {
		return gatePins{}, fmt.Errorf("edictad gate id %q is not the pinned %q", h.GateID, cfg.GateID)
	}
	if cfg.GatePubKey != "" {
		want, _ := hex.DecodeString(cfg.GatePubKey)
		if !bytes.Equal(want, h.GatePubKey) {
			return gatePins{}, errors.New("edictad gate public key is not the pinned --gate-pubkey")
		}
		p.gateKey, p.keyPinned = want, true
	}
	if cfg.Namespace != "" && cfg.Namespace != hex.EncodeToString(h.Namespace) {
		return gatePins{}, errors.New("edictad namespace is not the pinned --namespace")
	}
	return p, nil
}

// checkAccounts refuses an executor that is the Recorder's account: the two
// roles use two chain accounts.
func checkAccounts(dom transfer.Domain, recorderSigner []byte) error {
	raw, err := bankmsg.DecodeAddress(dom.HRP, dom.Sender)
	if err != nil {
		return fmt.Errorf("executor address: %w", err)
	}
	if bytes.Equal(raw, recorderSigner) {
		return errors.New("the executor key is the Recorder's key; use two different chain accounts")
	}
	return nil
}

// buildVerifier returns the inclusion verifier, the trust level it allows and
// a description of its strength.
func buildVerifier(ctx context.Context, cfg Config, chainID string, rd node.Reader) (v sdk.InclusionVerifier, trust sdk.SubmitterTrust, level string, closeFn func(), err error) {
	closeFn = func() {}
	switch cfg.Inclusion {
	case "self":
		sv, err := inclusion.NewSelfCheck(inclusion.SelfCheckConfig{ChainID: chainID, Node: rd})
		if err != nil {
			return nil, 0, "", closeFn, err
		}
		return sv, sdk.SubmitterSameOperator, inclusion.LevelSelfCheck.String(), closeFn, nil
	case "light":
		mk := func(u string) (provider.Provider, error) {
			if !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
				return nil, cfgErr("RPC providers must be http or https URLs")
			}
			return lighthttp.New(chainID, u)
		}
		primary, err := mk(cfg.RPCPrimary)
		if err != nil {
			return nil, 0, "", closeFn, fmt.Errorf("primary provider: %w", err)
		}
		var wit []provider.Provider
		for _, w := range cfg.RPCWitnesses {
			p, err := mk(w)
			if err != nil {
				return nil, 0, "", closeFn, fmt.Errorf("witness provider: %w", err)
			}
			wit = append(wit, p)
		}
		hash, _ := hex.DecodeString(cfg.TrustHash)
		lv, err := inclusion.NewLight(ctx, inclusion.LightConfig{
			ChainID: chainID,
			Trust:   light.TrustOptions{Period: cfg.TrustPeriod, Height: int64(cfg.TrustHeight), Hash: hash},
			Primary: primary, Witnesses: wit, Proofs: rd,
		})
		if err != nil {
			return nil, 0, "", closeFn, fmt.Errorf("light client: %w", err)
		}
		return lv, sdk.SubmitterUntrusted, inclusion.LevelLight.String(), closeFn, nil
	default:
		tok, err := readToken(cfg.CrossTokenFile)
		if err != nil {
			return nil, 0, "", closeFn, fmt.Errorf("crosscheck token: %w", err)
		}
		var srcs []inclusion.Source
		for _, a := range cfg.CrossBridges {
			c, r, err := node.NewReadOnly(ctx, node.BridgeConfig{Addr: a, Token: tok, TLS: cfg.CrossTLS})
			if err != nil {
				return nil, 0, "", closeFn, fmt.Errorf("crosscheck bridge %s: %w", a, err)
			}
			prev := closeFn
			closeFn = func() { prev(); _ = c.Close() }
			srcs = append(srcs, inclusion.Source{Name: a, Headers: r})
		}
		cv, err := inclusion.NewCrossCheck(inclusion.CrossCheckConfig{ChainID: chainID, Sources: srcs, Proofs: rd})
		if err != nil {
			return nil, 0, "", closeFn, err
		}
		return cv, sdk.SubmitterUntrusted, inclusion.LevelCrossCheck.String(), closeFn, nil
	}
}
