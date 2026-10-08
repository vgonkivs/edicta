package demo

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/pelletier/go-toml/v2"

	"github.com/vgonkivs/edicta/celestia/edictad"
	"github.com/vgonkivs/edicta/celestia/railtx"
	"github.com/vgonkivs/edicta/celestia/secret"
	"github.com/vgonkivs/edicta/edictaapi"
	"github.com/vgonkivs/edicta/examples/tia-transfer/bankaction"
	"github.com/vgonkivs/edicta/sdk/blob"
)

const (
	agentID      = "demo-agent"
	recorderName = "recorder"
	executorName = "executor"
	funderName   = "funder"
	skewS        = 30
)

// demoNamespace is a version-0 namespace: 18 zero bytes of id prefix and ten
// bytes of the demo's name.
var demoNamespace = func() string {
	ns := make([]byte, 29)
	copy(ns[19:], "edictademo")
	return hex.EncodeToString(ns)
}()

// runKeys are the per-run keys of the agent, the gate and the executor.
type runKeys struct {
	agent, gate, exec ed25519.PrivateKey
	// principal signs the mandate. It is used once and never printed.
	principal        ed25519.PrivateKey
	recipient        blob.Recipient
	apiToken, recTok string
}

func (k *runKeys) zero() {
	clear(k.agent)
	clear(k.gate)
	clear(k.exec)
	clear(k.principal)
}

func (r *Runner) newRunKeys() error {
	seed := func(name string) (ed25519.PrivateKey, error) {
		s, err := randBytes(ed25519.SeedSize)
		if err != nil {
			return nil, err
		}
		defer clear(s)
		if err := writeNew(filepath.Join(r.runDir, name), s); err != nil {
			return nil, fmt.Errorf("demo: %s: %w", name, err)
		}
		return ed25519.NewKeyFromSeed(s), nil
	}
	var err error
	k := &r.keys
	if k.agent, err = seed("agent.ed25519"); err != nil {
		return err
	}
	if k.gate, err = seed("gate.ed25519"); err != nil {
		return err
	}
	if k.exec, err = seed("executor.ed25519"); err != nil {
		return err
	}
	if k.principal, err = seed(principalFile); err != nil {
		return err
	}
	rk, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("demo: recipient key: %w", err)
	}
	if err := writeNew(filepath.Join(r.runDir, "recipient.x25519"), []byte(hex.EncodeToString(rk.Bytes())+"\n")); err != nil {
		return fmt.Errorf("demo: recipient key: %w", err)
	}
	k.recipient = blob.Recipient{KID: []byte("edicta-demo-1"), PublicKey: rk.PublicKey()}
	tok := func(name string) (string, error) {
		b, err := randBytes(32)
		if err != nil {
			return "", err
		}
		s := hex.EncodeToString(b)
		return s, writeNew(filepath.Join(r.runDir, name), []byte(s+"\n"))
	}
	if k.apiToken, err = tok("api.token"); err != nil {
		return err
	}
	if k.recTok, err = tok("record.token"); err != nil {
		return err
	}
	return nil
}

// prepare is steps 0a to 0c: no broadcast, nothing needs the user's Enter.
func (r *Runner) prepare(ctx context.Context) error {
	sc := r.deps.Screen
	var err error
	if r.dirs, err = prepareHome(r.cfg.Home); err != nil {
		return coded(ExitUsage, err)
	}
	if r.releaseHome, err = lockHome(filepath.Join(r.dirs.home, "lock")); err != nil {
		return coded(ExitUsage, err)
	}
	if err := r.loadChainKeys(); err != nil {
		return err
	}
	if r.runDir, err = newRunDir(r.dirs.runs, r.deps.now()); err != nil {
		return coded(ExitUsage, err)
	}
	r.out.RunDir = r.runDir
	if err := r.newRunKeys(); err != nil {
		return coded(ExitUsage, err)
	}
	sc.Info(fmt.Sprintf("run directory %s (kept); a fresh archive, registry and keys for this run", r.runDir))

	if err := r.checkEnv(ctx); err != nil {
		return err
	}
	return r.openFunder(ctx)
}

func (r *Runner) loadChainKeys() error {
	hrp := r.preset.HRP
	var err error
	if r.cfg.Funder.Generated() {
		r.funder, err = loadOrCreateKey(filepath.Join(r.dirs.chain, funderName), funderName, hrp)
	} else {
		r.funder, err = r.userFunderKey(hrp)
	}
	if err != nil {
		return coded(ExitUsage, err)
	}
	if r.recorderKey, err = loadOrCreateKey(filepath.Join(r.dirs.chain, recorderName), recorderName, hrp); err != nil {
		return coded(ExitUsage, err)
	}
	if r.executorKey, err = loadOrCreateKey(filepath.Join(r.dirs.chain, executorName), executorName, hrp); err != nil {
		return coded(ExitUsage, err)
	}
	a, b, c := r.funder.addr, r.recorderKey.addr, r.executorKey.addr
	if a == b || a == c || b == c {
		return coded(ExitUsage, ErrSameAccount)
	}
	return nil
}

func (r *Runner) userFunderKey(hrp string) (chainKey, error) {
	f := r.cfg.Funder
	k := chainKey{dir: f.KeyringDir, name: f.KeyName}
	var err error
	if f.PassphraseFile != "" {
		k.pass, err = secret.FromFile(f.PassphraseFile)
	} else {
		k.pass, err = r.deps.Console.Passphrase("funder keyring passphrase: ")
	}
	if err != nil {
		return k, fmt.Errorf("demo: funder passphrase: %w", err)
	}
	if k.addr, err = k.source().Address(hrp); err != nil {
		return k, fmt.Errorf("demo: funder key: %w", err)
	}
	if f.Address != "" && f.Address != k.addr {
		return k, ErrFunderAddressMismatch
	}
	return k, nil
}

func (r *Runner) checkEnv(ctx context.Context) error {
	sc, ch := r.deps.Screen, r.deps.Chain
	id, err := ch.ChainID(ctx)
	if err != nil {
		return coded(ExitInconclusive, fmt.Errorf("demo: funding node: %w", err))
	}
	if id != r.preset.ChainID {
		return coded(ExitInconclusive, fmt.Errorf("demo: the funding node is on %q, expected %q", id, r.preset.ChainID))
	}
	head, t, err := ch.Head(ctx)
	if err != nil {
		return coded(ExitInconclusive, fmt.Errorf("demo: chain head: %w", err))
	}
	skew := r.deps.now().Sub(t)
	if skew < 0 {
		skew = -skew
	}
	switch {
	case skew > skewS*time.Second:
		return coded(ExitInconclusive, fmt.Errorf("%w: %s", ErrClockSkew, skew.Round(time.Second)))
	case skew > skewS*time.Second/2:
		sc.Warn(fmt.Sprintf("local clock differs from chain time by %s", skew.Round(time.Second)))
	}
	if r.minGas, err = ch.MinGasPrice(ctx); err != nil {
		return coded(ExitInconclusive, fmt.Errorf("demo: minimum gas price: %w", err))
	}
	if err := ch.TxIndex(ctx); err != nil {
		return coded(ExitInconclusive, fmt.Errorf("demo: the funding node does not index transactions: %w", err))
	}
	sc.OK(fmt.Sprintf("network %s, head %d, clock skew %s", id, head, skew.Round(time.Second)))
	if r.cfg.TrustedHeader == "" && head > 20 {
		if _, err := r.deps.TrustRoot.HeaderHash(ctx, head-10); err != nil {
			sc.Warn(fmt.Sprintf("%s is not answering (%v); the trust-root step will ask you for a header", r.deps.TrustRoot.Name(), err))
		}
	}
	return nil
}

func (r *Runner) statePath() string {
	return filepath.Join(r.dirs.funding, "state-"+r.funder.addr+".json")
}

func (r *Runner) openFunder(ctx context.Context) error {
	sc, f := r.deps.Screen, r.preset.Funding
	fc := railtx.FunderConfig{
		Key: r.funder.source(), Consent: r.consent, GasLimit: f.GasLimit, TimeoutBlocks: f.TimeoutBlocks,
		MaxFee: f.MaxFee, MaxAmount: f.MaxAmount, MaxTotalAmount: f.MaxTotalAmount, PendingPath: r.statePath(),
	}
	fu, ab, err := r.deps.NewFunder(ctx, fc)
	if err != nil {
		return coded(ExitInconclusive, fmt.Errorf("demo: funder: %w", err))
	}
	r.funding, r.abandoner = fu, ab
	if h, th, ok := fu.Pending(); ok {
		sc.Warn(fmt.Sprintf("an earlier run left funding send %s (includable until height %d); nothing new is sent until it is resolved: %s",
			hex.EncodeToString(h[:]), th, r.explore.Address(r.funder.addr)))
	}
	if fu.Address() != r.funder.addr {
		return coded(ExitUsage, fmt.Errorf("demo: the funder reports %s, the key derives %s", fu.Address(), r.funder.addr))
	}
	if r.cfg.MaxTotalFunding > 0 {
		sc.Info(fmt.Sprintf("Lifetime funding cap for %s: %d utia (preset %d, sent so far %d).",
			r.funder.addr, r.cfg.MaxTotalFunding, r.presetBase.Funding.MaxTotalAmount, readTotalSent(r.statePath())))
		if !r.cfg.YesFundingCap {
			if err := r.deps.Console.Flush(); err != nil {
				return coded(ExitUsage, err)
			}
			ans, err := r.deps.Console.WaitEnter(ctx, "Enter = accept the cap, q = quit")
			if err != nil {
				return err
			}
			if ans == AnswerQuit {
				return coded(ExitInconclusive, ErrOperatorQuit)
			}
		}
	}
	r.loop = &fundingLoop{
		f: fu, ab: ab, chain: r.deps.Chain, console: r.deps.Console, screen: sc, denom: r.preset.Denom,
		explore: r.explore, poll: r.cfg.PollEvery, timeout: r.cfg.FundTimeout, sleep: r.deps.sleep, now: r.deps.now,
	}
	return nil
}

// readTotalSent reads the persisted lifetime total of a funder state file;
// a missing or unreadable file reads as zero.
func readTotalSent(path string) uint64 {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	var v struct {
		TotalSent uint64 `json:"total_sent"`
	}
	if json.Unmarshal(b, &v) != nil {
		return 0
	}
	return v.TotalSent
}

// startGate is step 1: write the gate's files, build its dependencies with
// the Recorder's submitter behind the Consent, and start it in this process.
func (r *Runner) startGate(ctx context.Context) error {
	sc := r.deps.Screen
	if err := r.writeConfigs(); err != nil {
		return coded(ExitUsage, err)
	}
	deps, closeDeps, err := r.deps.NewGateDeps(ctx, r.edCfg)
	if err != nil {
		return coded(ExitInconclusive, fmt.Errorf("demo: gate dependencies: %w", err))
	}
	r.closeGateDeps = closeDeps
	if deps.Fibre != nil {
		return coded(ExitUsage, ErrFibreRefused)
	}
	if deps.Submitter != nil {
		deps.Submitter = GuardSubmitter(deps.Submitter, r.consent)
	}
	r.gateDeps = deps
	r.gate, err = r.deps.Gate.Start(ctx, r.edCfg, deps)
	r.gateStarted = r.deps.now()
	if err != nil {
		return coded(ExitInconclusive, fmt.Errorf("demo: starting the gate: %w", err))
	}
	base := "http://" + r.gate.Addr()
	probe, err := edictaapi.NewClient(base, edictaapi.NewSecret(""), nil, r.deps.HTTP)
	if err != nil {
		return coded(ExitUsage, err)
	}
	hl, err := probe.Health(ctx)
	if err != nil {
		return coded(ExitInconclusive, fmt.Errorf("demo: gate health: %w", err))
	}
	switch {
	case hl.Status != 1:
		return coded(ExitInconclusive, fmt.Errorf("demo: the gate reports status %d", hl.Status))
	case hl.ChainID != r.preset.ChainID:
		return coded(ExitInconclusive, fmt.Errorf("demo: the gate is on %q, expected %q", hl.ChainID, r.preset.ChainID))
	case len(hl.AllowedDA) != 1 || hl.AllowedDA[0] != 2:
		return coded(ExitUsage, fmt.Errorf("%w: gate serves %v", ErrFibreRefused, hl.AllowedDA))
	case !bytes.Equal(hl.GatePubKey, r.keys.gate.Public().(ed25519.PublicKey)):
		return coded(ExitWrong, errors.New("demo: the gate answers with a key that is not this run's gate key"))
	case len(hl.RecorderSigner) != 20 || len(hl.Namespace) != 29:
		return coded(ExitInconclusive, errors.New("demo: the gate has no Recorder"))
	}
	r.gateID, r.gatePub = hl.GateID, ed25519.PublicKey(bytes.Clone(hl.GatePubKey))
	r.recSigner, r.namespace = hl.RecorderSigner, hl.Namespace
	mk := func(tok string, signer edictaapi.PublishSigner, opts ...edictaapi.ClientOption) (*edictaapi.Client, error) {
		return edictaapi.NewClient(base, edictaapi.NewSecret(tok), signer, r.deps.HTTP, opts...)
	}
	if r.pubClient, err = mk("", &publishSigner{id: agentID, key: r.keys.agent}, edictaapi.WithGateID(r.gateID), edictaapi.WithRetry(3, nil)); err != nil {
		return coded(ExitUsage, err)
	}
	if r.authClient, err = mk(r.keys.apiToken, nil, edictaapi.WithRetry(3, nil)); err != nil {
		return coded(ExitUsage, err)
	}
	if r.recClient, err = mk(r.keys.recTok, nil, edictaapi.WithRetry(3, nil)); err != nil {
		return coded(ExitUsage, err)
	}
	sc.OK(fmt.Sprintf("Gate started, network %s (gate id %s, key %s)", hl.ChainID, hl.GateID, hex.EncodeToString(hl.GatePubKey)[:8]))
	sc.Info(fmt.Sprintf("Fresh archive for this run: %s", r.edCfg.Archive.Dir))
	return nil
}

func (r *Runner) writeConfigs() error {
	agents := struct {
		Agents []map[string]string `toml:"agents"`
	}{Agents: []map[string]string{{"agent_id": agentID, "pubkey": hex.EncodeToString(r.keys.agent.Public().(ed25519.PublicKey))}}}
	ab, err := toml.Marshal(agents)
	if err != nil {
		return err
	}
	agentsPath := filepath.Join(r.runDir, "agents.toml")
	if err := writeNew(agentsPath, ab); err != nil {
		return err
	}
	gateID := "demo-" + filepath.Base(r.runDir)
	archiveDir := filepath.Join(r.runDir, "archive")
	if err := os.Mkdir(archiveDir, 0o700); err != nil {
		return err
	}
	mandatePath, err := r.writeMandate(gateID)
	if err != nil {
		return err
	}
	cfg := edictad.Config{
		Network: edictad.NetworkConfig{
			ChainID: r.preset.ChainID, DA: edictad.DAConfigBlob,
			Bridge:        edictad.EndpointConfig{Addr: r.preset.Bridge.Addr, TLS: r.preset.Bridge.TLS},
			ConsensusGRPC: edictad.EndpointConfig{Addr: r.preset.GRPC.Addr, TLS: r.preset.GRPC.TLS},
		},
		Archive: edictad.ArchiveConfig{Dir: archiveDir},
		Policy:  edictad.PolicyConfig{MandateFile: mandatePath},
		Recorder: edictad.RecorderConfig{
			Enabled: true, Namespace: demoNamespace,
			KeyringDir: r.recorderKey.dir, KeyringBackend: "file", KeyName: recorderName,
			PassphraseFile: filepath.Join(r.recorderKey.dir, recorderName+".pass"),
			Quota:          edictad.QuotaConfig{BlobsPerHour: 60, BytesPerDay: 64 << 20},
		},
		Gate: edictad.GateConfig{
			GateID: gateID, KeyFile: filepath.Join(r.runDir, "gate.ed25519"),
			RegistryPath: filepath.Join(r.runDir, "registry.db"), ActionTypes: []string{bankaction.ActionType},
			AllowlistFile: agentsPath, ExecutorKeys: []string{hex.EncodeToString(r.keys.exec.Public().(ed25519.PublicKey))},
			AnchorVerifier: "self",
		},
		HTTP: edictad.HTTPConfig{
			Listen:             "127.0.0.1:0",
			AuthorizeTokenFile: filepath.Join(r.runDir, "api.token"), RecordTokenFile: filepath.Join(r.runDir, "record.token"),
		},
	}
	raw, err := toml.Marshal(cfg)
	if err != nil {
		return err
	}
	if err := writeNew(filepath.Join(r.runDir, "edictad.toml"), raw); err != nil {
		return err
	}
	if r.edCfg, err = edictad.ParseConfig(raw); err != nil {
		return err
	}
	return nil
}

// fundAndStart shows the budget, waits for the one Enter that starts the run,
// arms the Consent and moves the funds.
func (r *Runner) fundAndStart(ctx context.Context) error {
	sc, l, f := r.deps.Screen, r.loop, r.preset.Funding
	if err := l.settle(ctx); err != nil {
		return err
	}
	bal := func(addr string) (uint64, error) {
		v, _, err := r.deps.Chain.BalanceAt(ctx, addr, r.preset.Denom, l.seen)
		if err != nil {
			return 0, coded(ExitInconclusive, fmt.Errorf("demo: balance of %s: %w", addr, err))
		}
		return v, nil
	}
	var have Balances
	var err error
	if have.Funder, err = bal(r.funder.addr); err != nil {
		return err
	}
	if have.Recorder, err = bal(r.recorderKey.addr); err != nil {
		return err
	}
	if have.Executor, err = bal(r.executorKey.addr); err != nil {
		return err
	}
	b, err := ComputeBudget(BudgetParams{
		MinGasPrice: r.minGas, SendGas: f.GasLimit, PFBGas: f.PFBGas, Amount: r.cfg.AmountUTIA, MaxAmount: f.MaxAmount,
	}, have)
	if err != nil {
		return coded(ExitUsage, err)
	}
	sc.Info(fmt.Sprintf("Funding node %s is trusted; at most %d utia per send, %d in total from this funder.", r.preset.GRPC.Addr, f.MaxAmount, f.MaxTotalAmount))
	var prompt string
	switch {
	case b.Total == 0:
		sc.Info("[funding] nothing to move: the demo accounts already hold enough")
		prompt = "Press Enter to start."
	case have.Funder >= b.Total:
		sc.Info(fmt.Sprintf("[funding] will move %d utia from %s (recorder %d, executor %d, fees %d)", b.Total, r.funder.addr, b.Recorder, b.Executor, b.FunderFees))
		prompt = fmt.Sprintf("Press Enter to move %d utia and start.", b.Total)
	default:
		sc.Info(fmt.Sprintf("[funding] will move %d utia from %s (recorder %d, executor %d, fees %d)", b.Total, r.funder.addr, b.Recorder, b.Executor, b.FunderFees))
		sc.Info(fmt.Sprintf("The funder holds %d. Fund %s (%s)", have.Funder, r.funder.addr, r.preset.FaucetHint))
		prompt = fmt.Sprintf("Will move %d utia from %s. Fund it, then press Enter to start.", b.Total, r.funder.addr)
	}
	if err := r.deps.Console.Flush(); err != nil {
		return coded(ExitUsage, err)
	}
	ans, err := r.deps.Console.WaitEnter(ctx, prompt)
	if err != nil {
		return err
	}
	if ans == AnswerQuit {
		return coded(ExitInconclusive, ErrOperatorQuit)
	}
	r.consent.Arm()
	if b.Total == 0 {
		return nil
	}
	if err := l.waitFor(ctx, r.funder.addr, b.Total); err != nil {
		return err
	}
	if b.Recorder > 0 {
		if err := l.ensure(ctx, "recorder", r.recorderKey.addr, b.WantRecorder); err != nil {
			return err
		}
	}
	if b.Executor > 0 {
		if err := l.ensure(ctx, "executor", r.executorKey.addr, b.WantExecutor); err != nil {
			return err
		}
	}
	r.out.Funding = l.sends
	sc.OK(fmt.Sprintf("accounts funded (%d send(s))", len(l.sends)))
	return nil
}
