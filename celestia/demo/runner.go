// Package demo runs the Edicta demo: one process, one gate, one agent, one
// executor and an independent verification, on a public test network.
package demo

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"path/filepath"
	"time"

	"github.com/vgonkivs/edicta/celestia/edictad"
	"github.com/vgonkivs/edicta/celestia/railtx"
	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/edictaapi"
	"github.com/vgonkivs/edicta/examples/tia-transfer/pricefeed"
	"github.com/vgonkivs/edicta/examples/tia-transfer/transfer"
	"github.com/vgonkivs/edicta/sdk"
)

// GateHandle is a running gate.
type GateHandle interface {
	Addr() string
	Shutdown(ctx context.Context) error
}

// Gate starts edictad. The real one runs it in this process.
type Gate interface {
	Start(ctx context.Context, cfg edictad.Config, d edictad.Deps) (GateHandle, error)
}

// Deps are the Runner's seams. Nil factories mean the real clients.
type Deps struct {
	Chain     Chain
	Console   Console
	Screen    Screen
	Gate      Gate
	TrustRoot TrustRoot // nil: the preset's trust-root service
	// The Runner wraps what the factories return with the Consent; only
	// NewFunder receives it, because railtx requires it.
	NewFunder   func(ctx context.Context, cfg railtx.FunderConfig) (Funding, Abandoner, error)
	NewGateDeps func(ctx context.Context, cfg edictad.Config) (edictad.Deps, func(), error)
	NewRail     func(ctx context.Context, key railtx.KeySource) (transfer.Rail, error)
	NewFeed     func() (pricefeed.Feed, error)
	Verify      func(ctx context.Context, args []string, out io.Writer) int
	Now         func() time.Time
	Sleep       func(ctx context.Context, d time.Duration) error
	HTTP        *http.Client
}

func (d Deps) now() time.Time {
	if d.Now != nil {
		return d.Now()
	}
	return time.Now()
}

func (d Deps) sleep(ctx context.Context, dur time.Duration) error {
	if d.Sleep != nil {
		return d.Sleep(ctx, dur)
	}
	t := time.NewTimer(dur)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// Runner runs the demo once.
type Runner struct {
	cfg     Config
	preset  Preset
	deps    Deps
	consent *railtx.Consent
	explore Explorer
	out     Outcome

	dirs   homeDirs
	runDir string
	start  time.Time

	funder, recorderKey, executorKey chainKey
	funding                          Funding
	abandoner                        Abandoner
	loop                             *fundingLoop
	// budget replaces the demo's budget when a scene funds other accounts.
	budget func(ctx context.Context) (Budget, error)

	keys        runKeys
	edCfg       edictad.Config
	gateDeps    edictad.Deps
	gate        GateHandle
	gateStarted time.Time
	archive     *archiveServer

	pubClient, authClient, recClient *edictaapi.Client
	gatePub                          ed25519.PublicKey
	gateID                           string
	recSigner, namespace             []byte
	builder                          *sdk.Builder
	exec                             *transfer.Executor
	rail                             *GuardedRail
	rawRail                          transfer.Rail
	dom                              transfer.Domain
	feed                             pricefeed.Feed
	minGas                           *big.Rat
	signer                           *sdk.Ed25519Signer
	store                            *transfer.MemStore

	mandateText string
	// mandateHash is what the agent's v1 commitments name as mandate_ref.
	mandateHash       commitment.Hash
	principalHex      string // public key
	presetBase        Preset
	closeGateDeps     func()
	releaseHome       func()
	root              TrustRootInfo
	haveRoot          bool
	step5Inconclusive bool
}

// New validates cfg and the preset and returns a Runner. It does no I/O.
func New(cfg Config, d Deps) (*Runner, error) {
	r, err := newRunner(cfg, d, nil)
	if err != nil {
		return nil, err
	}
	if d.NewRail == nil || d.NewFeed == nil {
		return nil, fmt.Errorf("%w: factories are required", ErrConfig)
	}
	return r, nil
}

// newRunner is New without the agent's rail and price feed; adjust, when
// set, changes the preset before it is validated.
func newRunner(cfg Config, d Deps, adjust func(*Preset)) (*Runner, error) {
	cfg = cfg.WithDefaults()
	if err := cfg.ValidateBasic(); err != nil {
		return nil, coded(ExitUsage, err)
	}
	p, err := LoadPreset(cfg.Network)
	if err != nil {
		return nil, coded(ExitUsage, err)
	}
	p = p.Apply(cfg.Overrides)
	base := p
	if cfg.MaxTotalFunding > 0 {
		p.Funding.MaxTotalAmount = cfg.MaxTotalFunding
	}
	if adjust != nil {
		adjust(&p)
	}
	if err := p.ValidateBasic(); err != nil {
		return nil, coded(ExitUsage, err)
	}
	if err := p.CheckTrustRootHost(); err != nil {
		return nil, coded(ExitUsage, err)
	}
	switch {
	case d.Console == nil || d.Screen == nil || d.Chain == nil || d.Gate == nil:
		return nil, fmt.Errorf("%w: console, screen, chain and gate are required", ErrConfig)
	case d.NewFunder == nil || d.NewGateDeps == nil || d.Verify == nil:
		return nil, fmt.Errorf("%w: factories are required", ErrConfig)
	}
	if d.TrustRoot == nil {
		tr, err := NewCeleniumTrustRoot(p.Verify.TrustRootAPI, p.Verify.TrustRootPage, p.Verify.TrustRootName, d.HTTP)
		if err != nil {
			return nil, coded(ExitUsage, err)
		}
		d.TrustRoot = tr
	}
	return &Runner{cfg: cfg, preset: p, deps: d, consent: &railtx.Consent{}, explore: newExplorer(p), presetBase: base}, nil
}

// Run does the demo. Out.Code is always set; the error says why a run
// stopped early.
func (r *Runner) Run(ctx context.Context) (Outcome, error) {
	err := r.run(ctx)
	r.out.Code = r.exitCode(ctx, err)
	switch {
	case ctx.Err() != nil && r.out.Code == ExitInterrupted:
		r.reportInterrupt()
	case err != nil:
		r.deps.Screen.Fail("stopped", err)
	default:
		r.deps.Screen.Info(fmt.Sprintf("Done in %s. Evidence: %s", r.deps.now().Sub(r.start).Round(time.Second), filepath.Join(r.runDir, "evidence.json")))
		r.deps.Screen.Info(fmt.Sprintf("Verify it offline: edicta verify %x --archive %s ... (see verify-step5.json for the full command)", r.out.CommitmentHash, filepath.Join(r.runDir, "archive")))
	}
	r.saveEvidence()
	return r.out, err
}

func (r *Runner) exitCode(ctx context.Context, err error) int {
	var ce *codedError
	switch {
	case ctx.Err() != nil && (err == nil || errors.Is(err, context.Canceled) || errors.Is(err, ctx.Err())):
		return ExitInterrupted
	case errors.As(err, &ce):
		return ce.code
	case err != nil:
		return ExitInconclusive
	}
	return r.out.Code
}

func (r *Runner) reportInterrupt() {
	for _, s := range r.out.Funding {
		r.deps.Screen.Info(fmt.Sprintf("funding send %s to %s, %d utia, includable until height %d", s.Hash, s.To, s.Amount, s.TimeoutHeight))
	}
	if r.out.TxHash != "" {
		r.deps.Screen.Info(fmt.Sprintf("transfer %s", r.out.TxHash))
	}
}

func (r *Runner) run(ctx context.Context) (err error) {
	r.start = r.deps.now()
	defer r.cleanup()
	sc := r.deps.Screen

	sc.Step(1, 7, "Environment")
	if err := r.prepare(ctx); err != nil {
		return err
	}
	if err := r.startGate(ctx); err != nil {
		return err
	}
	if err := r.fundAndStart(ctx); err != nil {
		return err
	}
	sc.Step(2, 7, "Mandate")
	sc.Mandate(r.mandateText)
	sc.Step(3, 7, "Agent decision")
	d, err := r.decide(ctx)
	if err != nil {
		return err
	}
	sc.Step(4, 7, "Publish and anchor")
	if err := r.publish(ctx, d); err != nil {
		return err
	}
	sc.Step(5, 7, "Authorize and execute")
	if err := r.authorizeAndExecute(ctx, d); err != nil {
		return err
	}
	sc.Step(6, 7, "Independent verification")
	if err := r.verifyStep(ctx, d); err != nil {
		return err
	}
	sc.Step(7, 7, "Cheating attempts")
	return r.attempts(ctx, d)
}

func (r *Runner) cleanup() {
	if r.gate != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		_ = r.gate.Shutdown(ctx)
		cancel()
	}
	if r.archive != nil {
		r.archive.Close()
	}
	if r.closeGateDeps != nil {
		r.closeGateDeps()
	}
	if r.funding != nil {
		_ = r.funding.Close()
	}
	if r.releaseHome != nil {
		r.releaseHome()
	}
	r.keys.zero()
	for _, k := range []chainKey{r.funder, r.recorderKey, r.executorKey} {
		k.pass.Zero()
	}
}

// archiveServer serves a read-only archive on a loopback port.
type archiveServer struct {
	url  string
	srv  *http.Server
	done chan struct{}
}

func serveArchive(h http.Handler) (*archiveServer, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("demo: archive listener: %w", err)
	}
	s := &archiveServer{url: "http://" + ln.Addr().String(), srv: &http.Server{Handler: h, ReadHeaderTimeout: 10 * time.Second}, done: make(chan struct{})}
	go func() { _ = s.srv.Serve(ln); close(s.done) }()
	return s, nil
}

func (a *archiveServer) Close() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if a.srv.Shutdown(ctx) != nil {
		_ = a.srv.Close()
	}
	<-a.done
}

func (r *Runner) saveEvidence() {
	if r.runDir == "" {
		return
	}
	_ = writeEvidence(filepath.Join(r.runDir, "evidence.json"), r.out)
}
