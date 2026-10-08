package edictad

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/archive/fsarchive"
	"github.com/vgonkivs/edicta/celestia/gatechain"
	"github.com/vgonkivs/edicta/celestia/heightcheck"
	"github.com/vgonkivs/edicta/celestia/node"
	"github.com/vgonkivs/edicta/celestia/recorder"
	"github.com/vgonkivs/edicta/celestia/secret"
	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/edictaapi"
	"github.com/vgonkivs/edicta/fibre/fibrecommit"
	"github.com/vgonkivs/edicta/gate"
	"github.com/vgonkivs/edicta/gate/dacommit/blobv1"
	"github.com/vgonkivs/edicta/gate/registry/boltreg"
	"github.com/vgonkivs/edicta/policy"
	"github.com/vgonkivs/edicta/retention"
	"github.com/vgonkivs/edicta/sdk"
)

// ErrDANotSupported means the configured data availability mode is not
// implemented yet.
var ErrDANotSupported = errors.New("edictad: data availability mode not supported yet")

// Deps are the daemon's external systems.
type Deps struct {
	Reader    node.Reader
	Consensus node.Consensus
	// Submitter pays for the Recorder's blobs. It is required when the
	// Recorder is enabled and never touched otherwise.
	Submitter recorder.Submitter
	// Fibre is required with da = "fibre" and ignored otherwise.
	Fibre *FibreDeps
	// Archive is where decisions, Authorizations and refusals are kept; nil
	// opens the filesystem archive of the configured directory.
	Archive archive.Store
	Clock   gate.Clock   // nil means the system clock
	Logger  *slog.Logger // nil means slog.Default()
	// Listen opens the API listener; nil means net.Listen.
	Listen func(network, addr string) (net.Listener, error)
	// WrapGate lets a test stand in for the gate behind the API; nil keeps it.
	WrapGate func(edictaapi.Gate) edictaapi.Gate
	// SweepTick paces the background archive sweep; nil means a ticker of
	// archive.sweep_interval_s. A test sends the ticks.
	SweepTick <-chan time.Time
}

// FibreDeps are the da = 1 dependencies.
type FibreDeps struct {
	// Chain reads the consensus endpoint: headers, result codes and validator
	// sets of an anchor.
	Chain node.FibreChainReader
	// Bridge serves the data availability header and the namespace data of the
	// anchor proof. A bridge that reports its limits must report the ones the
	// configuration asks for.
	Bridge node.FibreBridgeReader
	// Direct downloads blobs from the storage providers.
	Direct node.FibreDownloader
	// Fallback downloads through a bridge. It is used only if the configuration
	// asks for it and BridgeCompat passes.
	Fallback node.FibreDownloader
	// BridgeCompat is the capability probe of the fallback bridge. Nil means
	// no probe is available, so the fallback stays off.
	BridgeCompat func(ctx context.Context) error
	// Committer recomputes the da = 1 commitment; nil means a committer
	// capped at fibre.max_data_bytes.
	Committer *fibrecommit.Committer
	// Submitter, RecorderChain and SigningCloser are required with the
	// Recorder enabled. Submitter pays and signs through the operator's own
	// node and RecorderChain reads that same node. Start owns SigningCloser:
	// it closes it once, on a refused start or at Shutdown after the Recorder.
	Submitter     node.FibreSubmitter
	RecorderChain recorder.FibreChain
	SigningCloser io.Closer
	// NewFibre builds the Recorder; nil means recorder.NewFibre.
	NewFibre func(recorder.FibreConfig, recorder.FibreDeps) (FibreRecorder, error)
	// SelfTest, CheckBuild and CheckNMT replace the pin checks in tests; nil
	// runs the real ones.
	SelfTest, CheckBuild, CheckNMT func() error
}

// FibreRecorder is the da = 1 Recorder the daemon publishes through.
type FibreRecorder interface {
	sdk.Publisher
	// Close waits for draining uploads until ctx ends, then cancels them.
	Close(ctx context.Context) error
}

func newFibreRecorder(cfg recorder.FibreConfig, d recorder.FibreDeps) (FibreRecorder, error) {
	r, err := recorder.NewFibre(cfg, d)
	if err != nil {
		return nil, err
	}
	return r, nil
}

// onceCloser makes a closer safe to call from every exit path.
type onceCloser struct {
	once sync.Once
	c    io.Closer
	err  error
}

func (o *onceCloser) Close() error {
	if o == nil || o.c == nil {
		return nil
	}
	o.once.Do(func() { o.err = o.c.Close() })
	return o.err
}

type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now() }

// Server is a running daemon.
type Server struct {
	addr string
	http *http.Server
	gate *gate.Gate
	reg  interface{ Close() error }
	// rec and signing are the da = 1 Recorder and the signing client it uses;
	// both are nil for the other modes.
	rec          FibreRecorder
	closeTimeout time.Duration
	signing      *onceCloser
	log          *slog.Logger

	// stop ends the background goroutines; they are waited for on shutdown.
	stop context.CancelFunc
	bg   sync.WaitGroup
	// drain makes the last attempt to write what is still queued, within ctx.
	drain  func(context.Context) error
	mu     sync.Mutex
	closed bool
	served chan struct{}
}

// Addr is the address the API listens on.
func (s *Server) Addr() string { return s.addr }

// Shutdown stops accepting and lets in-flight requests finish. Then it makes
// the last attempt to write queued records, stops the background work, closes
// the Recorder (bounded by recorder.close_timeout_s and by ctx), the signing
// client, the gate and the registry, in that order. If ctx ends while requests
// are still running they are cut off and the rest is closed anyway, so every
// call closes everything once; the returned error joins what failed: the HTTP
// phase, the drain, and the Recorder, signing client and registry closes. A
// Recorder close that ends early may leave an upload cancelled; its outcome is
// resolved on the next publish. A second call returns nil.
func (s *Server) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	var errs []error
	if err := s.http.Shutdown(ctx); err != nil {
		_ = s.http.Close()
		errs = append(errs, fmt.Errorf("edictad: shutdown: %w", err))
	}
	<-s.served
	s.closed = true
	s.stop()
	s.bg.Wait()
	if s.drain != nil {
		if err := s.drain(ctx); err != nil {
			errs = append(errs, fmt.Errorf("edictad: archive drain: %w", err))
		}
	}
	if err := s.closeRecorder(ctx); err != nil {
		errs = append(errs, err)
	}
	if err := s.signing.Close(); err != nil {
		s.log.Error("edictad: closing the signing client", "err", err)
		errs = append(errs, fmt.Errorf("edictad: closing the signing client: %w", err))
	}
	_ = s.gate.Close()
	if err := s.reg.Close(); err != nil {
		errs = append(errs, fmt.Errorf("edictad: closing registry: %w", err))
	}
	return errors.Join(errs...)
}

// closeRecorder closes the da = 1 Recorder within recorder.close_timeout_s and
// ctx, whichever ends first.
func (s *Server) closeRecorder(ctx context.Context) error {
	if s.rec == nil {
		return nil
	}
	cctx, cancel := context.WithTimeout(ctx, s.closeTimeout)
	defer cancel()
	if err := s.rec.Close(cctx); err != nil {
		s.log.Error("edictad: closing the fibre recorder", "err", err)
		return fmt.Errorf("edictad: closing the fibre recorder: %w", err)
	}
	return nil
}

func isNil(v any) bool {
	if v == nil {
		return true
	}
	switch rv := reflect.ValueOf(v); rv.Kind() {
	case reflect.Pointer, reflect.Map, reflect.Slice, reflect.Func, reflect.Chan, reflect.Interface:
		return rv.IsNil()
	}
	return false
}

// checkFibreDeps refuses a da = 1 start that lacks a dependency, or whose
// bridge client was built for other limits than the configuration reads with.
func checkFibreDeps(cfg Config, d Deps) error {
	f := d.Fibre
	if f == nil || isNil(f.Chain) || isNil(f.Bridge) || isNil(f.Direct) {
		return cfgErr(`da = "fibre" needs a consensus reader, a bridge reader and a download client`)
	}
	if cfg.Recorder.Enabled && (isNil(f.Submitter) || isNil(f.RecorderChain)) {
		return cfgErr(`the da = "fibre" recorder needs a submitter and an own-node consensus reader`)
	}
	if l, ok := f.Bridge.(interface{ Limits() node.BridgeLimits }); ok && l.Limits() != cfg.FibreBridgeLimits() {
		return cfgErr("the bridge client's namespace data limit differs from fibre.max_read_bytes")
	}
	return nil
}

// Start validates everything, then serves. Order: secret files, the
// compatibility check, gate preflight, the archive, the registry, the
// retention observer, the archive sweep, the Recorder, the listener. A refusal
// returns a nil Server, with no listener bound, and the archive and the
// registry are not even created before the check and preflight pass.
func Start(ctx context.Context, cfg Config, d Deps) (*Server, error) {
	signing := &onceCloser{}
	if d.Fibre != nil && !isNil(d.Fibre.SigningCloser) {
		signing.c = d.Fibre.SigningCloser
	}
	srv, err := start(ctx, cfg, d, signing)
	if err != nil {
		if cerr := signing.Close(); cerr != nil {
			startLogger(d).Error("edictad: closing the signing client", "err", cerr)
		}
		return nil, err
	}
	return srv, nil
}

func startLogger(d Deps) *slog.Logger {
	if d.Logger != nil {
		return d.Logger
	}
	return slog.Default()
}

func start(ctx context.Context, cfg Config, d Deps, signing *onceCloser) (*Server, error) {
	cfg = cfg.WithDefaults()
	if err := cfg.ValidateBasic(); err != nil {
		return nil, err
	}
	if isNil(d.Reader) || isNil(d.Consensus) {
		return nil, cfgErr("a node reader and a consensus client are required")
	}
	fibre := cfg.DA() == commitment.DAFibre
	if fibre {
		if err := checkFibreDeps(cfg, d); err != nil {
			return nil, err
		}
	}
	log := d.Logger
	if log == nil {
		log = slog.Default()
	}
	var clock gate.Clock = systemClock{}
	if d.Clock != nil {
		clock = d.Clock
	}

	sec, err := loadSecrets(cfg)
	if err != nil {
		return nil, err
	}
	defer sec.zero()
	allow, err := loadAllowlist(cfg.Gate.AllowlistFile)
	if err != nil {
		return nil, err
	}
	execKeys, err := cfg.executorKeys()
	if err != nil {
		return nil, err
	}
	var (
		mandateBytes []byte
		mandate      *policy.SignedMandate
		extractors   *policy.Extractors
	)
	if cfg.Policy.Enabled() {
		if mandateBytes, mandate, _, err = loadMandate(cfg.Policy.MandateFile, cfg.Gate.GateID); err != nil {
			return nil, err
		}
		if extractors, err = policyExtractors(); err != nil {
			return nil, fmt.Errorf("edictad: policy extractors: %w", err)
		}
		for _, t := range cfg.Gate.ActionTypes {
			if !extractors.Has(t) {
				return nil, cfgErr("gate.action_types[%q] has no policy extractor; a mandate needs one for every action type", t)
			}
		}
	}
	var ns []byte
	if cfg.Recorder.Enabled {
		if ns, err = cfg.Recorder.namespace(); err != nil {
			return nil, err
		}
		if cfg.Recorder.KeyringBackend == "test" {
			log.Warn("edictad: test keyring backend, for development only")
		}
	}

	committers := map[commitment.DA]gate.DACommitter{commitment.DACelestiaBlob: blobv1.New()}
	var fibreCommitter *fibrecommit.Committer
	if fibre {
		if fibreCommitter = d.Fibre.Committer; fibreCommitter == nil {
			if fibreCommitter, err = fibrecommit.New(cfg.Fibre.MaxDataBytes); err != nil {
				return nil, fmt.Errorf("edictad: fibre gate without a da = 1 committer: %w", err)
			}
		}
		committers[commitment.DAFibre] = fibreCommitter
	}

	// What the at-height summary line says about the endpoints.
	var (
		head      node.Header
		bridgeSt  heightcheck.Status
		obsOnly   bool
		fallbackD node.FibreDownloader
		probeFn   func(context.Context)
	)
	if fibre {
		x := cfg.FibreExpect(log)
		x.Now = clock.Now
		x.Namespace = ns
		x.SelfTest, x.CheckBuild, x.CheckNMT = d.Fibre.SelfTest, d.Fibre.CheckBuild, d.Fibre.CheckNMT
		fs, err := node.CheckFibre(ctx, d.Reader, d.Consensus, x)
		if err != nil {
			return nil, fmt.Errorf("edictad: compatibility check: %w", err)
		}
		head, obsOnly = fs.Head, fs.ObservationsOnly
		fallbackD, probeFn = bridgeFallback(cfg, d.Fibre, log)
	} else {
		head, err = node.Check(ctx, d.Reader, d.Consensus, node.Expect{
			ChainID:       cfg.Network.ChainID,
			MinAppVersion: cfg.Network.MinAppVersion,
			MaxAppVersion: cfg.Network.MaxAppVersion,
			Namespace:     ns,
			Now:           clock.Now,
		})
		if err != nil {
			return nil, fmt.Errorf("edictad: compatibility check: %w", err)
		}
		ep := &recordedEndpoint{Endpoint: node.BridgeEndpoint("bridge", d.Reader)}
		if _, err := heightcheck.Startup(ctx, log, ep); err != nil {
			return nil, fmt.Errorf("edictad: compatibility check: %w", err)
		}
		bridgeSt = ep.status
	}

	gcfg := gate.DefaultConfig()
	gcfg.Scope = commitment.GateScope{GateID: cfg.Gate.GateID, ActionTypes: slices.Clone(cfg.Gate.ActionTypes)}
	gcfg.ExecutorKeys = execKeys
	gcfg.AllowedDA = []commitment.DA{cfg.DA()}
	gcfg.Mandate = mandateBytes
	gcfg.ArchiveWriteTimeout = time.Duration(cfg.Archive.WriteTimeoutS) * time.Second
	if fibre {
		gcfg.FibreMaxDataBytes = cfg.Fibre.MaxDataBytes
	}
	if err := gate.Preflight(ctx, gcfg, gate.Deps{Params: gatechain.NewParams(d.Consensus)}); err != nil {
		return nil, fmt.Errorf("edictad: gate preflight: %w", err)
	}

	signer, err := gate.NewEd25519Signer(sec.gateKey)
	if err != nil {
		return nil, fmt.Errorf("edictad: gate key: %w", err)
	}
	store := d.Archive
	if store == nil {
		if store, err = fsarchive.Open(cfg.Archive.Dir, committers); err != nil {
			return nil, fmt.Errorf("edictad: archive: %w", err)
		}
	}
	aio := newArchiveIO(store)
	reg, err := boltreg.Open(cfg.Gate.RegistryPath, uint64(clock.Now().Unix()))
	if err != nil {
		return nil, fmt.Errorf("edictad: registry: %w", err)
	}

	runCtx, stop := context.WithCancel(context.Background())
	s := &Server{stop: stop, reg: reg, served: make(chan struct{}), signing: signing, log: log,
		closeTimeout: time.Duration(cfg.Recorder.CloseTimeoutS) * time.Second}
	fail := func(err error) (*Server, error) {
		stop()
		s.bg.Wait()
		_ = s.closeRecorder(context.Background())
		_ = signing.Close()
		if s.gate != nil {
			_ = s.gate.Close()
		}
		_ = reg.Close()
		return nil, err
	}

	hl := &health{rd: d.Reader, clock: clock, log: log, gateID: cfg.Gate.GateID, gatePub: signer.PublicKey(),
		allowedDA: []uint64{uint64(cfg.DA())}, last: head, lastOK: true, lastAt: clock.Now()}

	gdeps := gate.Deps{
		Clock:      clock,
		Archive:    archive.NewGateSource(store),
		Archiver:   &archiver{io: aio},
		Committers: committers,
		Allowlist:  allow,
		Registry:   reg,
		Signer:     signer,
		Logger:     log,
		Extractors: extractors,
	}
	var reader node.FibreAnchorReader
	if fibre {
		var err error
		reader, err = node.NewFibreAnchorReader(d.Fibre.Chain, d.Fibre.Bridge)
		if err != nil {
			return fail(fmt.Errorf("edictad: fibre anchor reader: %w", err))
		}
		obsParams, err := startObserver(ctx, cfg, d, reg, clock, log)
		if err != nil {
			return fail(err)
		}
		s.bg.Add(1)
		go func() {
			defer s.bg.Done()
			err := obsParams.Run(runCtx, time.Duration(cfg.Fibre.SampleEveryS)*time.Second, time.Duration(cfg.Fibre.CanaryEveryS)*time.Second)
			if runCtx.Err() == nil {
				log.Error("edictad: retention observer stopped; heights it no longer covers fail closed", "err", err)
				hl.degraded.Store(true)
			}
		}()
		logAtHeightFibre(log, obsParams.ObservationsOnly(), obsOnly)

		opts := cfg.FibreAnchorOptions()
		opts.Log = log
		anchors := gatechain.NewFibreAnchors(reader, head.ChainID, opts)
		gdeps.Params = gatechain.NewFibreParams(obsParams)
		gdeps.Headers = gatechain.NewFibreHeaders(d.Fibre.Chain)
		gdeps.Anchors = anchors
		gdeps.DA = gatechain.NewFibreBlobs(anchors, d.Fibre.Direct, fallbackD, fibreCommitter)
	} else {
		logAtHeightBlob(log, bridgeSt)
		gdeps.Params = gatechain.NewParams(d.Consensus)
		gdeps.Headers = gatechain.NewHeaders(d.Reader)
		gdeps.Anchors = gatechain.NewAnchors(d.Reader)
		gdeps.DA = gatechain.NewBlobSource(d.Reader)
	}
	g, err := gate.New(ctx, gcfg, gdeps)
	if err != nil {
		return fail(fmt.Errorf("edictad: gate: %w", err))
	}
	s.gate = g

	timeout := time.Duration(cfg.Archive.WriteTimeoutS) * time.Second
	var pol *polInfo
	if mandate != nil {
		// The registry type is checked by the gate, which refused a mandate
		// without policy state.
		pol = &polInfo{gateID: cfg.Gate.GateID, counterKey: mandate.Mandate.CounterKey(), state: reg}
		if err := publishMandate(ctx, aio, mandateBytes, timeout); err != nil {
			return fail(err)
		}
		log.Info("edictad: mandate in force", "mandate_id", hex.EncodeToString(mandate.Mandate.MandateID),
			"version", mandate.Mandate.Version, "text", policy.Render(&mandate.Mandate))
	}
	q := &retryQueue{}
	sw := &sweeper{lister: reg, io: aio, q: q, log: log, timeout: timeout, pol: pol}
	// The pass before the listener has a time budget; what it does not reach
	// is finished in the background right away.
	sctx, scancel := context.WithTimeout(ctx, startupSweepBudget)
	first := sw.run(sctx, true)
	scancel()
	s.bg.Add(1)
	go func() {
		defer s.bg.Done()
		sw.loop(runCtx, d.SweepTick, time.Duration(cfg.Archive.SweepIntervalS)*time.Second,
			first.scanFailed || first.incomplete)
	}()
	s.drain = func(ctx context.Context) error {
		dctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		sw.run(dctx, false)
		n := q.len()
		if n == 0 {
			return nil
		}
		log.Error("edictad: records left in the archive retry queue at shutdown; the next start's sweep repairs them", "records", n)
		return ctx.Err()
	}

	hcfg := edictaapi.HandlerConfig{
		GateID:         cfg.Gate.GateID,
		Clock:          clock,
		Skew:           time.Duration(gcfg.SkewS) * time.Second,
		MaxBlobBytes:   cfg.Recorder.maxBlob(),
		GateKeys:       [][]byte{signer.PublicKey()},
		ExtraErrors:    recorderErrors,
		RequestTimeout: requestDeadline,
		PublishTimeout: cfg.publishDeadline(),
	}
	var pub sdk.Publisher
	var quota edictaapi.Quota
	switch {
	case cfg.Recorder.Enabled && fibre:
		rec, err := buildFibreRecorder(cfg, d, ns, store, clock, reader, head.ChainID, fibreCommitter, log)
		if err != nil {
			return fail(err)
		}
		s.rec = rec
		addr, err := d.Fibre.Submitter.Address(ctx)
		if err != nil {
			return fail(fmt.Errorf("edictad: recorder signer: %w", err))
		}
		pub, hl.signer, hl.namespace = rec, addr, ns
		quota = recorderQuota(cfg, clock)
	case cfg.Recorder.Enabled:
		if d.Submitter == nil {
			return fail(cfgErr("recorder is enabled but no submitter is available"))
		}
		// The Recorder archives the signed header of every blob it lands; without
		// the archive a restart can pay for the same blob twice, so a reader
		// that cannot serve one refuses the start.
		if _, ok := d.Reader.(signedHeaderReader); !ok {
			return fail(cfgErr("the recorder needs a node reader that can return signed headers"))
		}
		rcfg := recorder.Config{Namespace: ns, MaxBlobBytes: cfg.Recorder.maxBlob(), Archive: store, Now: clock.Now}
		rec, err := recorder.New(rcfg, d.Submitter, d.Reader)
		if err != nil {
			return fail(fmt.Errorf("edictad: recorder: %w", err))
		}
		addr, err := d.Submitter.Signer(ctx)
		if err != nil {
			return fail(fmt.Errorf("edictad: recorder signer: %w", err))
		}
		pub, hl.signer, hl.namespace = rec, addr, ns
		quota = recorderQuota(cfg, clock)
	}

	var api edictaapi.Gate = &archivingGate{
		g: g, clock: clock, gateID: cfg.Gate.GateID, q: q, pol: pol,
		w: &writer{io: aio, q: q, log: log, timeout: timeout},
	}
	if d.WrapGate != nil {
		api = d.WrapGate(api)
	}
	handler := guardTokens(edictaapi.NewHandler(api, pub, allow, quota, hl, hcfg, log), sec.authorize, sec.record)

	listen := d.Listen
	if listen == nil {
		listen = net.Listen
	}
	l, err := listen("tcp", cfg.HTTP.Listen)
	if err != nil {
		return fail(fmt.Errorf("edictad: listen: %w", err))
	}
	s.addr = l.Addr().String()
	s.http = &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}
	tls := cfg.HTTP.TLSCertFile != ""
	go func() {
		defer close(s.served)
		var err error
		if tls {
			err = s.http.ServeTLS(l, cfg.HTTP.TLSCertFile, cfg.HTTP.TLSKeyFile)
		} else {
			err = s.http.Serve(l)
		}
		if !errors.Is(err, http.ErrServerClosed) {
			log.Error("edictad: serve stopped", "err", err)
		}
	}()
	if probeFn != nil {
		s.bg.Add(1)
		go func() {
			defer s.bg.Done()
			probeFn(runCtx)
		}()
	}
	log.Info("edictad: serving", "addr", s.addr, "chain_id", head.ChainID, "gate_id", cfg.Gate.GateID,
		"da", cfg.Network.DA, "recorder", cfg.Recorder.Enabled)
	return s, nil
}

func recorderQuota(cfg Config, clock gate.Clock) edictaapi.Quota {
	return edictaapi.NewQuota(edictaapi.QuotaConfig{
		BlobsPerHour: cfg.Recorder.Quota.BlobsPerHour,
		BytesPerDay:  cfg.Recorder.Quota.BytesPerDay,
	}, clock)
}

// buildFibreRecorder builds the da = 1 Recorder. Nothing is submitted or
// broadcast here.
func buildFibreRecorder(cfg Config, d Deps, ns []byte, store archive.Store, clock gate.Clock,
	reader node.FibreAnchorReader, chainID string, committer *fibrecommit.Committer, log *slog.Logger) (FibreRecorder, error) {
	fc := cfg.FibreRecorderConfig(ns, store)
	fc.Now = clock.Now
	build := d.Fibre.NewFibre
	if build == nil {
		build = newFibreRecorder
	}
	rec, err := build(fc, recorder.FibreDeps{
		Submitter: d.Fibre.Submitter,
		Reader:    reader,
		Chain:     d.Fibre.RecorderChain,
		ChainID:   chainID,
		Committer: committer,
		Log:       log,
	})
	if err != nil {
		return nil, fmt.Errorf("edictad: fibre recorder: %w", err)
	}
	if isNil(rec) {
		return nil, errors.New("edictad: fibre recorder: the constructor returned no recorder")
	}
	return rec, nil
}

type signedHeaderReader interface {
	SignedHeader(ctx context.Context, height uint64) ([]byte, error)
}

// recordedEndpoint keeps the canary result so the summary line can name it.
type recordedEndpoint struct {
	heightcheck.Endpoint
	status heightcheck.Status
}

func (r *recordedEndpoint) Canary(ctx context.Context) (heightcheck.Status, error) {
	st, err := r.Endpoint.Canary(ctx)
	r.status = st
	return st, err
}

func (r *recordedEndpoint) Details() []any {
	if d, ok := r.Endpoint.(heightcheck.Described); ok {
		return d.Details()
	}
	return nil
}

// startObserver binds the registry's retention store to the chain and takes
// the first sample. A refusal here is a refusal to start: without the
// samples the gate could not answer for any past height.
func startObserver(ctx context.Context, cfg Config, d Deps, reg *boltreg.Registry, clock gate.Clock, log *slog.Logger) (*retention.Params, error) {
	latest, direct := gatechain.NewRetentionSources(d.Consensus)
	p, err := retention.NewParams(retention.Policy{AssumedLagBlocks: cfg.Fibre.AssumedLagBlocks},
		latest, direct, reg.RetentionStore(), clock, retention.WithLogger(log))
	if err != nil {
		return nil, fmt.Errorf("edictad: retention observer: %w", err)
	}
	if err := p.Start(ctx); err != nil {
		return nil, fmt.Errorf("edictad: retention observer: %w", err)
	}
	return p, nil
}

func logAtHeightFibre(log *slog.Logger, observationsOnly, consensusFailed bool) {
	if !observationsOnly {
		log.Info("edictad: at-height reads", "da", DAConfigFibre, "retention", "direct")
		return
	}
	reason := "the retention canary did not pass"
	if consensusFailed {
		reason = "the consensus endpoint did not pass the height canary"
	}
	log.Warn("edictad: at-height reads", "da", DAConfigFibre, "retention", "observations-only", "reason", reason)
}

func logAtHeightBlob(log *slog.Logger, bridge heightcheck.Status) {
	name := "inconclusive"
	switch bridge {
	case heightcheck.Honoured:
		name = "honoured"
	case heightcheck.Ignoring:
		name = "ignoring"
	}
	log.Info("edictad: at-height reads", "da", DAConfigBlob, "retention", "unused", "bridge", name)
}

// requestDeadline bounds one API request.
const requestDeadline = 2 * time.Minute

// minProbeRetry keeps a probe that fails at once from looping tightly.
const minProbeRetry = 10 * time.Second

// startupSweepBudget bounds the archive sweep that runs before the listener.
const startupSweepBudget = 30 * time.Second

// switchDownloader is the bridge download fallback behind a switch that stays
// off until the capability probe passes.
type switchDownloader struct {
	d atomic.Pointer[node.FibreDownloader]
}

func (s *switchDownloader) Download(ctx context.Context, id [33]byte, promiseHeight, maxSize uint64) ([]byte, error) {
	d := s.d.Load()
	if d == nil {
		return nil, fmt.Errorf("%w: bridge download fallback is off", node.ErrNotFound)
	}
	return (*d).Download(ctx, id, promiseHeight, maxSize)
}

// bridgeFallback returns the download client for the bridge fallback and the
// probe that switches it on. The fallback is on only after the capability
// probe has passed, which runs in the background so that a quiet chain cannot
// delay the start, and is repeated every canary_every_s until it passes. It
// never refuses the start: the fallback is optional, and a version or
// capability the operator declares is never a substitute for the probe. A nil
// probe means there is nothing to run.
func bridgeFallback(cfg Config, f *FibreDeps, log *slog.Logger) (node.FibreDownloader, func(context.Context)) {
	if !cfg.Fibre.BridgeFallback {
		log.Info("edictad: bridge download fallback off", "reason", "fibre.bridge_fallback is false")
		return nil, nil
	}
	if f.BridgeCompat == nil {
		log.Warn("edictad: bridge download fallback off", "reason", "no capability probe is available")
		return nil, nil
	}
	log.Info("edictad: bridge download fallback off until the capability probe passes")
	sw := &switchDownloader{}
	every := max(time.Duration(cfg.Fibre.CanaryEveryS)*time.Second, minProbeRetry)
	return sw, func(ctx context.Context) {
		for {
			err := f.BridgeCompat(ctx)
			switch {
			case err == nil && isNil(f.Fallback):
				log.Info("edictad: bridge download fallback off", "reason", "no bridge download client")
				return
			case err == nil:
				fb := f.Fallback
				sw.d.Store(&fb)
				log.Info("edictad: bridge download fallback on", "reason", "the capability probe passed")
				return
			case ctx.Err() != nil:
				return
			}
			log.Warn("edictad: bridge download fallback off", "reason", "the capability probe did not pass", "err", err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(every):
			}
		}
	}
}

var recorderErrors = []edictaapi.ErrorRule{
	{Code: "recorder.ErrTooLarge", Err: recorder.ErrTooLarge, Status: 413},
	{Code: "recorder.ErrOutcomeUnknown", Err: recorder.ErrOutcomeUnknown, Status: 503, Retryable: true},
	{Code: "recorder.ErrNodeUnavailable", Err: recorder.ErrNodeUnavailable, Status: 503, Retryable: true},
	{Code: "recorder.ErrTooManyPending", Err: recorder.ErrTooManyPending, Status: 503, Retryable: true},
	{Code: "recorder.ErrNotVisible", Err: recorder.ErrNotVisible, Status: 503, Retryable: true},
	{Code: "recorder.ErrSignerMismatch", Err: recorder.ErrSignerMismatch, Status: 502},
	{Code: "recorder.ErrSubmitMismatch", Err: recorder.ErrSubmitMismatch, Status: 502},
	{Code: "recorder.ErrArchiveUnavailable", Err: recorder.ErrArchiveUnavailable, Status: 503, Retryable: true},
	{Code: "recorder.ErrEscrowInsufficient", Err: recorder.ErrEscrowInsufficient, Status: 503, Retryable: true},
}

// archivingGate adapts *gate.Gate to the API's interface, which takes the
// executor key as plain bytes, and writes what follows the gate's decision to
// the archive. The archive write that must come before the signature is the
// gate's own stage, not this type's.
type archivingGate struct {
	g      *gate.Gate
	clock  gate.Clock
	gateID string
	q      *retryQueue
	w      *writer
	pol    *polInfo // nil without a mandate
}

func (a *archivingGate) Authorize(ctx context.Context, envelope, action []byte) (gate.Result, error) {
	// The hold starts before the gate can mark the registry and ends once the
	// record is written or queued, so a scan never sees the entry in between.
	finished := false
	if sc, derr := commitment.DecodeSigned(envelope); derr == nil {
		if h, herr := commitment.HashOf(&sc.Commitment); herr == nil {
			a.q.begin(h)
			defer func() {
				// A panic after the mark leaves no record behind; a later tick
				// repairs it from the registry.
				if !finished {
					a.q.markDroppedFor(h)
				}
				a.q.end(h)
			}()
		}
	}
	// One scope per request: the anchor stage and the payload stage read the
	// block once between them.
	res, err := a.g.Authorize(gatechain.WithAnchorScope(ctx), envelope, action)
	a.after(ctx, res, err)
	finished = true
	return res, err
}

// after archives the outcome. A failure here never changes the answer: the
// registry is the authority and the sweep repairs the archive.
func (a *archivingGate) after(ctx context.Context, res gate.Result, err error) {
	switch {
	case err == nil:
		auth := &archive.AuthorizationRecord{
			SignedAuthorization: res.Authorization, AuthorizedAt: res.AuthorizedAt, K2: k2Record(res.K2),
		}
		if a.pol == nil || len(res.PolicyVerdict) == 0 {
			a.w.write(ctx, auth)
			return
		}
		// Policy records first, so that a crash leaves no Authorization
		// record without its verdict.
		recs, perr := a.pol.allowRecords(res.ClosedBucket, res.ClosedSet, res.PolicyVerdict, res.CommitmentHash)
		if perr != nil {
			// The sweep rebuilds the records from the registry.
			a.w.log.Error("edictad: policy records of an allow cannot be built", "err", perr)
			a.q.markDroppedFor(res.CommitmentHash)
			return
		}
		a.w.write(ctx, &chain{recs: append(recs, auth)})
	case errors.Is(err, gate.ErrNonceUsed) && res.Authorization != nil:
		// The same decision again. The request that issued the Authorization
		// writes its record, with the retention inputs only it has, or queues
		// it; a copy from here could reach the archive first and leave the
		// record without them. A gap is repaired by the sweep.
	case res.DecisionArchived:
		name, ok := markerName(err)
		if !ok {
			return
		}
		marker := &archive.RejectionRecord{
			CommitmentHash: res.CommitmentHash, Error: name, GateID: a.gateID, RejectedAt: uint64(a.clock.Now().Unix()),
		}
		if len(res.PolicyVerdict) > 0 && errors.Is(err, policy.ErrDenied) {
			a.w.write(ctx, denyChain(res.PolicyVerdict, marker))
			return
		}
		a.w.write(ctx, marker)
	}
}

func (a *archivingGate) Record(ctx context.Context, envelope []byte, railRef string, execPub, execSig []byte) ([]byte, error) {
	return a.g.Record(ctx, envelope, railRef, ed25519.PublicKey(execPub), execSig)
}

// secrets holds what is read from files before anything else starts.
type secrets struct {
	gateKey   ed25519.PrivateKey
	authorize secret.Secret
	record    secret.Secret
	others    []secret.Secret
}

// zero wipes what Start does not hand on. The two tokens live as long as the
// server and are not wiped here.
func (s *secrets) zero() {
	clear(s.gateKey)
	for _, o := range s.others {
		o.Zero()
	}
}

func loadSecrets(cfg Config) (*secrets, error) {
	s := &secrets{}
	var err error
	if s.gateKey, err = readSeed(cfg.Gate.KeyFile); err != nil {
		return nil, err
	}
	fail := func(what string, err error) (*secrets, error) {
		s.zero()
		return nil, fmt.Errorf("edictad: %s: %w", what, err)
	}
	read := func(path string) (secret.Secret, error) {
		if path == "" {
			return secret.Secret{}, nil
		}
		return secret.FromFile(path)
	}
	if s.authorize, err = read(cfg.HTTP.AuthorizeTokenFile); err != nil {
		return fail("authorize token file", err)
	}
	if s.record, err = read(cfg.HTTP.RecordTokenFile); err != nil {
		return fail("record token file", err)
	}
	// These are used by the node adapters and the keyring, not here, but a
	// file that is too open must stop the daemon before anything else runs.
	extra := []struct{ what, path string }{
		{"bridge token file", cfg.Network.Bridge.TokenFile},
		{"consensus token file", cfg.Network.ConsensusGRPC.TokenFile},
	}
	if cfg.Recorder.Enabled {
		extra = append(extra, struct{ what, path string }{"passphrase file", cfg.Recorder.PassphraseFile})
	}
	for _, e := range extra {
		o, err := read(e.path)
		if err != nil {
			return fail(e.what, err)
		}
		s.others = append(s.others, o)
	}
	return s, nil
}

// health serves GET /v0/health from a copy refreshed at most once a minute, so
// the open endpoint cannot be used to hammer the node.
type health struct {
	rd        node.Reader
	clock     gate.Clock
	log       *slog.Logger
	gateID    string
	gatePub   []byte
	signer    []byte
	namespace []byte
	allowedDA []uint64

	// degraded is set when the retention observer has stopped.
	degraded atomic.Bool

	mu     sync.Mutex
	last   node.Header
	lastOK bool
	lastAt time.Time
}

const healthTTL = time.Minute

func (h *health) Health(ctx context.Context) (edictaapi.HealthInfo, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	now := h.clock.Now()
	if now.Sub(h.lastAt) >= healthTTL || now.Before(h.lastAt) {
		cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		hd, err := h.rd.Head(cctx)
		cancel()
		h.lastAt = now
		h.lastOK = err == nil
		if err == nil {
			h.last = hd
		} else {
			h.log.Warn("edictad: health: bridge node head failed", "err", err)
		}
	}
	status := uint64(1)
	if !h.lastOK || h.degraded.Load() {
		status = 2
	}
	return edictaapi.HealthInfo{
		Status:         status,
		ChainID:        h.last.ChainID,
		HeadHeight:     h.last.Height,
		HeadTime:       uint64(h.last.Time.Unix()),
		GateID:         h.gateID,
		GatePubKey:     h.gatePub,
		RecorderSigner: h.signer,
		Namespace:      h.namespace,
		AllowedDA:      h.allowedDA,
	}, nil
}

// guardTokens enforces the optional bearer tokens on /v0/authorize and
// /v0/record. Requests the API would refuse earlier (wrong method or media
// type) pass through so those answers keep their place in the check order.
func guardTokens(next http.Handler, authorize, record secret.Secret) http.Handler {
	want := map[string]secret.Secret{}
	if authorize.IsSet() {
		want["/v0/authorize"] = authorize
	}
	if record.IsSet() {
		want["/v0/record"] = record
	}
	if len(want) == 0 {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bearer, guarded := want[r.URL.Path]
		if !guarded || r.Method != http.MethodPost {
			next.ServeHTTP(w, r)
			return
		}
		if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/cbor" {
			next.ServeHTTP(w, r)
			return
		}
		got, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok || !equalSecret(got, bearer) {
			w.Header().Set("Content-Type", "application/cbor")
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("WWW-Authenticate", "Bearer")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write(tokenRefusal)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// equalSecret compares digests so the time taken does not depend on how much
// of a guess is right, nor on its length.
func equalSecret(got string, want secret.Secret) bool {
	a := sha256.Sum256([]byte(got))
	w := want.Reveal()
	defer clear(w)
	b := sha256.Sum256(w)
	return subtle.ConstantTimeCompare(a[:], b[:]) == 1
}

// tokenRefusal is the error body of the API for a missing or wrong token.
var tokenRefusal = func() []byte {
	text := func(s string) []byte { return append([]byte{0x78, byte(len(s))}, s...) }
	b := []byte{0xa3, 0x01}
	b = append(b, text("edictaapi.ErrTokenInvalid")...)
	b = append(b, 0x02)
	b = append(b, text(edictaapi.ErrTokenInvalid.Error())...)
	return append(b, 0x03, 0x00)
}()
