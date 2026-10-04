package edictad

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/vgonkivs/edicta/celestia/gatechain"
	"github.com/vgonkivs/edicta/celestia/node"
	"github.com/vgonkivs/edicta/celestia/recorder"
	"github.com/vgonkivs/edicta/celestia/secret"
	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/edictaapi"
	"github.com/vgonkivs/edicta/gate"
	"github.com/vgonkivs/edicta/gate/dacommit/blobv1"
	"github.com/vgonkivs/edicta/gate/registry/boltreg"
	"github.com/vgonkivs/edicta/sdk"
)

// Deps are the daemon's external systems.
type Deps struct {
	Reader    node.Reader
	Consensus node.Consensus
	// Submitter pays for the Recorder's blobs. It is required when the
	// Recorder is enabled and never touched otherwise.
	Submitter recorder.Submitter
	Clock     gate.Clock   // nil means the system clock
	Logger    *slog.Logger // nil means slog.Default()
	// Listen opens the API listener; nil means net.Listen.
	Listen func(network, addr string) (net.Listener, error)
	// WrapGate lets a test stand in for the gate behind the API; nil keeps it.
	WrapGate func(edictaapi.Gate) edictaapi.Gate
}

type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now() }

// Server is a running daemon.
type Server struct {
	addr string
	http *http.Server
	gate *gate.Gate
	reg  interface{ Close() error }

	mu     sync.Mutex
	closed bool
	served chan struct{}
}

// Addr is the address the API listens on.
func (s *Server) Addr() string { return s.addr }

// Shutdown stops accepting, lets in-flight requests finish, then releases the
// gate and closes the registry. If ctx ends first it returns ctx's error and
// may be called again. After a clean shutdown it returns nil.
func (s *Server) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	if err := s.http.Shutdown(ctx); err != nil {
		return fmt.Errorf("edictad: shutdown: %w", err)
	}
	<-s.served
	s.closed = true
	_ = s.gate.Close()
	if err := s.reg.Close(); err != nil {
		return fmt.Errorf("edictad: closing registry: %w", err)
	}
	return nil
}

// Start validates everything, then serves. Order: secret files, the
// compatibility check, gate preflight, the registry, the Recorder, the
// listener. A refusal returns a nil Server, with no listener bound, and the
// registry is not even created before the check and preflight pass.
func Start(ctx context.Context, cfg Config, d Deps) (*Server, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	if d.Reader == nil || d.Consensus == nil {
		return nil, cfgErr("a node reader and a consensus client are required")
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
	var ns []byte
	if cfg.Recorder.Enabled {
		if ns, err = cfg.Recorder.namespace(); err != nil {
			return nil, err
		}
		if cfg.Recorder.KeyringBackend == "test" {
			log.Warn("edictad: test keyring backend, for development only")
		}
	}

	head, err := node.Check(ctx, d.Reader, d.Consensus, node.Expect{
		ChainID:       cfg.Network.ChainID,
		MinAppVersion: cfg.Network.MinAppVersion,
		MaxAppVersion: cfg.Network.MaxAppVersion,
		Namespace:     ns,
		Now:           clock.Now,
	})
	if err != nil {
		return nil, fmt.Errorf("edictad: compatibility check: %w", err)
	}

	gcfg := gate.DefaultConfig()
	gcfg.Scope = commitment.GateScope{GateID: cfg.Gate.GateID, ActionTypes: slices.Clone(cfg.Gate.ActionTypes)}
	gcfg.ExecutorKeys = execKeys
	for _, da := range cfg.Gate.AllowedDA {
		gcfg.AllowedDA = append(gcfg.AllowedDA, commitment.DA(da))
	}
	params := gatechain.NewParams(d.Consensus)
	if err := gate.Preflight(ctx, gcfg, gate.Deps{Params: params}); err != nil {
		return nil, fmt.Errorf("edictad: gate preflight: %w", err)
	}

	signer, err := gate.NewEd25519Signer(sec.gateKey)
	if err != nil {
		return nil, fmt.Errorf("edictad: gate key: %w", err)
	}
	reg, err := boltreg.Open(cfg.Gate.RegistryPath, uint64(clock.Now().Unix()))
	if err != nil {
		return nil, fmt.Errorf("edictad: registry: %w", err)
	}
	g, err := gate.New(ctx, gcfg, gate.Deps{
		Clock:      clock,
		Params:     params,
		Headers:    gatechain.NewHeaders(d.Reader),
		Anchors:    gatechain.NewAnchors(d.Reader),
		DA:         gatechain.NewBlobSource(d.Reader),
		Archive:    gatechain.NoArchive,
		Committers: map[commitment.DA]gate.DACommitter{commitment.DACelestiaBlob: blobv1.New()},
		Allowlist:  allow,
		Registry:   reg,
		Signer:     signer,
		Logger:     log,
	})
	if err != nil {
		_ = reg.Close()
		return nil, fmt.Errorf("edictad: gate: %w", err)
	}
	fail := func(err error) (*Server, error) {
		_ = g.Close()
		_ = reg.Close()
		return nil, err
	}

	hcfg := edictaapi.HandlerConfig{
		GateID:         cfg.Gate.GateID,
		Clock:          clock,
		Skew:           time.Duration(gcfg.SkewS) * time.Second,
		MaxBlobBytes:   cfg.Recorder.maxBlob(),
		GateKeys:       [][]byte{signer.PublicKey()},
		ExtraErrors:    recorderErrors,
		RequestTimeout: 2 * time.Minute,
	}
	hl := &health{rd: d.Reader, clock: clock, log: log, gateID: cfg.Gate.GateID, gatePub: signer.PublicKey(),
		allowedDA: sortedDA(cfg.Gate.AllowedDA), last: head, lastOK: true, lastAt: clock.Now()}
	var pub sdk.Publisher
	var quota edictaapi.Quota
	if cfg.Recorder.Enabled {
		if d.Submitter == nil {
			return fail(cfgErr("recorder is enabled but no submitter is available"))
		}
		rec, err := recorder.New(recorder.Config{Namespace: ns, MaxBlobBytes: cfg.Recorder.maxBlob()}, d.Submitter, d.Reader)
		if err != nil {
			return fail(fmt.Errorf("edictad: recorder: %w", err))
		}
		addr, err := d.Submitter.Signer(ctx)
		if err != nil {
			return fail(fmt.Errorf("edictad: recorder signer: %w", err))
		}
		pub, hl.signer, hl.namespace = rec, addr, ns
		quota = edictaapi.NewQuota(edictaapi.QuotaConfig{
			BlobsPerHour: cfg.Recorder.Quota.BlobsPerHour,
			BytesPerDay:  cfg.Recorder.Quota.BytesPerDay,
		}, clock)
	}

	var api edictaapi.Gate = gateAPI{g}
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
	s := &Server{
		addr: l.Addr().String(),
		http: &http.Server{
			Handler:           handler,
			ReadHeaderTimeout: 10 * time.Second,
			IdleTimeout:       2 * time.Minute,
		},
		gate:   g,
		reg:    reg,
		served: make(chan struct{}),
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
	log.Info("edictad: serving", "addr", s.addr, "chain_id", head.ChainID, "gate_id", cfg.Gate.GateID,
		"recorder", cfg.Recorder.Enabled)
	return s, nil
}

var recorderErrors = []edictaapi.ErrorRule{
	{Code: "recorder.ErrTooLarge", Err: recorder.ErrTooLarge, Status: 413},
	{Code: "recorder.ErrOutcomeUnknown", Err: recorder.ErrOutcomeUnknown, Status: 503, Retryable: true},
	{Code: "recorder.ErrNotVisible", Err: recorder.ErrNotVisible, Status: 503, Retryable: true},
	{Code: "recorder.ErrSignerMismatch", Err: recorder.ErrSignerMismatch, Status: 502},
}

func sortedDA(in []uint64) []uint64 {
	out := slices.Clone(in)
	slices.Sort(out)
	return out
}

// gateAPI adapts *gate.Gate to the API's interface, which takes the executor
// key as plain bytes.
type gateAPI struct{ g *gate.Gate }

func (a gateAPI) Authorize(ctx context.Context, envelope, action []byte) (gate.Result, error) {
	return a.g.Authorize(ctx, envelope, action)
}

func (a gateAPI) Record(ctx context.Context, envelope []byte, railRef string, execPub, execSig []byte) ([]byte, error) {
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
	if !h.lastOK {
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
