package edictaapi

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/gate"
	"github.com/vgonkivs/edicta/policy"
	"github.com/vgonkivs/edicta/sdk"
)

const (
	contentType = "application/cbor"
	// The envelope, the action and the salt with their wrapper heads.
	authorizeLimit = 2176 + 65536 + 35 + 24
	recordLimit    = 2560
	// maxResponse bounds what the client reads from a server.
	maxResponse = 1 << 20
)

// Gate is the gate operations the handler serves.
type Gate interface {
	Authorize(ctx context.Context, envelope, action, salt []byte) (gate.Result, error)
	Record(ctx context.Context, envelope []byte, railRef string, execPub, execSig []byte) ([]byte, error)
}

// Health reports the state served at GET /v1/health.
type Health interface {
	Health(ctx context.Context) (HealthInfo, error)
}

// HandlerConfig configures NewHandler.
type HandlerConfig struct {
	// GateID is the server's own id, bound into every publish message.
	GateID string
	// Clock is the server clock; nil means the system clock.
	Clock gate.Clock
	// Skew is skew_s; a publish request is fresh for Skew + 300 s either side.
	Skew time.Duration
	// MaxBlobBytes is max_blob_bytes. Zero refuses every blob.
	MaxBlobBytes uint64
	// GateKeys are the gate public keys (rule L0 / PR4).
	GateKeys [][]byte
	// ExtraErrors are consulted after the built-in table of section 18.3, for
	// codes defined outside this module (for example recorder.*).
	ExtraErrors []ErrorRule
	// RequestTimeout bounds each request; expiry is reported as ErrDeadline.
	// Zero means no timeout beyond the request context.
	RequestTimeout time.Duration
	// PublishTimeout, when set, replaces RequestTimeout for /v1/publish: a
	// publish waits on a network upload that can outlast an authorization.
	PublishTimeout time.Duration
}

type handler struct {
	g     Gate
	p     sdk.Publisher
	al    gate.Allowlist
	q     Quota
	h     Health
	cfg   HandlerConfig
	log   *slog.Logger
	clock gate.Clock
	dedup *dedupe
}

// NewHandler returns the HTTP handler of section 18. p may be nil: publishing
// is then disabled and /v1/publish answers 404 ErrPublishDisabled.
func NewHandler(g Gate, p sdk.Publisher, al gate.Allowlist, q Quota, h Health, cfg HandlerConfig, log *slog.Logger) http.Handler {
	if log == nil {
		log = slog.Default()
	}
	clock := cfg.Clock
	if clock == nil {
		clock = systemClock{}
	}
	cfg.GateKeys = cloneKeys(cfg.GateKeys)
	cfg.ExtraErrors = append([]ErrorRule(nil), cfg.ExtraErrors...)
	window := cfg.Skew + 300*time.Second
	return &handler{g: g, p: p, al: al, q: q, h: h, cfg: cfg, log: log, clock: clock,
		dedup: newDedupe(clock, 2*window)}
}

func cloneKeys(in [][]byte) [][]byte {
	out := make([][]byte, len(in))
	for i, k := range in {
		out[i] = bytes.Clone(k)
	}
	return out
}

type response struct {
	status     int
	body       []byte
	retryAfter time.Duration
	allow      string
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	res := h.serve(r)
	hd := w.Header()
	hd.Set("Content-Type", contentType)
	hd.Set("X-Content-Type-Options", "nosniff")
	if res.allow != "" {
		hd.Set("Allow", res.allow)
	}
	if res.retryAfter > 0 {
		hd.Set("Retry-After", strconv.FormatInt(int64((res.retryAfter+time.Second-1)/time.Second), 10))
	}
	w.WriteHeader(res.status)
	_, _ = w.Write(res.body)
}

func (h *handler) serve(r *http.Request) (res response) {
	defer func() {
		if p := recover(); p != nil {
			if p == http.ErrAbortHandler {
				panic(p)
			}
			h.log.Error("edictaapi: handler panic", "path", r.URL.Path, "panic", fmt.Sprint(p))
			res = errorResponse(500, codeInternal, "internal error", false, nil, nil, 0)
		}
	}()

	var limit uint64
	method := http.MethodPost
	switch r.URL.Path {
	case "/v1/publish":
		if h.p == nil {
			return h.fail(r, ErrPublishDisabled, nil)
		}
		limit = h.cfg.MaxBlobBytes + requestOverhead
	case "/v1/authorize":
		limit = authorizeLimit
	case "/v1/record":
		limit = recordLimit
	case "/v1/health":
		method = http.MethodGet
	default:
		return h.fail(r, ErrRouteNotFound, nil)
	}
	if r.Method != method {
		res := h.fail(r, ErrMethodNotAllowed, nil)
		res.allow = method
		return res
	}

	ctx := r.Context()
	timeout := h.cfg.RequestTimeout
	if r.URL.Path == "/v1/publish" && h.cfg.PublishTimeout > 0 {
		timeout = h.cfg.PublishTimeout
	}
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	if method == http.MethodGet {
		info, err := h.h.Health(ctx)
		if err != nil {
			return h.failIn(ctx, r, err, nil, nil)
		}
		return response{status: 200, body: encodeHealth(info)}
	}

	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != contentType {
		return h.fail(r, ErrMediaType, nil)
	}
	body, err := readLimited(r, limit)
	if err != nil {
		return h.fail(r, err, nil)
	}

	var out []byte
	var stored, verdict []byte
	switch r.URL.Path {
	case "/v1/publish":
		out, err = h.publish(ctx, body)
	case "/v1/authorize":
		out, stored, verdict, err = h.authorize(ctx, body)
	case "/v1/record":
		out, stored, err = h.record(ctx, body)
	}
	if err != nil {
		return h.failIn(ctx, r, err, stored, verdict)
	}
	return response{status: 200, body: out}
}

// readLimited reads the body, answering ErrTooLarge above limit bytes.
func readLimited(r *http.Request, limit uint64) ([]byte, error) {
	if r.ContentLength > 0 && uint64(r.ContentLength) > limit {
		return nil, fmt.Errorf("%w: body of %d bytes", commitment.ErrTooLarge, r.ContentLength)
	}
	if r.Body == nil {
		return nil, nil
	}
	b, err := io.ReadAll(io.LimitReader(r.Body, int64(limit)+1))
	if err != nil {
		return nil, fmt.Errorf("%w: reading the body: %v", commitment.ErrMalformed, err)
	}
	if uint64(len(b)) > limit {
		return nil, fmt.Errorf("%w: body above %d bytes", commitment.ErrTooLarge, limit)
	}
	return b, nil
}

// fail maps err through section 18.3 and builds the error response. stored is
// attached only to the two 409 rows that carry a result.
func (h *handler) fail(r *http.Request, err error, stored []byte) response {
	return h.failIn(r.Context(), r, err, stored, nil)
}

// failIn is fail for an error returned under ctx, the request context with the
// handler's own deadline.
func (h *handler) failIn(ctx context.Context, r *http.Request, err error, stored, verdict []byte) response {
	own := r.Context().Err() == nil && errors.Is(ctx.Err(), context.DeadlineExceeded)
	rule, ok := classify(err, h.cfg.ExtraErrors, own)
	var pd privateDeny
	private := errors.As(err, &pd)
	if !ok {
		if private {
			h.log.Error("edictaapi: unmapped private policy deny", "path", r.URL.Path, "commitment_hash", hex.EncodeToString(pd.commitment[:]))
			return errorResponse(500, codeInternal, "internal error", false, nil, nil, 0)
		}
		h.log.Error("edictaapi: unmapped error", "path", r.URL.Path, "err", err)
		return errorResponse(500, codeInternal, "internal error", false, nil, nil, 0)
	}
	if !(len(stored) > 0 && (errors.Is(err, gate.ErrNonceUsed) || errors.Is(err, gate.ErrReceiptExists))) {
		stored = nil
	}
	if !(len(verdict) > 0 && (errors.Is(err, policy.ErrDenied) || (len(stored) > 0 && errors.Is(err, gate.ErrNonceUsed)))) {
		verdict = nil
	}
	msg := rule.Err.Error()
	if rule.Status == 500 {
		msg = "internal error"
	}
	var after time.Duration
	switch {
	case rule.Status == 429:
		after = retryAfter(err)
	case errors.Is(err, gate.ErrArchiveUnavailable),
		errors.Is(err, gate.ErrAnchorIntentUnavailable), errors.Is(err, gate.ErrAnchorIntentRejected):
		after = archiveRetryAfter
	}
	if private {
		h.log.Debug("edictaapi: private policy deny", "path", r.URL.Path, "commitment_hash", hex.EncodeToString(pd.commitment[:]))
	} else {
		h.log.Debug("edictaapi: request failed", "path", r.URL.Path, "code", rule.Code, "err", err)
	}
	return errorResponse(rule.Status, rule.Code, msg, rule.Retryable, stored, verdict, after)
}

// privateDeny marks a deny under a private mandate. The deny reason is part
// of the sealed content there, so neither its name nor its response code may
// reach a log; the client still gets the code in the response.
type privateDeny struct {
	err        error
	commitment commitment.Hash
}

func (e privateDeny) Error() string { return e.err.Error() }
func (e privateDeny) Unwrap() error { return e.err }

// archiveRetryAfter is the advised wait after ErrArchiveUnavailable.
const archiveRetryAfter = 5 * time.Second

func errorResponse(status int, code, msg string, retryable bool, stored, verdict []byte, after time.Duration) response {
	items := []kv{
		{key: 1, kind: fText, s: code},
		{key: 2, kind: fText, s: msg},
		{key: 3, kind: fUint, u: b2u(retryable)},
	}
	if len(stored) > 0 {
		items = append(items, kv{key: 4, kind: fBytes, b: stored})
	}
	if len(verdict) > 0 {
		items = append(items, kv{key: 5, kind: fBytes, b: verdict})
	}
	return response{status: status, body: encodeMap(items...), retryAfter: after}
}

func b2u(b bool) uint64 {
	if b {
		return 1
	}
	return 0
}

var (
	authorizeSchema = []fspec{
		{key: 1, name: "envelope", kind: fBytes, max: unbounded, required: true},
		{key: 2, name: "action", kind: fBytes, max: unbounded, required: true},
		{key: 3, name: "action_salt", kind: fBytes, min: commitment.ActionSaltSize, max: commitment.ActionSaltSize, required: true},
	}
	recordSchema = []fspec{
		{key: 1, name: "envelope", kind: fBytes, max: unbounded, required: true},
		{key: 2, name: "rail_ref", kind: fText, max: unbounded, required: true},
		{key: 3, name: "executor_pubkey", kind: fBytes, min: 32, max: 32, required: true},
		{key: 4, name: "executor_signature", kind: fBytes, min: 64, max: 64, required: true},
	}
)

func (h *handler) authorize(ctx context.Context, body []byte) (out, stored, verdict []byte, err error) {
	f, err := decodeFields(body, authorizeSchema)
	if err != nil {
		return nil, nil, nil, err
	}
	res, err := h.g.Authorize(ctx, f[1].b, f[2].b, f[3].b)
	if err != nil {
		if len(res.PrivatePart) > 0 {
			err = privateDeny{err: err, commitment: res.CommitmentHash}
		}
		return nil, res.Authorization, res.PolicyVerdict, err
	}
	if len(res.Authorization) == 0 {
		return nil, nil, nil, errors.New("edictaapi: gate returned no authorization")
	}
	items := []kv{{key: 1, kind: fBytes, b: res.Authorization}}
	if len(res.PolicyVerdict) > 0 {
		items = append(items, kv{key: 5, kind: fBytes, b: res.PolicyVerdict})
	}
	return encodeMap(items...), nil, nil, nil
}

func (h *handler) record(ctx context.Context, body []byte) (out, stored []byte, err error) {
	f, err := decodeFields(body, recordSchema)
	if err != nil {
		return nil, nil, err
	}
	receipt, err := h.g.Record(ctx, f[1].b, string(f[2].b), f[3].b, f[4].b)
	if err != nil {
		return nil, receipt, err
	}
	if len(receipt) == 0 {
		return nil, nil, errors.New("edictaapi: gate returned no receipt")
	}
	return encodeMap(kv{key: 1, kind: fBytes, b: receipt}), nil, nil
}

// publish runs rules PR1 to PR7 of section 17.3 and returns the encoded
// PublishResponse.
func (h *handler) publish(ctx context.Context, body []byte) ([]byte, error) {
	req, err := DecodePublishRequest(body, h.cfg.MaxBlobBytes) // PR1, PR2
	if err != nil {
		return nil, err
	}

	// PR3: an unknown agent and a bad signature are indistinguishable.
	key, err := h.al.PubKey(ctx, req.AgentID)
	switch {
	case errors.Is(err, gate.ErrAgentNotAllowed):
		return nil, ErrPublishSignature
	case err != nil:
		return nil, err
	}
	// The weak-key check runs first; crypto/ed25519 then checks S < L and the
	// signature itself (cofactorless).
	if commitment.CheckPublicKey(key[:]) != nil {
		return nil, ErrPublishSignature
	}
	msg, err := PublishMessage(h.cfg.GateID, req.AgentID, req.RequestedAt, req.Blob)
	if err != nil {
		return nil, fmt.Errorf("edictaapi: publish message: %w", err)
	}
	if !ed25519.Verify(key[:], msg, req.Signature) {
		return nil, ErrPublishSignature
	}

	// PR4
	for _, gk := range h.cfg.GateKeys {
		if bytes.Equal(gk, key[:]) {
			return nil, gate.ErrAgentKeyIsGateKey
		}
	}

	// PR5
	window := uint64((h.cfg.Skew + 300*time.Second) / time.Second)
	now := h.clock.Now().Unix()
	if now < 0 {
		now = 0
	}
	if diff := absDiff(uint64(now), req.RequestedAt); diff > window {
		return nil, ErrPublishStale
	}

	// PR6 (dedupe), PR7 (quota, only for a request that publishes), publish.
	sum := sha256.Sum256(req.Blob)
	return h.dedup.do(ctx, sum,
		func() error { return h.q.Allow(ctx, req.AgentID, uint64(len(req.Blob))) },
		func() ([]byte, error) {
			pub, err := h.p.Publish(ctx, req.Blob)
			if err != nil {
				return nil, err
			}
			// An invalid reference is a server bug: report it as internal (not
			// as the commitment sentinel) and never remember it.
			ref, err := commitment.EncodePayloadRef(pub.Ref)
			if err != nil {
				return nil, fmt.Errorf("edictaapi: publisher returned an invalid payload_ref: %v", err)
			}
			return encodeMap(
				kv{key: 1, kind: fBytes, b: ref},
				kv{key: 2, kind: fUint, u: pub.BlockTime},
				kv{key: 3, kind: fUint, u: pub.RetentionStart},
			), nil
		})
}

func absDiff(a, b uint64) uint64 {
	if a > b {
		return a - b
	}
	return b - a
}

// dedupe implements PR6: one publication per SHA-256(blob). Only successes are
// remembered, for ttl after completion; a failure releases the claim, so a
// retry submits again.
type dedupe struct {
	clock gate.Clock
	ttl   time.Duration

	mu        sync.Mutex
	m         map[[32]byte]*dedupeEntry
	nextSweep time.Time
}

type dedupeEntry struct {
	done    chan struct{}
	resp    []byte // written before done is closed
	ok      bool
	expires time.Time
}

func newDedupe(clock gate.Clock, ttl time.Duration) *dedupe {
	return &dedupe{clock: clock, ttl: ttl, m: make(map[[32]byte]*dedupeEntry)}
}

func (d *dedupe) sweepLocked(now time.Time) {
	if now.Before(d.nextSweep) {
		return
	}
	d.nextSweep = now.Add(time.Minute)
	for k, e := range d.m {
		select {
		case <-e.done:
			if !e.ok || now.After(e.expires) {
				delete(d.m, k)
			}
		default:
		}
	}
}

// do returns the stored response when the blob was published (or is being
// published and succeeds). Otherwise it becomes the publisher: it calls
// charge (the quota), then publish.
func (d *dedupe) do(ctx context.Context, key [32]byte, charge func() error, publish func() ([]byte, error)) ([]byte, error) {
	for {
		now := d.clock.Now()
		d.mu.Lock()
		d.sweepLocked(now)
		e := d.m[key]
		if e != nil {
			select {
			case <-e.done:
				if !e.ok || now.After(e.expires) {
					delete(d.m, key)
					e = nil
				}
			default:
			}
		}
		if e == nil {
			e = &dedupeEntry{done: make(chan struct{})}
			d.m[key] = e
			d.mu.Unlock()
			return d.lead(key, e, charge, publish)
		}
		d.mu.Unlock()

		select {
		case <-e.done:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		if e.ok {
			return e.resp, nil
		}
		// The publisher failed and released the claim: try to take it.
	}
}

func (d *dedupe) lead(key [32]byte, e *dedupeEntry, charge func() error, publish func() ([]byte, error)) ([]byte, error) {
	succeeded := false
	defer func() {
		if succeeded {
			return
		}
		d.mu.Lock()
		if d.m[key] == e {
			delete(d.m, key)
		}
		d.mu.Unlock()
		close(e.done)
	}()
	if err := charge(); err != nil {
		return nil, err
	}
	resp, err := publish()
	if err != nil {
		return nil, err
	}
	e.resp, e.ok, e.expires = resp, true, d.clock.Now().Add(d.ttl)
	succeeded = true
	close(e.done)
	return resp, nil
}
