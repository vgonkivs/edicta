package edictaapi_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/edictaapi"
	"github.com/vgonkivs/edicta/gate"
	"github.com/vgonkivs/edicta/sdk"
)

const (
	vecDir     = "../spec/vectors/api"
	cborType   = "application/cbor"
	gateIDVec  = "edictad-1"
	nowVec     = uint64(1791000060)
	skewVec    = 30 * time.Second
	maxBlobVec = uint64(1 << 20)
)

func u64(t testing.TB, s string) uint64 {
	t.Helper()
	v, err := strconv.ParseUint(s, 10, 64)
	require.NoError(t, err)
	return v
}

func unhex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	require.NoError(t, err)
	return b
}

func loadJSON(t testing.TB, name string, v any) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(vecDir, name))
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(b, v))
}

type errRow struct {
	Code      string   `json:"code"`
	Status    string   `json:"status"`
	Retryable string   `json:"retryable"`
	Stored    string   `json:"stored"`
	Endpoints []string `json:"endpoints"`
}

type errVectors struct {
	Errors   []errRow `json:"errors"`
	Examples []struct {
		ID          string `json:"id"`
		Endpoint    string `json:"endpoint"`
		Method      string `json:"method"`
		ContentType string `json:"content_type"`
		RequestHex  string `json:"request_cbor_hex"`
		Status      string `json:"status"`
		ResponseHex string `json:"response_cbor_hex"`
		PublishRef  string `json:"publish_ref"`
	} `json:"examples"`
	Limits map[string]struct {
		Path         string `json:"path"`
		RequestLimit string `json:"request_limit"`
	} `json:"endpoints"`
}

func loadErrVectors(t testing.TB) errVectors {
	var v errVectors
	loadJSON(t, "errors.json", &v)
	return v
}

type pubServer struct {
	GateID       string            `json:"gate_id"`
	Now          string            `json:"now"`
	SkewS        string            `json:"skew_s"`
	MaxBlobBytes string            `json:"max_blob_bytes"`
	Allowlist    map[string]string `json:"allowlist"`
	GateKeys     []string          `json:"gate_keys"`
}

type pubCase struct {
	ID          string `json:"id"`
	AgentID     string `json:"agent_id"`
	RequestedAt string `json:"requested_at"`
	BlobHex     string `json:"blob_hex"`
	BlobPattern string `json:"blob_pattern"`
	BlobSize    string `json:"blob_size"`
	BlobSHA     string `json:"blob_sha256_hex"`
	MessageHex  string `json:"publish_message_hex"`
	SigHex      string `json:"signature_hex"`
	RequestHex  string `json:"request_cbor_hex"`
	RequestSHA  string `json:"request_sha256_hex"`
	Expect      string `json:"expect_error"`
	Rule        string `json:"rule"`
	Server      *struct {
		MaxBlobBytes string            `json:"max_blob_bytes"`
		Allowlist    map[string]string `json:"allowlist"`
	} `json:"server"`
}

type pubVectors struct {
	Server   pubServer `json:"server"`
	Cases    []pubCase `json:"cases"`
	Reject   []pubCase `json:"reject"`
	Response []struct {
		ID           string `json:"id"`
		PayloadRef   string `json:"payload_ref_cbor_hex"`
		BlockTime    string `json:"block_time"`
		RetentionS   string `json:"retention_start"`
		ResponseHex  string `json:"response_cbor_hex"`
		CommitmentID string `json:"commitment_ref"`
	} `json:"response"`
}

func loadPubVectors(t testing.TB) pubVectors {
	var v pubVectors
	loadJSON(t, "publish_request.json", &v)
	return v
}

func (c pubCase) blob(t testing.TB) []byte {
	if c.BlobPattern == "" {
		return unhex(t, c.BlobHex)
	}
	require.Equal(t, "affine-7-3", c.BlobPattern)
	b := make([]byte, u64(t, c.BlobSize))
	for i := range b {
		b[i] = byte(7*i + 3)
	}
	return b
}

func (c pubCase) request(t testing.TB) []byte {
	if c.RequestHex != "" {
		return unhex(t, c.RequestHex)
	}
	b, err := edictaapi.EncodePublishRequest(edictaapi.PublishRequest{
		Blob: c.blob(t), AgentID: c.AgentID, RequestedAt: u64(t, c.RequestedAt), Signature: unhex(t, c.SigHex),
	})
	require.NoError(t, err)
	return b
}

// ---- fakes ----

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newClock(unix uint64) *fakeClock { return &fakeClock{now: time.Unix(int64(unix), 0)} }
func (c *fakeClock) Now() time.Time   { c.mu.Lock(); defer c.mu.Unlock(); return c.now }
func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

type fakeGate struct {
	mu         sync.Mutex
	authCalls  int
	recCalls   int
	lastEnv    []byte
	lastAction []byte
	lastSalt   []byte
	lastRef    string
	lastPub    []byte
	lastSig    []byte
	authFn     func(ctx context.Context, env, action []byte) (gate.Result, error)
	recFn      func(ctx context.Context, env []byte, ref string, pub, sig []byte) ([]byte, error)
}

func (g *fakeGate) Authorize(ctx context.Context, env, action, salt []byte) (gate.Result, error) {
	g.mu.Lock()
	g.authCalls++
	g.lastEnv, g.lastAction = append([]byte(nil), env...), append([]byte(nil), action...)
	g.lastSalt = append([]byte(nil), salt...)
	fn := g.authFn
	g.mu.Unlock()
	if fn == nil {
		return gate.Result{Authorization: []byte("auth")}, nil
	}
	return fn(ctx, env, action)
}

func (g *fakeGate) Record(ctx context.Context, env []byte, ref string, pub, sig []byte) ([]byte, error) {
	g.mu.Lock()
	g.recCalls++
	g.lastEnv, g.lastRef = append([]byte(nil), env...), ref
	g.lastPub, g.lastSig = append([]byte(nil), pub...), append([]byte(nil), sig...)
	fn := g.recFn
	g.mu.Unlock()
	if fn == nil {
		return []byte("receipt"), nil
	}
	return fn(ctx, env, ref, pub, sig)
}

func (g *fakeGate) calls() int { g.mu.Lock(); defer g.mu.Unlock(); return g.authCalls + g.recCalls }

type fakePub struct {
	mu     sync.Mutex
	calls  int
	blobs  [][]byte
	result sdk.Published
	err    error
	fn     func(ctx context.Context, blob []byte) (sdk.Published, error)
}

func (p *fakePub) Publish(ctx context.Context, blob []byte) (sdk.Published, error) {
	p.mu.Lock()
	p.calls++
	p.blobs = append(p.blobs, append([]byte(nil), blob...))
	fn, res, err := p.fn, p.result, p.err
	p.mu.Unlock()
	if fn != nil {
		return fn(ctx, blob)
	}
	return res, err
}

func (p *fakePub) count() int { p.mu.Lock(); defer p.mu.Unlock(); return p.calls }

type fakeQuota struct {
	mu    sync.Mutex
	calls int
	err   error
	seen  []string
}

func (q *fakeQuota) Allow(_ context.Context, agent string, _ uint64) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.calls++
	q.seen = append(q.seen, agent)
	return q.err
}

func (q *fakeQuota) count() int { q.mu.Lock(); defer q.mu.Unlock(); return q.calls }

type fakeHealth struct {
	info edictaapi.HealthInfo
	err  error
}

func (h *fakeHealth) Health(context.Context) (edictaapi.HealthInfo, error) { return h.info, h.err }

type fakeAllow map[string][32]byte

func (a fakeAllow) PubKey(_ context.Context, id string) ([32]byte, error) {
	k, ok := a[id]
	if !ok {
		return [32]byte{}, gate.ErrAgentNotAllowed
	}
	return k, nil
}

func allowFromHex(t testing.TB, m map[string]string) fakeAllow {
	a := fakeAllow{}
	for id, h := range m {
		var k [32]byte
		copy(k[:], unhex(t, h))
		a[id] = k
	}
	return a
}

// ---- environment ----

type env struct {
	gate   *fakeGate
	pub    *fakePub
	quota  edictaapi.Quota
	fq     *fakeQuota
	health *fakeHealth
	clock  *fakeClock
	allow  fakeAllow
	cfg    edictaapi.HandlerConfig
	h      http.Handler
}

var (
	errRecTooLarge     = errors.New("recorder: too large")
	errRecSignerMis    = errors.New("recorder: signer mismatch")
	errRecOutcomeUnk   = errors.New("recorder: outcome unknown")
	errRecNotVisible   = errors.New("recorder: not visible")
	errRecNodeUnavail  = errors.New("recorder: node unavailable")
	errRecTooManyPend  = errors.New("recorder: too many pending")
	errRecSubmitMis    = errors.New("recorder: submit mismatch")
	errRecArchiveUnav  = errors.New("recorder: archive unavailable")
	errRecEscrow       = errors.New("recorder: escrow insufficient")
	recorderRuleStatus = map[string]int{
		"recorder.ErrTooLarge": 413, "recorder.ErrSignerMismatch": 502,
		"recorder.ErrOutcomeUnknown": 503, "recorder.ErrNotVisible": 503,
		"recorder.ErrNodeUnavailable": 503, "recorder.ErrTooManyPending": 503,
		"recorder.ErrSubmitMismatch": 502, "recorder.ErrArchiveUnavailable": 503,
		"recorder.ErrEscrowInsufficient": 503,
	}
	recorderErrs = map[string]error{
		"recorder.ErrTooLarge": errRecTooLarge, "recorder.ErrSignerMismatch": errRecSignerMis,
		"recorder.ErrOutcomeUnknown": errRecOutcomeUnk, "recorder.ErrNotVisible": errRecNotVisible,
		"recorder.ErrNodeUnavailable": errRecNodeUnavail, "recorder.ErrTooManyPending": errRecTooManyPend,
		"recorder.ErrSubmitMismatch": errRecSubmitMis, "recorder.ErrArchiveUnavailable": errRecArchiveUnav,
		"recorder.ErrEscrowInsufficient": errRecEscrow,
	}
)

func extraRules() []edictaapi.ErrorRule {
	return []edictaapi.ErrorRule{
		{Code: "recorder.ErrTooLarge", Err: errRecTooLarge, Status: 413},
		{Code: "recorder.ErrSignerMismatch", Err: errRecSignerMis, Status: 502},
		{Code: "recorder.ErrOutcomeUnknown", Err: errRecOutcomeUnk, Status: 503, Retryable: true},
		{Code: "recorder.ErrNotVisible", Err: errRecNotVisible, Status: 503, Retryable: true},
		{Code: "recorder.ErrNodeUnavailable", Err: errRecNodeUnavail, Status: 503, Retryable: true},
		{Code: "recorder.ErrTooManyPending", Err: errRecTooManyPend, Status: 503, Retryable: true},
		{Code: "recorder.ErrSubmitMismatch", Err: errRecSubmitMis, Status: 502},
		{Code: "recorder.ErrArchiveUnavailable", Err: errRecArchiveUnav, Status: 503, Retryable: true},
		{Code: "recorder.ErrEscrowInsufficient", Err: errRecEscrow, Status: 503, Retryable: true},
	}
}

type option func(*env)

func withoutPublisher() option { return func(e *env) { e.pub = nil } }
func withRealQuota(c edictaapi.QuotaConfig) option {
	return func(e *env) { e.quota = edictaapi.NewQuota(c, e.clock) }
}

func newEnv(t testing.TB, allow map[string]string, opts ...option) *env {
	t.Helper()
	pv := loadPubVectors(t)
	if allow == nil {
		allow = pv.Server.Allowlist
	}
	var gateKeys [][]byte
	for _, k := range pv.Server.GateKeys {
		gateKeys = append(gateKeys, unhex(t, k))
	}
	e := &env{gate: &fakeGate{}, pub: &fakePub{}, fq: &fakeQuota{}, health: &fakeHealth{},
		clock: newClock(nowVec), allow: allowFromHex(t, allow)}
	e.quota = e.fq
	e.pub.result, _ = testRef(t)
	for _, o := range opts {
		o(e)
	}
	e.cfg = edictaapi.HandlerConfig{GateID: gateIDVec, Clock: e.clock, Skew: skewVec,
		MaxBlobBytes: maxBlobVec, GateKeys: gateKeys, ExtraErrors: extraRules()}
	var p sdk.Publisher
	if e.pub != nil {
		p = e.pub
	}
	e.h = edictaapi.NewHandler(e.gate, p, e.allow, e.quota, e.health, e.cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	return e
}

// useRequestTimeout rebuilds the handler with its own request deadline.
func (e *env) useRequestTimeout(d time.Duration) {
	cfg := e.cfg
	cfg.RequestTimeout = d
	var p sdk.Publisher
	if e.pub != nil {
		p = e.pub
	}
	e.h = edictaapi.NewHandler(e.gate, p, e.allow, e.quota, e.health, cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func (e *env) do(method, path, ctype string, body []byte) *httptest.ResponseRecorder {
	var r io.Reader
	if body != nil {
		r = bytes.NewReader(body)
	}
	req := httptest.NewRequest(method, path, r)
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	return rec
}

func (e *env) post(path string, body []byte) *httptest.ResponseRecorder {
	return e.do(http.MethodPost, path, cborType, body)
}

type errBody struct {
	Code      string
	Message   string
	Retryable uint64
	Stored    []byte
	HasStored bool
}

func decodeMap(t testing.TB, b []byte) map[uint64]any {
	t.Helper()
	var m map[uint64]any
	require.NoError(t, cbor.Unmarshal(b, &m))
	return m
}

func parseErr(t testing.TB, b []byte) errBody {
	t.Helper()
	m := decodeMap(t, b)
	out := errBody{}
	out.Code, _ = m[1].(string)
	out.Message, _ = m[2].(string)
	out.Retryable, _ = m[3].(uint64)
	require.Contains(t, m, uint64(1))
	require.Contains(t, m, uint64(3))
	if s, ok := m[4]; ok {
		out.HasStored = true
		out.Stored, _ = s.([]byte)
	}
	return out
}

func requireErr(t testing.TB, rec *httptest.ResponseRecorder, status int, code string, retryable bool) errBody {
	t.Helper()
	require.Equal(t, status, rec.Code, "body %x", rec.Body.Bytes())
	require.Equal(t, cborType, rec.Header().Get("Content-Type"))
	eb := parseErr(t, rec.Body.Bytes())
	require.Equal(t, code, eb.Code)
	want := uint64(0)
	if retryable {
		want = 1
	}
	require.Equal(t, want, eb.Retryable)
	return eb
}

func encMap(t testing.TB, m map[uint64]any) []byte {
	t.Helper()
	em, err := cbor.CoreDetEncOptions().EncMode()
	require.NoError(t, err)
	b, err := em.Marshal(m)
	require.NoError(t, err)
	return b
}

func sha(b []byte) []byte { s := sha256.Sum256(b); return s[:] }

// signedPublish builds a valid wire request for an agent key and the server's gate id.
func signedPublish(t testing.TB, gateID, agentID string, sk ed25519.PrivateKey, at uint64, blob []byte) []byte {
	t.Helper()
	msg, err := edictaapi.PublishMessage(gateID, agentID, at, blob)
	require.NoError(t, err)
	b, err := edictaapi.EncodePublishRequest(edictaapi.PublishRequest{Blob: blob, AgentID: agentID,
		RequestedAt: at, Signature: ed25519.Sign(sk, msg)})
	require.NoError(t, err)
	return b
}

func testKey(seed byte) (ed25519.PrivateKey, string) {
	s := bytes.Repeat([]byte{seed}, 32)
	sk := ed25519.NewKeyFromSeed(s)
	return sk, hex.EncodeToString(sk.Public().(ed25519.PublicKey))
}

func testRef(t testing.TB) (sdk.Published, []byte) {
	t.Helper()
	pv := loadPubVectors(t)
	raw := unhex(t, pv.Response[0].PayloadRef)
	ref, err := commitment.DecodePayloadRef(raw)
	require.NoError(t, err)
	return sdk.Published{Ref: ref, BlockTime: u64(t, pv.Response[0].BlockTime), RetentionStart: u64(t, pv.Response[0].RetentionS)}, unhex(t, pv.Response[0].ResponseHex)
}

// sentinels maps every root-module code of errors.json to its sentinel.
var sentinels = map[string]error{
	"ErrAnchorTooOld": gate.ErrAnchorTooOld, "ErrExpired": commitment.ErrExpired,
	"edictaapi.ErrPublishStale": edictaapi.ErrPublishStale,
	"ErrMalformed":              commitment.ErrMalformed, "ErrTrailingData": commitment.ErrTrailingData,
	"ErrFloat": commitment.ErrFloat, "ErrSimpleValue": commitment.ErrSimpleValue, "ErrTag": commitment.ErrTag,
	"ErrIndefiniteLength": commitment.ErrIndefiniteLength, "ErrNonMinimalInt": commitment.ErrNonMinimalInt,
	"ErrNestingTooDeep": commitment.ErrNestingTooDeep, "ErrUnsortedMap": commitment.ErrUnsortedMap,
	"ErrDuplicateKey": commitment.ErrDuplicateKey, "ErrKeyType": commitment.ErrKeyType,
	"ErrInvalidString": commitment.ErrInvalidString, "ErrUnknownKey": commitment.ErrUnknownKey,
	"ErrWrongType": commitment.ErrWrongType, "ErrMissingField": commitment.ErrMissingField,
	"ErrFieldSize": commitment.ErrFieldSize, "ErrNonCanonical": commitment.ErrNonCanonical,
	"ErrUnsupportedVersion": commitment.ErrUnsupportedVersion, "ErrIntRange": commitment.ErrIntRange,
	"ErrInvalidEnum": commitment.ErrInvalidEnum, "ErrZeroValue": commitment.ErrZeroValue,
	"ErrPayloadTooLarge": commitment.ErrPayloadTooLarge, "ErrInvalidNamespace": commitment.ErrInvalidNamespace,
	"ErrTimeOrder": commitment.ErrTimeOrder, "ErrActionSize": commitment.ErrActionSize,
	"edictaapi.ErrTokenInvalid": edictaapi.ErrTokenInvalid, "edictaapi.ErrPublishSignature": edictaapi.ErrPublishSignature,
	"ErrInvalidPublicKey": commitment.ErrInvalidPublicKey, "ErrSignatureInvalid": commitment.ErrSignatureInvalid,
	"ErrScopeMismatch": commitment.ErrScopeMismatch, "ErrActionTypeNotAllowed": commitment.ErrActionTypeNotAllowed,
	"ErrDANotAllowed": gate.ErrDANotAllowed, "ErrAgentKeyIsGateKey": gate.ErrAgentKeyIsGateKey,
	"ErrAgentNotAllowed": gate.ErrAgentNotAllowed, "ErrAgentKeyMismatch": gate.ErrAgentKeyMismatch,
	"ErrExecutorNotAllowed": gate.ErrExecutorNotAllowed, "ErrKeyRole": commitment.ErrKeyRole,
	"edictaapi.ErrRouteNotFound": edictaapi.ErrRouteNotFound, "edictaapi.ErrPublishDisabled": edictaapi.ErrPublishDisabled,
	"edictaapi.ErrMethodNotAllowed": edictaapi.ErrMethodNotAllowed,
	"ErrNonceUsed":                  gate.ErrNonceUsed, "ErrReceiptExists": gate.ErrReceiptExists,
	"ErrBeforeRegistryEpoch": gate.ErrBeforeRegistryEpoch, "ErrTooLarge": commitment.ErrTooLarge,
	"edictaapi.ErrMediaType": edictaapi.ErrMediaType,
	"ErrActionMismatch":      commitment.ErrActionMismatch, "ErrPayloadSizeMismatch": commitment.ErrPayloadSizeMismatch,
	"ErrPayloadHashMismatch": commitment.ErrPayloadHashMismatch, "ErrDACommitmentMismatch": gate.ErrDACommitmentMismatch,
	"ErrArchiveRecomputeUnsupported": gate.ErrArchiveRecomputeUnsupported,
	"ErrIssuedBeforeAnchor":          commitment.ErrIssuedBeforeAnchor, "ErrTTLTooLong": commitment.ErrTTLTooLong,
	"ErrNotAuthorized": gate.ErrNotAuthorized, "ErrNotYetValid": commitment.ErrNotYetValid,
	"ErrAnchorNotFound": gate.ErrAnchorNotFound, "edictaapi.ErrQuotaExceeded": edictaapi.ErrQuotaExceeded,
	"ErrPayloadUnavailable": gate.ErrPayloadUnavailable, "ErrRetentionUnavailable": gate.ErrRetentionUnavailable,
	"ErrChainUnavailable": gate.ErrChainUnavailable, "ErrAllowlistUnavailable": gate.ErrAllowlistUnavailable,
	"ErrRegistryUnavailable": gate.ErrRegistryUnavailable, "ErrClockRegression": gate.ErrClockRegression,
	"ErrPayloadAboveCap": gate.ErrPayloadAboveCap, "ErrArchiveUnavailable": gate.ErrArchiveUnavailable,
	"ErrClosed": gate.ErrClosed, "edictaapi.ErrDeadline": edictaapi.ErrDeadline, "edictaapi.ErrInternal": edictaapi.ErrInternal,
	"ErrAnchorPending": gate.ErrAnchorPending,
	"ErrNamespaceNotAllowed": gate.ErrNamespaceNotAllowed, "ErrMandateRefMissing": gate.ErrMandateRefMissing,
	"ErrMandateMismatch": gate.ErrMandateMismatch, "ErrH0TooOld": gate.ErrH0TooOld,
	"ErrAnchorWindowClosed": gate.ErrAnchorWindowClosed, "ErrAnchorIntentInvalid": gate.ErrAnchorIntentInvalid,
	"ErrCertInvalid": gate.ErrCertInvalid, "ErrAnchorIntentUnavailable": gate.ErrAnchorIntentUnavailable,
	"ErrAnchorIntentRejected": gate.ErrAnchorIntentRejected,
}

func sentinelFor(code string) (error, bool) {
	if e, ok := sentinels[code]; ok {
		return e, true
	}
	e, ok := recorderErrs[code]
	return e, ok
}
