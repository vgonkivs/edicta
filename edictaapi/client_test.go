package edictaapi_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/edictaapi"
	"github.com/vgonkivs/edicta/gate"
)

type fakeSigner struct {
	id string
	sk ed25519.PrivateKey
	mu sync.Mutex
	n  int
}

func (s *fakeSigner) AgentID() string { return s.id }
func (s *fakeSigner) SignPublish(_ context.Context, msg []byte) ([]byte, error) {
	s.mu.Lock()
	s.n++
	s.mu.Unlock()
	return ed25519.Sign(s.sk, msg), nil
}

type clientEnv struct {
	*env
	srv    *httptest.Server
	client *edictaapi.Client
	signer *fakeSigner
}

func newClientEnv(t *testing.T, opts ...edictaapi.ClientOption) *clientEnv {
	return newClientEnvTimeout(t, 0, opts...)
}

// newClientEnvTimeout sets the handler's own request deadline when d > 0.
func newClientEnvTimeout(t *testing.T, d time.Duration, opts ...edictaapi.ClientOption) *clientEnv {
	sk, pubHex := testKey(1)
	e := newEnv(t, map[string]string{"agent-a": pubHex})
	if d > 0 {
		e.useRequestTimeout(d)
	}
	srv := httptest.NewServer(e.h)
	t.Cleanup(srv.Close)
	signer := &fakeSigner{id: "agent-a", sk: sk}
	all := append([]edictaapi.ClientOption{edictaapi.WithGateID(gateIDVec), edictaapi.WithClock(e.clock)}, opts...)
	c, err := edictaapi.NewClient(srv.URL, edictaapi.Secret{}, signer, srv.Client(), all...)
	require.NoError(t, err)
	return &clientEnv{env: e, srv: srv, client: c, signer: signer}
}

func TestClientRoundTrips(t *testing.T) {
	ctx := context.Background()
	ce := newClientEnv(t)

	ce.pub.result, _ = testRef(t)
	got, err := ce.client.Publish(ctx, []byte("client blob"))
	require.NoError(t, err)
	require.Equal(t, ce.pub.result, got)
	require.Equal(t, []byte("client blob"), ce.pub.blobs[0])
	require.Equal(t, 1, ce.signer.n)

	ce.gate.authFn = func(context.Context, []byte, []byte) (gate.Result, error) {
		return gate.Result{Authorization: []byte("auth-bytes")}, nil
	}
	auth, err := ce.client.Authorize(ctx, []byte("env"), []byte("act"))
	require.NoError(t, err)
	require.Equal(t, []byte("auth-bytes"), auth)
	require.Equal(t, []byte("env"), ce.gate.lastEnv)
	require.Equal(t, []byte("act"), ce.gate.lastAction)

	rc, err := ce.client.Record(ctx, []byte("env"), "rail", bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 64))
	require.NoError(t, err)
	require.Equal(t, []byte("receipt"), rc)
	require.Equal(t, "rail", ce.gate.lastRef)

	ce.health.info = edictaapi.HealthInfo{Status: 2, ChainID: "mocha-4", HeadHeight: 5, HeadTime: 6, GateID: gateIDVec,
		GatePubKey: bytes.Repeat([]byte{1}, 32), AllowedDA: []uint64{1, 2}}
	hi, err := ce.client.Health(ctx)
	require.NoError(t, err)
	require.Equal(t, ce.health.info.ChainID, hi.ChainID)
	require.Equal(t, ce.health.info.AllowedDA, hi.AllowedDA)
	require.Equal(t, ce.health.info.GatePubKey, hi.GatePubKey)
	require.Empty(t, hi.RecorderSigner)
}

func TestClientErrorsMapToSentinels(t *testing.T) {
	ctx := context.Background()
	v := loadErrVectors(t)
	for _, row := range v.Errors {
		sent, ok := sentinelFor(row.Code)
		require.True(t, ok)
		t.Run(row.Code, func(t *testing.T) {
			var ce *clientEnv
			if row.Code == "edictaapi.ErrDeadline" {
				ce = newClientEnvTimeout(t, time.Nanosecond)
			} else {
				ce = newClientEnv(t)
			}
			injected := sent
			if row.Code == "edictaapi.ErrInternal" {
				injected = errors.New("boom")
			}
			if row.Code == "edictaapi.ErrDeadline" {
				injected = context.DeadlineExceeded
			}
			var err error
			switch {
			case contains(row.Endpoints, "/v0/authorize"):
				ce.gate.authFn = func(context.Context, []byte, []byte) (gate.Result, error) { return gate.Result{}, injected }
				_, err = ce.client.Authorize(ctx, []byte("e"), []byte("a"))
			case contains(row.Endpoints, "/v0/record"):
				ce.gate.recFn = func(context.Context, []byte, string, []byte, []byte) ([]byte, error) { return nil, injected }
				_, err = ce.client.Record(ctx, []byte("e"), "r", make([]byte, 32), make([]byte, 64))
			case contains(row.Endpoints, "/v0/publish"):
				ce.pub.err = injected
				_, err = ce.client.Publish(ctx, []byte("blob"))
			default:
				ce.health.err = injected
				_, err = ce.client.Health(ctx)
			}
			require.Error(t, err)
			if _, isRecorder := recorderErrs[row.Code]; !isRecorder {
				require.ErrorIs(t, err, sent, "errors.Is works across the API")
			}
			var ae *edictaapi.Error
			require.ErrorAs(t, err, &ae)
			require.Equal(t, int(u64(t, row.Status)), ae.Status)
			require.Equal(t, row.Code, ae.Code)
			require.Equal(t, row.Retryable == "1", ae.Retryable)
			require.Empty(t, ae.Stored)
		})
	}
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

func TestClientAnchorTooOldAlsoMatchesPayloadUnavailable(t *testing.T) {
	ce := newClientEnv(t)
	ce.gate.authFn = func(context.Context, []byte, []byte) (gate.Result, error) { return gate.Result{}, gate.ErrAnchorTooOld }
	_, err := ce.client.Authorize(context.Background(), []byte("e"), []byte("a"))
	require.ErrorIs(t, err, gate.ErrAnchorTooOld)
	var ae *edictaapi.Error
	require.ErrorAs(t, err, &ae)
	require.Equal(t, 410, ae.Status)
	require.False(t, ae.Retryable)
}

func TestClientStoredOn409(t *testing.T) {
	ce := newClientEnv(t)
	ce.gate.authFn = func(context.Context, []byte, []byte) (gate.Result, error) {
		return gate.Result{Authorization: []byte("stored-auth")}, gate.ErrNonceUsed
	}
	_, err := ce.client.Authorize(context.Background(), []byte("e"), []byte("a"))
	require.ErrorIs(t, err, gate.ErrNonceUsed)
	var ae *edictaapi.Error
	require.ErrorAs(t, err, &ae)
	require.Equal(t, []byte("stored-auth"), ae.Stored)

	ce.gate.recFn = func(context.Context, []byte, string, []byte, []byte) ([]byte, error) {
		return []byte("stored-receipt"), gate.ErrReceiptExists
	}
	_, err = ce.client.Record(context.Background(), []byte("e"), "r", make([]byte, 32), make([]byte, 64))
	require.ErrorIs(t, err, gate.ErrReceiptExists)
	require.ErrorAs(t, err, &ae)
	require.Equal(t, []byte("stored-receipt"), ae.Stored)
}

func TestClientRecorderCodesStayTyped(t *testing.T) {
	ce := newClientEnv(t)
	ce.pub.err = errRecOutcomeUnk
	_, err := ce.client.Publish(context.Background(), []byte("blob"))
	var ae *edictaapi.Error
	require.ErrorAs(t, err, &ae)
	require.Equal(t, "recorder.ErrOutcomeUnknown", ae.Code)
	require.Equal(t, 503, ae.Status)
	require.True(t, ae.Retryable)
}

// ---- raw server: retry behaviour ----

type rawResp struct {
	status      int
	code        string
	retryable   bool
	retryAfter  string
	okBody      []byte
	contentType string
}

type rawServer struct {
	*httptest.Server
	mu     sync.Mutex
	bodies [][]byte
	ctypes []string
	resps  []rawResp
}

func newRaw(t *testing.T, resps ...rawResp) *rawServer {
	rs := &rawServer{resps: resps}
	rs.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		rs.mu.Lock()
		i := len(rs.bodies)
		rs.bodies = append(rs.bodies, b)
		rs.ctypes = append(rs.ctypes, r.Header.Get("Content-Type"))
		rs.mu.Unlock()
		if i >= len(rs.resps) {
			i = len(rs.resps) - 1
		}
		rp := rs.resps[i]
		w.Header().Set("Content-Type", cborType)
		if rp.retryAfter != "" {
			w.Header().Set("Retry-After", rp.retryAfter)
		}
		w.WriteHeader(rp.status)
		if rp.status == 200 {
			_, _ = w.Write(rp.okBody)
			return
		}
		ret := uint64(0)
		if rp.retryable {
			ret = 1
		}
		_, _ = w.Write(encMap(t, map[uint64]any{1: rp.code, 2: "msg", 3: ret}))
	}))
	t.Cleanup(rs.Close)
	return rs
}

func (rs *rawServer) n() int { rs.mu.Lock(); defer rs.mu.Unlock(); return len(rs.bodies) }

func authOK(t *testing.T) rawResp {
	return rawResp{status: 200, okBody: encMap(t, map[uint64]any{1: []byte("auth")})}
}

type waits struct {
	mu       sync.Mutex
	attempts []int
	after    []time.Duration
	err      error
}

func (w *waits) fn(_ context.Context, attempt int, after time.Duration) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.attempts = append(w.attempts, attempt)
	w.after = append(w.after, after)
	return w.err
}

func rawClient(t *testing.T, rs *rawServer, opts ...edictaapi.ClientOption) (*edictaapi.Client, *fakeSigner) {
	sk, _ := testKey(1)
	signer := &fakeSigner{id: "agent-a", sk: sk}
	opts = append([]edictaapi.ClientOption{edictaapi.WithGateID(gateIDVec), edictaapi.WithClock(newClock(nowVec))}, opts...)
	c, err := edictaapi.NewClient(rs.URL, edictaapi.Secret{}, signer, rs.Client(), opts...)
	require.NoError(t, err)
	return c, signer
}

func TestClientDoesNotRetryByDefault(t *testing.T) {
	rs := newRaw(t, rawResp{status: 503, code: "ErrChainUnavailable", retryable: true}, authOK(t))
	c, _ := rawClient(t, rs)
	_, err := c.Authorize(context.Background(), []byte("e"), []byte("a"))
	require.ErrorIs(t, err, gate.ErrChainUnavailable)
	require.Equal(t, 1, rs.n())
	require.Equal(t, []string{cborType}, rs.ctypes)
}

func TestClientRetriesOnlyRetryableStatuses(t *testing.T) {
	v := loadErrVectors(t)
	byStatus := map[string]errRow{}
	for _, r := range v.Errors {
		if _, ok := byStatus[r.Status]; !ok {
			byStatus[r.Status] = r
		}
	}
	require.Len(t, byStatus, 16)
	for status, row := range byStatus {
		t.Run(status, func(t *testing.T) {
			rs := newRaw(t, rawResp{status: int(u64(t, status)), code: row.Code, retryable: row.Retryable == "1"}, authOK(t))
			w := &waits{}
			c, _ := rawClient(t, rs, edictaapi.WithRetry(3, w.fn))
			out, err := c.Authorize(context.Background(), []byte("e"), []byte("a"))
			if row.Retryable == "1" {
				require.NoError(t, err)
				require.Equal(t, []byte("auth"), out)
				require.Equal(t, 2, rs.n())
				require.Equal(t, rs.bodies[0], rs.bodies[1], "the same request, unchanged")
				require.Equal(t, []int{1}, w.attempts)
				return
			}
			require.Error(t, err)
			require.Equal(t, 1, rs.n(), "status %s is never retried", status)
			require.Empty(t, w.attempts)
		})
	}
}

func TestClientRetryBudgetAndRetryAfter(t *testing.T) {
	rs := newRaw(t, rawResp{status: 429, code: "edictaapi.ErrQuotaExceeded", retryable: true, retryAfter: "7"})
	w := &waits{}
	c, _ := rawClient(t, rs, edictaapi.WithRetry(3, w.fn))
	_, err := c.Authorize(context.Background(), []byte("e"), []byte("a"))
	require.ErrorIs(t, err, edictaapi.ErrQuotaExceeded)
	require.Equal(t, 3, rs.n(), "maxAttempts is the total number of requests")
	require.Equal(t, []int{1, 2}, w.attempts)
	require.Equal(t, []time.Duration{7 * time.Second, 7 * time.Second}, w.after)
	_ = strconv.Itoa
}

func TestClientRetryStopsWhenWaitFails(t *testing.T) {
	rs := newRaw(t, rawResp{status: 503, code: "ErrChainUnavailable", retryable: true}, authOK(t))
	w := &waits{err: context.Canceled}
	c, _ := rawClient(t, rs, edictaapi.WithRetry(5, w.fn))
	_, err := c.Authorize(context.Background(), []byte("e"), []byte("a"))
	require.ErrorIs(t, err, context.Canceled)
	require.Equal(t, 1, rs.n())
}

func TestClientPublishRetryResendsSameSignedRequest(t *testing.T) {
	ref, resp := testRef(t)
	_ = ref
	rs := newRaw(t, rawResp{status: 503, code: "recorder.ErrOutcomeUnknown", retryable: true},
		rawResp{status: 200, okBody: resp})
	w := &waits{}
	c, signer := rawClient(t, rs, edictaapi.WithRetry(2, w.fn))
	got, err := c.Publish(context.Background(), []byte("blob"))
	require.NoError(t, err)
	require.Equal(t, ref, got)
	require.Equal(t, 2, rs.n())
	require.Equal(t, rs.bodies[0], rs.bodies[1])
	require.Equal(t, 1, signer.n, "signed once, resent unchanged")
}

func TestClientUnknownCodeIsInternal(t *testing.T) {
	rs := newRaw(t, rawResp{status: 418, code: "weird.ErrNew"})
	c, _ := rawClient(t, rs)
	_, err := c.Authorize(context.Background(), []byte("e"), []byte("a"))
	require.ErrorIs(t, err, edictaapi.ErrInternal)
}

func TestClientPublishWithoutRecorderOrSigner(t *testing.T) {
	rs := newRaw(t, authOK(t))
	c, err := edictaapi.NewClient(rs.URL, edictaapi.Secret{}, nil, rs.Client())
	require.NoError(t, err)
	_, err = c.Publish(context.Background(), []byte("b"))
	require.Error(t, err)
	require.Zero(t, rs.n(), "no signer, no request")
	_, err = edictaapi.NewClient("", edictaapi.Secret{}, nil, nil)
	require.Error(t, err)
}

func TestClientBareDeadlineIsInternal(t *testing.T) {
	ce := newClientEnv(t)
	ce.gate.authFn = func(context.Context, []byte, []byte) (gate.Result, error) {
		return gate.Result{}, context.DeadlineExceeded
	}
	_, err := ce.client.Authorize(context.Background(), []byte("e"), []byte("a"))
	var ae *edictaapi.Error
	require.ErrorAs(t, err, &ae)
	require.Equal(t, 500, ae.Status)
	require.Equal(t, "edictaapi.ErrInternal", ae.Code)
	require.NotErrorIs(t, err, edictaapi.ErrDeadline)
}
