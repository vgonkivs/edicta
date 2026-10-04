package edictaapi_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/edictaapi"
	"github.com/vgonkivs/edicta/gate"
)

const (
	authorizeLimit = 67736
	recordLimit    = 2560
)

func authReq(t testing.TB) []byte {
	return encMap(t, map[uint64]any{1: []byte("envelope"), 2: []byte("action")})
}

func recReq(t testing.TB) []byte {
	return encMap(t, map[uint64]any{1: []byte("envelope"), 2: "rail-ref-1",
		3: bytes.Repeat([]byte{7}, 32), 4: bytes.Repeat([]byte{8}, 64)})
}

func TestRoutesMethodsMediaTypes(t *testing.T) {
	e := newEnv(t, nil)
	rec := e.do(http.MethodPost, "/v0/nope", cborType, authReq(t))
	requireErr(t, rec, 404, "edictaapi.ErrRouteNotFound", false)
	rec = e.do(http.MethodGet, "/v1/authorize", "", nil)
	requireErr(t, rec, 404, "edictaapi.ErrRouteNotFound", false)

	for _, p := range []string{"/v0/publish", "/v0/authorize", "/v0/record"} {
		rec = e.do(http.MethodGet, p, "", nil)
		requireErr(t, rec, 405, "edictaapi.ErrMethodNotAllowed", false)
		rec = e.do(http.MethodPut, p, cborType, []byte{0xa0})
		requireErr(t, rec, 405, "edictaapi.ErrMethodNotAllowed", false)
	}
	rec = e.do(http.MethodPost, "/v0/health", cborType, []byte{0xa0})
	requireErr(t, rec, 405, "edictaapi.ErrMethodNotAllowed", false)

	for _, ct := range []string{"application/json", "", "text/plain", "application/cbor-seq"} {
		for _, p := range []string{"/v0/publish", "/v0/authorize", "/v0/record"} {
			rec = e.do(http.MethodPost, p, ct, authReq(t))
			requireErr(t, rec, 415, "edictaapi.ErrMediaType", false)
		}
	}
	// Media type is checked before size: an oversized body with a wrong type is 415.
	rec = e.do(http.MethodPost, "/v0/authorize", "application/json", make([]byte, authorizeLimit+1))
	requireErr(t, rec, 415, "edictaapi.ErrMediaType", false)
	require.Zero(t, e.gate.calls())
}

func TestBodyLimits(t *testing.T) {
	e := newEnv(t, nil)
	cases := []struct {
		path  string
		limit int
	}{
		{"/v0/authorize", authorizeLimit},
		{"/v0/record", recordLimit},
		{"/v0/publish", int(maxBlobVec) + 256},
	}
	for _, c := range cases {
		t.Run(c.path, func(t *testing.T) {
			rec := e.post(c.path, make([]byte, c.limit+1))
			requireErr(t, rec, 413, "ErrTooLarge", false)
			// At the limit the size check passes; the body is rejected later and never as 413.
			rec = e.post(c.path, make([]byte, c.limit))
			require.NotEqual(t, 413, rec.Code)
		})
	}
	require.Zero(t, e.gate.calls())
	require.Zero(t, e.pub.count())
}

func TestWrapperDecoding(t *testing.T) {
	good := authReq(t)
	cases := []struct {
		name string
		path string
		body []byte
		code string
	}{
		{"truncated", "/v0/authorize", []byte{0xa2, 0x01}, "ErrMalformed"},
		{"trailing", "/v0/authorize", append(append([]byte{}, good...), 0x00), "ErrTrailingData"},
		{"unknown key", "/v0/authorize", encMap(t, map[uint64]any{1: []byte("e"), 2: []byte("a"), 9: []byte("x")}), "ErrUnknownKey"},
		{"missing key", "/v0/authorize", encMap(t, map[uint64]any{1: []byte("e")}), "ErrMissingField"},
		{"wrong type", "/v0/authorize", encMap(t, map[uint64]any{1: "text", 2: []byte("a")}), "ErrWrongType"},
		{"float", "/v0/authorize", []byte{0xfb, 0x3f, 0xf0, 0, 0, 0, 0, 0, 0}, ""},
		{"record truncated", "/v0/record", []byte{0xa4, 0x01}, "ErrMalformed"},
		{"record unknown key", "/v0/record", encMap(t, map[uint64]any{1: []byte("e"), 2: "r", 3: make([]byte, 32), 4: make([]byte, 64), 5: 1}), "ErrUnknownKey"},
		{"record short pubkey", "/v0/record", encMap(t, map[uint64]any{1: []byte("e"), 2: "r", 3: make([]byte, 31), 4: make([]byte, 64)}), "ErrFieldSize"},
		{"record short sig", "/v0/record", encMap(t, map[uint64]any{1: []byte("e"), 2: "r", 3: make([]byte, 32), 4: make([]byte, 63)}), "ErrFieldSize"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t, nil)
			rec := e.post(c.path, c.body)
			require.Equal(t, 400, rec.Code, "%x", rec.Body.Bytes())
			eb := parseErr(t, rec.Body.Bytes())
			if c.code != "" {
				require.Equal(t, c.code, eb.Code)
			}
			require.Zero(t, e.gate.calls(), "gate must not run on a malformed wrapper")
		})
	}
}

func TestAuthorizeAndRecordPassBytesThrough(t *testing.T) {
	e := newEnv(t, nil)
	e.gate.authFn = func(context.Context, []byte, []byte) (gate.Result, error) {
		return gate.Result{Authorization: []byte("signed-authorization")}, nil
	}
	rec := e.post("/v0/authorize", authReq(t))
	require.Equal(t, 200, rec.Code)
	require.Equal(t, cborType, rec.Header().Get("Content-Type"))
	require.Equal(t, []byte("signed-authorization"), decodeMap(t, rec.Body.Bytes())[1])
	require.Equal(t, []byte("envelope"), e.gate.lastEnv)
	require.Equal(t, []byte("action"), e.gate.lastAction)

	rec = e.post("/v0/record", recReq(t))
	require.Equal(t, 200, rec.Code)
	require.Equal(t, []byte("receipt"), decodeMap(t, rec.Body.Bytes())[1])
	require.Equal(t, "rail-ref-1", e.gate.lastRef)
	require.Equal(t, bytes.Repeat([]byte{7}, 32), e.gate.lastPub)
	require.Equal(t, bytes.Repeat([]byte{8}, 64), e.gate.lastSig)
}

func TestHealth(t *testing.T) {
	e := newEnv(t, nil)
	e.health.info = edictaapi.HealthInfo{Status: 1, ChainID: "mocha-4", HeadHeight: 10, HeadTime: 20, GateID: gateIDVec,
		GatePubKey: bytes.Repeat([]byte{1}, 32), RecorderSigner: bytes.Repeat([]byte{2}, 20),
		Namespace: bytes.Repeat([]byte{3}, 29), AllowedDA: []uint64{2}}
	rec := e.do(http.MethodGet, "/v0/health", "", nil)
	require.Equal(t, 200, rec.Code)
	require.Equal(t, cborType, rec.Header().Get("Content-Type"))
	m := decodeMap(t, rec.Body.Bytes())
	require.Equal(t, uint64(1), m[1])
	require.Equal(t, "mocha-4", m[2])
	require.Equal(t, gateIDVec, m[5])
	require.Contains(t, m, uint64(7))
	require.Contains(t, m, uint64(8))
	require.Equal(t, []any{uint64(2)}, m[9])

	e.health.info.RecorderSigner, e.health.info.Namespace = nil, nil
	m = decodeMap(t, e.do(http.MethodGet, "/v0/health", "", nil).Body.Bytes())
	require.NotContains(t, m, uint64(7))
	require.NotContains(t, m, uint64(8))

	e.health.err = gate.ErrClosed
	requireErr(t, e.do(http.MethodGet, "/v0/health", "", nil), 503, "ErrClosed", true)
}

// TestErrorTable drives every row of errors.json through the handler on every endpoint it lists.
func TestErrorTable(t *testing.T) {
	v := loadErrVectors(t)
	sk, pubHex := testKey(1)
	require.NotEmpty(t, v.Errors)
	seen := map[string]bool{}
	for _, row := range v.Errors {
		sent, ok := sentinelFor(row.Code)
		require.True(t, ok, "errors.json code %s has no sentinel in the test table", row.Code)
		require.False(t, seen[row.Code], "duplicate code %s", row.Code)
		seen[row.Code] = true
		status, retry := int(u64(t, row.Status)), row.Retryable == "1"
		for _, ep := range row.Endpoints {
			t.Run(row.Code+ep, func(t *testing.T) {
				e := newEnv(t, map[string]string{"agent-a": pubHex})
				injected := fmt.Errorf("operation: %w", sent)
				if row.Code == "edictaapi.ErrInternal" {
					injected = errors.New("boom secret-detail")
				}
				if row.Code == "edictaapi.ErrDeadline" {
					injected = fmt.Errorf("wrapped: %w", context.DeadlineExceeded)
				}
				switch ep {
				case "/v0/authorize":
					e.gate.authFn = func(context.Context, []byte, []byte) (gate.Result, error) { return gate.Result{}, injected }
					r := e.post(ep, authReq(t))
					eb := requireErr(t, r, status, row.Code, retry)
					checkNoLeak(t, row.Code, eb)
					checkExtras(t, r, status)
				case "/v0/record":
					e.gate.recFn = func(context.Context, []byte, string, []byte, []byte) ([]byte, error) { return nil, injected }
					r := e.post(ep, recReq(t))
					eb := requireErr(t, r, status, row.Code, retry)
					checkNoLeak(t, row.Code, eb)
					checkExtras(t, r, status)
				case "/v0/publish":
					e.pub.err = injected
					r := e.post(ep, signedPublish(t, gateIDVec, "agent-a", sk, nowVec, []byte("blob-"+row.Code)))
					eb := requireErr(t, r, status, row.Code, retry)
					checkNoLeak(t, row.Code, eb)
					checkExtras(t, r, status)
				case "/v0/health":
					e.health.err = injected
					r := e.do(http.MethodGet, ep, "", nil)
					eb := requireErr(t, r, status, row.Code, retry)
					checkNoLeak(t, row.Code, eb)
				default:
					t.Fatalf("unknown endpoint %s", ep)
				}
			})
		}
	}
	for _, name := range []string{"ErrInvalidParams", "ErrCertInvalid"} {
		_, ok := sentinels[name]
		require.False(t, ok, "%s never crosses the API", name)
	}
}

func checkNoLeak(t *testing.T, code string, eb errBody) {
	t.Helper()
	if code == "edictaapi.ErrInternal" {
		require.NotContains(t, eb.Message, "secret-detail", "500 message is redacted")
	}
	require.False(t, eb.HasStored, "no code other than the two 409 rows carries key 4 without a stored result")
}

func checkExtras(t *testing.T, r interface{ Header() http.Header }, status int) {
	t.Helper()
	if status == 429 {
		n, err := strconv.Atoi(r.Header().Get("Retry-After"))
		require.NoError(t, err)
		require.Positive(t, n)
	}
}

func TestErrorTableFirstMatchOrder(t *testing.T) {
	cases := []struct {
		name   string
		err    error
		status int
		code   string
		retry  bool
	}{
		{"anchor too old before payload unavailable", gate.ErrAnchorTooOld, 410, "ErrAnchorTooOld", false},
		{"wrapped anchor too old", fmt.Errorf("x: %w", gate.ErrAnchorTooOld), 410, "ErrAnchorTooOld", false},
		{"plain payload unavailable", gate.ErrPayloadUnavailable, 503, "ErrPayloadUnavailable", true},
		{"410 row before 503 row in a joined error", errors.Join(gate.ErrPayloadUnavailable, gate.ErrAnchorTooOld), 410, "ErrAnchorTooOld", false},
		{"unmapped", errors.New("whatever"), 500, "edictaapi.ErrInternal", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t, nil)
			e.gate.authFn = func(context.Context, []byte, []byte) (gate.Result, error) { return gate.Result{}, c.err }
			requireErr(t, e.post("/v0/authorize", authReq(t)), c.status, c.code, c.retry)
		})
	}
}

func TestRetryableFlagIsDerivedFromSentinel(t *testing.T) {
	retryable := map[int]bool{425: true, 429: true, 503: true, 504: true}
	v := loadErrVectors(t)
	for _, row := range v.Errors {
		st := int(u64(t, row.Status))
		require.Equal(t, retryable[st], row.Retryable == "1", row.Code)
	}
}

func TestConflictStored(t *testing.T) {
	stored := []byte("stored-authorization")
	t.Run("nonce used with stored authorization (retry rule holds)", func(t *testing.T) {
		e := newEnv(t, nil)
		e.gate.authFn = func(context.Context, []byte, []byte) (gate.Result, error) {
			return gate.Result{Authorization: stored}, gate.ErrNonceUsed
		}
		eb := requireErr(t, e.post("/v0/authorize", authReq(t)), 409, "ErrNonceUsed", false)
		require.True(t, eb.HasStored)
		require.Equal(t, stored, eb.Stored)
	})
	t.Run("nonce used without stored (retry rule fails)", func(t *testing.T) {
		e := newEnv(t, nil)
		e.gate.authFn = func(context.Context, []byte, []byte) (gate.Result, error) {
			return gate.Result{}, gate.ErrNonceUsed
		}
		eb := requireErr(t, e.post("/v0/authorize", authReq(t)), 409, "ErrNonceUsed", false)
		require.False(t, eb.HasStored, "key 4 absent: no oracle on used nonces")
	})
	t.Run("stored authorization never leaks with another error", func(t *testing.T) {
		e := newEnv(t, nil)
		e.gate.authFn = func(context.Context, []byte, []byte) (gate.Result, error) {
			return gate.Result{Authorization: stored}, gate.ErrBeforeRegistryEpoch
		}
		eb := requireErr(t, e.post("/v0/authorize", authReq(t)), 409, "ErrBeforeRegistryEpoch", false)
		require.False(t, eb.HasStored)
		e.gate.authFn = func(context.Context, []byte, []byte) (gate.Result, error) {
			return gate.Result{Authorization: stored}, fmt.Errorf("w: %w", gate.ErrChainUnavailable)
		}
		eb = requireErr(t, e.post("/v0/authorize", authReq(t)), 503, "ErrChainUnavailable", true)
		require.False(t, eb.HasStored)
	})
	t.Run("receipt exists returns the stored receipt", func(t *testing.T) {
		e := newEnv(t, nil)
		e.gate.recFn = func(context.Context, []byte, string, []byte, []byte) ([]byte, error) {
			return []byte("stored-receipt"), fmt.Errorf("record: %w", gate.ErrReceiptExists)
		}
		eb := requireErr(t, e.post("/v0/record", recReq(t)), 409, "ErrReceiptExists", false)
		require.True(t, eb.HasStored)
		require.Equal(t, []byte("stored-receipt"), eb.Stored)
	})
	t.Run("record error other than exists carries no stored", func(t *testing.T) {
		e := newEnv(t, nil)
		e.gate.recFn = func(context.Context, []byte, string, []byte, []byte) ([]byte, error) {
			return []byte("leak"), gate.ErrNotAuthorized
		}
		eb := requireErr(t, e.post("/v0/record", recReq(t)), 422, "ErrNotAuthorized", false)
		require.False(t, eb.HasStored)
	})
}

func TestDeadline(t *testing.T) {
	e := newEnv(t, nil)
	cfg := e.cfg
	cfg.RequestTimeout = time.Nanosecond
	e.gate.authFn = func(ctx context.Context, _, _ []byte) (gate.Result, error) {
		<-ctx.Done()
		return gate.Result{}, ctx.Err()
	}
	e.h = edictaapi.NewHandler(e.gate, e.pub, e.allow, e.quota, e.health, cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	requireErr(t, e.post("/v0/authorize", authReq(t)), 504, "edictaapi.ErrDeadline", true)
}

func TestPublishDisabled(t *testing.T) {
	sk, pubHex := testKey(1)
	e := newEnv(t, map[string]string{"agent-a": pubHex}, withoutPublisher())
	rec := e.post("/v0/publish", signedPublish(t, gateIDVec, "agent-a", sk, nowVec, []byte("blob")))
	requireErr(t, rec, 404, "edictaapi.ErrPublishDisabled", false)
	require.Zero(t, e.fq.count())
	// The rest of the API still works.
	require.Equal(t, 200, e.post("/v0/authorize", authReq(t)).Code)
}

// TestVectorExamples replays the examples of errors.json that need only the handler and fakes.
func TestVectorExamples(t *testing.T) {
	v := loadErrVectors(t)
	for _, ex := range v.Examples {
		ex := ex
		t.Run(ex.ID, func(t *testing.T) {
			status := int(u64(t, ex.Status))
			switch ex.Endpoint {
			case "/v0/authorize", "/v0/record":
				e := newEnv(t, nil)
				req := unhex(t, ex.RequestHex)
				want := decodeMap(t, unhex(t, ex.ResponseHex))
				var wantErr errBody
				var inject error
				if status != 200 {
					wantErr = parseErr(t, unhex(t, ex.ResponseHex))
					var ok bool
					inject, ok = sentinelFor(wantErr.Code)
					require.True(t, ok)
				}
				var reqMap map[uint64]any
				if status != 400 {
					reqMap = decodeMap(t, req)
				}
				if ex.Endpoint == "/v0/authorize" {
					e.gate.authFn = func(context.Context, []byte, []byte) (gate.Result, error) {
						if status == 200 {
							return gate.Result{Authorization: want[1].([]byte)}, nil
						}
						return gate.Result{Authorization: wantErr.Stored}, inject
					}
				} else {
					e.gate.recFn = func(context.Context, []byte, string, []byte, []byte) ([]byte, error) {
						if status == 200 {
							return want[1].([]byte), nil
						}
						return wantErr.Stored, inject
					}
				}
				rec := e.post(ex.Endpoint, req)
				require.Equal(t, status, rec.Code)
				if status == 200 {
					require.Equal(t, unhex(t, ex.ResponseHex), rec.Body.Bytes(), "200 bodies are byte-exact")
				} else {
					got := parseErr(t, rec.Body.Bytes())
					require.Equal(t, wantErr.Code, got.Code)
					require.Equal(t, wantErr.Retryable, got.Retryable)
					require.Equal(t, wantErr.HasStored, got.HasStored)
					require.Equal(t, wantErr.Stored, got.Stored)
				}
				if ex.Endpoint == "/v0/authorize" && e.gate.authCalls > 0 && reqMap != nil {
					require.Equal(t, reqMap[1], e.gate.lastEnv)
					require.Equal(t, reqMap[2], e.gate.lastAction)
				}
			case "/v0/health":
				e := newEnv(t, nil)
				m := decodeMap(t, unhex(t, ex.ResponseHex))
				info := edictaapi.HealthInfo{Status: m[1].(uint64), ChainID: m[2].(string), HeadHeight: m[3].(uint64),
					HeadTime: m[4].(uint64), GateID: m[5].(string), GatePubKey: m[6].([]byte)}
				if b, ok := m[7]; ok {
					info.RecorderSigner = b.([]byte)
				}
				if b, ok := m[8]; ok {
					info.Namespace = b.([]byte)
				}
				for _, d := range m[9].([]any) {
					info.AllowedDA = append(info.AllowedDA, d.(uint64))
				}
				e.health.info = info
				rec := e.do(http.MethodGet, "/v0/health", "", nil)
				require.Equal(t, 200, rec.Code)
				require.Equal(t, unhex(t, ex.ResponseHex), rec.Body.Bytes())
			case "/v0/publish":
				e := newEnv(t, nil)
				switch ex.ID {
				case "publish_wrong_media_type":
					rec := e.do(http.MethodPost, ex.Endpoint, ex.ContentType, unhex(t, ex.RequestHex))
					requireErr(t, rec, 415, "edictaapi.ErrMediaType", false)
					require.Zero(t, e.pub.count())
				case "publish_ok":
					e.pub.result, _ = testRef(t)
					rec := e.post(ex.Endpoint, unhex(t, ex.RequestHex))
					require.Equal(t, 200, rec.Code)
					require.Equal(t, unhex(t, ex.ResponseHex), rec.Body.Bytes())
				case "publish_quota":
					e.fq.err = edictaapi.ErrQuotaExceeded
					rec := e.post(ex.Endpoint, unhex(t, ex.RequestHex))
					requireErr(t, rec, 429, "edictaapi.ErrQuotaExceeded", true)
					require.NotEmpty(t, rec.Header().Get("Retry-After"))
					require.Zero(t, e.pub.count())
				default:
					t.Fatalf("unhandled publish example %s", ex.ID)
				}
			default:
				t.Fatalf("unknown endpoint %s", ex.Endpoint)
			}
		})
	}
}
