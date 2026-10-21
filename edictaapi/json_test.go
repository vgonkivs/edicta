// SPDX-License-Identifier: Apache-2.0

package edictaapi_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/edictaapi"
	"github.com/vgonkivs/edicta/gate"
)

const jsonType = "application/json"

var (
	authNames   = map[uint64]string{1: "envelope", 2: "action", 3: "action_salt"}
	recNames    = map[uint64]string{1: "envelope", 2: "rail_ref", 3: "executor_pubkey", 4: "executor_signature"}
	pubNames    = map[uint64]string{1: "blob", 2: "agent_id", 3: "requested_at", 4: "signature"}
	healthNames = map[uint64]string{1: "status", 2: "chain_id", 3: "head_height", 4: "head_time", 5: "gate_id",
		6: "gate_pubkey", 7: "recorder_signer", 8: "namespace", 9: "allowed_da"}
	pubRespNames = map[uint64]string{1: "payload_ref", 2: "block_time", 3: "retention_start"}
	errNames     = map[uint64]string{1: "code", 2: "message", 3: "retryable", 4: "stored", 5: "policy_verdict"}
)

// toJSON renders a CBOR wrapper map independently of the package under test.
func toJSON(t testing.TB, cborBody []byte, names map[uint64]string) []byte {
	t.Helper()
	out := map[string]any{}
	for k, v := range decodeMap(t, cborBody) {
		switch x := v.(type) {
		case []byte:
			out[names[k]] = base64.StdEncoding.EncodeToString(x)
		default:
			out[names[k]] = x
		}
	}
	b, err := json.Marshal(out)
	require.NoError(t, err)
	return b
}

// outsideJSON reports whether a CBOR wrapper has a key without a JSON name or
// an integer above 2^53-1.
func outsideJSON(t testing.TB, cborBody []byte, names map[uint64]string) bool {
	t.Helper()
	for k, v := range decodeMap(t, cborBody) {
		if _, ok := names[k]; !ok {
			return true
		}
		if u, ok := v.(uint64); ok && u > 1<<53-1 {
			return true
		}
	}
	return false
}

func (e *env) doH(method, path string, hdr map[string]string, body []byte) *httptest.ResponseRecorder {
	var r io.Reader
	if body != nil {
		r = bytes.NewReader(body)
	}
	req := httptest.NewRequest(method, path, r)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	return rec
}

func (e *env) postJSON(path string, body []byte) *httptest.ResponseRecorder {
	return e.doH(http.MethodPost, path, map[string]string{"Content-Type": jsonType}, body)
}

type jsonErr struct {
	Code      string  `json:"code"`
	Message   string  `json:"message"`
	Retryable *int    `json:"retryable"`
	Stored    *string `json:"stored"`
	Verdict   *string `json:"policy_verdict"`
}

func requireJSONErr(t testing.TB, rec *httptest.ResponseRecorder, status int, code string) jsonErr {
	t.Helper()
	require.Equal(t, status, rec.Code, "body %s", rec.Body.String())
	require.Equal(t, jsonType, rec.Header().Get("Content-Type"))
	var je jsonErr
	dec := json.NewDecoder(bytes.NewReader(rec.Body.Bytes()))
	dec.DisallowUnknownFields()
	require.NoError(t, dec.Decode(&je))
	require.Equal(t, code, je.Code)
	require.NotNil(t, je.Retryable)
	return je
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func TestJSONAuthorizeRecordMatchCBOR(t *testing.T) {
	cbor := newEnv(t, nil)
	js := newEnv(t, nil)
	for _, e := range []*env{cbor, js} {
		e.gate.authFn = func(context.Context, []byte, []byte) (gate.Result, error) {
			return gate.Result{Authorization: []byte("signed-authorization"), PolicyVerdict: []byte("verdict")}, nil
		}
	}
	a := cbor.post("/v1/authorize", authReq(t))
	b := js.postJSON("/v1/authorize", toJSON(t, authReq(t), authNames))
	require.Equal(t, 200, b.Code, b.Body.String())
	require.Equal(t, jsonType, b.Header().Get("Content-Type"))
	require.Equal(t, cbor.gate.lastEnv, js.gate.lastEnv)
	require.Equal(t, cbor.gate.lastAction, js.gate.lastAction)
	require.Equal(t, cbor.gate.lastSalt, js.gate.lastSalt)
	require.JSONEq(t, string(toJSON(t, a.Body.Bytes(), map[uint64]string{1: "signed_authorization", 5: "policy_verdict"})), b.Body.String())

	a = cbor.post("/v1/record", recReq(t))
	b = js.postJSON("/v1/record", toJSON(t, recReq(t), recNames))
	require.Equal(t, 200, b.Code, b.Body.String())
	require.Equal(t, cbor.gate.lastEnv, js.gate.lastEnv)
	require.Equal(t, cbor.gate.lastRef, js.gate.lastRef)
	require.Equal(t, cbor.gate.lastPub, js.gate.lastPub)
	require.Equal(t, cbor.gate.lastSig, js.gate.lastSig)
	require.JSONEq(t, string(toJSON(t, a.Body.Bytes(), map[uint64]string{1: "signed_receipt"})), b.Body.String())
}

func TestJSONPassesNonUTF8FreeBytesExactly(t *testing.T) {
	e := newEnv(t, nil)
	envBytes := make([]byte, 256)
	for i := range envBytes {
		envBytes[i] = byte(i)
	}
	body := `{"envelope":"` + b64(envBytes) + `","action":"` + b64([]byte{0xff, 0xfe, 0}) + `","action_salt":"` + b64(testSalt) + `"}`
	rec := e.postJSON("/v1/authorize", []byte(body))
	require.Equal(t, 200, rec.Code, rec.Body.String())
	require.Equal(t, envBytes, e.gate.lastEnv)
	require.Equal(t, []byte{0xff, 0xfe, 0}, e.gate.lastAction)
}

func TestJSONPublishVectorsMatchCBOR(t *testing.T) {
	pv := loadPubVectors(t)
	for _, c := range append(append([]pubCase{}, pv.Cases...), pv.Reject...) {
		t.Run(c.ID, func(t *testing.T) {
			req := c.request(t)
			var m map[uint64]any
			if cbor.Unmarshal(req, &m) != nil || !bytes.Equal(encMap(t, m), req) {
				t.Skip("non-canonical CBOR has no JSON form")
			}
			var allow map[string]string
			if c.Server != nil && c.Server.Allowlist != nil {
				allow = c.Server.Allowlist
			}
			mk := func() *env {
				e := newEnv(t, allow)
				if c.Server != nil && c.Server.MaxBlobBytes != "" {
					e.cfg.MaxBlobBytes = u64(t, c.Server.MaxBlobBytes)
					e.rebuild()
				}
				return e
			}
			ec, ej := mk(), mk()
			a := ec.post("/v1/publish", req)
			if outsideJSON(t, req, pubNames) {
				// Unknown keys and integers above 2^53-1 are ErrMalformed over JSON.
				b := ej.postJSON("/v1/publish", toJSON(t, req, pubNames))
				requireJSONErr(t, b, 400, "ErrMalformed")
				require.Zero(t, ej.pub.count())
				return
			}
			b := ej.postJSON("/v1/publish", toJSON(t, req, pubNames))
			require.Equal(t, a.Code, b.Code, "json: %s", b.Body.String())
			require.Equal(t, ec.pub.count(), ej.pub.count())
			require.Equal(t, ec.fq.count(), ej.fq.count())
			if a.Code == 200 {
				require.Equal(t, ec.pub.blobs, ej.pub.blobs)
				require.JSONEq(t, string(toJSON(t, a.Body.Bytes(), pubRespNames)), b.Body.String())
				return
			}
			eb := parseErr(t, a.Body.Bytes())
			je := requireJSONErr(t, b, a.Code, eb.Code)
			require.Equal(t, int(eb.Retryable), *je.Retryable)
		})
	}
}

func TestJSONErrorBodiesMirrorCBOR(t *testing.T) {
	stored := []byte("stored-authorization")
	e := newEnv(t, nil)
	e.gate.authFn = func(context.Context, []byte, []byte) (gate.Result, error) {
		return gate.Result{Authorization: stored, PolicyVerdict: []byte("v")}, gate.ErrNonceUsed
	}
	body := toJSON(t, authReq(t), authNames)
	cb := e.post("/v1/authorize", authReq(t))
	jb := e.postJSON("/v1/authorize", body)
	require.Equal(t, cb.Code, jb.Code)
	je := requireJSONErr(t, jb, 409, "ErrNonceUsed")
	require.NotNil(t, je.Stored)
	require.Equal(t, b64(stored), *je.Stored)
	require.NotNil(t, je.Verdict)
	require.JSONEq(t, string(toJSON(t, cb.Body.Bytes(), errNames)), jb.Body.String())

	e.gate.authFn = func(context.Context, []byte, []byte) (gate.Result, error) {
		return gate.Result{}, gate.ErrChainUnavailable
	}
	je = requireJSONErr(t, e.postJSON("/v1/authorize", body), 503, "ErrChainUnavailable")
	assert.Equal(t, 1, *je.Retryable)
	assert.Nil(t, je.Stored)
	assert.Nil(t, je.Verdict)
}

func TestJSONRequestRefusals(t *testing.T) {
	salt := b64(testSalt)
	okAuth := func(extra string) string {
		return `{"envelope":"ZW52","action":"YWN0","action_salt":"` + salt + `"` + extra + `}`
	}
	cases := []struct {
		name string
		path string
		body string
		code string
	}{
		{"duplicate key", "/v1/authorize", okAuth(`,"action":"YWN0"`), "ErrMalformed"},
		{"duplicate key by escape", "/v1/authorize", okAuth(`,"action":"YWN0"`), "ErrMalformed"},
		{"duplicate key different value", "/v1/authorize", okAuth(`,"envelope":"b3RoZXI="`), "ErrMalformed"},
		{"unknown field", "/v1/authorize", okAuth(`,"extra":"x"`), "ErrMalformed"},
		{"cbor key name", "/v1/authorize", okAuth(`,"1":"x"`), "ErrMalformed"},
		{"case differs", "/v1/authorize", `{"Envelope":"ZW52","action":"YWN0","action_salt":"` + salt + `"}`, "ErrMalformed"},
		{"base64 unpadded", "/v1/authorize", `{"envelope":"ZW52","action":"YWN0","action_salt":"` + strings.TrimRight(salt, "=") + `"}`, "ErrMalformed"},
		{"base64 url alphabet", "/v1/authorize", `{"envelope":"_-_-","action":"YWN0","action_salt":"` + salt + `"}`, "ErrMalformed"},
		{"base64 newline", "/v1/authorize", `{"envelope":"ZW\n52","action":"YWN0","action_salt":"` + salt + `"}`, "ErrMalformed"},
		{"base64 trailing bits", "/v1/authorize", `{"envelope":"YR==","action":"YWN0","action_salt":"` + salt + `"}`, "ErrMalformed"},
		{"base64 bad char", "/v1/authorize", `{"envelope":"ZW5*","action":"YWN0","action_salt":"` + salt + `"}`, "ErrMalformed"},
		{"base64 space", "/v1/authorize", `{"envelope":" ZW52","action":"YWN0","action_salt":"` + salt + `"}`, "ErrMalformed"},
		{"number for bytes", "/v1/authorize", `{"envelope":1,"action":"YWN0","action_salt":"` + salt + `"}`, "ErrWrongType"},
		{"string for uint", "/v1/publish", `{"blob":"YQ==","agent_id":"agent-a","requested_at":"5","signature":"` + b64(make([]byte, 64)) + `"}`, "ErrWrongType"},
		{"null", "/v1/authorize", `{"envelope":null,"action":"YWN0","action_salt":"` + salt + `"}`, "ErrMalformed"},
		{"bool", "/v1/authorize", `{"envelope":true,"action":"YWN0","action_salt":"` + salt + `"}`, "ErrMalformed"},
		{"nested object", "/v1/authorize", `{"envelope":{},"action":"YWN0","action_salt":"` + salt + `"}`, "ErrMalformed"},
		{"float", "/v1/publish", `{"blob":"YQ==","agent_id":"a","requested_at":1.0,"signature":"` + b64(make([]byte, 64)) + `"}`, "ErrMalformed"},
		{"exponent", "/v1/publish", `{"blob":"YQ==","agent_id":"a","requested_at":1e3,"signature":"` + b64(make([]byte, 64)) + `"}`, "ErrMalformed"},
		{"negative", "/v1/publish", `{"blob":"YQ==","agent_id":"a","requested_at":-1,"signature":"` + b64(make([]byte, 64)) + `"}`, "ErrMalformed"},
		{"leading zero", "/v1/publish", `{"blob":"YQ==","agent_id":"a","requested_at":01,"signature":"` + b64(make([]byte, 64)) + `"}`, "ErrMalformed"},
		{"above 2^53-1", "/v1/publish", `{"blob":"YQ==","agent_id":"a","requested_at":9007199254740992,"signature":"` + b64(make([]byte, 64)) + `"}`, "ErrMalformed"},
		{"huge integer", "/v1/publish", `{"blob":"YQ==","agent_id":"a","requested_at":99999999999999999999999,"signature":"` + b64(make([]byte, 64)) + `"}`, "ErrMalformed"},
		{"missing field", "/v1/authorize", `{"envelope":"ZW52","action":"YWN0"}`, "ErrMissingField"},
		{"short salt", "/v1/authorize", `{"envelope":"ZW52","action":"YWN0","action_salt":"` + b64(testSalt[:31]) + `"}`, "ErrFieldSize"},
		{"short pubkey", "/v1/record", `{"envelope":"ZW52","rail_ref":"r","executor_pubkey":"` + b64(make([]byte, 31)) + `","executor_signature":"` + b64(make([]byte, 64)) + `"}`, "ErrFieldSize"},
		{"trailing data", "/v1/authorize", okAuth("") + ` {}`, "ErrMalformed"},
		{"trailing garbage", "/v1/authorize", okAuth("") + `x`, "ErrMalformed"},
		{"top-level array", "/v1/authorize", `[]`, "ErrMalformed"},
		{"empty body", "/v1/authorize", ``, "ErrMalformed"},
		{"truncated", "/v1/authorize", `{"envelope":"ZW52",`, "ErrMalformed"},
		{"trailing comma", "/v1/authorize", `{"envelope":"ZW52","action":"YWN0","action_salt":"` + salt + `",}`, "ErrMalformed"},
		{"bom", "/v1/authorize", "\xef\xbb\xbf" + okAuth(""), "ErrMalformed"},
		{"single quotes", "/v1/authorize", `{'envelope':'ZW52'}`, "ErrMalformed"},
		{"invalid utf-8 in rail_ref", "/v1/record", "{\"envelope\":\"ZW52\",\"rail_ref\":\"\xff\",\"executor_pubkey\":\"" + b64(make([]byte, 32)) + "\",\"executor_signature\":\"" + b64(make([]byte, 64)) + "\"}", "ErrMalformed"},
		{"lone surrogate in rail_ref", "/v1/record", `{"envelope":"ZW52","rail_ref":"\ud800","executor_pubkey":"` + b64(make([]byte, 32)) + `","executor_signature":"` + b64(make([]byte, 64)) + `"}`, "ErrMalformed"},
		{"control char in string", "/v1/record", "{\"envelope\":\"ZW52\",\"rail_ref\":\"a\nb\",\"executor_pubkey\":\"" + b64(make([]byte, 32)) + "\",\"executor_signature\":\"" + b64(make([]byte, 64)) + "\"}", "ErrMalformed"},
		{"bad escape", "/v1/record", `{"envelope":"ZW52","rail_ref":"\x","executor_pubkey":"` + b64(make([]byte, 32)) + `","executor_signature":"` + b64(make([]byte, 64)) + `"}`, "ErrMalformed"},
		{"array for bytes", "/v1/authorize", `{"envelope":[1],"action":"YWN0","action_salt":"` + salt + `"}`, "ErrWrongType"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t, nil)
			rec := e.postJSON(c.path, []byte(c.body))
			requireJSONErr(t, rec, 400, c.code)
			require.Zero(t, e.gate.calls())
			require.Zero(t, e.pub.count())
		})
	}
}

func TestJSONRailRefEscapesAreText(t *testing.T) {
	e := newEnv(t, nil)
	body := `{"envelope":"ZW52","rail_ref":"aé😀\"\\/<>&","executor_pubkey":"` + b64(bytes.Repeat([]byte{7}, 32)) + `","executor_signature":"` + b64(bytes.Repeat([]byte{8}, 64)) + `"}`
	rec := e.postJSON("/v1/record", []byte(body))
	require.Equal(t, 200, rec.Code, rec.Body.String())
	require.Equal(t, "aé\U0001F600\"\\/<>&", e.gate.lastRef)
}

func TestJSONIntegerBoundary(t *testing.T) {
	_, pubHex := testKey(1)
	e := newEnv(t, map[string]string{"agent-a": pubHex})
	sig := b64(make([]byte, 64))
	// 2^53-1 is accepted by the JSON layer; the CBOR path then judges it (stale).
	body := `{"blob":"YQ==","agent_id":"agent-a","requested_at":9007199254740991,"signature":"` + sig + `"}`
	rec := e.postJSON("/v1/publish", []byte(body))
	require.NotEqual(t, 400, rec.Code, rec.Body.String())
}

func TestJSONMediaTypes(t *testing.T) {
	e := newEnv(t, nil)
	body := toJSON(t, authReq(t), authNames)
	for _, ct := range []string{"application/json", "application/json; charset=utf-8", "Application/JSON;charset=UTF-8"} {
		rec := e.doH(http.MethodPost, "/v1/authorize", map[string]string{"Content-Type": ct}, body)
		require.Equal(t, 200, rec.Code, ct)
		require.Equal(t, jsonType, rec.Header().Get("Content-Type"))
	}
	for _, ct := range []string{"application/json; charset=latin1", "text/json", "application/jsonx", "application/json-seq", "", "multipart/form-data"} {
		rec := e.doH(http.MethodPost, "/v1/authorize", map[string]string{"Content-Type": ct}, body)
		requireErr(t, rec, 415, "edictaapi.ErrMediaType", false)
	}
	// A CBOR body under the JSON type, and a JSON body under the CBOR type, are plain 400s.
	requireJSONErr(t, e.postJSON("/v1/authorize", authReq(t)), 400, "ErrMalformed")
	rec := e.post("/v1/authorize", body)
	require.Equal(t, 400, rec.Code)
	require.Equal(t, cborType, rec.Header().Get("Content-Type"))
	// Accept does not change the answer to a POST: it follows the request's media type.
	rec = e.doH(http.MethodPost, "/v1/authorize", map[string]string{"Content-Type": cborType, "Accept": jsonType}, authReq(t))
	require.Equal(t, 200, rec.Code)
	require.Equal(t, cborType, rec.Header().Get("Content-Type"))
	rec = e.doH(http.MethodPost, "/v1/authorize", map[string]string{"Content-Type": jsonType, "Accept": cborType}, body)
	require.Equal(t, 200, rec.Code)
	require.Equal(t, jsonType, rec.Header().Get("Content-Type"))
	require.Equal(t, "nosniff", rec.Header().Get("X-Content-Type-Options"))
}

func TestJSONRouteAndMethodErrorsAreJSON(t *testing.T) {
	e := newEnv(t, nil)
	hdr := map[string]string{"Content-Type": jsonType}
	requireJSONErr(t, e.doH(http.MethodPost, "/v1/nope", hdr, []byte(`{}`)), 404, "edictaapi.ErrRouteNotFound")
	rec := e.doH(http.MethodPut, "/v1/authorize", hdr, []byte(`{}`))
	requireJSONErr(t, rec, 405, "edictaapi.ErrMethodNotAllowed")
	require.Equal(t, http.MethodPost, rec.Header().Get("Allow"))
	rec = e.doH(http.MethodGet, "/v1/authorize", map[string]string{"Accept": jsonType}, nil)
	requireJSONErr(t, rec, 405, "edictaapi.ErrMethodNotAllowed")
	e = newEnv(t, nil, withoutPublisher())
	requireJSONErr(t, e.postJSON("/v1/publish", []byte(`{}`)), 404, "edictaapi.ErrPublishDisabled")
}

func TestJSONBodyLimits(t *testing.T) {
	e := newEnv(t, nil)
	// Far above any limit plus base64 overhead.
	for _, p := range []string{"/v1/authorize", "/v1/record", "/v1/publish"} {
		rec := e.postJSON(p, bytes.Repeat([]byte(" "), 4<<20))
		requireJSONErr(t, rec, 413, "ErrTooLarge")
	}
	// The CBOR limit still applies to the converted request: action of 67720
	// bytes makes the CBOR map 67772 > 67771 while the JSON stays under the
	// base64-adjusted limit.
	mk := func(action int) []byte {
		return []byte(`{"envelope":"` + b64([]byte("envelope")) + `","action":"` + b64(make([]byte, action)) + `","action_salt":"` + b64(testSalt) + `"}`)
	}
	requireJSONErr(t, e.postJSON("/v1/authorize", mk(67720)), 413, "ErrTooLarge")
	require.Zero(t, e.gate.calls())
	rec := e.postJSON("/v1/authorize", mk(67719))
	require.Equal(t, 200, rec.Code, rec.Body.String())
	require.Equal(t, 1, e.gate.calls())
	// The same two requests in CBOR give the same verdicts.
	cb := func(action int) []byte {
		return encMap(t, map[uint64]any{1: []byte("envelope"), 2: make([]byte, action), 3: testSalt})
	}
	require.Len(t, cb(67719), authorizeLimit)
	requireErr(t, e.post("/v1/authorize", cb(67720)), 413, "ErrTooLarge", false)
	require.Equal(t, 200, e.post("/v1/authorize", cb(67719)).Code)

	big := make([]byte, 2561)
	rec = e.postJSON("/v1/record", []byte(`{"envelope":"`+b64(big)+`","rail_ref":"r","executor_pubkey":"`+b64(make([]byte, 32))+`","executor_signature":"`+b64(make([]byte, 64))+`"}`))
	requireJSONErr(t, rec, 413, "ErrTooLarge")
}

func TestJSONPublishBlobLimit(t *testing.T) {
	e := newEnv(t, nil)
	blob := make([]byte, int(maxBlobVec)+1)
	body := `{"blob":"` + b64(blob) + `","agent_id":"agent-a","requested_at":5,"signature":"` + b64(make([]byte, 64)) + `"}`
	requireJSONErr(t, e.postJSON("/v1/publish", []byte(body)), 413, "ErrTooLarge")
	require.Zero(t, e.pub.count())
}

func TestJSONHealthNegotiation(t *testing.T) {
	e := newEnv(t, nil)
	e.health.info = edictaapi.HealthInfo{Status: 1, ChainID: "mocha-4", HeadHeight: 10, HeadTime: 20, GateID: gateIDVec,
		GatePubKey: bytes.Repeat([]byte{1}, 32), RecorderSigner: bytes.Repeat([]byte{2}, 20),
		Namespace: bytes.Repeat([]byte{3}, 29), AllowedDA: []uint64{1, 2}}
	plain := e.do(http.MethodGet, "/v1/health", "", nil)
	require.Equal(t, cborType, plain.Header().Get("Content-Type"))
	wantJSON := string(toJSON(t, plain.Body.Bytes(), healthNames))

	for accept, js := range map[string]bool{
		"":                                   false,
		"*/*":                                false,
		"application/cbor":                   false,
		"application/json":                   true,
		"application/json, application/cbor": false,
		"application/cbor, application/json": false,
		"application/json;q=0.9, application/cbor;q=0.5": true,
		"application/json;q=0.5, application/cbor;q=0.9": false,
		"application/json;q=0":                           false,
		"text/html, application/json;q=0.1":              true,
		"text/html":                                      false,
		"application/json;q=bogus":                       false,
		"APPLICATION/JSON":                               true,
	} {
		hdr := map[string]string{}
		if accept != "" {
			hdr["Accept"] = accept
		}
		rec := e.doH(http.MethodGet, "/v1/health", hdr, nil)
		require.Equal(t, 200, rec.Code, accept)
		if js {
			require.Equal(t, jsonType, rec.Header().Get("Content-Type"), accept)
			require.JSONEq(t, wantJSON, rec.Body.String(), accept)
		} else {
			require.Equal(t, cborType, rec.Header().Get("Content-Type"), accept)
			require.Equal(t, plain.Body.Bytes(), rec.Body.Bytes(), accept)
		}
	}

	e.health.err = gate.ErrClosed
	requireJSONErr(t, e.doH(http.MethodGet, "/v1/health", map[string]string{"Accept": jsonType}, nil), 503, "ErrClosed")
	requireErr(t, e.doH(http.MethodGet, "/v1/health", map[string]string{"Accept": cborType}, nil), 503, "ErrClosed", true)
}

func TestJSONHealthOptionalFieldsAbsent(t *testing.T) {
	e := newEnv(t, nil)
	e.health.info = edictaapi.HealthInfo{Status: 1, ChainID: "c", GateID: gateIDVec, GatePubKey: bytes.Repeat([]byte{1}, 32), AllowedDA: []uint64{2}}
	rec := e.doH(http.MethodGet, "/v1/health", map[string]string{"Accept": jsonType}, nil)
	var m map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &m))
	require.NotContains(t, m, "recorder_signer")
	require.NotContains(t, m, "namespace")
	require.Equal(t, []any{float64(2)}, m["allowed_da"])
}

func TestJSONResponseIntegerAboveSafeRangeIsInternal(t *testing.T) {
	e := newEnv(t, nil)
	e.health.info = edictaapi.HealthInfo{Status: 1, ChainID: "c", HeadHeight: 1 << 60, GateID: gateIDVec, GatePubKey: bytes.Repeat([]byte{1}, 32), AllowedDA: []uint64{2}}
	requireJSONErr(t, e.doH(http.MethodGet, "/v1/health", map[string]string{"Accept": jsonType}, nil), 500, "edictaapi.ErrInternal")
	require.Equal(t, 200, e.do(http.MethodGet, "/v1/health", "", nil).Code, "CBOR carries the full range")
}

func TestJSONAllowsInsignificantWhitespaceAndOrder(t *testing.T) {
	e := newEnv(t, nil)
	body := " \n\t{ \"action_salt\" : \"" + b64(testSalt) + "\" ,\r\n \"action\":\"YWN0\", \"envelope\" :\"ZW52\" }\n"
	rec := e.postJSON("/v1/authorize", []byte(body))
	require.Equal(t, 200, rec.Code, rec.Body.String())
	require.Equal(t, []byte("env"), e.gate.lastEnv)
	require.Equal(t, []byte("act"), e.gate.lastAction)
}

func TestJSONNeverReachesTheGateAsRewrittenBytes(t *testing.T) {
	// The envelope reaches the gate as the decoded base64, byte for byte,
	// including bytes that are not valid CBOR or UTF-8.
	e := newEnv(t, nil)
	raw := []byte{0xa1, 0x01, 0xff, 0x00, 0x80}
	rec := e.postJSON("/v1/authorize", []byte(`{"envelope":"`+b64(raw)+`","action":"YQ==","action_salt":"`+b64(testSalt)+`"}`))
	require.Equal(t, 200, rec.Code)
	require.Equal(t, raw, e.gate.lastEnv)
}

// ---- client ----

func TestClientJSONRoundTrips(t *testing.T) {
	ctx := context.Background()
	ce := newClientEnv(t, edictaapi.WithJSON())

	ce.pub.result, _ = testRef(t)
	got, err := ce.client.Publish(ctx, []byte("client blob"))
	require.NoError(t, err)
	require.Equal(t, ce.pub.result, got)
	require.Equal(t, []byte("client blob"), ce.pub.blobs[0])

	ce.gate.authFn = func(context.Context, []byte, []byte) (gate.Result, error) {
		return gate.Result{Authorization: []byte("auth-bytes"), PolicyVerdict: []byte("pv")}, nil
	}
	auth, verdict, err := ce.client.AuthorizeWithVerdict(ctx, []byte("env"), []byte("act"), testSalt)
	require.NoError(t, err)
	require.Equal(t, []byte("auth-bytes"), auth)
	require.Equal(t, []byte("pv"), verdict)
	require.Equal(t, []byte("env"), ce.gate.lastEnv)

	rc, err := ce.client.Record(ctx, []byte("env"), "rail", bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 64))
	require.NoError(t, err)
	require.Equal(t, []byte("receipt"), rc)

	ce.health.info = edictaapi.HealthInfo{Status: 2, ChainID: "mocha-4", HeadHeight: 5, HeadTime: 6, GateID: gateIDVec,
		GatePubKey: bytes.Repeat([]byte{1}, 32), RecorderSigner: bytes.Repeat([]byte{4}, 20), AllowedDA: []uint64{1, 2}}
	hi, err := ce.client.Health(ctx)
	require.NoError(t, err)
	require.Equal(t, ce.health.info, hi)
}

func TestClientJSONHeaders(t *testing.T) {
	var hdrs []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hdrs = append(hdrs, r.Method+"|"+r.Header.Get("Content-Type")+"|"+r.Header.Get("Accept"))
		w.Header().Set("Content-Type", jsonType)
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`{"status":1,"chain_id":"c","head_height":1,"head_time":2,"gate_id":"g","gate_pubkey":"` + b64(make([]byte, 32)) + `","allowed_da":[2]}`))
			return
		}
		_, _ = w.Write([]byte(`{"signed_authorization":"YQ=="}`))
	}))
	t.Cleanup(srv.Close)
	c, err := edictaapi.NewClient(srv.URL, edictaapi.Secret{}, nil, srv.Client(), edictaapi.WithJSON())
	require.NoError(t, err)
	_, err = c.Authorize(context.Background(), []byte("e"), []byte("a"), testSalt)
	require.NoError(t, err)
	_, err = c.Health(context.Background())
	require.NoError(t, err)
	require.Equal(t, []string{"POST|application/json|application/json", "GET||application/json"}, hdrs)
}

func TestClientJSONErrors(t *testing.T) {
	ctx := context.Background()
	ce := newClientEnv(t, edictaapi.WithJSON())
	stored := []byte("stored-auth")
	ce.gate.authFn = func(context.Context, []byte, []byte) (gate.Result, error) {
		return gate.Result{Authorization: stored}, gate.ErrNonceUsed
	}
	_, err := ce.client.Authorize(ctx, []byte("env"), []byte("act"), testSalt)
	require.ErrorIs(t, err, gate.ErrNonceUsed)
	var ae *edictaapi.Error
	require.ErrorAs(t, err, &ae)
	require.Equal(t, 409, ae.Status)
	require.Equal(t, stored, ae.Stored)

	ce.gate.authFn = func(context.Context, []byte, []byte) (gate.Result, error) {
		return gate.Result{}, gate.ErrChainUnavailable
	}
	_, err = ce.client.Authorize(ctx, []byte("env"), []byte("act"), testSalt)
	require.ErrorIs(t, err, gate.ErrChainUnavailable)
	require.ErrorAs(t, err, &ae)
	require.True(t, ae.Retryable)

	_, err = ce.client.Authorize(ctx, []byte("env"), []byte("act"), testSalt[:5])
	require.ErrorIs(t, err, commitment.ErrFieldSize)
}

func TestClientJSONSendsTheSameBytesAsCBOR(t *testing.T) {
	cb := newClientEnv(t)
	js := newClientEnv(t, edictaapi.WithJSON())
	ctx := context.Background()
	envBytes := []byte{0xde, 0xad, 0xbe, 0xef, 0, 1, 2}
	_, err := cb.client.Authorize(ctx, envBytes, []byte("act"), testSalt)
	require.NoError(t, err)
	_, err = js.client.Authorize(ctx, envBytes, []byte("act"), testSalt)
	require.NoError(t, err)
	require.Equal(t, cb.gate.lastEnv, js.gate.lastEnv)
	require.Equal(t, cb.gate.lastAction, js.gate.lastAction)
	require.Equal(t, cb.gate.lastSalt, js.gate.lastSalt)
}

func TestClientJSONRejectsBadResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", jsonType)
		_, _ = w.Write([]byte(`{"signed_authorization":"YQ==","signed_authorization":"Yg=="}`))
	}))
	t.Cleanup(srv.Close)
	c, err := edictaapi.NewClient(srv.URL, edictaapi.Secret{}, nil, srv.Client(), edictaapi.WithJSON())
	require.NoError(t, err)
	_, err = c.Authorize(context.Background(), []byte("e"), []byte("a"), testSalt)
	require.ErrorIs(t, err, commitment.ErrMalformed)

	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(502)
		_, _ = w.Write([]byte(`not json`))
	}))
	t.Cleanup(srv2.Close)
	c, err = edictaapi.NewClient(srv2.URL, edictaapi.Secret{}, nil, srv2.Client(), edictaapi.WithJSON())
	require.NoError(t, err)
	_, err = c.Authorize(context.Background(), []byte("e"), []byte("a"), testSalt)
	require.ErrorIs(t, err, edictaapi.ErrInternal)
}

func TestJSONVaryAndMediaTypeClassifier(t *testing.T) {
	e := newEnv(t, nil)
	for _, rec := range []*httptest.ResponseRecorder{
		e.doH(http.MethodGet, "/v1/health", nil, nil),
		e.postJSON("/v1/authorize", toJSON(t, authReq(t), authNames)),
		e.post("/v1/authorize", authReq(t)),
	} {
		require.Equal(t, "Accept, Content-Type", rec.Header().Get("Vary"))
	}
	for ct, want := range map[string][2]bool{
		"application/json":                 {true, true},
		"application/json; foo=bar":        {true, true},
		"application/cbor":                 {false, true},
		"application/problem+json":         {false, false},
		"application/json; charset=latin1": {false, false},
		"":                                 {false, false},
	} {
		isJSON, ok := edictaapi.MediaType(ct)
		require.Equal(t, want, [2]bool{isJSON, ok}, ct)
	}
}

func TestClientJSONFollowsResponseMediaType(t *testing.T) {
	var ctype string
	var body []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", ctype)
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	c, err := edictaapi.NewClient(srv.URL, edictaapi.Secret{}, nil, srv.Client(), edictaapi.WithJSON())
	require.NoError(t, err)

	ctype, body = cborType, encMap(t, map[uint64]any{1: []byte("auth")})
	got, err := c.Authorize(context.Background(), []byte("e"), []byte("a"), testSalt)
	require.NoError(t, err)
	require.Equal(t, []byte("auth"), got)

	ctype, body = "text/html", []byte(`{"signed_authorization":"YQ=="}`)
	_, err = c.Authorize(context.Background(), []byte("e"), []byte("a"), testSalt)
	require.ErrorIs(t, err, commitment.ErrMalformed)
	require.ErrorContains(t, err, "unexpected content type")
}
