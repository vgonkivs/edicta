// SPDX-License-Identifier: Apache-2.0

package signer_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/api/edictaapi"
	"github.com/vgonkivs/edicta/api/signerapi"
	"github.com/vgonkivs/edicta/services/signer"
	"github.com/vgonkivs/edicta/services/signer/signertest"
)

const token = "0123456789abcdef-token"

func newAPI(t *testing.T, e *env, o signer.HTTPOptions) *httptest.Server {
	t.Helper()
	if o.Token == nil {
		o.Token = []byte(token)
	}
	h, err := signer.NewHandler(e.svc, o, quiet)
	require.NoError(t, err)
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv
}

func post(t *testing.T, srv *httptest.Server, ctype string, body []byte, mut ...func(*http.Request)) (*http.Response, []byte) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, srv.URL+signerapi.RouteSign, bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("Authorization", "Bearer "+token)
	for _, m := range mut {
		m(req)
	}
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp, b
}

func errorCode(t *testing.T, ctype string, body []byte) string {
	t.Helper()
	if ctype == "application/json" {
		var e struct {
			Code string `json:"code"`
		}
		require.NoError(t, json.Unmarshal(body, &e))
		return e.Code
	}
	js, err := edictaapi.WrapperToJSON(body, edictaapi.ErrorSchema)
	require.NoError(t, err)
	return errorCode(t, "application/json", js)
}

func TestHTTPSignCBORAndJSONGiveTheSameBytes(t *testing.T) {
	e := newEnv(t)
	srv := newAPI(t, e, signer.HTTPOptions{})
	d := e.decision(signertest.DecisionOpts{})

	resp, body := post(t, srv, "application/cbor", signerapi.EncodeSignRequest(request(d)))
	require.Equal(t, http.StatusOK, resp.StatusCode, string(body))
	assert.Equal(t, "application/cbor", resp.Header.Get("Content-Type"))
	out, err := signerapi.DecodeSignResponse(body)
	require.NoError(t, err)
	assert.False(t, out.Repeat)
	assert.Equal(t, d.Hash, out.CommitmentHash)

	js, err := json.Marshal(map[string]string{
		"envelope": base64.StdEncoding.EncodeToString(d.Envelope), "action": base64.StdEncoding.EncodeToString(d.Action),
		"action_salt": base64.StdEncoding.EncodeToString(d.Salt), "signed_authorization": base64.StdEncoding.EncodeToString(d.Authorization),
	})
	require.NoError(t, err)
	resp, body = post(t, srv, "application/json", js)
	require.Equal(t, http.StatusOK, resp.StatusCode, string(body))
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
	var got struct {
		SignedTx string `json:"signed_tx"`
		RailRef  string `json:"rail_ref"`
		Repeat   int    `json:"repeat"`
	}
	require.NoError(t, json.Unmarshal(body, &got))
	assert.Equal(t, base64.StdEncoding.EncodeToString(out.Signed), got.SignedTx)
	assert.Equal(t, out.RailRef, got.RailRef)
	assert.Equal(t, 1, got.Repeat)
}

func TestHTTPRefusals(t *testing.T) {
	e := newEnv(t)
	srv := newAPI(t, e, signer.HTTPOptions{})
	good := signerapi.EncodeSignRequest(request(e.decision(signertest.DecisionOpts{})))

	cases := []struct {
		name   string
		ctype  string
		body   []byte
		mut    func(*http.Request)
		status int
		code   string
	}{
		{"no token", "application/cbor", good, func(r *http.Request) { r.Header.Del("Authorization") }, 401, "edictaapi.ErrTokenInvalid"},
		{"wrong token", "application/cbor", good, func(r *http.Request) { r.Header.Set("Authorization", "Bearer x"+token) }, 401, "edictaapi.ErrTokenInvalid"},
		{"Host not loopback", "application/cbor", good, func(r *http.Request) { r.Host = "evil.example:8402" }, 401, "edictaapi.ErrTokenInvalid"},
		{"media type", "text/plain", good, nil, 415, "edictaapi.ErrMediaType"},
		{"route", "application/cbor", good, func(r *http.Request) { r.URL.Path = "/v1/release" }, 404, "edictaapi.ErrRouteNotFound"},
		{"method", "application/cbor", good, func(r *http.Request) { r.Method = http.MethodPut }, 405, "edictaapi.ErrMethodNotAllowed"},
		{"too large", "application/cbor", make([]byte, signerapi.SignLimit+1), nil, 413, "ErrTooLarge"},
		{"trailing bytes", "application/cbor", append(append([]byte(nil), good...), 0x00), nil, 400, "ErrTrailingData"},
		{"missing field", "application/cbor", edictaapi.EncodeWrapper(edictaapi.BytesItem(1, []byte{1})), nil, 400, "ErrMissingField"},
		{"json duplicate member", "application/json", []byte(`{"envelope":"AA==","envelope":"AA=="}`), nil, 400, "ErrMalformed"},
		{"json unknown member", "application/json", []byte(`{"amount":"AA=="}`), nil, 400, "ErrMalformed"},
		{"json non-canonical base64", "application/json", []byte(`{"envelope":"AB=="}`), nil, 400, "ErrMalformed"},
		{"json number for bytes", "application/json", []byte(`{"envelope":1}`), nil, 400, "ErrWrongType"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var muts []func(*http.Request)
			if tc.mut != nil {
				muts = append(muts, tc.mut)
			}
			resp, body := post(t, srv, tc.ctype, tc.body, muts...)
			assert.Equal(t, tc.status, resp.StatusCode, string(body))
			ctype := "application/cbor"
			if strings.HasPrefix(tc.ctype, "application/json") {
				ctype = "application/json"
			}
			assert.Equal(t, tc.code, errorCode(t, ctype, body))
		})
	}
	assert.Zero(t, e.chain.SentCount(), "no refused request reached the chain")
}

func TestHTTPRefusalOfTheSignerHasItsCode(t *testing.T) {
	e := newEnv(t)
	srv := newAPI(t, e, signer.HTTPOptions{})
	r := request(e.decision(signertest.DecisionOpts{}))
	r.Salt = make([]byte, 32)
	resp, body := post(t, srv, "application/cbor", signerapi.EncodeSignRequest(r))
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	assert.Equal(t, "signer.ErrNotAuthorized", errorCode(t, "application/cbor", body))

	e.chain.Set(func(c *signertest.Chain) { c.CodeErr = io.ErrUnexpectedEOF })
	resp, body = post(t, srv, "application/cbor", signerapi.EncodeSignRequest(request(e.decision(signertest.DecisionOpts{Label: "x"}))))
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode, "a failed code check refuses, retryably")
	assert.Equal(t, "signer.ErrUnavailable", errorCode(t, "application/cbor", body))
}

func TestHTTPHealthNeedsTheToken(t *testing.T) {
	e := newEnv(t)
	srv := newAPI(t, e, signer.HTTPOptions{})
	req, err := http.NewRequest(http.MethodGet, srv.URL+signerapi.RouteHealth, nil)
	require.NoError(t, err)
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	resp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	resp, err = srv.Client().Do(req)
	require.NoError(t, err)
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.JSONEq(t, `{"status":"ok"}`, string(b))
}

func TestHTTPOptionsAndBind(t *testing.T) {
	require.Error(t, signer.HTTPOptions{Token: []byte("short")}.ValidateBasic())
	require.NoError(t, signer.CheckBind("127.0.0.1:8402", false))
	require.NoError(t, signer.CheckBind("[::1]:8402", false))
	require.Error(t, signer.CheckBind("0.0.0.0:8402", false))
	require.NoError(t, signer.CheckBind("0.0.0.0:8402", true))
}
