// SPDX-License-Identifier: Apache-2.0

package edictad_test

import (
	"bytes"
	"encoding/base64"
	"io"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

func postType(t *testing.T, addr, path, ctype, authz string, body []byte) (*http.Response, []byte) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, "http://"+addr+path, bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", ctype)
	if authz != "" {
		req.Header.Set("Authorization", authz)
	}
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp, b
}

func TestBearerTokensCoverJSON(t *testing.T) {
	e := newEnv(t)
	e.start(
		rep(`authorize_token_file = ""`, `authorize_token_file = "`+e.path("auth.token")+`"`),
		rep(`record_token_file = ""`, `record_token_file = "`+e.path("rec.token")+`"`))
	b64 := base64.StdEncoding.EncodeToString
	jsonBodies := map[string][]byte{
		"/v1/authorize": []byte(`{"envelope":"ZQ==","action":"YQ==","action_salt":"` + b64(testSalt) + `"}`),
		"/v1/record":    []byte(`{"envelope":"ZQ==","rail_ref":"r","executor_pubkey":"` + b64(e.execPub) + `","executor_signature":"` + b64(make([]byte, 64)) + `"}`),
	}
	tokens := map[string]string{"/v1/authorize": canaryAuthTok, "/v1/record": canaryRecTok}
	addr := e.srv.Addr()

	for path, body := range jsonBodies {
		for _, authz := range []string{"", "Bearer wrong", "Bearer " + tokens[path] + "x", "Basic " + tokens[path]} {
			resp, got := postType(t, addr, path, "application/json", authz, body)
			require.Equal(t, http.StatusUnauthorized, resp.StatusCode, "%s %q", path, authz)
			require.Equal(t, "Bearer", resp.Header.Get("WWW-Authenticate"))
			require.Equal(t, "application/json", resp.Header.Get("Content-Type"))
			require.JSONEq(t, `{"code":"edictaapi.ErrTokenInvalid","message":"edictaapi: bearer token missing or invalid","retryable":0}`, string(got))
		}
		// charset parameter and letter case do not change the classification
		resp, _ := postType(t, addr, path, "Application/JSON; charset=utf-8", "", body)
		require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	}
	a, r := e.spy.calls()
	require.Zero(t, a+r, "the gate must not be reached without a valid token")

	resp, got := postType(t, addr, "/v1/authorize", "application/json", "Bearer "+canaryAuthTok, jsonBodies["/v1/authorize"])
	require.Equal(t, http.StatusOK, resp.StatusCode, string(got))
	require.Equal(t, "application/json", resp.Header.Get("Content-Type"))
	resp, got = postType(t, addr, "/v1/record", "application/json", "Bearer "+canaryRecTok, jsonBodies["/v1/record"])
	require.Equal(t, http.StatusOK, resp.StatusCode, string(got))
	a, r = e.spy.calls()
	require.Equal(t, 2, a+r)

	// CBOR is unchanged: still guarded, still a CBOR body.
	resp, got = postType(t, addr, "/v1/authorize", "application/cbor", "", authorizeBody("e", "a"))
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	require.Equal(t, "application/cbor", resp.Header.Get("Content-Type"))
	require.Equal(t, byte(0xa3), got[0])

	// A type the API refuses is refused with 415 before anything runs, token or not.
	for _, ct := range []string{"text/plain", "", "application/json-seq", "application/problem+json", "application/json; charset=latin1"} {
		for _, authz := range []string{"", "Bearer " + canaryAuthTok} {
			resp, _ = postType(t, addr, "/v1/authorize", ct, authz, jsonBodies["/v1/authorize"])
			require.Equal(t, http.StatusUnsupportedMediaType, resp.StatusCode, "%q %q", ct, authz)
		}
	}
	a2, r2 := e.spy.calls()
	require.Equal(t, a+r, a2+r2)
}
