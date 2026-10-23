// SPDX-License-Identifier: Apache-2.0

package signer_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/api/edictaapi"
	"github.com/vgonkivs/edicta/api/signerapi"
	"github.com/vgonkivs/edicta/engine/commitment"
	"github.com/vgonkivs/edicta/plugins/edenescrow"
	"github.com/vgonkivs/edicta/services/signer"
	"github.com/vgonkivs/edicta/services/signer/signertest"
)

var updateWire = flag.Bool("update-wire", false, "rewrite testdata/wire.golden.json")

// wireCase is one pinned message: a codec value or an HTTP answer. A JSON
// body is kept as text, a CBOR body as hex.
type wireCase struct {
	Name    string            `json:"name"`
	Status  int               `json:"status,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
	CBOR    string            `json:"cbor_hex,omitempty"`
	JSON    string            `json:"json,omitempty"`
}

// wireTime fixes the clock so that every decision, signature and receipt of
// the pinned answers is the same on every run.
var wireTime = time.Unix(1_800_000_000, 0)

// TestWireFormatIsPinned pins the bytes of every request and answer of the
// signer API, in CBOR and in JSON, and the status, code and body of every
// refusal, against testdata/wire.golden.json.
func TestWireFormatIsPinned(t *testing.T) {
	var got []wireCase
	got = append(got, codecCases(t)...)
	got = append(got, flowCases(t)...)
	got = append(got, refusalCases(t)...)

	path := filepath.Join("testdata", "wire.golden.json")
	if *updateWire {
		b, err := json.MarshalIndent(got, "", "  ")
		require.NoError(t, err)
		require.NoError(t, os.MkdirAll("testdata", 0o755))
		require.NoError(t, os.WriteFile(path, append(b, '\n'), 0o644))
	}
	b, err := os.ReadFile(path)
	require.NoError(t, err)
	var want []wireCase
	require.NoError(t, json.Unmarshal(b, &want))
	require.Equal(t, len(want), len(got), "number of pinned cases")
	for i := range want {
		assert.Equal(t, want[i], got[i])
	}
}

func (c *clock) set(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = t
}

func fill(b byte, n int) []byte { return bytes.Repeat([]byte{b}, n) }

func toJSON(t *testing.T, cbor []byte, s edictaapi.Schema) string {
	t.Helper()
	js, err := edictaapi.WrapperToJSON(cbor, s)
	require.NoError(t, err)
	back, err := edictaapi.JSONToWrapper(js, s)
	require.NoError(t, err)
	require.Equal(t, cbor, back, "JSON and CBOR carry the same message")
	return string(js)
}

func codecCases(t *testing.T) []wireCase {
	t.Helper()
	var out []wireCase
	add := func(name string, cbor []byte, s edictaapi.Schema) {
		out = append(out, wireCase{Name: "codec/" + name, CBOR: hex.EncodeToString(cbor), JSON: toJSON(t, cbor, s)})
	}
	req := signer.Request{Envelope: fill(1, 3), Action: fill(2, 4), Salt: fill(3, 32), Authorization: fill(4, 5)}
	reqR := req
	reqR.Requirements = []byte(`{"x402Version":2}`)
	for _, r := range []signer.Request{req, reqR} {
		back, err := signerapi.DecodeSignRequest(signerapi.EncodeSignRequest(r))
		require.NoError(t, err)
		assert.Equal(t, r, back)
	}
	add("sign-request", signerapi.EncodeSignRequest(req), signerapi.SignRequestSchema)
	add("sign-request-requirements", signerapi.EncodeSignRequest(reqR), signerapi.SignRequestSchema)

	var ch commitment.Hash
	copy(ch[:], fill(5, 32))
	for _, r := range []signer.Request{req, reqR} {
		p := signer.PaymentProofRequest{CommitmentHash: ch, Field: "paymentId", Request: r}
		b := signerapi.EncodePaymentRequest(p)
		back, err := signerapi.DecodePaymentRequest(b)
		require.NoError(t, err)
		assert.Equal(t, p, back)
	}
	add("payment-request", signerapi.EncodePaymentRequest(signer.PaymentProofRequest{CommitmentHash: ch, Field: "paymentId", Request: req}), signerapi.PaymentRequestSchema)
	add("payment-request-requirements", signerapi.EncodePaymentRequest(signer.PaymentProofRequest{CommitmentHash: ch, Field: "paymentId", Request: reqR}), signerapi.PaymentRequestSchema)

	for _, repeat := range []bool{false, true} {
		var rep uint64
		if repeat {
			rep = 1
		}
		b := edictaapi.EncodeWrapper(edictaapi.BytesItem(1, fill(6, 7)), edictaapi.TextItem(2, "0xrailref"),
			edictaapi.BytesItem(3, ch[:]), edictaapi.UintItem(4, rep))
		o, err := signerapi.DecodeSignResponse(b)
		require.NoError(t, err)
		assert.Equal(t, signer.Output{CommitmentHash: ch, Signed: fill(6, 7), RailRef: "0xrailref", Repeat: repeat}, o)
		assert.Equal(t, b, signerapi.EncodeSignResponse(o))
		add(fmt.Sprintf("sign-response-repeat-%t", repeat), b, signerapi.SignResponseSchema)
	}

	pb := edictaapi.EncodeWrapper(edictaapi.TextItem(1, "0xproof"), edictaapi.BytesItem(2, fill(7, 32)), edictaapi.UintItem(3, 1))
	p, err := signerapi.DecodePaymentResponse(pb)
	require.NoError(t, err)
	assert.Equal(t, signer.PaymentProof{Message: [32]byte(fill(7, 32)), Signature: []byte("0xproof"), Repeat: true}, p)
	assert.Equal(t, pb, signerapi.EncodePaymentResponse(p))
	add("payment-response", pb, signerapi.PaymentResponseSchema)

	full := edictaapi.EncodeWrapper(
		edictaapi.TextItem(1, string(signer.StateRecorded)), edictaapi.BytesItem(2, ch[:]), edictaapi.UintItem(3, 1),
		edictaapi.TextItem(4, "0xrailref"), edictaapi.BytesItem(5, fill(6, 7)), edictaapi.TextItem(6, "executed"),
		edictaapi.TextItem(7, "detail"), edictaapi.UintItem(8, 1), edictaapi.BytesItem(9, fill(8, 9)),
	)
	st, err := signerapi.DecodeStatusResponse(full)
	require.NoError(t, err)
	assert.Equal(t, signer.Status{State: signer.StateRecorded, Sent: true, RailRef: "0xrailref", Signed: fill(6, 7),
		Outcome: "executed", Detail: "detail", PaymentProofAllowed: true, Receipt: fill(8, 9)}, st)
	assert.Equal(t, full, signerapi.EncodeStatusResponse(ch, st))
	add("status-response-full", full, signerapi.StatusResponseSchema)
	minimal := edictaapi.EncodeWrapper(edictaapi.TextItem(1, string(signer.StateReserved)), edictaapi.BytesItem(2, ch[:]),
		edictaapi.UintItem(3, 0), edictaapi.UintItem(8, 0))
	st, err = signerapi.DecodeStatusResponse(minimal)
	require.NoError(t, err)
	assert.Equal(t, signer.Status{State: signer.StateReserved}, st)
	assert.Equal(t, minimal, signerapi.EncodeStatusResponse(ch, st))
	add("status-response-minimal", minimal, signerapi.StatusResponseSchema)

	add("requeue-request", edictaapi.EncodeWrapper(edictaapi.BytesItem(1, ch[:])), signerapi.RequeueRequestSchema)
	add("requeue-response", edictaapi.EncodeWrapper(edictaapi.TextItem(1, string(signer.StateSigned))), signerapi.RequeueResponseSchema)
	add("health-response", edictaapi.EncodeWrapper(edictaapi.TextItem(1, "ok")), signerapi.HealthSchema)

	states := []signer.State{signer.StateReserved, signer.StateSigned, signer.StateExecuted, signer.StateReverted,
		signer.StateRecorded, signer.StateNotExecuted, signer.StateWrong}
	routes := []string{signerapi.RouteSign, signerapi.RouteHealth, signerapi.RouteRequeue, signerapi.RoutePaymentSignature, signerapi.RouteStatusPrefix}
	limits := []int{signerapi.MaxRequirementsSize, signerapi.SignLimit, signerapi.PaymentLimit}
	consts, err := json.Marshal(map[string]any{"states": states, "routes": routes, "limits": limits})
	require.NoError(t, err)
	out = append(out, wireCase{Name: "constants", JSON: string(consts)})
	return out
}

// pinServer serves one env's API and records each answer as a wireCase.
type pinServer struct {
	t   *testing.T
	srv *httptest.Server
}

func newPinServer(t *testing.T, e *env, o signer.HTTPOptions) *pinServer {
	t.Helper()
	h, err := signer.NewHandler(e.svc, o, quiet)
	require.NoError(t, err)
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return &pinServer{t: t, srv: srv}
}

// do sends one request; ctype is the request's Content-Type and accept its
// Accept header (either may be empty).
func (p *pinServer) do(name, method, path, tok, ctype, accept string, body []byte) wireCase {
	t := p.t
	t.Helper()
	req, err := http.NewRequest(method, p.srv.URL+path, bytes.NewReader(body))
	require.NoError(t, err)
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	resp, err := p.srv.Client().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	c := wireCase{Name: "http/" + name, Status: resp.StatusCode, Headers: map[string]string{}}
	for _, h := range []string{"Content-Type", "Allow", "Vary", "X-Content-Type-Options", "Cache-Control"} {
		if v := resp.Header.Get(h); v != "" {
			c.Headers[h] = v
		}
	}
	if resp.Header.Get("Content-Type") == "application/json" {
		c.JSON = string(b)
	} else {
		c.CBOR = hex.EncodeToString(b)
	}
	return c
}

// both sends a POST body in CBOR and again in JSON.
func (p *pinServer) both(name, path, tok string, cbor []byte, s edictaapi.Schema) []wireCase {
	p.t.Helper()
	js, err := edictaapi.WrapperToJSON(cbor, s)
	require.NoError(p.t, err)
	return []wireCase{
		p.do(name+"/cbor", http.MethodPost, path, tok, "application/cbor", "", cbor),
		p.do(name+"/json", http.MethodPost, path, tok, "application/json", "", js),
	}
}

// get sends a GET asking for CBOR and again for JSON.
func (p *pinServer) get(name, path, tok string) []wireCase {
	p.t.Helper()
	return []wireCase{
		p.do(name+"/cbor", http.MethodGet, path, tok, "", "", nil),
		p.do(name+"/json", http.MethodGet, path, tok, "", "application/json", nil),
	}
}

// flowCases pins the answers of a payment-mode decision from the first
// signature to its payment proof.
func flowCases(t *testing.T) []wireCase {
	t.Helper()
	e := paymentEnv(t)
	e.clk.set(wireTime)
	d, dep := e.quoted("wire")
	const agentToken, otherToken = "agent-a-token-0123456789", "agent-b-token-0123456789"
	p := newPinServer(t, e, signer.HTTPOptions{Credentials: []signer.Credential{
		{Token: []byte(agentToken), Agent: e.keys.AgentPub()},
		{Token: []byte(otherToken), Agent: otherAgent.Public().(ed25519.PublicKey)},
	}})
	status := signerapi.RouteStatusPrefix + hex.EncodeToString(d.Hash[:])

	var out []wireCase
	out = append(out, p.get("flow/status-before", status, agentToken)...)
	out = append(out, p.both("flow/sign", signerapi.RouteSign, agentToken, signerapi.EncodeSignRequest(quotedRequest(d, dep)), signerapi.SignRequestSchema)...)
	out = append(out, p.get("flow/status-signed", status, agentToken)...)
	out = append(out, p.both("flow/payment-before-execution", signerapi.RoutePaymentSignature, agentToken,
		signerapi.EncodePaymentRequest(proofRequest(d)), signerapi.PaymentRequestSchema)...)

	signed := e.entry(d.Hash).Signed
	e.second.Land(signed)
	e.waitState(d.Hash, signer.StateRecorded)
	out = append(out, p.get("flow/status-recorded", status, agentToken)...)
	out = append(out, p.get("flow/status-other-agent", status, otherToken)...)
	out = append(out, p.both("flow/payment", signerapi.RoutePaymentSignature, agentToken,
		signerapi.EncodePaymentRequest(proofRequest(d)), signerapi.PaymentRequestSchema)...)
	out = append(out, p.both("flow/payment-other-agent", signerapi.RoutePaymentSignature, otherToken,
		signerapi.EncodePaymentRequest(proofRequest(d)), signerapi.PaymentRequestSchema)...)
	other := proofRequest(d)
	other.Field = "nonce"
	out = append(out, p.both("flow/payment-field", signerapi.RoutePaymentSignature, agentToken,
		signerapi.EncodePaymentRequest(other), signerapi.PaymentRequestSchema)...)
	return out
}

// failingCheck refuses every request at the profile's checks with err when
// it is set, and reports a settlement in state wrong.
type failingCheck struct {
	signer.Handler
	err *error
}

func (f failingCheck) Check(ctx context.Context, v signer.Verified, now time.Time) (signer.Plan, error) {
	if *f.err != nil {
		return signer.Plan{}, *f.err
	}
	return f.Handler.Check(ctx, v, now)
}

func (f failingCheck) Settle(context.Context, signer.Entry, bool) (signer.Settlement, error) {
	return signer.Settlement{State: signer.StateWrong, Detail: "pinned wrong state"}, nil
}

// refusalCases pins the answer to every refusal class of the error table, in
// table order, the order in which classes that wrap each other match, and the
// transport refusals.
func refusalCases(t *testing.T) []wireCase {
	t.Helper()
	var checkErr error
	e := newEnvOpts(t, envOpts{wrap: func(h signer.Handler) signer.Handler { return failingCheck{h, &checkErr} }})
	e.clk.set(wireTime)
	const adminToken, agentToken = "admin-token-0123456789", "agent-a-token-0123456789"
	p := newPinServer(t, e, signer.HTTPOptions{Token: []byte(token), AdminToken: []byte(adminToken),
		Credentials: []signer.Credential{{Token: []byte(agentToken), Agent: e.keys.AgentPub()}}})
	d := e.decision(signertest.DecisionOpts{Label: "wire"})
	good := signerapi.EncodeSignRequest(request(d))

	classes := []struct {
		name string
		err  error
	}{
		{"unavailable", signer.ErrUnavailable},
		{"expired", signer.ErrExpired},
		{"not-authorized", signer.ErrNotAuthorized},
		{"pin-mismatch", signer.ErrPinMismatch},
		{"escrow-code", signer.ErrEscrowCode},
		{"fast-mode-refused", signer.ErrFastModeRefused},
		{"digest-conflict", signer.ErrDigestConflict},
		{"not-requeueable", signer.ErrNotRequeueable},
		{"unknown-decision", signer.ErrUnknownDecision},
		{"shared-credential", signer.ErrSharedCredential},
		{"risk-limit", signer.ErrRiskLimit},
		{"not-executed", signer.ErrNotExecuted},
		{"requirements", signer.ErrRequirements},
		{"edenescrow-requirements", edenescrow.ErrRequirements},
		{"edenescrow-malformed", edenescrow.ErrMalformed},
		{"edenescrow-unknown-domain", edenescrow.ErrUnknownDomain},
		{"token-invalid", edictaapi.ErrTokenInvalid},
		{"route-not-found", edictaapi.ErrRouteNotFound},
		{"method-not-allowed", edictaapi.ErrMethodNotAllowed},
		{"media-type", edictaapi.ErrMediaType},
		{"too-large", commitment.ErrTooLarge},
		{"deadline", edictaapi.ErrDeadline},
		{"malformed", commitment.ErrMalformed},
		{"trailing-data", commitment.ErrTrailingData},
		{"float", commitment.ErrFloat},
		{"simple-value", commitment.ErrSimpleValue},
		{"tag", commitment.ErrTag},
		{"indefinite-length", commitment.ErrIndefiniteLength},
		{"non-minimal-int", commitment.ErrNonMinimalInt},
		{"nesting-too-deep", commitment.ErrNestingTooDeep},
		{"unsorted-map", commitment.ErrUnsortedMap},
		{"duplicate-key", commitment.ErrDuplicateKey},
		{"key-type", commitment.ErrKeyType},
		{"invalid-string", commitment.ErrInvalidString},
		{"unknown-key", commitment.ErrUnknownKey},
		{"wrong-type", commitment.ErrWrongType},
		{"missing-field", commitment.ErrMissingField},
		{"field-size", commitment.ErrFieldSize},
		{"internal", errors.New("pinned internal failure")},
		{"order/escrow-code-unavailable", fmt.Errorf("%w: %w", signer.ErrEscrowCode, signer.ErrUnavailable)},
		{"order/pin-mismatch-unavailable", fmt.Errorf("%w: %w", signer.ErrPinMismatch, signer.ErrUnavailable)},
		{"order/requirements-edenescrow", fmt.Errorf("%w: %w", signer.ErrRequirements, edenescrow.ErrRequirements)},
		{"order/pin-mismatch-edenescrow", fmt.Errorf("%w: %w", edenescrow.ErrRequirements, signer.ErrPinMismatch)},
		{"order/edenescrow-malformed-cbor", fmt.Errorf("%w: %w", commitment.ErrMalformed, edenescrow.ErrMalformed)},
		{"order/edenescrow-deadline", fmt.Errorf("%w: %w", edictaapi.ErrDeadline, edenescrow.ErrUnknownDomain)},
		{"order/token-malformed", fmt.Errorf("%w: %w", commitment.ErrMalformed, edictaapi.ErrTokenInvalid)},
	}
	var out []wireCase
	for _, c := range classes {
		checkErr = fmt.Errorf("%w: pinned", c.err)
		out = append(out, p.both("refusal/"+c.name, signerapi.RouteSign, token, good, signerapi.SignRequestSchema)...)
	}
	checkErr = nil

	big := request(d)
	big.Requirements = fill('x', signerapi.MaxRequirementsSize+1)
	statusPath := signerapi.RouteStatusPrefix + hex.EncodeToString(d.Hash[:])
	out = append(out,
		p.do("transport/route", http.MethodPost, "/v1/release", token, "application/cbor", "", good),
		p.do("transport/method-sign", http.MethodPut, signerapi.RouteSign, token, "application/cbor", "", good),
		p.do("transport/method-payment", http.MethodGet, signerapi.RoutePaymentSignature, token, "", "", nil),
		p.do("transport/method-status", http.MethodPost, statusPath, agentToken, "application/cbor", "", good),
		p.do("transport/method-health", http.MethodPost, signerapi.RouteHealth, token, "application/cbor", "", good),
		p.do("transport/media-type", http.MethodPost, signerapi.RouteSign, token, "text/plain", "", good),
		p.do("transport/no-token", http.MethodPost, signerapi.RouteSign, "", "application/cbor", "", good),
		p.do("transport/wrong-token", http.MethodPost, signerapi.RouteSign, "x"+token, "application/cbor", "", good),
		p.do("transport/admin-token-on-sign", http.MethodPost, signerapi.RouteSign, adminToken, "application/cbor", "", good),
		p.do("transport/too-large", http.MethodPost, signerapi.RouteSign, token, "application/cbor", "", make([]byte, signerapi.SignLimit+1)),
		p.do("transport/payment-too-large", http.MethodPost, signerapi.RoutePaymentSignature, token, "application/cbor", "", make([]byte, signerapi.PaymentLimit+1)),
		p.do("transport/requirements-too-large", http.MethodPost, signerapi.RouteSign, token, "application/cbor", "", signerapi.EncodeSignRequest(big)),
		p.do("transport/trailing", http.MethodPost, signerapi.RouteSign, token, "application/cbor", "", append(bytes.Clone(good), 0)),
		p.do("transport/json-unknown-member", http.MethodPost, signerapi.RouteSign, token, "application/json", "", []byte(`{"amount":"AA=="}`)),
		p.do("transport/status-shared", http.MethodGet, statusPath, token, "", "application/json", nil),
		p.do("transport/status-bad-hash", http.MethodGet, signerapi.RouteStatusPrefix+"ABCD", agentToken, "", "", nil),
		p.do("transport/status-unknown", http.MethodGet, signerapi.RouteStatusPrefix+hex.EncodeToString(fill(9, 32)), agentToken, "", "", nil),
		p.do("transport/payment-field-off", http.MethodPost, signerapi.RoutePaymentSignature, agentToken, "application/cbor", "",
			signerapi.EncodePaymentRequest(signer.PaymentProofRequest{CommitmentHash: d.Hash, Field: "paymentId", Request: request(d)})),
		p.do("transport/requeue-agent-token", http.MethodPost, signerapi.RouteRequeue, token, "application/cbor", "",
			edictaapi.EncodeWrapper(edictaapi.BytesItem(1, d.Hash[:]))),
		p.do("transport/requeue-unknown", http.MethodPost, signerapi.RouteRequeue, adminToken, "application/cbor", "",
			edictaapi.EncodeWrapper(edictaapi.BytesItem(1, fill(9, 32)))),
	)
	out = append(out, p.get("transport/health", signerapi.RouteHealth, token)...)

	out = append(out, p.both("flow/sign-shared", signerapi.RouteSign, token, good, signerapi.SignRequestSchema)...)
	out = append(out, p.both("flow/requeue-not-wrong", signerapi.RouteRequeue, adminToken,
		edictaapi.EncodeWrapper(edictaapi.BytesItem(1, d.Hash[:])), signerapi.RequeueRequestSchema)...)
	e.waitState(d.Hash, signer.StateWrong)
	out = append(out, p.get("flow/status-wrong", statusPath, agentToken)...)
	out = append(out, p.do("flow/requeue/cbor", http.MethodPost, signerapi.RouteRequeue, adminToken, "application/cbor", "",
		edictaapi.EncodeWrapper(edictaapi.BytesItem(1, d.Hash[:]))))
	return out
}
