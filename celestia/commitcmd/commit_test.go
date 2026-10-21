// SPDX-License-Identifier: Apache-2.0

package commitcmd_test

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/celestia/commitcmd"
	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/edictaapi"
	"github.com/vgonkivs/edicta/sdk"
	"github.com/vgonkivs/edicta/sdk/blob"
	"github.com/vgonkivs/edicta/sdk/sdktest"
)

const (
	gateID = "gate-test-1"
	now    = int64(1_800_000_000)
)

// fakeGate signs an Authorization over the envelope it is given, as a gate
// that accepted it would. It never looks at the agent key.
type fakeGate struct {
	mu    sync.Mutex
	priv  ed25519.PrivateKey
	fast  bool
	err   error
	calls int
	// lose makes the first call issue an Authorization but fail with a
	// transport error; later calls answer 409 with the stored one.
	lose   bool
	hook   func()
	issued []byte
	action []byte
	salt   []byte
}

func (g *fakeGate) AuthorizeWithVerdict(_ context.Context, envelope, action, salt []byte) ([]byte, []byte, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.calls++
	if g.hook != nil {
		g.hook()
	}
	g.action, g.salt = action, salt
	if g.err != nil {
		return nil, nil, g.err
	}
	if g.issued != nil {
		return nil, nil, &edictaapi.Error{Status: 409, Code: "ErrNonceUsed", Message: "used", Stored: g.issued}
	}
	sc, err := commitment.DecodeSigned(envelope)
	if err != nil {
		return nil, nil, err
	}
	h, err := commitment.HashOf(&sc.Commitment)
	if err != nil {
		return nil, nil, err
	}
	a := commitment.Authorization{
		Version: commitment.Version, CommitmentHash: h[:], ActionHash: sc.Commitment.Action.Hash,
		GateID: gateID, Expires: sc.Commitment.ValidUntil, Path: commitment.PathDA, Mode: commitment.ModeStrict,
	}
	if g.fast {
		a.Mode, a.AnchorDeadline = commitment.ModeFast, uint64(now)+600
	}
	canon, err := commitment.EncodeAuthorization(&a)
	if err != nil {
		return nil, nil, err
	}
	sig := ed25519.Sign(g.priv, commitment.AuthorizationSigningMessage(commitment.HashAuthorization(canon)))
	b, err := commitment.EncodeSignedAuthorization(&commitment.SignedAuthorization{Authorization: a, Signature: sig})
	if err == nil && g.lose {
		g.issued = b
		return nil, nil, errors.New("connection reset")
	}
	return b, nil, err
}

type rig struct {
	t      *testing.T
	pub    *sdktest.Publisher
	gate   *fakeGate
	gatePk ed25519.PublicKey
	agent  ed25519.PrivateKey
	svc    *commitcmd.Service
	// pending, when set, turns the publisher's answer into a pending reference.
	pending bool
	modes   []string
	ttls    []time.Duration
}

type pendingPub struct {
	inner *sdktest.Publisher
	on    func() bool
}

func (p pendingPub) Publish(ctx context.Context, b []byte) (sdk.Published, error) {
	out, err := p.inner.Publish(ctx, b)
	if err == nil && p.on() {
		out.Ref.Anchor = commitment.AnchorPending
	}
	return out, err
}

type pendingOK struct{ t uint64 }

func (p pendingOK) VerifyPending(context.Context, commitment.PayloadRef, uint64) (uint64, error) {
	return p.t, nil
}

func newRig(t *testing.T) *rig {
	t.Helper()
	gpub, gpriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	_, agent, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	r := &rig{t: t, pub: sdktest.NewPublisher(commitment.DACelestiaBlob), gate: &fakeGate{priv: gpriv}, gatePk: gpub, agent: agent}
	r.pub.SetBlockTime(uint64(now) - 20)
	clock := sdktest.NewClock(now)
	rk, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer, err := sdk.NewEd25519Signer(agent)
	require.NoError(t, err)
	r.svc = &commitcmd.Service{
		Gate: r.gate, GateKeys: [][]byte{gpub}, GateID: gateID, Clock: clock.Now, Wait: func(context.Context, int) error { return nil },
		Builders: func(mode string, validFor time.Duration) (*sdk.Builder, error) {
			r.modes = append(r.modes, mode)
			r.ttls = append(r.ttls, validFor)
			cfg := sdk.DefaultConfig()
			cfg.AgentID = "agent-1"
			cfg.Scope = commitment.Scope{GateID: gateID}
			cfg.Recipients = []blob.Recipient{{KID: []byte("auditor-1"), PublicKey: rk.PublicKey()}}
			cfg.SubmitterTrust = sdk.SubmitterSameOperator
			if validFor > 0 {
				cfg.TTLS = uint64(validFor / time.Second)
			}
			d := sdk.Deps{Publisher: pendingPub{inner: r.pub, on: func() bool { return r.pending }}, Signer: signer, Clock: clock}
			if mode == commitcmd.ModeFast {
				d.Pending = pendingOK{t: uint64(now) - 20}
			}
			return sdk.New(cfg, d)
		},
	}
	return r
}

func request() commitcmd.Request {
	return commitcmd.Request{
		ActionType: "application/vnd.test.order+json",
		Action:     []byte(`{"buy":"1"}`),
		Context:    []byte(` {"price": 10,  "src":"feed"} `),
		Model:      commitcmd.Named{ID: "m1"},
		Policy:     commitcmd.Named{ID: "p1", Text: "dca"},
	}
}

func exitOf(t *testing.T, err error) int {
	t.Helper()
	var f *commitcmd.Failure
	require.True(t, errors.As(err, &f), "got %T", err)
	return f.Exit
}

func TestStrictCommitAuthorizesTheExactActionBytes(t *testing.T) {
	r := newRig(t)
	resp, err := r.svc.Commit(context.Background(), request())
	require.NoError(t, err)
	assert.Equal(t, commitcmd.ModeStrict, resp.Mode)
	assert.Zero(t, resp.AnchorDeadline)
	assert.Equal(t, []byte(`{"buy":"1"}`), resp.Action, "the action is committed as given")
	assert.Equal(t, resp.Action, r.gate.action)
	assert.Equal(t, resp.Salt, r.gate.salt)
	assert.Len(t, resp.Salt, commitment.ActionSaltSize)
	assert.Len(t, resp.CommitmentHash, 64)

	sc, err := commitment.DecodeSigned(resp.Envelope)
	require.NoError(t, err)
	h, err := commitment.HashOf(&sc.Commitment)
	require.NoError(t, err)
	assert.Equal(t, hex.EncodeToString(h[:]), resp.CommitmentHash)
	assert.Equal(t, r.agent.Public(), ed25519.PublicKey(sc.Commitment.AgentPubKey))
	assert.Len(t, r.pub.Blobs(), 1, "the payload was published once")
	assert.Equal(t, []string{commitcmd.ModeStrict}, r.modes)
}

func TestFastCommitReportsTheAnchorDeadline(t *testing.T) {
	r := newRig(t)
	r.pending, r.gate.fast = true, true
	req := request()
	req.Mode = "fast"
	resp, err := r.svc.Commit(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, commitcmd.ModeFast, resp.Mode)
	assert.Equal(t, uint64(now)+600, resp.AnchorDeadline)
	ref, err := commitment.DecodePayloadRef(resp.PayloadRef)
	require.NoError(t, err)
	assert.True(t, ref.Pending())
}

func TestStrictRefusesAPendingReference(t *testing.T) {
	r := newRig(t)
	r.pending = true
	_, err := r.svc.Commit(context.Background(), request())
	require.Error(t, err)
	assert.Zero(t, r.gate.calls, "nothing is sent to the gate")
	assert.NotEqual(t, commitcmd.ExitOK, exitOf(t, err))
}

func TestStrictRefusesAFastAuthorization(t *testing.T) {
	r := newRig(t)
	r.gate.fast = true
	_, err := r.svc.Commit(context.Background(), request())
	require.Error(t, err)
	assert.Equal(t, commitcmd.ExitRefused, exitOf(t, err))
}

func TestGateRefusalIsExit3AndRetryableIsExit6(t *testing.T) {
	r := newRig(t)
	r.gate.err = &edictaapi.Error{Status: 409, Code: "ErrNonceUsed", Message: "used"}
	_, err := r.svc.Commit(context.Background(), request())
	assert.Equal(t, commitcmd.ExitRefused, exitOf(t, err))
	var f *commitcmd.Failure
	require.ErrorAs(t, err, &f)
	assert.Equal(t, "ErrNonceUsed", f.Code)

	r.gate.err = &edictaapi.Error{Status: 503, Code: "ErrUnavailable", Message: "down", Retryable: true}
	_, err = r.svc.Commit(context.Background(), request())
	assert.Equal(t, commitcmd.ExitUnavailable, exitOf(t, err))
}

func TestPublisherOutageIsExit6(t *testing.T) {
	r := newRig(t)
	r.pub.Fail(errors.New("connection refused"))
	_, err := r.svc.Commit(context.Background(), request())
	assert.Equal(t, commitcmd.ExitUnavailable, exitOf(t, err))
	assert.Zero(t, r.gate.calls)
}

func TestBadInputIsExit64(t *testing.T) {
	cases := map[string]func(*commitcmd.Request){
		"no action type": func(q *commitcmd.Request) { q.ActionType = "" },
		"no action":      func(q *commitcmd.Request) { q.Action = nil },
		"no context":     func(q *commitcmd.Request) { q.Context = nil },
		"null context":   func(q *commitcmd.Request) { q.Context = []byte("null") },
		"bad context":    func(q *commitcmd.Request) { q.Context = []byte("{") },
		"no model":       func(q *commitcmd.Request) { q.Model.ID = "" },
		"no policy":      func(q *commitcmd.Request) { q.Policy.ID = "" },
		"bad mode":       func(q *commitcmd.Request) { q.Mode = "turbo" },
		"bad valid_for":  func(q *commitcmd.Request) { q.ValidFor = "soon" },
		"zero valid_for": func(q *commitcmd.Request) { q.ValidFor = "0s" },
	}
	for name, mod := range cases {
		t.Run(name, func(t *testing.T) {
			r := newRig(t)
			q := request()
			mod(&q)
			_, err := r.svc.Commit(context.Background(), q)
			require.Error(t, err)
			assert.Equal(t, commitcmd.ExitUsage, exitOf(t, err))
			assert.Empty(t, r.pub.Blobs(), "nothing is published for a bad request")
			assert.Zero(t, r.gate.calls)
		})
	}
}

func TestValidForReachesTheBuilder(t *testing.T) {
	r := newRig(t)
	q := request()
	q.ValidFor = "10m"
	_, err := r.svc.Commit(context.Background(), q)
	require.NoError(t, err)
	assert.Equal(t, []time.Duration{10 * time.Minute}, r.ttls)
}

func TestAuthorizationOfAnotherGateKeyIsRefused(t *testing.T) {
	r := newRig(t)
	other, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	r.svc.GateKeys = [][]byte{other}
	_, err = r.svc.Commit(context.Background(), request())
	assert.Equal(t, commitcmd.ExitRefused, exitOf(t, err))
}

func TestDecodeRequestIsStrict(t *testing.T) {
	ok := `{"action_type":"a/b","action":"eyJhIjoxfQ==","context":{"x":1},"model":{"id":"m"},"policy":{"id":"p"}}`
	req, err := commitcmd.DecodeRequest(strings.NewReader(ok))
	require.NoError(t, err)
	assert.Equal(t, []byte(`{"a":1}`), req.Action)

	for name, in := range map[string]string{
		"unknown key":      `{"action_type":"a/b","bogus":1}`,
		"duplicate key":    `{"action_type":"a/b","action_type":"c/d"}`,
		"nested duplicate": `{"model":{"id":"a","id":"b"}}`,
		"trailing data":    ok + `{}`,
		"bad base64":       `{"action":"%%%"}`,
		"not an object":    `[]`,
	} {
		_, err := commitcmd.DecodeRequest(strings.NewReader(in))
		require.Error(t, err, name)
		assert.Equal(t, commitcmd.ExitUsage, exitOf(t, err), name)
	}
}

func TestCheckBind(t *testing.T) {
	for _, a := range []string{"127.0.0.1:8500", "[::1]:8500", "localhost:8500"} {
		assert.NoError(t, commitcmd.CheckBind(a, false), a)
	}
	for _, a := range []string{":8500", "0.0.0.0:8500", "10.0.0.5:8500", "example.com:80", "nonsense"} {
		require.ErrorIs(t, commitcmd.CheckBind(a, false), commitcmd.ErrBind, a)
	}
	assert.NoError(t, commitcmd.CheckBind("0.0.0.0:8500", true))
}

func post(h http.Handler, host, ct, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/v1/commit", strings.NewReader(body))
	req.Host = host
	if ct != "" {
		req.Header.Set("Content-Type", ct)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestServeCommitsAndRefusesBadCallers(t *testing.T) {
	r := newRig(t)
	h := commitcmd.Handler(r.svc, commitcmd.Options{})
	body := `{"action_type":"application/vnd.test.order+json","action":"eyJidXkiOiIxIn0=","context":{"p":1},"model":{"id":"m"},"policy":{"id":"p"}}`

	rec := post(h, "127.0.0.1:8500", "application/json", body)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Contains(t, rec.Body.String(), `"commitment_hash"`)
	assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"))

	rec = post(h, "evil.example:8500", "application/json", body)
	assert.Equal(t, http.StatusForbidden, rec.Code, "a rebound Host header is refused")

	rec = post(h, "localhost:8500", "text/plain", body)
	assert.Equal(t, http.StatusUnsupportedMediaType, rec.Code)

	rec = post(h, "localhost:8500", "application/json", `{"nope":1}`)
	assert.Equal(t, http.StatusBadRequest, rec.Code)

	get := httptest.NewRequest(http.MethodGet, "/v1/commit", nil)
	get.Host = "localhost"
	gr := httptest.NewRecorder()
	h.ServeHTTP(gr, get)
	assert.Equal(t, http.StatusMethodNotAllowed, gr.Code)

	assert.Equal(t, 1, r.gate.calls, "only the good request reached the gate")
}

func TestServeMapsFailuresToStatus(t *testing.T) {
	r := newRig(t)
	h := commitcmd.Handler(r.svc, commitcmd.Options{})
	body := `{"action_type":"application/vnd.test.order+json","action":"eyJidXkiOiIxIn0=","context":{"p":1},"model":{"id":"m"},"policy":{"id":"p"}}`
	r.gate.err = &edictaapi.Error{Status: 403, Code: "ErrPolicyDenied", Message: "no"}
	rec := post(h, "localhost", "application/json", body)
	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Contains(t, rec.Body.String(), "ErrPolicyDenied")

	r.gate.err = nil
	r.pub.Fail(errors.New("down"))
	rec = post(h, "localhost", "application/json", body)
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
	assert.Contains(t, rec.Body.String(), `"retryable":true`)
}

func TestServeRefusesRemoteBindWithoutTheFlag(t *testing.T) {
	r := newRig(t)
	err := commitcmd.Serve(context.Background(), "0.0.0.0:0", r.svc, commitcmd.Options{}, nil)
	require.ErrorIs(t, err, commitcmd.ErrBind)
}

func TestServeListensOnLoopbackAndStops(t *testing.T) {
	r := newRig(t)
	ctx, cancel := context.WithCancel(context.Background())
	addr := make(chan string, 1)
	done := make(chan error, 1)
	go func() {
		done <- commitcmd.Serve(ctx, "127.0.0.1:0", r.svc, commitcmd.Options{}, func(a net.Addr) { addr <- a.String() })
	}()
	var a string
	select {
	case a = <-addr:
	case <-time.After(5 * time.Second):
		t.Fatal("no listener")
	}
	body := `{"action_type":"application/vnd.test.order+json","action":"eyJidXkiOiIxIn0=","context":{"p":1},"model":{"id":"m"},"policy":{"id":"p"}}`
	resp, err := http.Post("http://"+a+"/v1/commit", "application/json", bytes.NewReader([]byte(body)))
	require.NoError(t, err)
	_ = resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	cancel()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(10 * time.Second):
		t.Fatal("serve did not stop")
	}
}

func deep(n int) string { return strings.Repeat("[", n) + strings.Repeat("]", n) }

func TestNestedBodyIsRefusedWithoutOverflowingTheStack(t *testing.T) {
	body := `{"context":` + deep(100000) + `}`
	_, err := commitcmd.DecodeRequest(strings.NewReader(body))
	require.Error(t, err)
	assert.Equal(t, commitcmd.ExitUsage, exitOf(t, err))

	big := `{"context":` + strings.Repeat("[", 1<<20) + `}`
	_, err = commitcmd.DecodeRequest(strings.NewReader(big))
	require.Error(t, err)

	_, err = commitcmd.DecodeRequest(strings.NewReader(`{"context":` + deep(commitcmd.MaxJSONDepth-2) + `}`))
	assert.NoError(t, err, "ordinary nesting passes")
}

func TestKeysThatDifferOnlyInCaseAreDuplicates(t *testing.T) {
	_, err := commitcmd.DecodeRequest(strings.NewReader(`{"action":"QUFB","ACTION":"QkJC"}`))
	require.Error(t, err)
	assert.Equal(t, commitcmd.ExitUsage, exitOf(t, err))
	assert.Error(t, commitcmd.CheckJSON([]byte(`{"a":1,"A":2}`)))
	assert.NoError(t, commitcmd.CheckJSON([]byte(`{"a":{"b":1},"c":{"b":2}}`)))
}

func TestContextWithDuplicateKeysIsRefused(t *testing.T) {
	r := newRig(t)
	q := request()
	q.Context = []byte(`{"price":1,"price":2}`)
	_, err := r.svc.Commit(context.Background(), q)
	require.Error(t, err)
	assert.Equal(t, commitcmd.ExitUsage, exitOf(t, err))
	assert.Empty(t, r.pub.Blobs())
}

func TestNoGateKeyFailsClosed(t *testing.T) {
	r := newRig(t)
	r.svc.GateKeys = nil
	_, err := r.svc.Commit(context.Background(), request())
	require.Error(t, err)
	assert.Equal(t, commitcmd.ExitUsage, exitOf(t, err))
	assert.Empty(t, r.pub.Blobs(), "nothing is published")
}

func TestARefusedAuthorizationIsKeptInTheFailure(t *testing.T) {
	r := newRig(t)
	r.gate.fast = true
	_, err := r.svc.Commit(context.Background(), request())
	var f *commitcmd.Failure
	require.ErrorAs(t, err, &f)
	assert.Equal(t, "mode_mismatch", f.Code)
	assert.NotEmpty(t, f.Authorization, "the issued Authorization is returned")
	assert.NotEmpty(t, f.Envelope)
}

func TestALostAuthorizeResponseIsRecoveredFromTheStoredOne(t *testing.T) {
	r := newRig(t)
	r.gate.lose = true
	resp, err := r.svc.Commit(context.Background(), request())
	require.NoError(t, err)
	assert.Equal(t, 2, r.gate.calls, "authorize was repeated with the same envelope")
	assert.Len(t, r.pub.Blobs(), 1, "the payload was published once")
	assert.NotEmpty(t, resp.Authorization)
}

func TestCallerCancellationDoesNotAbandonAnAuthorize(t *testing.T) {
	r := newRig(t)
	r.gate.lose = true
	ctx, cancel := context.WithCancel(context.Background())
	r.gate.hook = cancel
	resp, err := r.svc.Commit(ctx, request())
	require.NoError(t, err, "the authorize step finished after the caller gave up")
	assert.NotEmpty(t, resp.Authorization)
	assert.Equal(t, 2, r.gate.calls)
}

func TestResumeAuthorizesWithoutPublishing(t *testing.T) {
	r := newRig(t)
	r.gate.err = &edictaapi.Error{Status: 503, Code: "ErrUnavailable", Message: "down", Retryable: true}
	_, err := r.svc.Commit(context.Background(), request())
	var f *commitcmd.Failure
	require.ErrorAs(t, err, &f)
	assert.Equal(t, commitcmd.ExitUnavailable, f.Exit)
	require.NotEmpty(t, f.Envelope)
	assert.Len(t, r.pub.Blobs(), 1)

	r.gate.err = nil
	resp, err := r.svc.Commit(context.Background(), commitcmd.Request{Resume: &commitcmd.Resume{Envelope: f.Envelope, Action: f.Action, Salt: f.Salt}})
	require.NoError(t, err)
	assert.Equal(t, f.Action, resp.Action)
	assert.Len(t, r.pub.Blobs(), 1, "no second publish")

	_, err = r.svc.Commit(context.Background(), commitcmd.Request{Resume: &commitcmd.Resume{}})
	assert.Equal(t, commitcmd.ExitUsage, exitOf(t, err))
}

func TestStrictAgainstAFastRecorderSaysSo(t *testing.T) {
	r := newRig(t)
	r.pending = true
	_, err := r.svc.Commit(context.Background(), request())
	var f *commitcmd.Failure
	require.ErrorAs(t, err, &f)
	assert.Equal(t, "recorder_fast_mode", f.Code)
	assert.Len(t, r.pub.Blobs(), 1, "published once, not reissued")
}

func TestPayloadErrorsAreNotRetryable(t *testing.T) {
	for _, e := range []error{sdk.ErrPayloadMismatch, sdk.ErrAlreadyFinalized, sdk.ErrSignerClosed, sdk.ErrPlaintextHashMismatch} {
		r := newRig(t)
		r.svc.Builders = func(string, time.Duration) (*sdk.Builder, error) { return nil, e }
		_, err := r.svc.Commit(context.Background(), request())
		var f *commitcmd.Failure
		require.ErrorAs(t, err, &f)
		assert.Equal(t, commitcmd.ExitRefused, f.Exit)
		assert.False(t, f.Retryable)
	}
}

func TestRemoteModeNeedsTokenHostAndNoForeignOrigin(t *testing.T) {
	r := newRig(t)
	opts := commitcmd.Options{AllowRemote: true, Token: []byte("s3cret"), AllowedHosts: []string{"agent:8500"}}
	h := commitcmd.Handler(r.svc, opts)
	body := `{"action_type":"application/vnd.test.order+json","action":"eyJidXkiOiIxIn0=","context":{"p":1},"model":{"id":"m"},"policy":{"id":"p"}}`
	do := func(host, auth, origin string) int {
		req := httptest.NewRequest(http.MethodPost, "/v1/commit", strings.NewReader(body))
		req.Host = host
		req.Header.Set("Content-Type", "application/json")
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	assert.Equal(t, http.StatusOK, do("agent:8500", "Bearer s3cret", ""))
	assert.Equal(t, http.StatusUnauthorized, do("agent:8500", "", ""))
	assert.Equal(t, http.StatusUnauthorized, do("agent:8500", "Bearer wrong", ""))
	assert.Equal(t, http.StatusUnauthorized, do("agent:8500", "s3cret", ""))
	assert.Equal(t, http.StatusForbidden, do("evil:8500", "Bearer s3cret", ""))
	assert.Equal(t, http.StatusForbidden, do("127.0.0.1:8500", "Bearer s3cret", ""), "loopback is not special in remote mode")
	assert.Equal(t, http.StatusForbidden, do("agent:8500", "Bearer s3cret", "https://evil.example"))
	assert.Equal(t, 1, r.gate.calls)

	opts.AllowedOrigins = []string{"https://ui.example"}
	h = commitcmd.Handler(newRig(t).svc, opts)
	assert.Equal(t, http.StatusOK, do("agent:8500", "Bearer s3cret", "https://ui.example"))
}

func TestRemoteOptionsMustBeComplete(t *testing.T) {
	r := newRig(t)
	require.ErrorIs(t, commitcmd.Options{AllowRemote: true}.ValidateBasic(), commitcmd.ErrBind)
	require.ErrorIs(t, commitcmd.Options{AllowRemote: true, Token: []byte("x")}.ValidateBasic(), commitcmd.ErrBind)
	require.NoError(t, commitcmd.Options{AllowRemote: true, Token: []byte("x"), AllowedHosts: []string{"a:1"}}.ValidateBasic())
	require.ErrorIs(t, commitcmd.Serve(context.Background(), "0.0.0.0:0", r.svc, commitcmd.Options{AllowRemote: true}, nil), commitcmd.ErrBind)

	h := commitcmd.Handler(r.svc, commitcmd.Options{AllowRemote: true})
	rec := post(h, "agent:8500", "application/json", "{}")
	assert.Equal(t, http.StatusForbidden, rec.Code, "a misconfigured remote handler refuses everything")
}

func TestOriginOnLoopbackStaysAllowedByHostAndContentTypeChecks(t *testing.T) {
	r := newRig(t)
	h := commitcmd.Handler(r.svc, commitcmd.Options{})
	rec := post(h, "127.0.0.1:8500", "text/plain", "{}")
	assert.Equal(t, http.StatusUnsupportedMediaType, rec.Code)
}

func TestAForgedStoredAuthorizationIsNotAccepted(t *testing.T) {
	r := newRig(t)
	r.gate.err = &edictaapi.Error{Status: 409, Code: "ErrNonceUsed", Message: "used", Stored: []byte{1}}
	_, err := r.svc.Commit(context.Background(), request())
	var f *commitcmd.Failure
	require.ErrorAs(t, err, &f)
	assert.Equal(t, "authorization_invalid", f.Code)
	assert.Equal(t, []byte{1}, f.Authorization)
}
