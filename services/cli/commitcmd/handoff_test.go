// SPDX-License-Identifier: Apache-2.0

package commitcmd_test

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/plugins/edenescrow"
	"github.com/vgonkivs/edicta/services/cli/commitcmd"
)

var quietLog = slog.New(slog.NewTextHandler(io.Discard, nil))

// livePaymentID is the paymentId of the saved build fixture, w0 of its
// action.
const livePaymentID = "64b7e0cf7a15035882485d6a704853c17d7ed8d2b3278c88dc2971236113fed7"

func liveHeader(t *testing.T) string {
	return base64.StdEncoding.EncodeToString(liveFixture(t, "houston-payment-required.json"))
}

// otherQuoteHeader is the saved quote with another paymentId.
func otherQuoteHeader(t *testing.T) string {
	r := strings.ReplaceAll(string(liveFixture(t, "houston-payment-required.json")), livePaymentID, strings.Repeat("1", 64))
	require.NotContains(t, r, livePaymentID)
	return base64.StdEncoding.EncodeToString([]byte(r))
}

const buyerText = "signer is neither the escrow buyer nor an authorized device key"

func TestRecognisedRefusal(t *testing.T) {
	pid := [32]byte(mustHex(t, livePaymentID))
	big := strings.Repeat("x", commitcmd.MaxRetryAnswer) + buyerText
	dup := base64.StdEncoding.EncodeToString([]byte(`{"x402Version":2,"x402Version":2,"accepts":[{"scheme":"escrow-upto","extra":{"paymentId":"0x` + livePaymentID + `"}}]}`))
	cases := []struct {
		name   string
		status int
		header string
		body   string
		want   string
	}{
		{"402 asking again for this paymentId", 402, liveHeader(t), "", commitcmd.RefusalAsksAgain},
		{"403 with the buyer-check text", 403, "", `{"error":"` + buyerText + `"}`, commitcmd.RefusalBuyer},
		{"403 with the text and a quote header", 403, liveHeader(t), buyerText, commitcmd.RefusalBuyer},
		{"402 naming another paymentId", 402, otherQuoteHeader(t), "", ""},
		{"402 without the header", 402, "", buyerText, ""},
		{"402 with a URL-safe header", 402, strings.NewReplacer("+", "-", "/", "_").Replace(liveHeader(t)) + "-", "", ""},
		{"402 whose quote repeats a member", 402, dup, "", ""},
		{"402 with an answer over 16384 bytes", 402, liveHeader(t), big, ""},
		{"403 with an answer over 16384 bytes", 403, "", big, ""},
		{"403 with another text", 403, "", `{"error":"forbidden"}`, ""},
		{"403 with the text in other case", 403, "", strings.ToUpper(buyerText), ""},
	}
	for _, status := range []int{200, 201, 204, 302, 307, 400, 401, 404, 409, 422, 429, 500, 502, 503} {
		cases = append(cases, struct {
			name   string
			status int
			header string
			body   string
			want   string
		}{http.StatusText(status), status, liveHeader(t), buyerText, ""})
	}
	for _, c := range cases {
		assert.Equal(t, c.want, commitcmd.RecognisedRefusal(c.status, c.header, []byte(c.body), pid), c.name)
	}
}

func TestHandoffConfig(t *testing.T) {
	c := commitcmd.HandoffConfig{PaymentServer: "https://pay.example"}
	c.ApplyDefaults()
	assert.Equal(t, 10*time.Second, c.PickupDelay)
	require.NoError(t, c.ValidateBasic())
	for name, mut := range map[string]func(*commitcmd.HandoffConfig){
		"plain http":            func(c *commitcmd.HandoffConfig) { c.PaymentServer = "http://pay.example" },
		"a query":               func(c *commitcmd.HandoffConfig) { c.PaymentServer = "https://pay.example/?to=x" },
		"no server":             func(c *commitcmd.HandoffConfig) { c.PaymentServer = "" },
		"pickup above 120 s":    func(c *commitcmd.HandoffConfig) { c.PickupDelay = 121 * time.Second },
		"negative pickup":       func(c *commitcmd.HandoffConfig) { c.PickupDelay = -time.Second },
		"server timeout of 61s": func(c *commitcmd.HandoffConfig) { c.ServerTimeout = 61 * time.Second },
	} {
		bad := c
		mut(&bad)
		assert.Error(t, bad.ValidateBasic(), name)
	}
	c.PickupDelay = 120 * time.Second
	assert.NoError(t, c.ValidateBasic())
}

// fakeRelay is the payment server's /deposit/send.
type fakeRelay struct {
	mu     sync.Mutex
	srv    *httptest.Server
	paths  []string
	bodies []map[string]string
	status int
}

func newFakeRelay(t *testing.T) *fakeRelay {
	f := &fakeRelay{status: http.StatusOK}
	f.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var b map[string]string
		_ = json.NewDecoder(r.Body).Decode(&b)
		f.mu.Lock()
		defer f.mu.Unlock()
		f.paths = append(f.paths, r.URL.Path)
		f.bodies = append(f.bodies, b)
		w.WriteHeader(f.status)
		_, _ = io.WriteString(w, `{"deprecation":true}`)
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeRelay) calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.paths)
}

// handoffRig is an Eden decision that executed and whose Payment-Signature
// the client holds, with the handoff configured against a fake relay.
type handoffRig struct {
	*edenRig
	relay *fakeRelay
	now   time.Time
	resp  commitcmd.Response
	dir   string
}

func newHandoffRig(t *testing.T) *handoffRig {
	t.Helper()
	r := &handoffRig{edenRig: newEdenRig(t), relay: newFakeRelay(t), dir: filepath.Join(t.TempDir(), "state")}
	st, err := commitcmd.NewFileStateStore(r.dir)
	require.NoError(t, err)
	r.svc.State = st
	req := edenRequest(t)
	req.Sign, req.Broadcast, req.Record, req.PaymentSignature = true, true, true, true
	r.resp, err = r.svc.Commit(context.Background(), req)
	require.NoError(t, err)
	require.NotEmpty(t, r.resp.PaymentSignature)

	r.now = time.Unix(edenNow+60, 0)
	r.svc.Clock = func() time.Time { return r.now }
	r.svc.Handoff = r.handoff(t, r.relay.srv.URL+"/api")
	return r
}

func (r *handoffRig) handoff(t *testing.T, base string) *commitcmd.Handoff {
	t.Helper()
	cfg := commitcmd.HandoffConfig{PaymentServer: base, ServerTimeout: 2 * time.Second}
	cfg.ApplyDefaults()
	h, err := commitcmd.NewHandoff(cfg, r.relay.srv.Client(), quietLog)
	require.NoError(t, err)
	return h
}

func (r *handoffRig) report(status int, header, body string) commitcmd.PaidRetry {
	return commitcmd.PaidRetry{
		CommitmentHash: r.resp.CommitmentHash, PaymentSignature: r.resp.PaymentSignature,
		Status: status, PaymentRequired: header, Body: []byte(body),
	}
}

func (r *handoffRig) state(t *testing.T) commitcmd.State {
	t.Helper()
	st, ok, err := r.svc.State.Load(r.resp.CommitmentHash)
	require.NoError(t, err)
	require.True(t, ok)
	return st
}

func (r *handoffRig) after(d time.Duration) { r.now = r.now.Add(d) }

func TestHandoffAfterTwoRecognisedRefusalsPickupDelayApart(t *testing.T) {
	r := newHandoffRig(t)
	ctx := context.Background()
	assert.Equal(t, r.resp.PaymentSignature, r.state(t).PaymentSignature, "the released proof is stored")

	ok, err := r.svc.PaidRetry(ctx, r.report(200, "", `{"choices":[]}`))
	require.NoError(t, err)
	assert.Equal(t, commitcmd.NextNone, ok.Next, "a success is not a refusal")
	assert.Zero(t, r.state(t).RefusedAtMS)

	first, err := r.svc.PaidRetry(ctx, r.report(403, "", buyerText))
	require.NoError(t, err)
	assert.Equal(t, commitcmd.RefusalBuyer, first.Refusal)
	assert.Equal(t, commitcmd.NextRetry, first.Next)
	assert.Equal(t, int64(10_000), first.RetryAfterMS)
	assert.Equal(t, r.resp.PaymentSignature, first.PaymentSignature, "the same Payment-Signature is reused")
	assert.False(t, first.HandedOff)

	r.after(4 * time.Second)
	early, err := r.svc.PaidRetry(ctx, r.report(402, liveHeader(t), ""))
	require.NoError(t, err)
	assert.Equal(t, commitcmd.NextRetry, early.Next, "a second refusal within the pickup delay does not count")
	assert.Equal(t, int64(6_000), early.RetryAfterMS)

	r.after(3 * time.Second)
	other, err := r.svc.PaidRetry(ctx, r.report(500, "", buyerText))
	require.NoError(t, err)
	assert.Equal(t, commitcmd.NextNone, other.Next, "a server error is reported, not acted on")
	assert.Zero(t, r.relay.calls())

	r.after(3 * time.Second)
	second, err := r.svc.PaidRetry(ctx, r.report(402, liveHeader(t), ""))
	require.NoError(t, err)
	assert.Equal(t, commitcmd.RefusalAsksAgain, second.Refusal)
	assert.True(t, second.HandedOff)
	assert.Empty(t, second.RelayFault)
	assert.Equal(t, commitcmd.NextRetry, second.Next)
	assert.Equal(t, int64(10_000), second.RetryAfterMS)
	require.Equal(t, 1, r.relay.calls())
	assert.Equal(t, "/api"+"/deposit/send", r.relay.paths[0], "only the configured payment server")
	assert.Equal(t, map[string]string{
		"signedTx":  "0x" + hex.EncodeToString(r.resp.SignedTx),
		"paymentId": "0x" + livePaymentID,
	}, r.relay.bodies[0], "exactly the stored signed bytes and the action's paymentId")
	assert.Equal(t, r.now.UnixMilli(), r.state(t).HandoffAtMS)

	r.after(2 * time.Second)
	wait, err := r.svc.PaidRetry(ctx, r.report(403, "", buyerText))
	require.NoError(t, err)
	assert.Equal(t, commitcmd.NextRetry, wait.Next)
	assert.Equal(t, int64(8_000), wait.RetryAfterMS)

	r.after(8 * time.Second)
	last, err := r.svc.PaidRetry(ctx, r.report(403, "", buyerText))
	require.NoError(t, err)
	assert.Equal(t, commitcmd.NextOperator, last.Next)
	assert.False(t, last.HandedOff)
	assert.Equal(t, 1, r.relay.calls(), "never a second handoff")
}

func TestHandoffOnceSurvivesARestart(t *testing.T) {
	r := newHandoffRig(t)
	ctx := context.Background()
	_, err := r.svc.PaidRetry(ctx, r.report(403, "", buyerText))
	require.NoError(t, err)

	// A new process on the same state directory keeps the first refusal.
	restart := func() {
		st, err := commitcmd.NewFileStateStore(r.dir)
		require.NoError(t, err)
		r.svc = &commitcmd.Service{State: st, Clock: r.svc.Clock, Handoff: r.handoff(t, r.relay.srv.URL)}
	}
	restart()
	r.after(10 * time.Second)
	out, err := r.svc.PaidRetry(ctx, r.report(403, "", buyerText))
	require.NoError(t, err)
	require.True(t, out.HandedOff)
	require.Equal(t, 1, r.relay.calls())

	restart()
	for range 3 {
		r.after(time.Minute)
		out, err = r.svc.PaidRetry(ctx, r.report(402, liveHeader(t), ""))
		require.NoError(t, err)
		assert.Equal(t, commitcmd.NextOperator, out.Next)
	}
	assert.Equal(t, 1, r.relay.calls(), "the once mark outlives the process")
}

func TestHandoffRelayFaultIsNotRetried(t *testing.T) {
	r := newHandoffRig(t)
	r.relay.status = http.StatusBadRequest
	ctx := context.Background()
	_, err := r.svc.PaidRetry(ctx, r.report(403, "", buyerText))
	require.NoError(t, err)
	r.after(10 * time.Second)
	out, err := r.svc.PaidRetry(ctx, r.report(403, "", buyerText))
	require.NoError(t, err)
	assert.True(t, out.HandedOff)
	assert.NotEmpty(t, out.RelayFault)
	assert.Equal(t, commitcmd.NextRetry, out.Next, "the relay's answer moves no state")

	r.after(10 * time.Second)
	out, err = r.svc.PaidRetry(ctx, r.report(403, "", buyerText))
	require.NoError(t, err)
	assert.Equal(t, commitcmd.NextOperator, out.Next)
	assert.Equal(t, 1, r.relay.calls())
}

func TestHandoffRefusesBytesThatDoNotHashToTheRailRef(t *testing.T) {
	for name, mut := range map[string]func(*commitcmd.State){
		"another rail_ref":     func(s *commitcmd.State) { s.RailRef = strings.Repeat("0", 64) },
		"changed signed bytes": func(s *commitcmd.State) { s.Signed[len(s.Signed)-1] ^= 1 },
		"no signed bytes":      func(s *commitcmd.State) { s.Signed, s.RailRef = nil, "" },
		"re-signed bytes with their own rail_ref": func(s *commitcmd.State) {
			s.Signed[len(s.Signed)-1] ^= 1
			s.RailRef = edenescrow.RailRef(s.Signed)
		},
	} {
		t.Run(name, func(t *testing.T) {
			r := newHandoffRig(t)
			ctx := context.Background()
			st := r.state(t)
			mut(&st)
			require.NoError(t, r.svc.State.Save(r.resp.CommitmentHash, st))

			_, err := r.svc.PaidRetry(ctx, r.report(403, "", buyerText))
			require.NoError(t, err)
			r.after(10 * time.Second)
			_, err = r.svc.PaidRetry(ctx, r.report(403, "", buyerText))
			f := failureOf(t, err)
			assert.Equal(t, "handoff_refused", f.Code)
			assert.Zero(t, r.relay.calls())
			assert.Zero(t, r.state(t).HandoffAtMS, "a refused handoff spends no mark")
		})
	}
}

func TestHandoffPreconditions(t *testing.T) {
	ctx := context.Background()
	r := newHandoffRig(t)

	rep := r.report(403, "", buyerText)
	rep.PaymentSignature = "0x" + strings.Repeat("ab", 65)
	_, err := r.svc.PaidRetry(ctx, rep)
	assert.Equal(t, "handoff_refused", failureOf(t, err).Code, "another Payment-Signature")

	st := r.state(t)
	st.PaymentSignature = ""
	require.NoError(t, r.svc.State.Save(r.resp.CommitmentHash, st))
	_, err = r.svc.PaidRetry(ctx, r.report(403, "", buyerText))
	assert.Equal(t, "handoff_refused", failureOf(t, err).Code, "no Payment-Signature held")

	_, err = r.svc.PaidRetry(ctx, commitcmd.PaidRetry{CommitmentHash: strings.Repeat("c", 64), Status: 403, Body: []byte(buyerText)})
	assert.Equal(t, commitcmd.ExitUsage, failureOf(t, err).Exit, "an unknown decision")

	h := r.svc.Handoff
	r.svc.Handoff = nil
	_, err = r.svc.PaidRetry(ctx, r.report(403, "", buyerText))
	assert.Equal(t, commitcmd.ExitUsage, failureOf(t, err).Exit, "no payment server configured")
	r.svc.Handoff, r.svc.State = h, nil
	_, err = r.svc.PaidRetry(ctx, r.report(403, "", buyerText))
	assert.Equal(t, commitcmd.ExitUsage, failureOf(t, err).Exit, "no state store for the once mark")
	assert.Zero(t, r.relay.calls())
}

func TestAResumeKeepsTheHandoffMarks(t *testing.T) {
	r := newHandoffRig(t)
	ctx := context.Background()
	_, err := r.svc.PaidRetry(ctx, r.report(403, "", buyerText))
	require.NoError(t, err)
	r.after(10 * time.Second)
	_, err = r.svc.PaidRetry(ctx, r.report(403, "", buyerText))
	require.NoError(t, err)
	before := r.state(t)
	require.NotZero(t, before.HandoffAtMS)

	_, err = r.svc.Commit(ctx, commitcmd.Request{
		Resume: &commitcmd.Resume{Envelope: r.resp.Envelope, Action: r.resp.Action, Salt: r.resp.Salt},
		Eden:   &commitcmd.EdenInput{PaymentRequired: liveHeader(t)},
	})
	require.NoError(t, err)
	after := r.state(t)
	assert.Equal(t, before.HandoffAtMS, after.HandoffAtMS)
	assert.Equal(t, before.RefusedAtMS, after.RefusedAtMS)
	assert.Equal(t, before.PaymentSignature, after.PaymentSignature)
}

func TestServePaidRetryRoute(t *testing.T) {
	r := newHandoffRig(t)
	h := commitcmd.Handler(r.svc, commitcmd.Options{})
	body, err := json.Marshal(r.report(403, "", buyerText))
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/v1/paid-retry", strings.NewReader(string(body)))
	req.Host = "127.0.0.1:8500"
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var out commitcmd.PaidRetryResult
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &out))
	assert.Equal(t, commitcmd.NextRetry, out.Next)
	assert.Equal(t, commitcmd.RefusalBuyer, out.Refusal)

	req = httptest.NewRequest(http.MethodPost, "/v1/paid-retry", strings.NewReader(`{"commitment_hash":"`+r.resp.CommitmentHash+`","extra":1}`))
	req.Host = "127.0.0.1:8500"
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code, "unknown fields are refused")
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	require.NoError(t, err)
	return b
}
