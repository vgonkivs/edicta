// SPDX-License-Identifier: Apache-2.0

package commitcmd_test

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/internal/testkit"
	"github.com/vgonkivs/edicta/plugins/edenescrow"
	"github.com/vgonkivs/edicta/services/cli/commitcmd"
)

func TestRecognisedRefusalAmbiguousAnswers(t *testing.T) {
	pid := [32]byte(mustHex(t, livePaymentID))
	quote := func(entries ...string) string {
		return base64.StdEncoding.EncodeToString([]byte(`{"x402Version":2,"accepts":[` + strings.Join(entries, ",") + `]}`))
	}
	entry := func(id string) string { return `{"scheme":"escrow-upto","extra":{"paymentId":"0x` + id + `"}}` }
	atLimit := buyerText + strings.Repeat(" ", commitcmd.MaxRetryAnswer-len(buyerText))
	require.Len(t, atLimit, commitcmd.MaxRetryAnswer)

	cases := []struct {
		name   string
		status int
		header string
		body   string
		want   string
	}{
		{"403 with the text at exactly 16384 bytes", 403, "", atLimit, commitcmd.RefusalBuyer},
		{"403 one byte over", 403, "", atLimit + " ", ""},
		{"402 for this payment, minimal quote", 402, quote(entry(livePaymentID)), "", commitcmd.RefusalAsksAgain},
		{"402 naming this payment twice", 402, quote(entry(livePaymentID), entry(livePaymentID)), "", ""},
		{"402 naming another payment, buyer text in the body", 402, quote(entry(strings.Repeat("2", 64))), buyerText, ""},
		{"402 whose header is not base64", 402, "not base64!", "", ""},
		{"402 whose quote is x402Version 1", 402, base64.StdEncoding.EncodeToString(
			[]byte(`{"x402Version":1,"accepts":[` + entry(livePaymentID) + `]}`)), "", ""},
		{"402 whose quote is not an object", 402, base64.StdEncoding.EncodeToString([]byte(`[1]`)), "", ""},
		{"403 with the text only in the header", 403, buyerText, "", ""},
		{"403 with the text cut short", 403, "", "neither the escrow buye", ""},
		{"403 with the text spaced differently", 403, "", "neither  the escrow buyer", ""},
		{"403 with a look-alike non-ASCII text", 403, "", "neither the escrow buy\u00e9r", ""},
		{"no status: timeout or transport error", 0, liveHeader(t), buyerText, ""},
		{"a negative status", -403, "", buyerText, ""},
		{"408 request timeout", 408, liveHeader(t), buyerText, ""},
		{"504 gateway timeout", 504, liveHeader(t), buyerText, ""},
		{"401 with the buyer text", 401, "", buyerText, ""},
		{"301 redirect with the quote", 301, liveHeader(t), "", ""},
	}
	for _, c := range cases {
		assert.Equal(t, c.want, commitcmd.RecognisedRefusal(c.status, c.header, []byte(c.body), pid), c.name)
	}
}

// Ambiguous answers between recognised refusals neither trigger nor move the
// first refusal's time.
func TestHandoffNeverOnAmbiguousRefusals(t *testing.T) {
	ctx := context.Background()
	ambiguous := []commitcmd.PaidRetry{}
	r := newHandoffRig(t)
	for _, a := range []struct {
		status       int
		header, body string
	}{
		{500, "", buyerText},
		{402, otherQuoteHeader(t), ""},
		{403, "", `{"error":"forbidden"}`},
		{0, "", ""},
		{429, liveHeader(t), buyerText},
		{200, "", "ok"},
	} {
		ambiguous = append(ambiguous, r.report(a.status, a.header, a.body))
	}

	for range 3 {
		for _, rep := range ambiguous {
			r.after(time.Minute)
			out, err := r.svc.PaidRetry(ctx, rep)
			require.NoError(t, err)
			assert.Equal(t, commitcmd.NextNone, out.Next, "status %d", rep.Status)
			assert.Empty(t, out.Refusal)
		}
	}
	assert.Zero(t, r.state(t).RefusedAtMS, "no ambiguous answer counts as the first refusal")

	_, err := r.svc.PaidRetry(ctx, r.report(403, "", buyerText))
	require.NoError(t, err)
	refusedAt := r.state(t).RefusedAtMS
	for _, rep := range ambiguous {
		r.after(time.Minute)
		_, err := r.svc.PaidRetry(ctx, rep)
		require.NoError(t, err)
	}
	assert.Equal(t, refusedAt, r.state(t).RefusedAtMS)
	assert.Zero(t, r.state(t).HandoffAtMS)
	assert.Zero(t, r.relay.calls(), "ambiguous answers never hand off")
}

func TestHandoffPickupDelayBoundary(t *testing.T) {
	ctx := context.Background()
	r := newHandoffRig(t)
	cfg := commitcmd.HandoffConfig{PaymentServer: r.relay.srv.URL, PickupDelay: 30 * time.Second, ServerTimeout: 2 * time.Second}
	h, err := commitcmd.NewHandoff(cfg, r.relay.srv.Client(), quietLog)
	require.NoError(t, err)
	r.svc.Handoff = h

	_, err = r.svc.PaidRetry(ctx, r.report(403, "", buyerText))
	require.NoError(t, err)
	for _, step := range []time.Duration{10 * time.Second, 10 * time.Second, 9*time.Second + 999*time.Millisecond} {
		r.after(step)
		out, err := r.svc.PaidRetry(ctx, r.report(402, liveHeader(t), ""))
		require.NoError(t, err)
		assert.Equal(t, commitcmd.NextRetry, out.Next)
		assert.False(t, out.HandedOff, "refusals closer than the pickup delay")
	}
	assert.Zero(t, r.relay.calls())

	r.after(time.Millisecond)
	out, err := r.svc.PaidRetry(ctx, r.report(402, liveHeader(t), ""))
	require.NoError(t, err)
	assert.True(t, out.HandedOff, "exactly the pickup delay after the first refusal")
	assert.Equal(t, int64(30_000), out.RetryAfterMS)
	assert.Equal(t, 1, r.relay.calls())
}

func TestHandoffConcurrentReportsHandOffOnce(t *testing.T) {
	ctx := context.Background()
	r := newHandoffRig(t)
	_, err := r.svc.PaidRetry(ctx, r.report(403, "", buyerText))
	require.NoError(t, err)
	r.after(10 * time.Second)

	var handed atomic.Int32
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			out, err := r.svc.PaidRetry(ctx, r.report(403, "", buyerText))
			if assert.NoError(t, err) && out.HandedOff {
				handed.Add(1)
			}
		})
	}
	wg.Wait()
	assert.Equal(t, int32(1), handed.Load())
	assert.Equal(t, 1, r.relay.calls())
}

// A second process on the same state directory sees the first one's once
// mark; while the first one serves, the directory lock keeps it out.
func TestHandoffOnceMarkAcrossProcessesOnOneDirectory(t *testing.T) {
	ctx := context.Background()
	r := newHandoffRig(t)
	unlock, err := commitcmd.LockStateDir(r.dir)
	require.NoError(t, err)
	_, err = commitcmd.LockStateDir(r.dir)
	require.ErrorIs(t, err, commitcmd.ErrStateDirInUse, "a second serve on the directory is refused")

	_, err = r.svc.PaidRetry(ctx, r.report(403, "", buyerText))
	require.NoError(t, err)
	r.after(10 * time.Second)
	out, err := r.svc.PaidRetry(ctx, r.report(403, "", buyerText))
	require.NoError(t, err)
	require.True(t, out.HandedOff)
	unlock()

	again, err := commitcmd.LockStateDir(r.dir)
	require.NoError(t, err)
	defer again()
	st, err := commitcmd.NewFileStateStore(r.dir)
	require.NoError(t, err)
	second := &commitcmd.Service{State: st, Clock: r.svc.Clock, Handoff: r.handoff(t, r.relay.srv.URL)}
	for range 2 {
		r.after(time.Hour)
		out, err := second.PaidRetry(ctx, r.report(402, liveHeader(t), ""))
		require.NoError(t, err)
		assert.Equal(t, commitcmd.NextOperator, out.Next)
		assert.False(t, out.HandedOff)
	}
	assert.Equal(t, 1, r.relay.calls())
}

// otherSignedVector is a valid signed deposit of another decision, with its
// own rail_ref.
func otherSignedVector(t *testing.T) ([]byte, string) {
	t.Helper()
	var v struct {
		Cases []struct {
			SignedHex string `json:"signed_hex"`
			RailRef   string `json:"rail_ref"`
		} `json:"cases"`
	}
	b, err := os.ReadFile(testkit.SpecPath(t, "vectors", "profiles", "eden-escrow", "signed.json"))
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(b, &v))
	require.NotEmpty(t, v.Cases)
	signed := mustHex(t, v.Cases[0].SignedHex)
	require.Equal(t, v.Cases[0].RailRef, edenescrow.RailRef(signed))
	return signed, v.Cases[0].RailRef
}

func TestHandoffNeverPostsBytesOfAnotherDecisionOrPayer(t *testing.T) {
	other, otherRef := otherSignedVector(t)
	stranger, err := secp256k1.GeneratePrivateKey()
	require.NoError(t, err)
	for name, mut := range map[string]func(*testing.T, *commitcmd.State){
		"another decision's signed bytes with their rail_ref": func(_ *testing.T, s *commitcmd.State) {
			s.Signed, s.RailRef = other, otherRef
		},
		"another decision's signed bytes under this rail_ref": func(_ *testing.T, s *commitcmd.State) {
			s.Signed = other
		},
		"the committed transaction signed by another payer": func(t *testing.T, s *commitcmd.State) {
			tx, err := edenescrow.DecodeTxAction(s.Action)
			require.NoError(t, err)
			signed, _, err := tx.SignTx(stranger)
			require.NoError(t, err)
			s.Signed, s.RailRef = signed, edenescrow.RailRef(signed)
		},
		"a Payment-Signature of another payer": func(t *testing.T, s *commitcmd.State) {
			tx, err := edenescrow.DecodeTxAction(s.Action)
			require.NoError(t, err)
			s.PaymentSignature = personalSig(t, stranger, tx.Deposit.PaymentID)
		},
		"a Payment-Signature that is not hex": func(_ *testing.T, s *commitcmd.State) {
			s.PaymentSignature = "0x" + strings.Repeat("zz", 65)
		},
	} {
		t.Run(name, func(t *testing.T) {
			r := newHandoffRig(t)
			ctx := context.Background()
			st := r.state(t)
			mut(t, &st)
			require.NoError(t, r.svc.State.Save(r.resp.CommitmentHash, st))

			rep := r.report(403, "", buyerText)
			rep.PaymentSignature = st.PaymentSignature
			_, err := r.svc.PaidRetry(ctx, rep)
			require.NoError(t, err)
			r.after(10 * time.Second)
			_, err = r.svc.PaidRetry(ctx, rep)
			assert.Equal(t, "handoff_refused", failureOf(t, err).Code)
			assert.Zero(t, r.relay.calls(), "nothing is posted")
			assert.Zero(t, r.state(t).HandoffAtMS, "a refused handoff spends no mark")
		})
	}
}

// personalSig is the EIP-191 signature of the 32 raw bytes of m by k, as
// the signer returns it: 0x and r || s || v with v in {27, 28}.
func personalSig(t *testing.T, k *secp256k1.PrivateKey, m [32]byte) string {
	t.Helper()
	sig, err := edenescrow.Sign(k, edenescrow.PersonalDigest(m))
	require.NoError(t, err)
	b := make([]byte, 65)
	copy(b, sig.R[:])
	copy(b[32:], sig.S[:])
	b[64] = sig.YParity + 27
	who, err := edenescrow.RecoverPersonal(m, [65]byte(b))
	require.NoError(t, err)
	require.Equal(t, edenescrow.Address(k.PubKey()), who)
	return "0x" + hex.EncodeToString(b)
}

// The relay target is the configured payment server only: never a URL from
// the paid retry's answer, never one a report names, never a redirect.
func TestHandoffRelayURLIsOnlyTheConfiguredServer(t *testing.T) {
	var evilCalls atomic.Int32
	evil := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { evilCalls.Add(1) }))
	t.Cleanup(evil.Close)
	ctx := context.Background()

	t.Run("URLs in the refused answer", func(t *testing.T) {
		r := newHandoffRig(t)
		body := `{"error":"` + buyerText + `","relay":"` + evil.URL + `/deposit/send","location":"` + evil.URL + `"}`
		_, err := r.svc.PaidRetry(ctx, r.report(403, "", body))
		require.NoError(t, err)
		r.after(10 * time.Second)
		out, err := r.svc.PaidRetry(ctx, r.report(403, "", body))
		require.NoError(t, err)
		require.True(t, out.HandedOff)
		require.Equal(t, 1, r.relay.calls())
		assert.Equal(t, "/api/deposit/send", r.relay.paths[0])
	})

	t.Run("a report naming a server", func(t *testing.T) {
		r := newHandoffRig(t)
		h := commitcmd.Handler(r.svc, commitcmd.Options{})
		for _, field := range []string{"payment_server", "relay_url", "url", "PaymentServer"} {
			body := `{"commitment_hash":"` + r.resp.CommitmentHash + `","payment_signature":"` + r.resp.PaymentSignature +
				`","status":403,"body":"` + base64.StdEncoding.EncodeToString([]byte(buyerText)) + `","` + field + `":"` + evil.URL + `"}`
			rec := postPaidRetry(h, body, nil)
			assert.Equal(t, http.StatusBadRequest, rec.Code, field)
		}
		assert.Zero(t, r.state(t).RefusedAtMS)
	})

	t.Run("a redirect from the relay", func(t *testing.T) {
		r := newHandoffRig(t)
		redirect := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			http.Redirect(w, req, evil.URL+"/deposit/send", http.StatusTemporaryRedirect)
		}))
		t.Cleanup(redirect.Close)
		cfg := commitcmd.HandoffConfig{PaymentServer: redirect.URL, ServerTimeout: 2 * time.Second}
		cfg.ApplyDefaults()
		hc := redirect.Client()
		hc.Transport.(*http.Transport).TLSClientConfig.RootCAs.AddCert(evil.Certificate())
		h, err := commitcmd.NewHandoff(cfg, hc, quietLog)
		require.NoError(t, err)
		r.svc.Handoff = h
		_, err = r.svc.PaidRetry(ctx, r.report(403, "", buyerText))
		require.NoError(t, err)
		r.after(10 * time.Second)
		out, err := r.svc.PaidRetry(ctx, r.report(403, "", buyerText))
		require.NoError(t, err)
		assert.True(t, out.HandedOff)
		assert.NotEmpty(t, out.RelayFault, "a redirect is a relay fault")
	})
	assert.Zero(t, evilCalls.Load(), "the other server is never called")
}

func postPaidRetry(h http.Handler, body string, hdr map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/v1/paid-retry", strings.NewReader(body))
	req.Host = "127.0.0.1:8500"
	req.Header.Set("Content-Type", "application/json")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	if hdr != nil && hdr["Host"] != "" {
		req.Host = hdr["Host"]
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// A caller of /v1/paid-retry that is not this agent's serve client cannot
// obtain this agent's Payment-Signature, nor make it hand off.
func TestPaidRetryRouteNeverReleasesThePaymentSignature(t *testing.T) {
	ctx := context.Background()
	r := newHandoffRig(t)
	sig := r.resp.PaymentSignature
	report := func(paymentSignature string) string {
		b, err := json.Marshal(commitcmd.PaidRetry{
			CommitmentHash: r.resp.CommitmentHash, PaymentSignature: paymentSignature, Status: 403, Body: []byte(buyerText),
		})
		require.NoError(t, err)
		return string(b)
	}

	t.Run("another agent's bearer token in remote mode", func(t *testing.T) {
		opts := commitcmd.Options{AllowRemote: true, Token: []byte("agent-a-token"), AllowedHosts: []string{"agent:8500"}}
		h := commitcmd.Handler(r.svc, opts)
		for _, auth := range []string{"", "Bearer agent-b-token", "Bearer agent-a-token "} {
			rec := postPaidRetry(h, report(sig), map[string]string{"Host": "agent:8500", "Authorization": auth})
			assert.Equal(t, http.StatusUnauthorized, rec.Code, auth)
			assert.NotContains(t, rec.Body.String(), sig[2:])
		}
		assert.Zero(t, r.state(t).RefusedAtMS, "a refused caller records nothing")
	})

	t.Run("a report without this decision's Payment-Signature", func(t *testing.T) {
		h := commitcmd.Handler(r.svc, commitcmd.Options{})
		for _, guess := range []string{"", "0x", sig[:len(sig)-2], strings.ToUpper(sig), "0x" + strings.Repeat("00", 65)} {
			rec := postPaidRetry(h, report(guess), nil)
			assert.NotEqual(t, http.StatusOK, rec.Code, guess)
			assert.NotContains(t, rec.Body.String(), sig[2:], "the stored signature never leaves")
		}
		assert.Zero(t, r.state(t).RefusedAtMS)
	})

	t.Run("another agent's serve with its own state directory", func(t *testing.T) {
		st, err := commitcmd.NewFileStateStore(filepath.Join(t.TempDir(), "agent-b"))
		require.NoError(t, err)
		b := &commitcmd.Service{State: st, Clock: r.svc.Clock, Handoff: r.handoff(t, r.relay.srv.URL)}
		h := commitcmd.Handler(b, commitcmd.Options{})
		for range 2 {
			rec := postPaidRetry(h, report(sig), nil)
			assert.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
			assert.NotContains(t, rec.Body.String(), sig[2:])
			r.after(time.Minute)
		}
		_, err = b.PaidRetry(ctx, commitcmd.PaidRetry{CommitmentHash: r.resp.CommitmentHash, PaymentSignature: sig, Status: 403, Body: []byte(buyerText)})
		require.Error(t, err)
	})
	assert.Zero(t, r.relay.calls())
}
