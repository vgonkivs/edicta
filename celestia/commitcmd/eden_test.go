// SPDX-License-Identifier: Apache-2.0

package commitcmd_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/celestia/commitcmd"
	"github.com/vgonkivs/edicta/engine/commitment"
	"github.com/vgonkivs/edicta/internal/testkit"
	"github.com/vgonkivs/edicta/plugins/edenescrow"
	"github.com/vgonkivs/edicta/signer"
)

// The quote of the saved fixture expires at this time.
const (
	quoteExpiresAt = int64(1792466814)
	edenNow        = quoteExpiresAt - 200
)

func liveFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(testkit.SpecPath(t, "vectors", "profiles", "eden-escrow", "live", name))
	require.NoError(t, err)
	return b
}

func edenInput(t *testing.T) *commitcmd.EdenInput {
	t.Helper()
	return &commitcmd.EdenInput{
		Build:           liveFixture(t, "houston-deposit-build.json"),
		PaymentRequired: base64.StdEncoding.EncodeToString(liveFixture(t, "houston-payment-required.json")),
		Resource:        "https://inference.bot.fun/v1/chat/completions",
	}
}

func edenRequest(t *testing.T) commitcmd.Request {
	t.Helper()
	return commitcmd.Request{
		Eden:    edenInput(t),
		Context: []byte(`{"why":"dca"}`),
		Model:   commitcmd.Named{ID: "m1"},
		Policy:  commitcmd.Named{ID: "p1"},
		Mode:    "strict",
	}
}

// expectedAction is what the vectors say the fixture converts to.
func expectedAction(t *testing.T) []byte {
	t.Helper()
	rr := liveFixture(t, "houston-payment-required.json")
	action, _, err := edenescrow.ActionFromDepositBuild(liveFixture(t, "houston-deposit-build.json"),
		"https://inference.bot.fun/v1/chat/completions", edenescrow.RequirementsHash(rr))
	require.NoError(t, err)
	return action
}

type fakeSigner struct {
	mu   sync.Mutex
	priv *secp256k1.PrivateKey

	signReqs   []signer.Request
	proofCalls int
	proofReqs  []signer.PaymentProofRequest

	signErr     error
	notExecuted int
	proofErr    error

	// statusRoute turns the status route on; without it the fake answers
	// like a signer that lacks the route.
	statusRoute bool
	signedTx    []byte
	statusPolls int
	signCtxErrs []error
	// blockProof makes the payment-signature call wait for its context.
	blockProof bool

	finalState   signer.State
	statusShared bool

	badTx    bool
	badRail  bool
	badMsg   bool
	proofKey *secp256k1.PrivateKey
}

func newFakeSigner(t *testing.T) *fakeSigner {
	t.Helper()
	priv, err := secp256k1.GeneratePrivateKey()
	require.NoError(t, err)
	return &fakeSigner{priv: priv}
}

func (f *fakeSigner) Sign(ctx context.Context, req signer.Request) (signer.Output, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.signReqs = append(f.signReqs, req)
	f.signCtxErrs = append(f.signCtxErrs, ctx.Err())
	if f.signErr != nil {
		return signer.Output{}, f.signErr
	}
	tx, err := edenescrow.DecodeTxAction(req.Action)
	if err != nil {
		return signer.Output{}, err
	}
	signed, _, err := tx.SignTx(f.priv)
	if err != nil {
		return signer.Output{}, err
	}
	if f.badTx {
		signed[20] ^= 1
	}
	sc, err := commitment.DecodeSigned(req.Envelope)
	if err != nil {
		return signer.Output{}, err
	}
	h, err := commitment.HashOf(&sc.Commitment)
	if err != nil {
		return signer.Output{}, err
	}
	ref := edenescrow.RailRef(signed)
	if f.badRail {
		ref = strings.Repeat("0", 64)
	}
	f.signedTx = signed
	return signer.Output{CommitmentHash: h, Signed: signed, RailRef: ref}, nil
}

func (f *fakeSigner) Status(_ context.Context, _ commitment.Hash) (signer.Status, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.statusShared {
		return signer.Status{}, &commitcmd.SignerError{Status: 403, Code: "signer.ErrSharedCredential", Message: "shared"}
	}
	if !f.statusRoute {
		return signer.Status{}, &commitcmd.SignerError{Status: 404, Code: "edictaapi.ErrRouteNotFound", Message: "no route"}
	}
	if f.signedTx == nil {
		return signer.Status{}, &commitcmd.SignerError{Status: 404, Code: "signer.ErrUnknownDecision", Message: "unknown"}
	}
	f.statusPolls++
	if f.finalState != "" {
		return signer.Status{State: f.finalState, Signed: f.signedTx, Detail: "d"}, nil
	}
	st := signer.Status{State: signer.StateSigned, Sent: true, RailRef: edenescrow.RailRef(f.signedTx), Signed: f.signedTx}
	if f.statusPolls > f.notExecuted {
		st.State = signer.StateRecorded
		st.Receipt = []byte("receipt")
	}
	return st, nil
}

func (f *fakeSigner) PaymentSignature(ctx context.Context, req signer.PaymentProofRequest) (signer.PaymentProof, error) {
	if f.blockProof {
		<-ctx.Done()
		return signer.PaymentProof{}, ctx.Err()
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.proofCalls++
	f.proofReqs = append(f.proofReqs, req)
	if f.proofCalls <= f.notExecuted {
		return signer.PaymentProof{}, &commitcmd.SignerError{Status: 409, Code: "signer.ErrNotExecuted", Message: "not executed", Retryable: true}
	}
	if f.proofErr != nil {
		return signer.PaymentProof{}, f.proofErr
	}
	tx, err := edenescrow.DecodeTxAction(req.Action)
	if err != nil {
		return signer.PaymentProof{}, err
	}
	m, err := edenescrow.PaymentProofMessage(tx, req.Requirements)
	if err != nil {
		return signer.PaymentProof{}, err
	}
	if f.badMsg {
		m[0] ^= 1
	}
	key := f.priv
	if f.proofKey != nil {
		key = f.proofKey
	}
	sig, err := edenescrow.Sign(key, edenescrow.PersonalDigest(m))
	if err != nil {
		return signer.PaymentProof{}, err
	}
	raw := append(append(append([]byte{}, sig.R[:]...), sig.S[:]...), 27+sig.YParity)
	return signer.PaymentProof{CommitmentHash: req.CommitmentHash, Message: m, Signature: []byte("0x" + hex.EncodeToString(raw))}, nil
}

type memState struct {
	mu       sync.Mutex
	m        map[string]commitcmd.State
	failSave bool
}

func (s *memState) Save(hash string, st commitcmd.State) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failSave {
		return errors.New("disk full")
	}
	if s.m == nil {
		s.m = map[string]commitcmd.State{}
	}
	s.m[hash] = st
	return nil
}

func (s *memState) Load(hash string) (commitcmd.State, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.m[hash]
	return st, ok, nil
}

type edenRig struct {
	*rig
	signer *fakeSigner
	state  *memState
	sleeps []time.Duration
}

func newEdenRig(t *testing.T) *edenRig {
	t.Helper()
	r := &edenRig{rig: newRigAt(t, edenNow), signer: newFakeSigner(t), state: &memState{}}
	r.svc.Signer, r.svc.State = r.signer, r.state
	r.svc.PollInterval = 2 * time.Second
	r.svc.Sleep = func(_ context.Context, d time.Duration) error { r.sleeps = append(r.sleeps, d); return nil }
	return r
}

func failureOf(t *testing.T, err error) *commitcmd.Failure {
	t.Helper()
	var f *commitcmd.Failure
	require.ErrorAs(t, err, &f)
	return f
}

func TestEdenCommitsTheConvertedActionBytes(t *testing.T) {
	r := newEdenRig(t)
	resp, err := r.svc.Commit(context.Background(), edenRequest(t))
	require.NoError(t, err)
	assert.Equal(t, expectedAction(t), resp.Action, "the action is the edenescrow conversion, nothing re-encoded")
	assert.Equal(t, resp.Action, r.gate.action)
	require.NotNil(t, resp.Deposit)
	assert.Equal(t, "64b7e0cf7a15035882485d6a704853c17d7ed8d2b3278c88dc2971236113fed7", resp.Deposit.PaymentIDHex)
	assert.Equal(t, 0, r.signer.proofCalls+len(r.signer.signReqs), "no sign flag, no signer call")

	sc, err := commitment.DecodeSigned(resp.Envelope)
	require.NoError(t, err)
	assert.Equal(t, edenescrow.ActionType, sc.Commitment.Action.Type)
}

func TestEdenFullFlowSignsSendsAndWaitsForSettlement(t *testing.T) {
	r := newEdenRig(t)
	r.signer.notExecuted = 3
	req := edenRequest(t)
	req.Sign, req.Broadcast, req.Record, req.PaymentSignature = true, true, true, true
	resp, err := r.svc.Commit(context.Background(), req)
	require.NoError(t, err)

	require.Len(t, r.signer.signReqs, 1)
	sr := r.signer.signReqs[0]
	assert.Equal(t, resp.Envelope, sr.Envelope)
	assert.Equal(t, resp.Action, sr.Action)
	assert.Equal(t, resp.Salt, sr.Salt)
	assert.Equal(t, resp.Authorization, sr.Authorization)
	assert.Equal(t, liveFixture(t, "houston-payment-required.json"), sr.Requirements, "R travels with the sign request")

	assert.Equal(t, 4, r.signer.proofCalls)
	assert.Equal(t, []time.Duration{2 * time.Second, 2 * time.Second, 2 * time.Second}, r.sleeps)
	assert.Equal(t, commitcmd.PaymentField, r.signer.proofReqs[0].Field)
	assert.True(t, resp.Settled)
	assert.Regexp(t, `^0x[0-9a-f]{130}$`, resp.PaymentSignature)
	assert.Equal(t, edenescrow.RailRef(resp.SignedTx), resp.RailRef)
	assert.Regexp(t, `^0x[0-9a-f]{40}$`, resp.Payer)
}

func TestEdenRecordWithoutPaymentSignatureDoesNotPrintIt(t *testing.T) {
	r := newEdenRig(t)
	req := edenRequest(t)
	req.Sign, req.Broadcast, req.Record = true, true, true
	resp, err := r.svc.Commit(context.Background(), req)
	require.NoError(t, err)
	assert.True(t, resp.Settled)
	assert.Empty(t, resp.PaymentSignature)
}

func TestEdenFlagRulesAreCheckedBeforeAnythingIsPublished(t *testing.T) {
	cases := map[string]func(*commitcmd.Request, *edenRig){
		"sign without broadcast": func(q *commitcmd.Request, _ *edenRig) { q.Sign = true },
		"broadcast without sign": func(q *commitcmd.Request, _ *edenRig) { q.Broadcast = true },
		"no signer":              func(q *commitcmd.Request, r *edenRig) { q.Sign, q.Broadcast = true, true; r.svc.Signer = nil },
		"flags without eden": func(q *commitcmd.Request, _ *edenRig) {
			q.Eden, q.Sign, q.Broadcast = nil, true, true
			q.ActionType, q.Action = "application/vnd.test.order+json", []byte("x")
		},
		"record without sign":              func(q *commitcmd.Request, _ *edenRig) { q.Record = true },
		"payment signature without sign":   func(q *commitcmd.Request, _ *edenRig) { q.PaymentSignature = true },
		"bad wait":                         func(q *commitcmd.Request, _ *edenRig) { q.Record, q.Wait = true, "2h" },
		"no build":                         func(q *commitcmd.Request, _ *edenRig) { q.Eden.Build = nil },
		"no header":                        func(q *commitcmd.Request, _ *edenRig) { q.Eden.PaymentRequired = "" },
		"action given":                     func(q *commitcmd.Request, _ *edenRig) { q.Action = []byte("x") },
		"context is an array":              func(q *commitcmd.Request, _ *edenRig) { q.Context = []byte(`[1]`) },
		"context takes the key":            func(q *commitcmd.Request, _ *edenRig) { q.Context = []byte(`{"Eden_Escrow":1}`) },
		"quote names http and no resource": func(q *commitcmd.Request, _ *edenRig) { q.Eden.Resource = "" },
		"http resource":                    func(q *commitcmd.Request, _ *edenRig) { q.Eden.Resource = "http://inference.bot.fun/x" },
		"valid_for before quote":           func(q *commitcmd.Request, _ *edenRig) { q.ValidFor = "1m" },
		"resume hash no state":             func(q *commitcmd.Request, r *edenRig) { q.ResumeHash = strings.Repeat("a", 64); r.svc.State = nil },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			r := newEdenRig(t)
			req := edenRequest(t)
			mutate(&req, r)
			_, err := r.svc.Commit(context.Background(), req)
			require.Error(t, err)
			assert.Equal(t, commitcmd.ExitUsage, failureOf(t, err).Exit)
			assert.Empty(t, r.pub.Blobs())
			assert.Zero(t, r.gate.calls)
		})
	}
}

func TestEdenRefusesAServerTransactionThatDoesNotMatchTheQuote(t *testing.T) {
	build := string(liveFixture(t, "houston-deposit-build.json"))
	cases := map[string]func(*commitcmd.EdenInput){
		// The calldata still names the quoted paymentId, but the wei amount
		// differs from the quote.
		"value changed": func(e *commitcmd.EdenInput) {
			e.Build = []byte(strings.Replace(build, `"value":"7208392580248"`, `"value":"7208392580249"`, 1))
		},
		"escrow changed": func(e *commitcmd.EdenInput) {
			e.Build = []byte(strings.Replace(build, "0x65d77c98E73DFbEA91eCb72B27c9753e186a94c8", "0x65d77c98E73DFbEA91eCb72B27c9753e186a94c9", 1))
		},
		"header is not base64": func(e *commitcmd.EdenInput) { e.PaymentRequired = "not base64!" },
		"header of another quote": func(e *commitcmd.EdenInput) {
			rr := strings.Replace(string(liveFixture(t, "houston-payment-required.json")), `"amount": "7208392580248"`, `"amount": "1"`, 1)
			e.PaymentRequired = base64.StdEncoding.EncodeToString([]byte(rr))
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			r := newEdenRig(t)
			req := edenRequest(t)
			mutate(req.Eden)
			_, err := r.svc.Commit(context.Background(), req)
			require.Error(t, err)
			f := failureOf(t, err)
			assert.Equal(t, commitcmd.ExitUsage, f.Exit)
			assert.Equal(t, "eden_input", f.Code)
			assert.Empty(t, r.pub.Blobs(), "nothing is published for a refused conversion")
		})
	}
}

func TestEdenRefusesAnExpiredQuote(t *testing.T) {
	r := newRigAt(t, quoteExpiresAt+1)
	r.svc.Signer = newFakeSigner(t)
	_, err := r.svc.Commit(context.Background(), edenRequest(t))
	require.Error(t, err)
	f := failureOf(t, err)
	assert.Equal(t, commitcmd.ExitRefused, f.Exit)
	assert.Equal(t, "quote_expired", f.Code)
	assert.Empty(t, r.pub.Blobs())
}

func TestEdenRefusesAQuoteThatOutlivesTheAuthorization(t *testing.T) {
	r := newEdenRig(t)
	req := edenRequest(t)
	req.Sign, req.Broadcast = true, true
	r.svc.Clock = func() time.Time { return time.Unix(edenNow, 0) }
	// The gate authorizes for less than the commitment's validity.
	r.gate.shorten = 800
	_, err := r.svc.Commit(context.Background(), req)
	require.Error(t, err)
	f := failureOf(t, err)
	assert.Equal(t, "quote_outlives_authorization", f.Code)
	assert.Empty(t, r.signer.signReqs, "the signer is not asked")
	assert.NotEmpty(t, f.CommitmentHash)
	assert.NotEmpty(t, f.Envelope, "the committed material comes back for a resume")
}

func TestEdenSignerAnswersAreCheckedAgainstTheCommittedAction(t *testing.T) {
	cases := map[string]func(*fakeSigner){
		"another transaction": func(s *fakeSigner) { s.badTx = true },
		"another rail ref":    func(s *fakeSigner) { s.badRail = true },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			r := newEdenRig(t)
			mutate(r.signer)
			req := edenRequest(t)
			req.Sign, req.Broadcast = true, true
			_, err := r.svc.Commit(context.Background(), req)
			require.Error(t, err)
			f := failureOf(t, err)
			assert.Equal(t, commitcmd.ExitRefused, f.Exit)
			assert.Equal(t, "signer_response_invalid", f.Code)
			assert.NotEmpty(t, f.CommitmentHash)
		})
	}
}

func TestEdenPaymentProofIsCheckedAgainstThePayer(t *testing.T) {
	other, err := secp256k1.GeneratePrivateKey()
	require.NoError(t, err)
	cases := map[string]func(*fakeSigner){
		"made by another key": func(s *fakeSigner) { s.proofKey = other },
		"another message":     func(s *fakeSigner) { s.badMsg = true },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			r := newEdenRig(t)
			mutate(r.signer)
			req := edenRequest(t)
			req.Sign, req.Broadcast, req.PaymentSignature = true, true, true
			_, err := r.svc.Commit(context.Background(), req)
			require.Error(t, err)
			assert.Equal(t, "signer_response_invalid", failureOf(t, err).Code)
		})
	}
}

func TestEdenSignerFailureClasses(t *testing.T) {
	cases := []struct {
		name string
		err  error
		exit int
		code string
	}{
		{"refusal", &commitcmd.SignerError{Status: 403, Code: "signer.ErrNotAuthorized", Message: "no"}, commitcmd.ExitRefused, "signer.ErrNotAuthorized"},
		{"unavailable", &commitcmd.SignerError{Status: 503, Code: "signer.ErrUnavailable", Message: "down", Retryable: true}, commitcmd.ExitUnavailable, "signer.ErrUnavailable"},
		{"transport", errors.New("connection refused"), commitcmd.ExitUnavailable, "source_unavailable"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := newEdenRig(t)
			r.signer.signErr = tc.err
			req := edenRequest(t)
			req.Sign, req.Broadcast = true, true
			_, err := r.svc.Commit(context.Background(), req)
			require.Error(t, err)
			f := failureOf(t, err)
			assert.Equal(t, tc.exit, f.Exit)
			assert.Equal(t, tc.code, f.Code)
			assert.Len(t, f.CommitmentHash, 64)
			assert.NotEmpty(t, f.Authorization, "the spent Authorization is returned")
		})
	}
}

func TestEdenSettlementWaitIsBounded(t *testing.T) {
	r := newEdenRig(t)
	r.signer.notExecuted = 1 << 20
	req := edenRequest(t)
	req.Sign, req.Broadcast, req.Record, req.Wait = true, true, true, "10s"
	_, err := r.svc.Commit(context.Background(), req)
	require.Error(t, err)
	f := failureOf(t, err)
	assert.Equal(t, commitcmd.ExitUnavailable, f.Exit)
	assert.Equal(t, "settlement_pending", f.Code)
	assert.True(t, f.Retryable)
	assert.Len(t, f.CommitmentHash, 64)
	assert.Len(t, r.sleeps, 5, "ten seconds in two second steps")
}

func TestEdenSettlementRefusalStopsAtOnce(t *testing.T) {
	r := newEdenRig(t)
	r.signer.proofErr = &commitcmd.SignerError{Status: 422, Code: "signer.ErrRequirements", Message: "bad R"}
	req := edenRequest(t)
	req.Sign, req.Broadcast, req.Record = true, true, true
	_, err := r.svc.Commit(context.Background(), req)
	require.Error(t, err)
	f := failureOf(t, err)
	assert.Equal(t, commitcmd.ExitRefused, f.Exit)
	assert.Equal(t, 1, r.signer.proofCalls)
	assert.Empty(t, r.sleeps)
}

func TestEdenResumesByCommitmentHashWithoutPublishingAgain(t *testing.T) {
	r := newEdenRig(t)
	r.signer.signErr = &commitcmd.SignerError{Status: 503, Code: "signer.ErrUnavailable", Message: "down", Retryable: true}
	req := edenRequest(t)
	req.Sign, req.Broadcast, req.Record, req.PaymentSignature = true, true, true, true
	_, err := r.svc.Commit(context.Background(), req)
	require.Error(t, err)
	hash := failureOf(t, err).CommitmentHash
	require.Len(t, hash, 64)
	require.Len(t, r.pub.Blobs(), 1)
	gateCalls := r.gate.calls

	// The process is gone; a new call has the hash and the quote only.
	r.signer.signErr = nil
	again := commitcmd.Request{
		ResumeHash: hash, Eden: &commitcmd.EdenInput{PaymentRequired: req.Eden.PaymentRequired},
		Sign: true, Broadcast: true, Record: true, PaymentSignature: true,
	}
	resp, err := r.svc.Commit(context.Background(), again)
	require.NoError(t, err)
	assert.Equal(t, hash, resp.CommitmentHash)
	assert.Len(t, r.pub.Blobs(), 1, "nothing is published again")
	assert.Equal(t, gateCalls, r.gate.calls, "the stored Authorization is reused")
	assert.True(t, resp.Settled)
	assert.NotEmpty(t, resp.PaymentSignature)
}

func TestEdenResumeAfterSigningOnlyWaits(t *testing.T) {
	r := newEdenRig(t)
	r.signer.notExecuted = 1 << 20
	req := edenRequest(t)
	req.Sign, req.Broadcast, req.Record, req.Wait = true, true, true, "4s"
	_, err := r.svc.Commit(context.Background(), req)
	hash := failureOf(t, err).CommitmentHash
	require.Len(t, r.signer.signReqs, 1)

	r.signer.notExecuted = 0
	resp, err := r.svc.Commit(context.Background(), commitcmd.Request{ResumeHash: hash, Record: true, PaymentSignature: true})
	require.NoError(t, err)
	assert.Len(t, r.signer.signReqs, 1, "the deposit is not signed again")
	assert.True(t, resp.Settled)
}

func TestEdenResumeFromTheStoreWithoutSignAsksOnlyForTheProof(t *testing.T) {
	r := newEdenRig(t)
	req := edenRequest(t)
	req.Sign, req.Broadcast = true, true
	first, err := r.svc.Commit(context.Background(), req)
	require.NoError(t, err)

	resp, err := r.svc.Commit(context.Background(), commitcmd.Request{ResumeHash: first.CommitmentHash, Record: true, PaymentSignature: true})
	require.NoError(t, err, "the stored quote is used")
	assert.Len(t, r.signer.signReqs, 1, "no second sign")
	assert.True(t, resp.Settled)
	assert.Equal(t, first.RailRef, resp.RailRef)
}

func TestEdenResumeRefusesAStateOfAnotherCommitment(t *testing.T) {
	r := newEdenRig(t)
	first, err := r.svc.Commit(context.Background(), edenRequest(t))
	require.NoError(t, err)
	other := strings.Repeat("b", 64)
	r.state.m[other] = r.state.m[first.CommitmentHash]
	_, err = r.svc.Commit(context.Background(), commitcmd.Request{ResumeHash: other})
	require.Error(t, err)
	assert.Equal(t, commitcmd.ExitUsage, failureOf(t, err).Exit)

	_, err = r.svc.Commit(context.Background(), commitcmd.Request{ResumeHash: strings.Repeat("c", 64)})
	require.Error(t, err, "unknown hash")
	_, err = r.svc.Commit(context.Background(), commitcmd.Request{ResumeHash: "ABC"})
	require.Error(t, err, "malformed hash")
	_, err = r.svc.Commit(context.Background(), commitcmd.Request{ResumeHash: first.CommitmentHash, Model: commitcmd.Named{ID: "x"}})
	require.Error(t, err, "resume takes no build fields")
}

func TestEdenResumeAfterTheAuthorizationExpiredFollowsTheSignedBytes(t *testing.T) {
	r := newEdenRig(t)
	req := edenRequest(t)
	req.Sign, req.Broadcast = true, true
	first, err := r.svc.Commit(context.Background(), req)
	require.NoError(t, err)

	r.svc.Clock = func() time.Time { return time.Unix(int64(first.Expires)+3600, 0) }
	resp, err := r.svc.Commit(context.Background(), commitcmd.Request{ResumeHash: first.CommitmentHash, Record: true})
	require.NoError(t, err)
	assert.True(t, resp.Settled)

	resp, err = r.svc.Commit(context.Background(), commitcmd.Request{ResumeHash: first.CommitmentHash, Sign: true, Broadcast: true, Record: true})
	require.NoError(t, err, "stored signed bytes are followed, not signed again")
	assert.Len(t, r.signer.signReqs, 1)
	assert.True(t, resp.Settled)
}

// loseSigned drops the signed bytes from the stored state, as a crash between
// the signer's answer and the write would.
func (r *edenRig) loseSigned(hash string) {
	st := r.state.m[hash]
	st.Signed, st.RailRef = nil, ""
	r.state.m[hash] = st
}

func TestEdenExpiredAuthorizationAdoptsWhatTheSignerHolds(t *testing.T) {
	r := newEdenRig(t)
	r.signer.statusRoute = true
	req := edenRequest(t)
	req.Sign, req.Broadcast = true, true
	first, err := r.svc.Commit(context.Background(), req)
	require.NoError(t, err)
	r.loseSigned(first.CommitmentHash)

	r.svc.Clock = func() time.Time { return time.Unix(int64(first.Expires)+3600, 0) }
	resp, err := r.svc.Commit(context.Background(), commitcmd.Request{ResumeHash: first.CommitmentHash, Sign: true, Broadcast: true, Record: true})
	require.NoError(t, err)
	assert.Len(t, r.signer.signReqs, 1, "the signer is not asked to sign again")
	assert.Equal(t, first.RailRef, resp.RailRef)
	assert.True(t, resp.Settled)
	assert.True(t, resp.Recorded)
	assert.Equal(t, r.signer.signedTx, r.state.m[first.CommitmentHash].Signed, "the adopted bytes are stored")
}

func TestEdenNeverAdvisesCommitAgainWhileTheSignerMayHoldTheDecision(t *testing.T) {
	r := newEdenRig(t)
	req := edenRequest(t)
	req.Sign, req.Broadcast = true, true
	first, err := r.svc.Commit(context.Background(), req)
	require.NoError(t, err)
	r.loseSigned(first.CommitmentHash)
	r.svc.Clock = func() time.Time { return time.Unix(int64(first.Expires)+3600, 0) }
	again := commitcmd.Request{ResumeHash: first.CommitmentHash, Sign: true, Broadcast: true}

	// No status route: the CLI cannot tell.
	_, err = r.svc.Commit(context.Background(), again)
	require.Error(t, err)
	f := failureOf(t, err)
	assert.Equal(t, "authorization_expired", f.Code)
	assert.Contains(t, f.Message, "do not commit again")
	assert.Empty(t, r.signer.signReqs[1:], "no second sign")

	// Status route answering unknown: only then is a new commitment right.
	r.signer.statusRoute, r.signer.signedTx = true, nil
	_, err = r.svc.Commit(context.Background(), again)
	require.Error(t, err)
	assert.Contains(t, failureOf(t, err).Message, "commit again")
	assert.NotContains(t, failureOf(t, err).Message, "do not commit again")
}

func TestEdenSharedSignerCredentialIsNeverReadAsUnknown(t *testing.T) {
	r := newEdenRig(t)
	req := edenRequest(t)
	req.Sign, req.Broadcast = true, true
	first, err := r.svc.Commit(context.Background(), req)
	require.NoError(t, err)
	r.loseSigned(first.CommitmentHash)
	r.signer.statusShared = true
	r.svc.Clock = func() time.Time { return time.Unix(int64(first.Expires)+3600, 0) }
	_, err = r.svc.Commit(context.Background(), commitcmd.Request{ResumeHash: first.CommitmentHash, Sign: true, Broadcast: true})
	require.Error(t, err)
	assert.Contains(t, failureOf(t, err).Message, "do not commit again")
	assert.Len(t, r.signer.signReqs, 1)

	_, err = r.svc.Commit(context.Background(), commitcmd.Request{ResumeHash: first.CommitmentHash, Record: true})
	require.Error(t, err)
	assert.NotContains(t, failureOf(t, err).Message, "commit again")
}

func TestEdenResumeObjectKeepsTheStoredAuthorizationAndSignedBytes(t *testing.T) {
	r := newEdenRig(t)
	req := edenRequest(t)
	req.Sign, req.Broadcast = true, true
	first, err := r.svc.Commit(context.Background(), req)
	require.NoError(t, err)
	before := r.state.m[first.CommitmentHash]
	require.NotEmpty(t, before.Signed)

	_, err = r.svc.Commit(context.Background(), commitcmd.Request{
		Resume: &commitcmd.Resume{Envelope: first.Envelope, Action: first.Action, Salt: first.Salt},
		Eden:   &commitcmd.EdenInput{PaymentRequired: req.Eden.PaymentRequired},
	})
	require.NoError(t, err)
	assert.Equal(t, before, r.state.m[first.CommitmentHash], "the stored state is not erased")
}

func TestEdenResumeObjectWithAWrongQuoteLeavesTheStoreAlone(t *testing.T) {
	r := newEdenRig(t)
	first, err := r.svc.Commit(context.Background(), edenRequest(t))
	require.NoError(t, err)
	before := r.state.m[first.CommitmentHash]
	other := strings.Replace(string(liveFixture(t, "houston-payment-required.json")), `"amount": "7208392580248"`, `"amount": "1"`, 1)

	_, err = r.svc.Commit(context.Background(), commitcmd.Request{
		Resume: &commitcmd.Resume{Envelope: first.Envelope, Action: first.Action, Salt: first.Salt},
		Eden:   &commitcmd.EdenInput{PaymentRequired: base64.StdEncoding.EncodeToString([]byte(other))},
	})
	require.Error(t, err)
	assert.Equal(t, commitcmd.ExitUsage, failureOf(t, err).Exit)
	assert.Equal(t, before, r.state.m[first.CommitmentHash])
}

func TestEdenSignRunsDetachedFromTheCallersCancellation(t *testing.T) {
	r := newEdenRig(t)
	ctx, cancel := context.WithCancel(context.Background())
	r.gate.hook = cancel
	req := edenRequest(t)
	req.Sign, req.Broadcast = true, true
	_, err := r.svc.Commit(ctx, req)
	require.NoError(t, err)
	require.Len(t, r.signer.signCtxErrs, 1)
	assert.NoError(t, r.signer.signCtxErrs[0], "the sign call is not cancelled with the caller")
	assert.NotEmpty(t, r.state.m[failHash(t, r)].Signed, "the answer is stored")
}

func failHash(t *testing.T, r *edenRig) string {
	t.Helper()
	require.Len(t, r.state.m, 1)
	for h := range r.state.m {
		return h
	}
	return ""
}

func TestEdenRecordFollowsTheStatusRoute(t *testing.T) {
	r := newEdenRig(t)
	r.signer.statusRoute = true
	r.signer.notExecuted = 2
	req := edenRequest(t)
	req.Sign, req.Broadcast, req.Record = true, true, true
	resp, err := r.svc.Commit(context.Background(), req)
	require.NoError(t, err)
	assert.True(t, resp.Settled)
	assert.True(t, resp.Recorded)
	assert.Equal(t, []byte("receipt"), resp.Receipt)
	assert.Zero(t, r.signer.proofCalls, "no payment proof is fetched for record")
	assert.Len(t, r.sleeps, 2)

	r2 := newEdenRig(t)
	r2.signer.statusRoute = true
	req.PaymentSignature = true
	resp, err = r2.svc.Commit(context.Background(), req)
	require.NoError(t, err)
	assert.Regexp(t, `^0x[0-9a-f]{130}$`, resp.PaymentSignature)
}

func TestEdenRecordFinalStates(t *testing.T) {
	for _, st := range []struct {
		state signer.State
		code  string
	}{{signer.StateReverted, "deposit_reverted"}, {signer.StateNotExecuted, "deposit_not_executed"}, {signer.StateWrong, "settlement_wrong"}} {
		t.Run(string(st.state), func(t *testing.T) {
			r := newEdenRig(t)
			r.signer.statusRoute = true
			r.signer.finalState = st.state
			req := edenRequest(t)
			req.Sign, req.Broadcast, req.Record = true, true, true
			_, err := r.svc.Commit(context.Background(), req)
			require.Error(t, err)
			f := failureOf(t, err)
			assert.Equal(t, st.code, f.Code)
			assert.Equal(t, commitcmd.ExitRefused, f.Exit)
		})
	}
}

func TestEdenSettlementWaitIsAlsoAWallClockBound(t *testing.T) {
	r := newEdenRig(t)
	r.signer.blockProof = true
	req := edenRequest(t)
	req.Sign, req.Broadcast, req.PaymentSignature, req.Wait = true, true, true, "50ms"
	start := time.Now()
	_, err := r.svc.Commit(context.Background(), req)
	require.Error(t, err)
	assert.Less(t, time.Since(start), 5*time.Second)
	f := failureOf(t, err)
	assert.Equal(t, "settlement_pending", f.Code)
	assert.Equal(t, commitcmd.ExitUnavailable, f.Exit)
}

func TestEdenUnparsableSignerFailureIsUnknownNotRefused(t *testing.T) {
	r := newEdenRig(t)
	r.signer.signErr = &commitcmd.SignerError{Status: 502, Code: "signer.unparsable", Message: "bad gateway", Retryable: true}
	req := edenRequest(t)
	req.Sign, req.Broadcast = true, true
	_, err := r.svc.Commit(context.Background(), req)
	require.Error(t, err)
	f := failureOf(t, err)
	assert.Equal(t, commitcmd.ExitUnavailable, f.Exit)
	assert.Contains(t, f.Message, "do not commit again")
}

func TestEdenStateWriteFailureReturnsTheResumeMaterial(t *testing.T) {
	r := newEdenRig(t)
	r.state.failSave = true
	_, err := r.svc.Commit(context.Background(), edenRequest(t))
	require.Error(t, err)
	f := failureOf(t, err)
	assert.Equal(t, "state_unavailable", f.Code)
	assert.Equal(t, commitcmd.ExitUnavailable, f.Exit)
	assert.NotEmpty(t, f.Envelope)
	assert.Zero(t, r.gate.calls, "nothing is authorized without a durable state")
}

func TestEdenRequestOverJSONServeRoute(t *testing.T) {
	r := newEdenRig(t)
	h := commitcmd.Handler(r.svc, commitcmd.Options{})
	build := liveFixture(t, "houston-deposit-build.json")
	body, err := json.Marshal(map[string]any{
		"eden": map[string]any{
			"build":            json.RawMessage(build),
			"payment_required": base64.StdEncoding.EncodeToString(liveFixture(t, "houston-payment-required.json")),
			"resource":         "https://inference.bot.fun/v1/chat/completions",
		},
		"model": map[string]any{"id": "m"}, "policy": map[string]any{"id": "p"},
		"sign": true, "broadcast": true, "record": true, "payment_signature": true, "wait": "30s",
	})
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/v1/commit", bytes.NewReader(body))
	req.Host = "127.0.0.1:8500"
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var out map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &out))
	assert.Equal(t, true, out["settled"])
	assert.Contains(t, out, "payment_signature")
	assert.Contains(t, out, "signed_tx")
	assert.Contains(t, out, "deposit")

	// A refusal carries the commitment hash for the resume.
	r.signer.signErr = &commitcmd.SignerError{Status: 403, Code: "signer.ErrNotAuthorized", Message: "no"}
	req = httptest.NewRequest(http.MethodPost, "/v1/commit", bytes.NewReader(body))
	req.Host = "127.0.0.1:8500"
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
	assert.Contains(t, w.Body.String(), `"commitment_hash"`)
}

func TestEdenRequestRejectsUnknownAndRepeatedKeys(t *testing.T) {
	_, err := commitcmd.DecodeRequest(strings.NewReader(`{"eden":{"build":{},"payment_required":"x","extra":1}}`))
	require.Error(t, err)
	_, err = commitcmd.DecodeRequest(strings.NewReader(`{"eden":{"build":{"a":1,"a":2},"payment_required":"x"}}`))
	require.Error(t, err)
	_, err = commitcmd.DecodeRequest(strings.NewReader(`{"sign":true,"Sign":false}`))
	require.Error(t, err)
}
