// SPDX-License-Identifier: Apache-2.0

package signer_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/plugins/edenescrow"
	"github.com/vgonkivs/edicta/plugins/edenescrow/edenexec"
	"github.com/vgonkivs/edicta/signer"
	"github.com/vgonkivs/edicta/signer/eden"
	"github.com/vgonkivs/edicta/signer/signertest"
)

// otherAgent is a second served agent with its own key.
var otherAgent = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x0b}, 32))

func paymentEnv(t *testing.T) *env {
	t.Helper()
	return newEnvOpts(t, envOpts{payment: true}, func(c *signer.Config) {
		c.AgentKeys = append(c.AgentKeys, otherAgent.Public().(ed25519.PublicKey))
	})
}

// quoted is a decision for a deposit to the quote facilitator, with R.
func (e *env) quoted(label string, mut ...func(*signertest.Deposit)) (signertest.Decision, signertest.Deposit) {
	t := e.t
	t.Helper()
	d := signertest.NewDeposit(e.clk.Now())
	for _, m := range mut {
		m(&d)
	}
	d, err := signertest.QuotedDeposit(d)
	require.NoError(t, err)
	action, err := d.Action()
	require.NoError(t, err)
	dec, err := signertest.NewDecision(e.keys, action, e.clk.Now(), signertest.DecisionOpts{Label: label})
	require.NoError(t, err)
	return dec, d
}

func quotedRequest(d signertest.Decision, dep signertest.Deposit) signer.Request {
	r := request(d)
	r.Requirements = dep.Requirements
	return r
}

func proofRequest(d signertest.Decision) signer.PaymentProofRequest {
	return signer.PaymentProofRequest{CommitmentHash: d.Hash, Field: eden.FieldPaymentID, Request: request(d)}
}

// executed signs the decision, lets both operators include it and waits
// until it is recorded.
func (e *env) executed(d signertest.Decision, dep signertest.Deposit) signer.Output {
	t := e.t
	t.Helper()
	out, err := e.svc.Sign(context.Background(), quotedRequest(d, dep))
	require.NoError(t, err)
	e.second.Land(out.Signed)
	got := e.waitState(d.Hash, signer.StateRecorded)
	require.True(t, got.PaymentProofAllowed)
	return out
}

func TestPaymentSignatureForTheAgentsOwnExecutedDeposit(t *testing.T) {
	e := paymentEnv(t)
	d, dep := e.quoted("a")
	e.executed(d, dep)

	// The Authorization has expired since; the reservation's clock counts.
	e.clk.Add(time.Hour)
	p, err := e.svc.PaymentProof(context.Background(), proofRequest(d), e.keys.AgentPub())
	require.NoError(t, err)
	assert.Equal(t, dep.PaymentID, p.Message)
	assert.False(t, p.Repeat)
	require.True(t, strings.HasPrefix(string(p.Signature), "0x"))
	raw, err := hex.DecodeString(string(p.Signature[2:]))
	require.NoError(t, err)
	require.Len(t, raw, 65)
	assert.Contains(t, []byte{27, 28}, raw[64])
	got, err := edenescrow.RecoverPersonal(dep.PaymentID, [65]byte(raw))
	require.NoError(t, err)
	assert.Equal(t, e.keys.PayerAddress(), got)

	again, err := e.svc.PaymentProof(context.Background(), proofRequest(d), e.keys.AgentPub())
	require.NoError(t, err)
	assert.True(t, again.Repeat)
	assert.Equal(t, p.Signature, again.Signature)
	assert.Equal(t, p.Signature, e.entry(d.Hash).PaymentProof)
}

func TestPaymentSignatureRefusals(t *testing.T) {
	ctx := context.Background()
	e := paymentEnv(t)
	d, dep := e.quoted("a")
	e.executed(d, dep)
	e.chain.Set(func(c *signertest.Chain) { c.Nonce = 8 })
	other, otherDep := e.quoted("b", func(x *signertest.Deposit) {
		x.Nonce = 8
		x.PaymentID[0] ^= 1
	})
	e.executed(other, otherDep)

	t.Run("another agent's credential", func(t *testing.T) {
		_, err := e.svc.PaymentProof(ctx, proofRequest(d), otherAgent.Public().(ed25519.PublicKey))
		require.ErrorIs(t, err, signer.ErrNotAuthorized)
		_, err = e.svc.PaymentProof(ctx, proofRequest(d), nil)
		require.ErrorIs(t, err, signer.ErrNotAuthorized, "a shared credential names no agent")
	})
	t.Run("the material of another decision", func(t *testing.T) {
		req := proofRequest(other)
		req.CommitmentHash = d.Hash
		_, err := e.svc.PaymentProof(ctx, req, e.keys.AgentPub())
		require.ErrorIs(t, err, signer.ErrNotAuthorized)
	})
	t.Run("a decision the signer never paid", func(t *testing.T) {
		never, _ := e.quoted("never")
		_, err := e.svc.PaymentProof(ctx, proofRequest(never), e.keys.AgentPub())
		require.ErrorIs(t, err, signer.ErrNotAuthorized)
	})
	t.Run("R of another paymentId presented", func(t *testing.T) {
		req := proofRequest(d)
		req.Requirements = otherDep.Requirements
		_, err := e.svc.PaymentProof(ctx, req, e.keys.AgentPub())
		require.ErrorIs(t, err, signer.ErrRequirements)
	})
	t.Run("field nonce", func(t *testing.T) {
		req := proofRequest(d)
		req.Field = "nonce"
		_, err := e.svc.PaymentProof(ctx, req, e.keys.AgentPub())
		require.ErrorIs(t, err, signer.ErrPinMismatch)
	})
}

func TestPaymentSignatureOnlyAfterExecutionAtL1(t *testing.T) {
	ctx := context.Background()
	e := paymentEnv(t)
	d, dep := e.quoted("a")
	out, err := e.svc.Sign(ctx, quotedRequest(d, dep))
	require.NoError(t, err)
	_, err = e.svc.PaymentProof(ctx, proofRequest(d), e.keys.AgentPub())
	require.ErrorIs(t, err, signer.ErrNotExecuted, "signed and sent, not yet included")

	// One operator shows it; the second does not: never executed at L1.
	ctx2, cancel := context.WithTimeout(ctx, 300*time.Millisecond)
	defer cancel()
	e.svc.Advance(ctx2, e.entry(d.Hash))
	assert.Equal(t, signer.StateSigned, e.entry(d.Hash).State)
	_, err = e.svc.PaymentProof(ctx, proofRequest(d), e.keys.AgentPub())
	require.ErrorIs(t, err, signer.ErrNotExecuted)

	// Executed on a level too weak for a payment proof.
	_, err = e.store.Update(ctx, d.Hash, func(x *signer.Entry) error {
		x.State, x.Outcome, x.PaymentProofAllowed = signer.StateExecuted, string(edenexec.OutcomeExecuted), false
		return nil
	})
	require.NoError(t, err)
	_, err = e.svc.PaymentProof(ctx, proofRequest(d), e.keys.AgentPub())
	require.ErrorIs(t, err, signer.ErrNotExecuted)

	_, err = e.store.Update(ctx, d.Hash, func(x *signer.Entry) error {
		x.State, x.Outcome, x.PaymentProofAllowed = signer.StateReverted, string(edenexec.OutcomeReverted), true
		return nil
	})
	require.NoError(t, err)
	_, err = e.svc.PaymentProof(ctx, proofRequest(d), e.keys.AgentPub())
	require.ErrorIs(t, err, signer.ErrNotExecuted, "a reverted deposit moved no money")
	assert.NotEmpty(t, out.Signed)
}

func TestPaymentSignatureNeedsAnHTTPSResource(t *testing.T) {
	e := paymentEnv(t)
	d, dep := e.quoted("a", func(x *signertest.Deposit) { x.Resource = "http://api.example/v1/data" })
	e.executed(d, dep)
	_, err := e.svc.PaymentProof(context.Background(), proofRequest(d), e.keys.AgentPub())
	require.ErrorIs(t, err, signer.ErrRequirements)
}

// With the Payment-Signature on, the deposit needs R with the
// facilitator's signature, so the signer never pays a deposit whose proof it
// would refuse.
func TestDepositNeedsTheSignedQuoteWhilePaymentSignatureIsOn(t *testing.T) {
	ctx := context.Background()
	e := paymentEnv(t)
	d, dep := e.quoted("a")
	_, err := e.svc.Sign(ctx, request(d))
	require.ErrorIs(t, err, signer.ErrRequirements, "no R")

	var s secp256k1.ModNScalar
	s.SetByteSlice(bytes.Repeat([]byte{0x77}, 32))
	forged, err := signertest.Quote(dep, secp256k1.NewPrivateKey(&s))
	require.NoError(t, err)
	fd := dep
	fd.Requirements = forged
	action, err := fd.Action()
	require.NoError(t, err)
	fdec, err := signertest.NewDecision(e.keys, action, e.clk.Now(), signertest.DecisionOpts{Label: "forged"})
	require.NoError(t, err)
	_, err = e.svc.Sign(ctx, quotedRequest(fdec, fd))
	require.ErrorIs(t, err, signer.ErrRequirements, "serverSignature by another key")

	_, err = e.svc.Sign(ctx, quotedRequest(d, signertest.Deposit{Requirements: forged}))
	require.ErrorIs(t, err, signer.ErrRequirements, "R not bound by the action")
	assert.Zero(t, e.chain.SentCount())

	_, err = e.svc.Sign(ctx, quotedRequest(d, dep))
	require.NoError(t, err)
	assert.Equal(t, dep.Requirements, e.entry(d.Hash).Requirements, "R is kept with the reservation")
}

func TestPaymentSignatureIsOffByConfiguration(t *testing.T) {
	e := newEnv(t)
	d := e.decision(signertest.DecisionOpts{})
	_, err := e.svc.Sign(context.Background(), request(d))
	require.NoError(t, err)
	_, err = e.svc.PaymentProof(context.Background(), proofRequest(d), e.keys.AgentPub())
	require.ErrorIs(t, err, signer.ErrPinMismatch)
	assert.False(t, e.svc.PaymentProofsEnabled())
}

func TestPaymentSignatureNeedsTwoLabelledOperators(t *testing.T) {
	k := signertest.NewKeys(t.Name())
	one, two := signertest.NewChain(714), signertest.NewChain(714)
	two.Host = "second-host"
	pins := eden.ChainPins{
		ChainID: 714, Payer: k.PayerAddress(), Facilitators: [][20]byte{signertest.QuoteFacilitator()},
		MaxRefundDelay: 7200, MaxFeePerGas: big.NewInt(10_000), MaxGas: 300_000, MaxFeePerAction: big.NewInt(3e9), Broadcast: eden.BroadcastDirect,
	}
	build := func(level edenexec.Level, srcs ...edenexec.Source) error {
		cc := edenexec.Config{MinLevel: level}
		cc.ApplyDefaults()
		chk, err := edenexec.NewChecker(cc, srcs, nil)
		require.NoError(t, err)
		hc := eden.Config{Chains: []eden.ChainPins{pins}}
		hc.ApplyDefaults()
		_, err = eden.New(hc, eden.Deps{Chains: map[uint64]eden.Chain{714: one}, Settlers: map[uint64]eden.Settler{714: chk}})
		return err
	}
	require.NoError(t, build(edenexec.LevelMultiSource, labelled{one, "a"}, labelled{two, "b"}))
	assert.Error(t, build(edenexec.LevelMultiSource, labelled{one, "a"}, labelled{two, "a"}), "one operator behind two hosts")
	assert.Error(t, build(edenexec.LevelMultiSource, labelled{one, "a"}, two), "a host standing in as the label")
	assert.Error(t, build(edenexec.LevelNodeAttested, labelled{one, "a"}, labelled{two, "b"}), "L0")
}

func TestHTTPPaymentSignature(t *testing.T) {
	e := paymentEnv(t)
	d, dep := e.quoted("a")
	e.executed(d, dep)
	const agentToken, otherToken = "agent-a-token-0123456789", "agent-b-token-0123456789"
	opts := signer.HTTPOptions{Credentials: []signer.Credential{
		{Token: []byte(agentToken), Agent: e.keys.AgentPub()},
		{Token: []byte(otherToken), Agent: otherAgent.Public().(ed25519.PublicKey)},
	}}
	_, err := signer.NewHandler(e.svc, signer.HTTPOptions{Token: []byte(token)}, quiet)
	require.Error(t, err, "a shared credential while payment signatures are on")
	_, err = signer.NewHandler(e.svc, signer.HTTPOptions{Credentials: []signer.Credential{
		{Token: []byte(agentToken), Agent: bytes.Repeat([]byte{0x01}, 32)},
	}}, quiet)
	require.Error(t, err, "a credential pinned to an agent the signer does not serve")
	h, err := signer.NewHandler(e.svc, opts, quiet)
	require.NoError(t, err)
	srv := httptest.NewServer(h)
	defer srv.Close()

	call := func(tok string, body []byte) (int, []byte) {
		req, err := http.NewRequest(http.MethodPost, srv.URL+signer.RoutePaymentSignature, bytes.NewReader(body))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/cbor")
		req.Header.Set("Authorization", "Bearer "+tok)
		resp, err := srv.Client().Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		b, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		return resp.StatusCode, b
	}
	body := signer.EncodePaymentRequest(proofRequest(d))
	status, b := call(otherToken, body)
	assert.Equal(t, http.StatusForbidden, status)
	assert.Equal(t, "signer.ErrNotAuthorized", errorCode(t, "application/cbor", b))
	status, _ = call("not-a-token-0123456789", body)
	assert.Equal(t, http.StatusUnauthorized, status)

	status, b = call(agentToken, body)
	require.Equal(t, http.StatusOK, status, string(b))
	p, err := signer.DecodePaymentResponse(b)
	require.NoError(t, err)
	assert.Equal(t, dep.PaymentID, p.Message)
	assert.Len(t, p.Signature, 132)

	status, _ = call(otherToken, signer.EncodeSignRequest(quotedRequest(d, dep)))
	assert.Equal(t, http.StatusBadRequest, status, "a sign request is not a payment request")
}

func TestHTTPCredentialOptions(t *testing.T) {
	tok := []byte("0123456789abcdef-cred")
	require.Error(t, signer.HTTPOptions{}.ValidateBasic(), "no credential")
	require.Error(t, signer.HTTPOptions{Credentials: []signer.Credential{{Token: tok}, {Token: tok}}}.ValidateBasic(), "one token twice")
	require.Error(t, signer.HTTPOptions{Credentials: []signer.Credential{{Token: tok, Agent: []byte{1}}}}.ValidateBasic(), "agent key length")
	require.Error(t, signer.HTTPOptions{Credentials: []signer.Credential{{Token: tok}}, AdminToken: tok}.ValidateBasic(), "admin token reused")
	require.NoError(t, signer.HTTPOptions{Credentials: []signer.Credential{{Token: tok}}}.ValidateBasic())
}
