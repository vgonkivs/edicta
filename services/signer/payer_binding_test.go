// SPDX-License-Identifier: Apache-2.0

package signer_test

import (
	"context"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/plugins/edenescrow"
	"github.com/vgonkivs/edicta/services/signer"
	"github.com/vgonkivs/edicta/services/signer/signertest"
)

// quotedFor is e.quoted for the decision of k's agent.
func (e *env) quotedFor(k signertest.Keys, label string, mut ...func(*signertest.Deposit)) (signertest.Decision, signertest.Deposit) {
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
	dec, err := signertest.NewDecision(k, action, e.clk.Now(), signertest.DecisionOpts{Label: label})
	require.NoError(t, err)
	return dec, d
}

func signerOf(t *testing.T, action, signed []byte) [20]byte {
	t.Helper()
	a, err := edenescrow.DecodeTxAction(action)
	require.NoError(t, err)
	_, payer, err := edenescrow.ParseSigned(a, signed)
	require.NoError(t, err)
	return payer
}

// A restart with the two agents' payer keys swapped must never let the
// other agent's key sign for a decision reserved under the first payer:
// neither a repeat of an executed or in-flight deposit nor its
// Payment-Signature. The in-flight nonce stays held on the old payer.
func TestSwappedPayersAfterRestartNeverSignAnotherAgentsDecision(t *testing.T) {
	ctx := context.Background()
	e := newEnvOpts(t, envOpts{payment: true, agent2: true})
	payerA, payerB := e.keys.PayerAddress(), e.keys2.PayerAddress()
	require.NotEqual(t, payerA, payerB)

	done, doneDep := e.quoted("executed")
	out := e.executed(done, doneDep)
	assert.Equal(t, payerA, signerOf(t, done.Action, out.Signed))

	e.chain.Set(func(c *signertest.Chain) { c.Nonce = 8 })
	inflight, inflightDep := e.quoted("inflight", func(d *signertest.Deposit) {
		d.Nonce = 8
		d.PaymentID[0] ^= 1
	})
	first, err := e.svc.Sign(ctx, quotedRequest(inflight, inflightDep))
	require.NoError(t, err)
	require.Equal(t, signer.StateSigned, e.entry(inflight.Hash).State, "the deposit is in flight")
	sentBefore := e.chain.SentCount()

	e.keys.Payer, e.keys2.Payer = e.keys2.Payer, e.keys.Payer
	e.reopen()
	require.Equal(t, payerB, e.keys.PayerAddress(), "agent A is now pinned to B's former payer")

	_, err = e.svc.Sign(ctx, quotedRequest(done, doneDep))
	require.ErrorIs(t, err, signer.ErrPinMismatch, "repeat of an executed deposit under another payer")
	_, err = e.svc.Sign(ctx, quotedRequest(inflight, inflightDep))
	require.ErrorIs(t, err, signer.ErrPinMismatch, "repeat of an in-flight deposit under another payer")
	assert.Equal(t, first.Signed, e.entry(inflight.Hash).Signed, "the stored bytes are untouched")
	assert.Equal(t, payerA, e.entry(inflight.Hash).Payer)

	_, err = e.svc.PaymentProof(ctx, proofRequest(done), e.keys.AgentPub())
	require.ErrorIs(t, err, signer.ErrPinMismatch, "the proof is only ever the deposit payer's")
	assert.Empty(t, e.entry(done.Hash).PaymentProof)

	// Agent B now owns payer A, whose nonce 8 is still held by A's
	// unresolved deposit.
	clash, clashDep := e.quotedFor(e.keys2, "clash", func(d *signertest.Deposit) {
		d.Nonce = 8
		d.PaymentID[1] ^= 1
	})
	_, err = e.svc.Sign(ctx, quotedRequest(clash, clashDep))
	require.ErrorIs(t, err, signer.ErrPinMismatch, "the in-flight nonce of the old payer stays held")
	assert.Equal(t, sentBefore, e.chain.SentCount(), "nothing new reached the chain")
}

// One served agent's envelope through the other agent's credential, for the
// deposit and the Payment-Signature.
func TestAnotherAgentsCredentialSignsNothingForThisAgent(t *testing.T) {
	ctx := context.Background()
	e := newEnvOpts(t, envOpts{payment: true, agent2: true})
	d, dep := e.quoted("a")
	_, err := e.svc.SignAs(ctx, quotedRequest(d, dep), e.keys2.AgentPub())
	require.ErrorIs(t, err, signer.ErrNotAuthorized)
	_, found, err := e.store.Get(ctx, d.Hash)
	require.NoError(t, err)
	assert.False(t, found, "nothing is reserved")

	e.executed(d, dep)
	_, err = e.svc.PaymentProof(ctx, proofRequest(d), e.keys2.AgentPub())
	require.ErrorIs(t, err, signer.ErrNotAuthorized)
	assert.Empty(t, e.entry(d.Hash).PaymentProof)

	p, err := e.svc.PaymentProof(ctx, proofRequest(d), e.keys.AgentPub())
	require.NoError(t, err)
	_, err = e.svc.PaymentProof(ctx, proofRequest(d), e.keys2.AgentPub())
	require.ErrorIs(t, err, signer.ErrNotAuthorized, "a stored proof is not returned to another agent either")
	got, err := edenescrow.RecoverPersonal(dep.PaymentID, mustSig(t, p.Signature))
	require.NoError(t, err)
	assert.Equal(t, e.keys.PayerAddress(), got)
}

func mustSig(t *testing.T, s []byte) [65]byte {
	t.Helper()
	require.Len(t, s, 132)
	b, err := hex.DecodeString(string(s[2:]))
	require.NoError(t, err)
	return [65]byte(b)
}
