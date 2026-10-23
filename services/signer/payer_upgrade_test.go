// SPDX-License-Identifier: Apache-2.0

package signer_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"log/slog"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/services/signer"
	"github.com/vgonkivs/edicta/services/signer/signertest"
)

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) take() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.b.String()
	s.b.Reset()
	return out
}

const foreignPayerLine = "reserved under a payer its agent no longer has"

// A payer configuration that changes under decisions still in flight, as an
// upgrade from one shared payer per chain does: the start names each of
// them, and the refusals say why.
func TestStartNamesDecisionsInFlightUnderAPayerTheirAgentNoLongerHas(t *testing.T) {
	ctx := context.Background()
	logs := &syncBuf{}
	e := newEnvOpts(t, envOpts{payment: true, agent2: true, log: slog.New(slog.NewTextHandler(logs, nil))})
	payerA := e.keys.PayerAddress()

	done, doneDep := e.quoted("executed")
	e.executed(done, doneDep)
	e.chain.Set(func(c *signertest.Chain) { c.Nonce = 8 })
	inflight, inflightDep := e.quoted("inflight", func(d *signertest.Deposit) {
		d.Nonce = 8
		d.PaymentID[0] ^= 1
	})
	_, err := e.svc.Sign(ctx, quotedRequest(inflight, inflightDep))
	require.NoError(t, err)
	require.Equal(t, signer.StateSigned, e.entry(inflight.Hash).State)

	logs.take()
	e.reopen()
	assert.NotContains(t, logs.take(), foreignPayerLine, "an unchanged configuration names nothing")

	e.keys.Payer, e.keys2.Payer = e.keys2.Payer, e.keys.Payer
	e.reopen()
	out := logs.take()
	require.Equal(t, 1, strings.Count(out, foreignPayerLine), out)
	payerNow := e.keys.PayerAddress()
	assert.Contains(t, out, "commitment_hash="+hex.EncodeToString(inflight.Hash[:]))
	assert.Contains(t, out, "stored_payer="+hex.EncodeToString(payerA[:]))
	assert.Contains(t, out, "configured_payer="+hex.EncodeToString(payerNow[:]))

	_, err = e.svc.Sign(ctx, quotedRequest(inflight, inflightDep))
	require.ErrorIs(t, err, signer.ErrPinMismatch)
	assert.ErrorContains(t, err, "not this agent's payer")
	_, err = e.svc.PaymentProof(ctx, proofRequest(done), e.keys.AgentPub())
	require.ErrorIs(t, err, signer.ErrPinMismatch)
	assert.ErrorContains(t, err, "only that key signs its Payment-Signature")

	// The stored payer given back to its agent releases the proof.
	e.keys.Payer, e.keys2.Payer = e.keys2.Payer, e.keys.Payer
	e.reopen()
	assert.NotContains(t, logs.take(), foreignPayerLine)
	_, err = e.svc.PaymentProof(ctx, proofRequest(done), e.keys.AgentPub())
	require.NoError(t, err)
}
