// SPDX-License-Identifier: Apache-2.0

package signer_test

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/edenescrow"
	"github.com/vgonkivs/edicta/signer"
	"github.com/vgonkivs/edicta/signer/signertest"
)

// A nonce signed for one unresolved decision is refused for another, even
// when the chain's pending nonce still reads it (the transaction may sit in
// the sequencer's private pool).
func TestInFlightNonceIsRefused(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	e.chain.Set(func(c *signertest.Chain) { c.AutoLand = false })
	first := e.decision(signertest.DecisionOpts{Label: "first"})
	_, err := e.svc.Sign(ctx, request(first))
	require.NoError(t, err)

	second := e.decision(signertest.DecisionOpts{Label: "second"})
	_, err = e.svc.Sign(ctx, request(second))
	require.ErrorIs(t, err, signer.ErrPinMismatch)
	_, found, err := e.store.Get(ctx, second.Hash)
	require.NoError(t, err)
	assert.False(t, found, "a refusal stores and counts nothing")

	// The operator looks at a wrong decision: it keeps the nonce.
	_, err = e.store.Update(ctx, first.Hash, func(x *signer.Entry) error { x.State = signer.StateWrong; return nil })
	require.NoError(t, err)
	_, err = e.svc.Sign(ctx, request(second))
	require.ErrorIs(t, err, signer.ErrPinMismatch)

	// Final as not executed: the nonce is free again.
	_, err = e.store.Update(ctx, first.Hash, func(x *signer.Entry) error { x.State = signer.StateNotExecuted; return nil })
	require.NoError(t, err)
	out, err := e.svc.Sign(ctx, request(second))
	require.NoError(t, err)
	assert.False(t, out.Repeat)
}

// A reservation that was never signed holds the nonce only while a repeat
// could still sign it.
func TestUnsignedReservationHoldsTheNonceUntilItsAuthorizationExpires(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	first := e.decision(signertest.DecisionOpts{Label: "first"})
	a, err := edenescrow.DecodeTxAction(first.Action)
	require.NoError(t, err)
	slot := fmt.Sprintf("eden-escrow/714/%x/nonce/7", e.keys.PayerAddress())
	_, _, err = e.store.Reserve(ctx, signer.Entry{
		CommitmentHash: first.Hash, Digest: a.SigHash(), State: signer.StateReserved, Value: a.Value,
		Payer: e.keys.PayerAddress(), ReservedAt: e.clk.Now().Unix(), AuthExpires: first.Expires, Slot: slot,
	}, 0, admitAll)
	require.NoError(t, err)

	second := e.decision(signertest.DecisionOpts{Label: "second"})
	_, err = e.svc.Sign(ctx, request(second))
	require.ErrorIs(t, err, signer.ErrPinMismatch)

	e.clk.Add(time.Duration(first.Expires-uint64(e.clk.Now().Unix())+e.cfg.SkewS) * time.Second)
	third := e.decision(signertest.DecisionOpts{Label: "third"})
	_, err = e.svc.Sign(ctx, request(third))
	require.NoError(t, err)
}

func TestParallelSameNonceSignsOnce(t *testing.T) {
	const n = 16
	e := newEnv(t)
	e.chain.Set(func(c *signertest.Chain) { c.AutoLand = false })
	reqs := make([]signer.Request, n)
	for i := range n {
		reqs[i] = request(e.decision(signertest.DecisionOpts{Label: fmt.Sprint("d", i)}))
	}
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, errs[i] = e.svc.Sign(context.Background(), reqs[i])
		}()
	}
	wg.Wait()
	ok := 0
	for _, err := range errs {
		if err == nil {
			ok++
			continue
		}
		require.ErrorIs(t, err, signer.ErrPinMismatch)
	}
	assert.Equal(t, 1, ok)
}
