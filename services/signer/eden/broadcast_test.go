// SPDX-License-Identifier: Apache-2.0

package eden_test

import (
	"context"
	"encoding/hex"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/plugins/edenescrow"
	"github.com/vgonkivs/edicta/plugins/edenescrow/edenexec"
	"github.com/vgonkivs/edicta/plugins/edenescrow/edenrelay"
	"github.com/vgonkivs/edicta/services/signer"
	"github.com/vgonkivs/edicta/services/signer/eden"
	"github.com/vgonkivs/edicta/services/signer/signertest"
)

// relayHandler is a form T handler that broadcasts through relay, on the
// system clock.
func relayHandler(t *testing.T, w *world, relay eden.Relay, mut ...func(*eden.Config)) *eden.Handler {
	t.Helper()
	p := w.pins
	p.Broadcast = eden.BroadcastRelay
	cfg := eden.Config{Chains: []eden.ChainPins{p}, ResendEvery: 20 * time.Millisecond, PaymentSignatureField: eden.FieldOff}
	for _, m := range mut {
		m(&cfg)
	}
	cfg.ApplyDefaults()
	d := deps(w.chain, newChecker(t, w.chain), time.Now)
	d.Relays = map[uint64]eden.Relay{714: relay}
	h, err := eden.New(cfg, d)
	require.NoError(t, err)
	return h
}

func TestDirectIsTheDefaultAndTheRelayNeedsARelay(t *testing.T) {
	w := newWorld(t)
	p := w.pins
	p.Broadcast = ""
	cfg := eden.Config{Chains: []eden.ChainPins{p}, PaymentSignatureField: eden.FieldOff}
	cfg.ApplyDefaults()
	assert.Equal(t, eden.BroadcastDirect, cfg.Chains[0].Broadcast)
	_, err := eden.New(cfg, deps(w.chain, newChecker(t, w.chain), nil))
	require.NoError(t, err, "a direct chain needs no relay")

	cfg.Chains[0].Broadcast = eden.BroadcastRelay
	_, err = eden.New(cfg, deps(w.chain, newChecker(t, w.chain), nil))
	require.ErrorContains(t, err, "relay")

	cfg.Chains[0].Broadcast = "mempool"
	require.Error(t, cfg.ValidateBasic())
	cfg.Chains[0].Broadcast = eden.BroadcastRelay
	cfg.RelayGrace = cfg.AwaitGrace + time.Second
	require.Error(t, cfg.ValidateBasic(), "RelayGrace above AwaitGrace")
}

func TestSendGoesThroughTheRelayWithTheActionsPaymentID(t *testing.T) {
	w := newWorld(t)
	relay := &signertest.Relay{}
	h := relayHandler(t, w, relay)
	d := signertest.NewDeposit(w.now)
	e := signedEntry(t, w, d, time.Now().Add(time.Minute))
	require.NoError(t, h.Send(context.Background(), 714, e.Action, e.Signed))
	require.Equal(t, 1, relay.Calls())
	assert.Equal(t, e.Signed, relay.Sent[0].Signed)
	assert.Equal(t, e.RailRef, relay.Sent[0].RailRef)
	assert.Equal(t, d.PaymentID, relay.Sent[0].PaymentID)
	assert.Zero(t, w.chain.SentCount(), "no direct send while the relay accepts")

	relay.Set(func(r *signertest.Relay) { r.Err = edenrelay.ErrRelayFault })
	require.NoError(t, h.Send(context.Background(), 714, e.Action, e.Signed))
	require.Equal(t, 1, w.chain.SentCount(), "a relay fault sends the same bytes directly")
	assert.Equal(t, e.Signed, w.chain.Sent[0])

	require.Error(t, h.Send(context.Background(), 1, e.Action, e.Signed), "the action names chain 714")
}

// A relay that answers success and withholds the bytes costs at most
// RelayGrace.
func TestSettleSendsDirectlyAfterRelayGrace(t *testing.T) {
	w := newWorld(t)
	w.chain.Set(func(c *signertest.Chain) { c.AutoLand = true })
	relay := &signertest.Relay{}
	h := relayHandler(t, w, relay, func(c *eden.Config) { c.RelayGrace = time.Second })
	e := signedEntry(t, w, signertest.NewDeposit(w.now), time.Now().Add(time.Minute))
	e.ReservedAt = time.Now().Unix()
	res, err := h.Settle(context.Background(), e, true)
	require.NoError(t, err)
	assert.Equal(t, signer.StateExecuted, res.State)
	assert.Zero(t, relay.Calls(), "the relay had the bytes once, when signed")
	assert.GreaterOrEqual(t, w.chain.SentCount(), 1)
	for _, s := range w.chain.Sent {
		assert.Equal(t, e.Signed, s)
	}
}

// A sighting does not stop the direct resends after RelayGrace: a relay
// that answered success and withholds the bytes, with a soft block rolled
// back after one source showed the deposit, must not pin the nonce.
func TestSettleSendsDirectlyAfterRelayGraceEvenWhenSeen(t *testing.T) {
	w := newWorld(t)
	w.chain.Set(func(c *signertest.Chain) { c.AutoLand = true })
	relay := &signertest.Relay{}
	h := relayHandler(t, w, relay)
	e := signedEntry(t, w, signertest.NewDeposit(w.now), time.Now().Add(time.Minute))
	e.ReservedAt = time.Now().Add(-time.Hour).Unix()
	e.Seen = true
	res, err := h.Settle(context.Background(), e, true)
	require.NoError(t, err)
	assert.Equal(t, signer.StateExecuted, res.State)
	assert.Zero(t, relay.Calls())
	require.GreaterOrEqual(t, w.chain.SentCount(), 1)
	assert.Equal(t, e.Signed, w.chain.Sent[0])
}

// Within RelayGrace a relayed deposit is left to the relay: no resend.
func TestSettleLeavesARelayedDepositToTheRelayWithinTheGrace(t *testing.T) {
	w := newWorld(t)
	w.chain.Set(func(c *signertest.Chain) { c.AutoLand = true })
	relay := &signertest.Relay{}
	h := relayHandler(t, w, relay, func(c *eden.Config) { c.RelayGrace = time.Minute })
	e := signedEntry(t, w, signertest.NewDeposit(w.now), time.Now().Add(1500*time.Millisecond))
	e.ReservedAt = time.Now().Unix()
	_, err := h.Settle(context.Background(), e, true)
	require.Error(t, err, "nothing landed: unknown")
	assert.Zero(t, relay.Calls())
	assert.Zero(t, w.chain.SentCount())
}

// A facilitator removed from the allowlist since the deposit gets no more
// payment proofs.
func TestPaymentProofRechecksTheFacilitator(t *testing.T) {
	d, err := signertest.QuotedDeposit(signertest.NewDeposit(time.Now()))
	require.NoError(t, err)
	action, err := d.Action()
	require.NoError(t, err)
	allowed := newWorld(t, func(p *eden.ChainPins) { p.Facilitators = append(p.Facilitators, signertest.QuoteFacilitator()) })
	m, _, err := allowed.h.PaymentProofDigest(action, d.Requirements)
	require.NoError(t, err)
	assert.Equal(t, d.PaymentID, m)
	removed := newWorld(t)
	_, _, err = removed.h.PaymentProofDigest(action, d.Requirements)
	require.ErrorIs(t, err, signer.ErrPinMismatch)
}

// scriptedSettler answers the calls of one wait in turn and records the
// seen fact each call was given.
type scriptedSettler struct {
	mu      sync.Mutex
	answers []func() (edenexec.Report, error)
	seen    []bool
}

func (s *scriptedSettler) AwaitSeen(_ context.Context, _ edenexec.Target, until time.Time, seen bool) (edenexec.Report, error) {
	// Like Await, a call returns at its horizon at the earliest.
	time.Sleep(time.Until(until))
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seen = append(s.seen, seen)
	i := min(len(s.seen), len(s.answers)) - 1
	return s.answers[i]()
}

func notFoundEverywhere() (edenexec.Report, error) {
	return edenexec.Report{State: edenexec.AwaitNotExecuted, Sources: []edenexec.SourceResult{
		{Operator: "one", State: edenexec.StateNotFound}, {Operator: "two", State: edenexec.StateNotFound},
	}}, edenexec.ErrNotFound
}

// A source seen in an earlier horizon keeps not executed out of reach in
// the last one; Settle carries the fact into each call and back out.
func TestSettleCarriesSeenAcrossCalls(t *testing.T) {
	w := newWorld(t)
	st := &scriptedSettler{answers: []func() (edenexec.Report, error){
		func() (edenexec.Report, error) {
			return edenexec.Report{State: edenexec.AwaitUnknown, Seen: true}, edenexec.ErrSettlementUnknown
		},
		notFoundEverywhere,
	}}
	cfg := eden.Config{Chains: []eden.ChainPins{w.pins}, ResendEvery: 20 * time.Millisecond, PaymentSignatureField: eden.FieldOff}
	cfg.ApplyDefaults()
	h, err := eden.New(cfg, deps(w.chain, st, time.Now))
	require.NoError(t, err)
	e := signedEntry(t, w, signertest.NewDeposit(w.now), time.Now().Add(1500*time.Millisecond))
	// Resending splits the wait into calls, one per resend.
	res, err := h.Settle(context.Background(), e, true)
	require.Error(t, err, "seen once: unknown, never not executed")
	assert.True(t, res.Seen)
	require.GreaterOrEqual(t, len(st.seen), 2)
	assert.False(t, st.seen[0])
	for _, s := range st.seen[1:] {
		assert.True(t, s, "every later call continues the wait")
	}

	// A restart continues the wait from the stored fact.
	st2 := &scriptedSettler{answers: []func() (edenexec.Report, error){notFoundEverywhere}}
	h2, err := eden.New(cfg, deps(w.chain, st2, time.Now))
	require.NoError(t, err)
	e.Until = time.Now().Add(-time.Second).Unix()
	e.Seen = true
	_, err = h2.Settle(context.Background(), e, false)
	require.Error(t, err)
	assert.Equal(t, []bool{true}, st2.seen)

	e.Seen = false
	res, err = h2.Settle(context.Background(), e, false)
	require.NoError(t, err)
	assert.Equal(t, signer.StateNotExecuted, res.State)
}

func TestCheckNonceRelease(t *testing.T) {
	ctx := context.Background()
	w := newWorld(t)
	e := signedEntry(t, w, signertest.NewDeposit(w.now), w.now.Add(-time.Second))
	e.Payer = w.keys.PayerAddress()
	require.Error(t, w.h.CheckNonceRelease(ctx, e), "only a decision final as not executed")
	e.State = signer.StateNotExecuted
	w.chain.Set(func(c *signertest.Chain) { c.Latest = 7 })
	require.NoError(t, w.h.CheckNonceRelease(ctx, e))
	w.chain.Set(func(c *signertest.Chain) { c.Latest = 8 })
	require.ErrorContains(t, w.h.CheckNonceRelease(ctx, e), "executed", "the nonce was used: the deposit landed")
	e.Until = w.now.Add(time.Minute).Unix()
	w.chain.Set(func(c *signertest.Chain) { c.Latest = 7 })
	require.Error(t, w.h.CheckNonceRelease(ctx, e), "before the deadline")
}

// R presented with the deposit must pass even while the Payment-Signature
// is off.
func TestCheckHoldsAPresentedQuote(t *testing.T) {
	ctx := context.Background()
	w := newWorld(t, func(p *eden.ChainPins) { p.Facilitators = append(p.Facilitators, signertest.QuoteFacilitator()) })
	d, err := signertest.QuotedDeposit(signertest.NewDeposit(w.now))
	require.NoError(t, err)
	v := w.verified(t, d)
	v.Requirements = d.Requirements
	_, err = w.h.Check(ctx, v, w.now)
	require.NoError(t, err)

	v.Requirements = []byte(`{"x402Version":2,"accepts":[]}`)
	_, err = w.h.Check(ctx, v, w.now)
	require.ErrorIs(t, err, signer.ErrRequirements)
	require.ErrorIs(t, err, edenescrow.ErrRequirements)

	v.Requirements = nil
	_, err = w.h.Check(ctx, v, w.now)
	require.NoError(t, err, "R is optional while the Payment-Signature is off")
}

func TestPlanHoldsTheNonceSlot(t *testing.T) {
	w := newWorld(t)
	p, err := w.h.Check(context.Background(), w.verified(t, signertest.NewDeposit(w.now)), w.now)
	require.NoError(t, err)
	payer := w.keys.PayerAddress()
	assert.Equal(t, "eden-escrow/714/"+hex.EncodeToString(payer[:])+"/nonce/7", p.Slot)
}
