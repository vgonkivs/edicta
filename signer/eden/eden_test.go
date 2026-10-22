// SPDX-License-Identifier: Apache-2.0

package eden_test

import (
	"context"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/edenescrow"
	"github.com/vgonkivs/edicta/edenexec"
	"github.com/vgonkivs/edicta/engine/commitment"
	"github.com/vgonkivs/edicta/signer"
	"github.com/vgonkivs/edicta/signer/eden"
	"github.com/vgonkivs/edicta/signer/signertest"
)

type world struct {
	keys  signertest.Keys
	chain *signertest.Chain
	pins  eden.ChainPins
	h     *eden.Handler
	now   time.Time
}

func pins(k signertest.Keys) eden.ChainPins {
	return eden.ChainPins{
		ChainID: 714, Payer: k.PayerAddress(), Facilitators: [][20]byte{signertest.Facilitator},
		MaxRefundDelay: 7200, MaxFeePerGas: big.NewInt(10_000), MaxGas: 300_000,
		MaxFeePerAction: big.NewInt(10_000 * 300_000), Broadcast: eden.BroadcastDirect,
	}
}

// deps are the handler's collaborators on one fake chain.
func deps(chain *signertest.Chain, st eden.Settler, now func() time.Time) eden.Deps {
	return eden.Deps{
		Chains: map[uint64]eden.Chain{714: chain}, Settlers: map[uint64]eden.Settler{714: st}, Now: now,
	}
}

func newChecker(t testing.TB, src edenexec.Source) *edenexec.Checker {
	t.Helper()
	cfg := edenexec.Config{MinLevel: edenexec.LevelNodeAttested, PollInterval: 5 * time.Millisecond}
	cfg.ApplyDefaults()
	c, err := edenexec.NewChecker(cfg, []edenexec.Source{src}, nil)
	require.NoError(t, err)
	return c
}

func newWorld(t testing.TB, mut ...func(*eden.ChainPins)) *world {
	t.Helper()
	w := &world{keys: signertest.NewKeys(t.Name()), chain: signertest.NewChain(714), now: time.Now().Truncate(time.Second)}
	w.chain.Nonce = 7
	w.pins = pins(w.keys)
	for _, m := range mut {
		m(&w.pins)
	}
	cfg := eden.Config{Chains: []eden.ChainPins{w.pins}, ResendEvery: 20 * time.Millisecond, PaymentSignatureField: eden.FieldOff}
	cfg.ApplyDefaults()
	h, err := eden.New(cfg, deps(w.chain, newChecker(t, w.chain), func() time.Time { return w.now }))
	require.NoError(t, err)
	w.h = h
	return w
}

func (w *world) verified(t testing.TB, d signertest.Deposit) signer.Verified {
	t.Helper()
	action, err := d.Action()
	require.NoError(t, err)
	return w.verifiedAction(action)
}

func (w *world) verifiedAction(action []byte) signer.Verified {
	return signer.Verified{
		Authorization: commitment.Authorization{Version: 1, Expires: uint64(w.now.Unix()) + 600, Mode: commitment.ModeFast},
		Action:        action, SkewS: 30,
	}
}

func TestCheckPlansExactlyTheActionDigest(t *testing.T) {
	w := newWorld(t)
	d := signertest.NewDeposit(w.now)
	v := w.verified(t, d)
	plan, err := w.h.Check(context.Background(), v, w.now)
	require.NoError(t, err)

	a, err := edenescrow.DecodeTxAction(v.Action)
	require.NoError(t, err)
	assert.Equal(t, a.SigHash(), plan.Digest)
	assert.Equal(t, uint64(714), plan.Key)
	assert.Equal(t, w.keys.PayerAddress(), plan.Payer)
	assert.Equal(t, 0, plan.Value.Cmp(d.Value))
	assert.Equal(t, 0, plan.Fee.Cmp(big.NewInt(2299*200_000)))
	assert.Equal(t, int64(d.ExpiresAt)+int64(edenexec.DefaultAwaitGrace/time.Second), plan.Until)
}

func TestCheckRefusesOutsideThePins(t *testing.T) {
	cases := []struct {
		name string
		pin  func(*eden.ChainPins)
		dep  func(*signertest.Deposit)
	}{
		{"facilitator not allowed", nil, func(d *signertest.Deposit) { d.Facilitator = [20]byte{0xbb} }},
		{"refund delay above the pin", nil, func(d *signertest.Deposit) { d.RefundAfter = d.ExpiresAt + 7201 }},
		{"max fee per gas above the pin", nil, func(d *signertest.Deposit) { d.MaxFeePerGas = 10_001 }},
		{"gas limit above the pin", nil, func(d *signertest.Deposit) { d.GasLimit = 300_001 }},
		{"fee bound above the pin", func(p *eden.ChainPins) { p.MaxFeePerAction = big.NewInt(2299*200_000 - 1) }, nil},
		{"chain in the table but not served", nil, func(d *signertest.Deposit) { d.ChainID = 3735928814 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var muts []func(*eden.ChainPins)
			if tc.pin != nil {
				muts = append(muts, tc.pin)
			}
			w := newWorld(t, muts...)
			d := signertest.NewDeposit(w.now)
			if tc.dep != nil {
				tc.dep(&d)
			}
			_, err := w.h.Check(context.Background(), w.verified(t, d), w.now)
			require.ErrorIs(t, err, signer.ErrPinMismatch)
			assert.NotErrorIs(t, err, signer.ErrUnavailable)
		})
	}
}

func TestCheckBoundariesAreInclusive(t *testing.T) {
	w := newWorld(t, func(p *eden.ChainPins) {
		p.MaxFeePerGas, p.MaxGas = big.NewInt(2299), 200_000
		p.MaxFeePerAction = big.NewInt(2299 * 200_000)
	})
	d := signertest.NewDeposit(w.now)
	d.RefundAfter = d.ExpiresAt + 7200
	_, err := w.h.Check(context.Background(), w.verified(t, d), w.now)
	require.NoError(t, err)
}

func TestCheckRefusesWhatTheDecoderRefuses(t *testing.T) {
	w := newWorld(t)
	_, err := w.h.Check(context.Background(), w.verifiedAction([]byte{0xa0}), w.now)
	require.ErrorIs(t, err, edenescrow.ErrMalformed)

	other, err := signertest.NewDeposit(w.now).ActionTo([20]byte{0x01})
	require.ErrorIs(t, err, edenescrow.ErrUnknownDomain, "the encoder refuses another escrow")
	assert.Nil(t, other)
}

func TestEscrowCodeIsCheckedBeforeEverySignatureAndFailsClosed(t *testing.T) {
	w := newWorld(t)
	v := w.verified(t, signertest.NewDeposit(w.now))
	_, err := w.h.Check(context.Background(), v, w.now)
	require.NoError(t, err)

	row, _ := edenescrow.Lookup(714)
	w.chain.Set(func(c *signertest.Chain) { delete(c.Code, row.Escrow) })
	_, err = w.h.Check(context.Background(), v, w.now)
	require.ErrorIs(t, err, signer.ErrEscrowCode, "no code at the escrow: a deposit would be a plain transfer")
	assert.NotErrorIs(t, err, signer.ErrUnavailable)

	w.chain.Set(func(c *signertest.Chain) { c.Code[row.Escrow] = signertest.Keccak([]byte("other code")) })
	_, err = w.h.Check(context.Background(), v, w.now)
	require.ErrorIs(t, err, signer.ErrEscrowCode)

	w.chain.Set(func(c *signertest.Chain) { c.Code[row.Escrow] = row.CodeHash; c.CodeErr = errors.New("rpc down") })
	_, err = w.h.Check(context.Background(), v, w.now)
	require.ErrorIs(t, err, signer.ErrEscrowCode, "an RPC error refuses")
	require.ErrorIs(t, err, signer.ErrUnavailable)
}

func TestPayerWithCodeIsRefused(t *testing.T) {
	w := newWorld(t)
	w.chain.Set(func(c *signertest.Chain) {
		c.Code[w.keys.PayerAddress()] = signertest.Keccak([]byte{0xef, 0x01, 0x00})
	})
	_, err := w.h.Check(context.Background(), w.verified(t, signertest.NewDeposit(w.now)), w.now)
	require.ErrorIs(t, err, signer.ErrPinMismatch)
}

func TestNonceMustBeThePendingOneExceptOnARepeat(t *testing.T) {
	w := newWorld(t)
	w.chain.Set(func(c *signertest.Chain) { c.Nonce = 8 })
	v := w.verified(t, signertest.NewDeposit(w.now))
	_, err := w.h.Check(context.Background(), v, w.now)
	require.ErrorIs(t, err, signer.ErrPinMismatch)

	v.Repeat = true
	_, err = w.h.Check(context.Background(), v, w.now)
	require.NoError(t, err, "after the first signature the pending nonce has moved on")

	v.Repeat = false
	w.chain.Set(func(c *signertest.Chain) { c.Nonce, c.NonceErr = 7, errors.New("rpc down") })
	_, err = w.h.Check(context.Background(), v, w.now)
	require.ErrorIs(t, err, signer.ErrUnavailable)
}

func TestTimeRules(t *testing.T) {
	w := newWorld(t)
	now := uint64(w.now.Unix())
	cases := []struct {
		name      string
		expiresAt uint64
		expires   uint64
		ok        bool
	}{
		{"deposit ends with the Authorization", now + 300, now + 300, true},
		{"deposit after the Authorization", now + 301, now + 300, false},
		{"Authorization within skew", now + 20, now + 30, false},
		{"deposit expiry already within skew", now + 30, now + 600, false},
		{"deposit expiry just outside skew", now + 31, now + 600, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := signertest.NewDeposit(w.now)
			d.ExpiresAt, d.RefundAfter = tc.expiresAt, tc.expiresAt+60
			v := w.verified(t, d)
			v.Authorization.Expires = tc.expires
			_, err := w.h.Check(context.Background(), v, w.now)
			if tc.ok {
				require.NoError(t, err)
				return
			}
			require.ErrorIs(t, err, signer.ErrExpired)
		})
	}
}

func payerKey(t testing.TB, k signertest.Keys) *secp256k1.PrivateKey {
	t.Helper()
	var s secp256k1.ModNScalar
	require.False(t, s.SetByteSlice(k.Payer))
	return secp256k1.NewPrivateKey(&s)
}

func TestFinishSplicesIntoTheActionBytes(t *testing.T) {
	w := newWorld(t)
	action, err := signertest.NewDeposit(w.now).Action()
	require.NoError(t, err)
	a, err := edenescrow.DecodeTxAction(action)
	require.NoError(t, err)
	want, _, err := a.SignTx(payerKey(t, w.keys))
	require.NoError(t, err)

	wallet, err := signer.NewKeyWallet(w.keys.Payer)
	require.NoError(t, err)
	sig, err := wallet.SignDigest(context.Background(), a.SigHash())
	require.NoError(t, err)
	signed, railRef, err := w.h.Finish(action, sig, w.keys.PayerAddress())
	require.NoError(t, err)
	assert.Equal(t, want, signed)
	assert.Equal(t, edenescrow.RailRef(want), railRef)
	_, payer, err := edenescrow.ParseSigned(a, signed)
	require.NoError(t, err)
	assert.Equal(t, w.keys.PayerAddress(), payer)

	_, _, err = w.h.Finish(action, sig, [20]byte{0x01})
	require.ErrorIs(t, err, edenescrow.ErrSignature, "a signature that does not recover to the payer")
}

func TestStartChecksPayerChainAndCode(t *testing.T) {
	ctx := context.Background()
	w := newWorld(t)
	payers := map[uint64][20]byte{714: w.keys.PayerAddress()}
	require.NoError(t, w.h.Start(ctx, payers))

	require.Error(t, w.h.Start(ctx, map[uint64][20]byte{}), "no payer key for a served chain")
	require.Error(t, w.h.Start(ctx, map[uint64][20]byte{714: {0x01}}), "the key is not the pinned payer")

	w.chain.Set(func(c *signertest.Chain) { c.ID = 3735928814 })
	require.Error(t, w.h.Start(ctx, payers), "the RPC serves another chain")
	w.chain.Set(func(c *signertest.Chain) { c.ID = 714 })

	row, _ := edenescrow.Lookup(714)
	w.chain.Set(func(c *signertest.Chain) { delete(c.Code, row.Escrow) })
	require.ErrorIs(t, w.h.Start(ctx, payers), signer.ErrEscrowCode)
}

func TestConfigRefusesUnsafePins(t *testing.T) {
	k := signertest.NewKeys(t.Name())
	cases := []struct {
		name string
		mut  func(*eden.ChainPins)
	}{
		{"chain not in the table", func(p *eden.ChainPins) { p.ChainID = 1 }},
		{"no payer", func(p *eden.ChainPins) { p.Payer = [20]byte{} }},
		{"no facilitator", func(p *eden.ChainPins) { p.Facilitators = nil }},
		{"zero facilitator", func(p *eden.ChainPins) { p.Facilitators = [][20]byte{{}} }},
		{"no refund delay", func(p *eden.ChainPins) { p.MaxRefundDelay = 0 }},
		{"no gas", func(p *eden.ChainPins) { p.MaxGas = 0 }},
		{"no fee per gas", func(p *eden.ChainPins) { p.MaxFeePerGas = nil }},
		{"no fee per action", func(p *eden.ChainPins) { p.MaxFeePerAction = big.NewInt(0) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := pins(k)
			tc.mut(&p)
			cfg := eden.Config{Chains: []eden.ChainPins{p}}
			cfg.ApplyDefaults()
			require.Error(t, cfg.ValidateBasic())
		})
	}
	p := pins(k)
	cfg := eden.Config{Chains: []eden.ChainPins{p, p}}
	cfg.ApplyDefaults()
	require.Error(t, cfg.ValidateBasic(), "one chain pinned twice")
}

// signedEntry is the store entry of a signed deposit.
func signedEntry(t testing.TB, w *world, d signertest.Deposit, until time.Time) signer.Entry {
	t.Helper()
	action, err := d.Action()
	require.NoError(t, err)
	a, err := edenescrow.DecodeTxAction(action)
	require.NoError(t, err)
	signed, _, err := a.SignTx(payerKey(t, w.keys))
	require.NoError(t, err)
	return signer.Entry{
		Action: action, Signed: signed, RailRef: edenescrow.RailRef(signed), Until: until.Unix(),
		AuthExpires: uint64(w.now.Unix()) + 600, State: signer.StateSigned, SendStarted: true,
	}
}

func TestSettleResendsAndReportsTheOutcome(t *testing.T) {
	ctx := context.Background()
	w := newWorld(t)
	w.chain.Set(func(c *signertest.Chain) { c.AutoLand = true })
	e := signedEntry(t, w, signertest.NewDeposit(w.now), time.Now().Add(time.Minute))
	res, err := w.h.Settle(ctx, e, true)
	require.NoError(t, err)
	assert.Equal(t, signer.StateExecuted, res.State)
	assert.Equal(t, string(edenexec.OutcomeExecuted), res.Outcome)
	assert.Equal(t, 1, w.chain.SentCount(), "the stored bytes, resent once")
	assert.Equal(t, e.Signed, w.chain.Sent[0])

	w.chain.Set(func(c *signertest.Chain) { c.Revert = true })
	res, err = w.h.Settle(ctx, e, false)
	require.NoError(t, err)
	assert.Equal(t, signer.StateReverted, res.State, "a reverted deposit is an honest outcome")
}

func TestSettleKeepsResendingUntilItLands(t *testing.T) {
	w := newWorld(t)
	w.chain.Set(func(c *signertest.Chain) { c.AutoLand = false })
	e := signedEntry(t, w, signertest.NewDeposit(w.now), time.Now().Add(time.Minute))
	go func() {
		for w.chain.SentCount() < 3 {
			time.Sleep(5 * time.Millisecond)
		}
		w.chain.Land(e.Signed)
	}()
	hcfg := eden.Config{Chains: []eden.ChainPins{w.pins}, AwaitGrace: time.Minute, ResendEvery: 20 * time.Millisecond, PaymentSignatureField: eden.FieldOff}
	hcfg.ApplyDefaults()
	h, err := eden.New(hcfg, deps(w.chain, newChecker(t, w.chain), time.Now))
	require.NoError(t, err)
	res, err := h.Settle(context.Background(), e, true)
	require.NoError(t, err)
	assert.Equal(t, signer.StateExecuted, res.State)
	assert.GreaterOrEqual(t, w.chain.SentCount(), 3)
	for _, s := range w.chain.Sent {
		assert.Equal(t, e.Signed, s, "every resend is byte-identical")
	}
}

func TestSettleNotExecutedOnlyPastTheDeadline(t *testing.T) {
	ctx := context.Background()
	w := newWorld(t)
	w.chain.Set(func(c *signertest.Chain) { c.AutoLand = false })
	e := signedEntry(t, w, signertest.NewDeposit(w.now), time.Now().Add(-time.Second))
	w.now = time.Now()
	_, err := w.h.Settle(ctx, e, true)
	require.ErrorIs(t, err, edenexec.ErrSettlementUnknown, "one source saying not found is not final")
	require.NotErrorIs(t, err, edenexec.ErrNotFound)
	assert.Zero(t, w.chain.SentCount(), "no send after the deadline")

	second := signertest.NewChain(714)
	second.Host, second.AutoLand = "second-operator", false
	cfg := edenexec.Config{MinLevel: edenexec.LevelNodeAttested, PollInterval: 5 * time.Millisecond}
	cfg.ApplyDefaults()
	both, err := edenexec.NewChecker(cfg, []edenexec.Source{w.chain, second}, nil)
	require.NoError(t, err)
	hcfg := eden.Config{Chains: []eden.ChainPins{w.pins}, PaymentSignatureField: eden.FieldOff}
	hcfg.ApplyDefaults()
	h, err := eden.New(hcfg, deps(w.chain, both, time.Now))
	require.NoError(t, err)
	res, err := h.Settle(ctx, e, false)
	require.NoError(t, err)
	assert.Equal(t, signer.StateNotExecuted, res.State, "two operators agree it is not there")

	second.Land(e.Signed)
	second.Set(func(c *signertest.Chain) { c.Depth = 1 })
	_, err = h.Settle(ctx, e, false)
	require.Error(t, err, "one operator has it, below depth: unknown, not final")

	w.chain.Set(func(c *signertest.Chain) { c.TxErr = errors.New("rpc down") })
	_, err = w.h.Settle(ctx, e, false)
	require.Error(t, err, "no source answered: the state is unknown, not not-executed")
}

func TestSettleReportsAClaimOfOtherBytesAsWrong(t *testing.T) {
	w := newWorld(t)
	e := signedEntry(t, w, signertest.NewDeposit(w.now), time.Now().Add(time.Minute))
	d := signertest.NewDeposit(w.now)
	d.Nonce = 8
	other := signedEntry(t, w, d, time.Now().Add(time.Minute))
	w.chain.Land(other.Signed)
	e.RailRef = other.RailRef
	res, err := w.h.Settle(context.Background(), e, false)
	require.NoError(t, err)
	assert.Equal(t, signer.StateWrong, res.State)
}
