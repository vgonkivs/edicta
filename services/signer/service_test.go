// SPDX-License-Identifier: Apache-2.0

package signer_test

import (
	"context"
	"crypto/ed25519"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/engine/commitment"
	"github.com/vgonkivs/edicta/plugins/edenescrow"
	"github.com/vgonkivs/edicta/services/signer"
	"github.com/vgonkivs/edicta/services/signer/signertest"
)

func TestSignSignsExactlyTheAuthorizedBytes(t *testing.T) {
	e := newEnv(t)
	d := e.decision(signertest.DecisionOpts{})
	out, err := e.svc.Sign(context.Background(), request(d))
	require.NoError(t, err)

	a, err := edenescrow.DecodeTxAction(d.Action)
	require.NoError(t, err)
	_, payer, err := edenescrow.ParseSigned(a, out.Signed)
	require.NoError(t, err, "the output is the action's own transaction with one signature")
	assert.Equal(t, e.keys.PayerAddress(), payer)
	assert.Equal(t, edenescrow.RailRef(out.Signed), out.RailRef)
	assert.Equal(t, d.Hash, out.CommitmentHash)
	assert.False(t, out.Repeat)

	got := e.entry(d.Hash)
	assert.Equal(t, signer.StateSigned, got.State)
	assert.Equal(t, out.Signed, got.Signed, "the signed bytes are durable before they leave")
	assert.True(t, got.SendStarted)
	require.Equal(t, 1, e.chain.SentCount())
	assert.Equal(t, out.Signed, e.chain.Sent[0])
}

func TestTheGateAloneCannotPay(t *testing.T) {
	other := signertest.NewKeys("someone else")
	cases := []struct {
		name string
		req  func(e *env) signer.Request
	}{
		{"envelope of an agent that is not pinned", func(e *env) signer.Request {
			k := e.keys
			k.Agent = other.Agent
			action, err := signertest.NewDeposit(e.clk.Now()).Action()
			require.NoError(t, err)
			d, err := signertest.NewDecision(k, action, e.clk.Now(), signertest.DecisionOpts{})
			require.NoError(t, err)
			return request(d)
		}},
		{"envelope with a broken agent signature", func(e *env) signer.Request {
			r := request(e.decision(signertest.DecisionOpts{}))
			r.Envelope[len(r.Envelope)-1] ^= 0x01
			return r
		}},
		{"no envelope", func(e *env) signer.Request {
			r := request(e.decision(signertest.DecisionOpts{}))
			r.Envelope = nil
			return r
		}},
		{"Authorization from another gate key", func(e *env) signer.Request {
			return request(e.decision(signertest.DecisionOpts{GateKey: other.Gate}))
		}},
		{"Authorization for other bytes", func(e *env) signer.Request {
			d := signertest.NewDeposit(e.clk.Now())
			d.Value = big.NewInt(1)
			otherAction, err := d.Action()
			require.NoError(t, err)
			return request(e.decision(signertest.DecisionOpts{AuthAction: otherAction}))
		}},
		{"Authorization for another commitment", func(e *env) signer.Request {
			h := commitment.Hash{0x01}
			return request(e.decision(signertest.DecisionOpts{AuthCommitment: &h}))
		}},
		{"action bytes the agent did not commit", func(e *env) signer.Request {
			r := request(e.decision(signertest.DecisionOpts{}))
			d := signertest.NewDeposit(e.clk.Now())
			d.Value = big.NewInt(1)
			var err error
			r.Action, err = d.Action()
			require.NoError(t, err)
			return r
		}},
		{"another salt", func(e *env) signer.Request {
			r := request(e.decision(signertest.DecisionOpts{}))
			r.Salt = make([]byte, 32)
			return r
		}},
		{"an action type without a handler", func(e *env) signer.Request {
			return request(e.decision(signertest.DecisionOpts{ActionType: "application/vnd.example.other.v1+cbor"}))
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			r := tc.req(e)
			_, err := e.svc.Sign(context.Background(), r)
			require.ErrorIs(t, err, signer.ErrNotAuthorized)
			assert.Zero(t, e.chain.SentCount())
			list, err := e.store.Unfinished(context.Background(), signer.StateReserved, signer.StateSigned)
			require.NoError(t, err)
			assert.Empty(t, list, "a refusal stores and counts nothing")
		})
	}
}

func TestExpiredAuthorizationIsRefused(t *testing.T) {
	e := newEnv(t)
	d := e.decision(signertest.DecisionOpts{Expires: uint64(e.clk.Now().Unix()) + 30})
	_, err := e.svc.Sign(context.Background(), request(d))
	require.ErrorIs(t, err, signer.ErrExpired)
}

func TestRepeatReturnsTheStoredBytesAndCountsNothing(t *testing.T) {
	// The hour cap admits exactly one deposit: a repeat must not count.
	e := newEnv(t, func(c *signer.Config) {
		c.Caps.MaxValuePerAction = signertest.NewDeposit(time.Now()).Value
		c.Caps.MaxValuePerHour = signertest.NewDeposit(time.Now()).Value
	})
	d := e.decision(signertest.DecisionOpts{})
	first, err := e.svc.Sign(context.Background(), request(d))
	require.NoError(t, err)
	e.chain.Set(func(c *signertest.Chain) { c.Nonce = 8 })

	again, err := e.svc.Sign(context.Background(), request(d))
	require.NoError(t, err)
	assert.True(t, again.Repeat)
	assert.Equal(t, first.Signed, again.Signed)
	assert.Equal(t, first.RailRef, again.RailRef)
	assert.Equal(t, 1, e.chain.SentCount(), "a repeat sends nothing itself")

	d2 := e.decision(signertest.DecisionOpts{Label: "second"}, func(dep *signertest.Deposit) { dep.Nonce = 8 })
	_, err = e.svc.Sign(context.Background(), request(d2))
	require.ErrorIs(t, err, signer.ErrRiskLimit, "the first decision is counted once")
}

func TestReservedButUnsignedDecisionIsSignedOnRepeatWithTheSameBytes(t *testing.T) {
	e := newEnv(t)
	d := e.decision(signertest.DecisionOpts{})
	a, err := edenescrow.DecodeTxAction(d.Action)
	require.NoError(t, err)
	// A crash between the reservation and the signature leaves this behind.
	_, _, err = e.store.Reserve(context.Background(), signer.Entry{
		CommitmentHash: d.Hash, Digest: a.SigHash(), State: signer.StateReserved, Value: a.Value, Payer: e.keys.PayerAddress(),
		ReservedAt: e.clk.Now().Unix(),
	}, 0, func(signer.Totals) error { return nil })
	require.NoError(t, err)

	out, err := e.svc.Sign(context.Background(), request(d))
	require.NoError(t, err)
	assert.True(t, out.Repeat)
	_, payer, err := edenescrow.ParseSigned(a, out.Signed)
	require.NoError(t, err)
	assert.Equal(t, e.keys.PayerAddress(), payer)
}

func TestAnotherDigestForADecisionIsRefused(t *testing.T) {
	e := newEnv(t)
	d := e.decision(signertest.DecisionOpts{})
	_, _, err := e.store.Reserve(context.Background(), signer.Entry{
		CommitmentHash: d.Hash, Digest: [32]byte{0x01}, State: signer.StateReserved,
	}, 0, func(signer.Totals) error { return nil })
	require.NoError(t, err)
	_, err = e.svc.Sign(context.Background(), request(d))
	require.ErrorIs(t, err, signer.ErrDigestConflict)
	assert.Zero(t, e.chain.SentCount())
}

func TestOperatorCaps(t *testing.T) {
	value := signertest.NewDeposit(time.Now()).Value
	feeBound := big.NewInt(2299 * 200_000)
	t.Run("value per action", func(t *testing.T) {
		e := newEnv(t, func(c *signer.Config) { c.Caps.MaxValuePerAction = new(big.Int).Sub(value, big.NewInt(1)) })
		_, err := e.svc.Sign(context.Background(), request(e.decision(signertest.DecisionOpts{})))
		require.ErrorIs(t, err, signer.ErrRiskLimit)
	})
	t.Run("value per hour, rolling", func(t *testing.T) {
		e := newEnv(t, func(c *signer.Config) {
			c.Caps.MaxValuePerAction = value
			c.Caps.MaxValuePerHour = new(big.Int).Mul(value, big.NewInt(2))
		})
		for i, label := range []string{"a", "b"} {
			d := e.decision(signertest.DecisionOpts{Label: label}, func(dep *signertest.Deposit) { dep.Nonce = 7 + uint64(i) })
			e.chain.Set(func(c *signertest.Chain) { c.Nonce = 7 + uint64(i) })
			_, err := e.svc.Sign(context.Background(), request(d))
			require.NoError(t, err)
			e.clk.Add(time.Second)
		}
		e.chain.Set(func(c *signertest.Chain) { c.Nonce = 9 })
		d := e.decision(signertest.DecisionOpts{Label: "c"}, func(dep *signertest.Deposit) { dep.Nonce = 9 })
		_, err := e.svc.Sign(context.Background(), request(d))
		require.ErrorIs(t, err, signer.ErrRiskLimit)

		e.clk.Add(signer.HourWindow - 3*time.Second) // 3599 s after the first
		d = e.decision(signertest.DecisionOpts{Label: "d"}, func(dep *signertest.Deposit) { dep.Nonce = 9 })
		_, err = e.svc.Sign(context.Background(), request(d))
		require.ErrorIs(t, err, signer.ErrRiskLimit, "the first is still inside the hour")
		e.clk.Add(time.Second)
		d = e.decision(signertest.DecisionOpts{Label: "e"}, func(dep *signertest.Deposit) { dep.Nonce = 9 })
		_, err = e.svc.Sign(context.Background(), request(d))
		require.NoError(t, err, "3600 s after the first, it no longer counts")
	})
	t.Run("fee per hour", func(t *testing.T) {
		e := newEnv(t, func(c *signer.Config) { c.Caps.MaxFeePerHour = new(big.Int).Mul(feeBound, big.NewInt(1)) })
		_, err := e.svc.Sign(context.Background(), request(e.decision(signertest.DecisionOpts{Label: "a"})))
		require.NoError(t, err)
		e.chain.Set(func(c *signertest.Chain) { c.Nonce = 8 })
		d := e.decision(signertest.DecisionOpts{Label: "b"}, func(dep *signertest.Deposit) { dep.Nonce = 8; dep.Value = big.NewInt(1) })
		_, err = e.svc.Sign(context.Background(), request(d))
		require.ErrorIs(t, err, signer.ErrRiskLimit, "gas burn is bounded per hour")
	})
}

func TestFastModeRefusal(t *testing.T) {
	e := newEnv(t, func(c *signer.Config) { c.RefuseFast = true })
	_, err := e.svc.Sign(context.Background(), request(e.decision(signertest.DecisionOpts{})))
	require.ErrorIs(t, err, signer.ErrFastModeRefused)
	_, err = e.svc.Sign(context.Background(), request(e.decision(signertest.DecisionOpts{Strict: true, Label: "strict"})))
	require.NoError(t, err)
}

func TestRecordOnlyAfterTheRailIncludedIt(t *testing.T) {
	e := newEnv(t)
	e.chain.Set(func(c *signertest.Chain) { c.AutoLand = false })
	d := e.decision(signertest.DecisionOpts{})
	out, err := e.svc.Sign(context.Background(), request(d))
	require.NoError(t, err)

	// Not on chain yet: the worker keeps waiting and records nothing.
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	_ = e.svc.Run(ctx)
	cancel()
	assert.Equal(t, signer.StateSigned, e.entry(d.Hash).State)
	assert.Zero(t, e.gate.Calls())
	assert.Greater(t, e.chain.SentCount(), 1, "the stored bytes are resent while waiting")

	e.chain.Land(out.Signed)
	got := e.waitState(d.Hash, signer.StateRecorded)
	assert.Equal(t, string(signer.StateExecuted), got.Outcome)
	r, _, err := commitment.VerifyReceipt(got.Receipt)
	require.NoError(t, err)
	assert.Equal(t, out.RailRef, r.Receipt.RailRef)
	assert.Equal(t, []byte(e.keys.ExecutorPub()), r.Receipt.ExecutorPubKey, "signed with the executor key")
}

func TestRestartResumesFromTheStore(t *testing.T) {
	e := newEnv(t)
	e.chain.Set(func(c *signertest.Chain) { c.AutoLand = false })
	d := e.decision(signertest.DecisionOpts{})
	first, err := e.svc.Sign(context.Background(), request(d))
	require.NoError(t, err)

	e.reopen()
	e.chain.Set(func(c *signertest.Chain) { c.Nonce = 8 })
	again, err := e.svc.Sign(context.Background(), request(d))
	require.NoError(t, err)
	assert.True(t, again.Repeat)
	assert.Equal(t, first.Signed, again.Signed, "never other bytes after a restart")

	e.chain.Land(first.Signed)
	e.waitState(d.Hash, signer.StateRecorded)
	for _, s := range e.chain.Sent {
		assert.Equal(t, first.Signed, s)
	}
}

func TestRecordRetriesWhileTheGateIsDown(t *testing.T) {
	e := newEnv(t)
	e.gate.err = errUnavailable
	d := e.decision(signertest.DecisionOpts{})
	_, err := e.svc.Sign(context.Background(), request(d))
	require.NoError(t, err)
	e.waitState(d.Hash, signer.StateExecuted)
	e.gate.mu.Lock()
	e.gate.err = nil
	e.gate.mu.Unlock()
	e.waitState(d.Hash, signer.StateRecorded)
}

func TestKeyRolesNeverOverlap(t *testing.T) {
	e := newEnv(t)
	k := e.keys
	cfg := defaultConfig(k)
	cfg.AgentKeys = append(cfg.AgentKeys, k.GatePub())
	require.Error(t, cfg.ValidateBasic(), "an agent key that is the gate key")

	for _, priv := range []ed25519.PrivateKey{k.Gate, k.Agent} {
		exec, err := signer.NewEd25519Executor(priv)
		require.NoError(t, err)
		_, err = signer.New(defaultConfig(k), signer.Deps{
			Store: e.store, Wallets: map[uint64]signer.WalletBackend{714: mustWallet(t, k)}, Handlers: []signer.Handler{e.h},
			Executor: exec, Recorder: signer.GateRecorder{C: e.gate},
		})
		require.ErrorContains(t, err, "executor key")
	}
}

func TestSignBeforeStartIsRefused(t *testing.T) {
	e := newEnv(t)
	svc, err := signer.New(e.cfg, signer.Deps{
		Store: e.store, Wallets: map[uint64]signer.WalletBackend{714: mustWallet(t, e.keys)}, Handlers: []signer.Handler{e.h},
	})
	require.NoError(t, err)
	_, err = svc.Sign(context.Background(), request(e.decision(signertest.DecisionOpts{})))
	require.ErrorIs(t, err, signer.ErrUnavailable)
}
