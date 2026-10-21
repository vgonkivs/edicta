// SPDX-License-Identifier: Apache-2.0

package edenexec

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeClock advances only when the checker sleeps.
type fakeClock struct {
	now    time.Time
	sleeps int
}

func (c *fakeClock) install(chk *Checker) {
	chk.now = func() time.Time { return c.now }
	chk.sleep = func(ctx context.Context, d time.Duration) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		c.sleeps++
		c.now = c.now.Add(d)
		return nil
	}
}

func awaitChecker(t *testing.T, srcs ...Source) (*Checker, *fakeClock) {
	t.Helper()
	chk := newTestChecker(t, Config{PollInterval: time.Second}, srcs...)
	clk := &fakeClock{now: time.Unix(scnTime, 0)}
	clk.install(chk)
	return chk, clk
}

func TestAwaitUntil(t *testing.T) {
	s := newScenario(t)
	cfg := Config{}
	cfg.ApplyDefaults()
	want := time.Unix(int64(s.action.Deposit.ExpiresAt), 0).Add(DefaultAwaitGrace)
	assert.Equal(t, want, cfg.AwaitUntil(s.target))
}

func TestAwaitFoundAfterPolls(t *testing.T) {
	s := newScenario(t)
	src := s.source("own")
	src.OnTransaction = func(n int, h [32]byte) (TxView, error) {
		if n < 3 {
			return TxView{}, ErrNotFound
		}
		return s.tx, nil
	}
	chk, clk := awaitChecker(t, src)
	rep, err := chk.Await(context.Background(), s.target, clk.now.Add(time.Minute))
	require.NoError(t, err)
	assert.Equal(t, StatusPass, rep.Status)
	assert.Equal(t, OutcomeExecuted, rep.Outcome)
	assert.Equal(t, 2, clk.sleeps)
}

func TestAwaitReverted(t *testing.T) {
	s := newScenario(t)
	s.receipt.Status, s.receipt.Logs = 0, nil
	chk, clk := awaitChecker(t, s.source("own"))
	rep, err := chk.Await(context.Background(), s.target, clk.now.Add(time.Minute))
	require.NoError(t, err)
	assert.Equal(t, OutcomeReverted, rep.Outcome)
}

func TestAwaitNotExecuted(t *testing.T) {
	s := newScenario(t)
	src := s.source("own")
	src.Txs = nil
	chk, clk := awaitChecker(t, src)
	start := clk.now
	rep, err := chk.Await(context.Background(), s.target, start.Add(10*time.Second))
	require.ErrorIs(t, err, ErrNotFound)
	assert.Equal(t, ReasonNotFound, rep.Reason)
	assert.Equal(t, 10, clk.sleeps, "polls once per interval until the deadline")
	assert.False(t, clk.now.Before(start.Add(10*time.Second)))
}

func TestAwaitNoSourceAnswered(t *testing.T) {
	s := newScenario(t)
	src := s.source("own")
	src.ChainErr = errors.New("connection refused")
	chk, clk := awaitChecker(t, src)
	rep, err := chk.Await(context.Background(), s.target, clk.now.Add(3*time.Second))
	require.ErrorIs(t, err, ErrSourceUnavailable)
	require.NotErrorIs(t, err, ErrNotFound, "no answer is never not executed")
	assert.Equal(t, ReasonSourceUnavailable, rep.Reason)
}

func TestAwaitSeenThenGone(t *testing.T) {
	s := newScenario(t)
	src := s.source("own")
	src.HeadNum = scnNumber // below the depth while seen
	src.OnTransaction = func(n int, h [32]byte) (TxView, error) {
		if n == 1 {
			return s.tx, nil
		}
		return TxView{}, ErrNotFound
	}
	chk, clk := awaitChecker(t, src)
	rep, err := chk.Await(context.Background(), s.target, clk.now.Add(3*time.Second))
	require.ErrorIs(t, err, ErrUnconfirmed)
	require.NotErrorIs(t, err, ErrNotFound, "a transaction that was seen is never reported not executed")
	assert.Equal(t, ReasonUnconfirmed, rep.Reason)
}

func TestAwaitUnconfirmedAtDeadline(t *testing.T) {
	s := newScenario(t)
	src := s.source("own")
	src.HeadNum = scnNumber + 1
	chk, clk := awaitChecker(t, src)
	_, err := chk.Await(context.Background(), s.target, clk.now.Add(2*time.Second))
	require.ErrorIs(t, err, ErrUnconfirmed)
}

func TestAwaitStopsAtOnce(t *testing.T) {
	s := newScenario(t)
	t.Run("malformed rail_ref", func(t *testing.T) {
		chk, clk := awaitChecker(t, s.source("own"))
		tg := s.target
		tg.RailRef = "0x" + s.railRef
		_, err := chk.Await(context.Background(), tg, clk.now.Add(time.Hour))
		require.ErrorIs(t, err, ErrMalformedRailRef)
		assert.Zero(t, clk.sleeps)
	})
	t.Run("wrong transaction", func(t *testing.T) {
		src := s.source("own")
		tx := s.tx
		tx.Nonce = []byte{0x08}
		tx.R = []byte{0x01}
		// A served transaction that hashes to the asked hash but is not the
		// action: the rail_ref is the hash of these other bytes.
		other, err := RebuildSigned(tx)
		require.NoError(t, err)
		tx.Hash = keccak256(other)
		src.Txs = map[[32]byte]TxView{tx.Hash: tx}
		chk, clk := awaitChecker(t, src)
		tg := s.target
		tg.RailRef = hexOf(tx.Hash)
		rep, err := chk.Await(context.Background(), tg, clk.now.Add(time.Hour))
		require.ErrorIs(t, err, ErrWrongTx)
		assert.Equal(t, StatusViolated, rep.Status)
		assert.Zero(t, clk.sleeps)
	})
}

func TestAwaitCancelled(t *testing.T) {
	s := newScenario(t)
	src := s.source("own")
	src.Txs = nil
	chk, clk := awaitChecker(t, src)
	ctx, cancel := context.WithCancel(context.Background())
	chk.sleep = func(context.Context, time.Duration) error {
		cancel()
		return context.Canceled
	}
	_, err := chk.Await(ctx, s.target, clk.now.Add(time.Hour))
	require.ErrorIs(t, err, context.Canceled)
}

func TestAwaitRealTimer(t *testing.T) {
	s := newScenario(t)
	src := s.source("own")
	src.Txs = nil
	chk := newTestChecker(t, Config{PollInterval: time.Millisecond}, src)
	_, err := chk.Await(context.Background(), s.target, time.Now().Add(20*time.Millisecond))
	require.ErrorIs(t, err, ErrNotFound)
}

func TestAwaitAsksOwnNodeFirst(t *testing.T) {
	s := newScenario(t)
	public := s.source("public")
	own := s.source("own")
	own.SrcClass = ClassOwnNode
	var order []string
	for _, f := range []*FakeSource{public, own} {
		name := f.SrcName
		f.OnTransaction = func(int, [32]byte) (TxView, error) {
			order = append(order, name)
			return s.tx, nil
		}
	}
	chk, clk := awaitChecker(t, public, own)
	rep, err := chk.Await(context.Background(), s.target, clk.now.Add(time.Minute))
	require.NoError(t, err)
	assert.Equal(t, []string{"own"}, order, "the first source at the depth is enough")
	require.Len(t, rep.Sources, 1)
	assert.Equal(t, "own", rep.Sources[0].Name)
	assert.Equal(t, SourceUsed, rep.Sources[0].Result)
	assert.Equal(t, LevelNodeAttested, rep.Level, "Await stops at L0")
}
