// SPDX-License-Identifier: Apache-2.0

package edenexec

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/internal/evm"
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

// awaitChecker waits at L0, as an explicit configuration may: one source's
// word decides an outcome, never not executed.
func awaitChecker(t *testing.T, srcs ...Source) (*Checker, *fakeClock) {
	t.Helper()
	return awaitCheckerAt(t, LevelNodeAttested, srcs...)
}

func awaitCheckerAt(t *testing.T, level Level, srcs ...Source) (*Checker, *fakeClock) {
	t.Helper()
	chk := newTestChecker(t, Config{MinLevel: level, PollInterval: time.Second}, srcs...)
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
	assert.Equal(t, AwaitExecuted, rep.State)
	assert.Equal(t, 2, clk.sleeps)
	assert.True(t, rep.RecordAllowed())
	assert.False(t, rep.PaymentSignatureAllowed(), "one operator's word is L0")
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
	a, b := s.source("own"), s.source("public")
	a.Txs, b.Txs = nil, nil
	chk, clk := awaitChecker(t, a, b)
	start := clk.now
	rep, err := chk.Await(context.Background(), s.target, start.Add(10*time.Second))
	require.ErrorIs(t, err, ErrNotFound)
	assert.Equal(t, ReasonNotFound, rep.Reason)
	assert.Equal(t, AwaitNotExecuted, rep.State)
	assert.True(t, rep.NonceReleaseAllowed())
	assert.Equal(t, 10, clk.sleeps, "polls once per interval until the deadline")
	assert.False(t, clk.now.Before(start.Add(10*time.Second)))
}

// One operator's not found is never not executed, at any level.
func TestAwaitOneOperatorNotFoundIsUnknown(t *testing.T) {
	s := newScenario(t)
	a, b := s.source("own"), s.source("public")
	a.Txs = nil
	b.ChainErr = errors.New("down")
	same := s.source("other-host")
	same.Txs = nil
	for name, srcs := range map[string][]Source{
		"one source":                {a},
		"other source unavailable":  {a, b},
		"two hosts of one operator": {a, &operated{FakeSource: same, op: "own"}},
	} {
		chk, clk := awaitChecker(t, srcs...)
		rep, err := chk.Await(context.Background(), s.target, clk.now.Add(3*time.Second))
		require.ErrorIs(t, err, ErrSettlementUnknown, name)
		require.NotErrorIs(t, err, ErrNotFound, name)
		assert.Equal(t, AwaitUnknown, rep.State, name)
		assert.False(t, rep.NonceReleaseAllowed(), name)
	}
}

// operated gives a fake source an operator label.
type operated struct {
	*FakeSource
	op string
}

func (o *operated) Operator() string { return o.op }

func TestAwaitNoSourceAnswered(t *testing.T) {
	s := newScenario(t)
	src := s.source("own")
	src.ChainErr = errors.New("connection refused")
	chk, clk := awaitChecker(t, src)
	rep, err := chk.Await(context.Background(), s.target, clk.now.Add(3*time.Second))
	require.ErrorIs(t, err, ErrSettlementUnknown)
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
	require.ErrorIs(t, err, ErrSettlementUnknown)
	require.NotErrorIs(t, err, ErrNotFound, "one source is never enough for not executed")
	assert.Equal(t, ReasonNotFound, rep.Reason)
}

// Two operators: one serves the transaction below the depth in the first
// poll, then both answer not found past until. Seen sticks for the whole
// wait, and across calls that continue it.
func TestAwaitSeenInAnEarlierPollBlocksNotExecuted(t *testing.T) {
	s := newScenario(t)
	a := &operated{FakeSource: s.source("a"), op: "one"}
	b := &operated{FakeSource: s.source("b"), op: "two"}
	a.HeadNum = scnNumber + 1
	a.OnTransaction = func(n int, h [32]byte) (TxView, error) {
		if n == 1 {
			return s.tx, nil
		}
		return TxView{}, ErrNotFound
	}
	b.Txs = nil
	chk, clk := awaitCheckerAt(t, LevelMultiSource, a, b)
	rep, err := chk.Await(context.Background(), s.target, clk.now.Add(3*time.Second))
	require.ErrorIs(t, err, ErrSettlementUnknown)
	require.NotErrorIs(t, err, ErrNotFound)
	assert.Equal(t, AwaitUnknown, rep.State)
	assert.True(t, rep.Seen)
	assert.False(t, rep.NonceReleaseAllowed())

	// A later call of the same wait, every source now answering not found.
	rep, err = chk.AwaitSeen(context.Background(), s.target, clk.now, true)
	require.ErrorIs(t, err, ErrSettlementUnknown)
	assert.True(t, rep.Seen)
	assert.Equal(t, AwaitUnknown, rep.State)

	// Without the carried fact the same answers would be not executed.
	rep, err = chk.AwaitSeen(context.Background(), s.target, clk.now, false)
	require.ErrorIs(t, err, ErrNotFound)
	assert.False(t, rep.Seen)
	assert.Equal(t, AwaitNotExecuted, rep.State)
}

// Seen never stops a later poll from reaching an outcome.
func TestAwaitSeenStillReachesExecuted(t *testing.T) {
	s := newScenario(t)
	a := &operated{FakeSource: s.source("a"), op: "one"}
	b := &operated{FakeSource: s.source("b"), op: "two"}
	chk, clk := awaitCheckerAt(t, LevelMultiSource, a, b)
	rep, err := chk.AwaitSeen(context.Background(), s.target, clk.now.Add(time.Minute), true)
	require.NoError(t, err)
	assert.Equal(t, AwaitExecuted, rep.State)
	assert.True(t, rep.PaymentSignatureAllowed())
}

func TestCheckPaymentProofSetup(t *testing.T) {
	s := newScenario(t)
	one := &operated{FakeSource: s.source("a"), op: "one"}
	two := &operated{FakeSource: s.source("b"), op: "two"}
	sameOp := &operated{FakeSource: s.source("c"), op: "one"}
	ok := newTestChecker(t, Config{MinLevel: LevelMultiSource}, one, two)
	require.NoError(t, ok.CheckPaymentProofSetup())
	for name, chk := range map[string]*Checker{
		"L0":             newTestChecker(t, Config{MinLevel: LevelNodeAttested}, one, two),
		"unlabelled":     newTestChecker(t, Config{MinLevel: LevelMultiSource}, one, s.source("d")),
		"one operator":   newTestChecker(t, Config{MinLevel: LevelMultiSource}, one, sameOp),
		"three required": newTestChecker(t, Config{MinLevel: LevelMultiSource, MinSources: 3}, one, two),
	} {
		assert.Error(t, chk.CheckPaymentProofSetup(), name)
	}
}

func TestAwaitUnconfirmedAtDeadline(t *testing.T) {
	s := newScenario(t)
	src := s.source("own")
	src.HeadNum = scnNumber + 1
	chk, clk := awaitChecker(t, src)
	rep, err := chk.Await(context.Background(), s.target, clk.now.Add(2*time.Second))
	require.ErrorIs(t, err, ErrSettlementUnknown)
	assert.Equal(t, ReasonUnconfirmed, rep.Reason)
	assert.Equal(t, AwaitUnknown, rep.State)
}

// A source below the depth blocks not executed, whatever the others say.
func TestAwaitUnconfirmedBlocksNotExecuted(t *testing.T) {
	s := newScenario(t)
	a, b, c := s.source("a"), s.source("b"), s.source("c")
	a.Txs, b.Txs = nil, nil
	c.HeadNum = scnNumber + 1
	chk, clk := awaitCheckerAt(t, LevelMultiSource, a, b, c)
	rep, err := chk.Await(context.Background(), s.target, clk.now.Add(2*time.Second))
	require.ErrorIs(t, err, ErrSettlementUnknown)
	assert.Equal(t, AwaitUnknown, rep.State)
	assert.False(t, rep.NonceReleaseAllowed())
}

func TestAwaitL1(t *testing.T) {
	s := newScenario(t)
	t.Run("two operators agree", func(t *testing.T) {
		a := &operated{FakeSource: s.source("a"), op: "one"}
		b := &operated{FakeSource: s.source("b"), op: "two"}
		chk, clk := awaitCheckerAt(t, LevelMultiSource, a, b)
		rep, err := chk.Await(context.Background(), s.target, clk.now.Add(time.Minute))
		require.NoError(t, err)
		assert.Equal(t, AwaitExecuted, rep.State)
		assert.Equal(t, LevelMultiSource, rep.Level)
		assert.True(t, rep.PaymentSignatureAllowed())
	})
	t.Run("hosts standing in as labels give no payment proof", func(t *testing.T) {
		b := &operated{FakeSource: s.source("b"), op: "two"}
		chk, clk := awaitCheckerAt(t, LevelMultiSource, s.source("a"), b)
		rep, err := chk.Await(context.Background(), s.target, clk.now.Add(time.Minute))
		require.NoError(t, err)
		assert.Equal(t, LevelMultiSource, rep.Level)
		assert.True(t, rep.RecordAllowed())
		assert.False(t, rep.PaymentSignatureAllowed())
	})
	t.Run("one operator keeps it pending until the deadline", func(t *testing.T) {
		b := s.source("b")
		b.Txs = nil
		chk, clk := awaitCheckerAt(t, LevelMultiSource, s.source("a"), b)
		rep, err := chk.Await(context.Background(), s.target, clk.now.Add(5*time.Second))
		require.ErrorIs(t, err, ErrSettlementUnknown)
		assert.Equal(t, AwaitUnknown, rep.State)
		assert.Equal(t, ReasonBelowLevel, rep.Reason)
		assert.Equal(t, 5, clk.sleeps)
		assert.False(t, rep.RecordAllowed())
	})
	t.Run("a disagreement stays disputed and never violated", func(t *testing.T) {
		b := s.source("b")
		rc := b.Receipts[s.R]
		rc.Status, rc.Logs = 0, nil
		b.Receipts[s.R] = rc
		chk, clk := awaitCheckerAt(t, LevelMultiSource, s.source("a"), b)
		rep, err := chk.Await(context.Background(), s.target, clk.now.Add(3*time.Second))
		require.ErrorIs(t, err, ErrDisagree)
		assert.Equal(t, AwaitDisputed, rep.State)
		assert.Equal(t, StatusUnchecked, rep.Status)
		assert.Equal(t, 3, clk.sleeps, "a later poll may resolve it")
		assert.False(t, rep.RecordAllowed())
		assert.False(t, rep.NonceReleaseAllowed())
	})
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
		tx.Hash = evm.Keccak256(other)
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
	other := s.source("other")
	other.Txs = nil
	chk := newTestChecker(t, Config{PollInterval: time.Millisecond}, src, other)
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
	assert.Equal(t, []string{"own", "public"}, order, "every source is asked, so a disagreement shows")
	require.Len(t, rep.Sources, 2)
	assert.Equal(t, "own", rep.Sources[0].Name)
	assert.Equal(t, SourceUsed, rep.Sources[0].Result)
	assert.Equal(t, SourceAgree, rep.Sources[1].Result)
	assert.Equal(t, LevelMultiSource, rep.Level, "two operators reach L1 even when L0 is configured")
}
