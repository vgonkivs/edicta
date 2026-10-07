package demo

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/celestia/node"
	"github.com/vgonkivs/edicta/celestia/railtx"
)

const (
	testFunder   = "celestia1funder"
	testRecorder = "celestia1recorder"
)

type loopEnv struct {
	l    *fundingLoop
	f    *fakeFunding
	ab   *fakeAbandoner
	ch   *fakeChain
	con  *fakeConsole
	log  []string
	text bytes.Buffer
}

func newLoopEnv() *loopEnv {
	e := &loopEnv{ab: &fakeAbandoner{}, con: &fakeConsole{}}
	e.f = &fakeFunding{addr: testFunder, log: &e.log}
	e.ch = &fakeChain{balances: map[string]uint64{}, log: &e.log}
	now := time.Unix(0, 0)
	e.l = &fundingLoop{
		f: e.f, ab: e.ab, chain: e.ch, console: e.con, screen: NewScreen(&e.text, false, false), denom: "utia",
		explore: explorer{addr: "https://x/{address}"}, poll: time.Second, timeout: time.Minute,
		sleep: noSleep, now: func() time.Time { now = now.Add(time.Second); return now },
	}
	return e
}

func TestSettleBeforeEveryRead(t *testing.T) {
	e := newLoopEnv()
	e.f.send = []func() ([32]byte, uint64, error){func() ([32]byte, uint64, error) {
		e.ch.balances[testRecorder] = 500
		return [32]byte{1}, 1100, nil
	}}
	require.NoError(t, e.l.ensure(context.Background(), "recorder", testRecorder, 500))
	require.NotEmpty(t, e.log)
	for i, ev := range e.log {
		if ev == "read" {
			require.Positive(t, i)
			assert.Equal(t, "settle", e.log[i-1], "a Settle comes right before every balance read: %v", e.log)
		}
	}
}

func TestSettledSendIsNotRepeatedWithTheOldAmount(t *testing.T) {
	e := newLoopEnv()
	// The previous send commits between our read and Send: Send reports
	// ErrSettled and the balance now already covers the need.
	e.f.send = []func() ([32]byte, uint64, error){func() ([32]byte, uint64, error) {
		e.ch.balances[testRecorder] = 500
		return [32]byte{}, 0, railtx.ErrSettled
	}}
	require.NoError(t, e.l.ensure(context.Background(), "recorder", testRecorder, 500))
	assert.Len(t, e.f.sends, 1, "no second send after ErrSettled when the re-read shows enough")

	e = newLoopEnv()
	e.ch.balances[testRecorder] = 100
	e.f.send = []func() ([32]byte, uint64, error){
		func() ([32]byte, uint64, error) {
			e.ch.balances[testRecorder] = 300
			return [32]byte{}, 0, railtx.ErrSettled
		},
		func() ([32]byte, uint64, error) {
			e.ch.balances[testRecorder] = 500
			return [32]byte{2}, 1100, nil
		},
	}
	require.NoError(t, e.l.ensure(context.Background(), "recorder", testRecorder, 500))
	require.Len(t, e.f.sends, 2)
	assert.EqualValues(t, 400, e.f.sends[0].amount)
	assert.EqualValues(t, 200, e.f.sends[1].amount, "the amount is recomputed from a fresh read")
}

func TestReadsArePinnedAboveTheHeightWhereASendWasSeen(t *testing.T) {
	e := newLoopEnv()
	e.f.pending = true
	e.f.status = node.TxStatus{Found: true, Height: 4242}
	e.f.settle = []func() (bool, error){func() (bool, error) { e.f.pending = false; return true, nil }}
	e.ch.balances[testRecorder] = 10
	require.NoError(t, e.l.ensure(context.Background(), "recorder", testRecorder, 10))
	require.NotEmpty(t, e.ch.minSeen)
	assert.EqualValues(t, 4242, e.ch.minSeen[0])
}

func TestFundingCaps(t *testing.T) {
	for _, tc := range []struct {
		err  error
		code int
	}{
		{fmt.Errorf("%w: sent 1, this 2, max 3", railtx.ErrTotalAboveMax), ExitInconclusive},
		{railtx.ErrAmountAboveMax, ExitUsage},
		{railtx.ErrFeeAboveMax, ExitUsage},
		{railtx.ErrNotStarted, ExitWrong},
	} {
		e := newLoopEnv()
		e.f.send = []func() ([32]byte, uint64, error){func() ([32]byte, uint64, error) { return [32]byte{}, 0, tc.err }}
		err := e.l.ensure(context.Background(), "recorder", testRecorder, 500)
		require.ErrorIs(t, err, tc.err)
		assert.Equal(t, tc.code, ExitCodeOf(err))
		assert.Len(t, e.f.sends, 1, "no retry after a cap")
	}
	e := newLoopEnv()
	e.f.send = []func() ([32]byte, uint64, error){func() ([32]byte, uint64, error) { return [32]byte{}, 0, railtx.ErrTotalAboveMax }}
	err := e.l.ensure(context.Background(), "recorder", testRecorder, 500)
	require.ErrorIs(t, err, ErrFundingCap)
}

func TestAbandonNeedsTheTypedWord(t *testing.T) {
	advanced := func() (bool, error) {
		return false, fmt.Errorf("%w: pending: %w", railtx.ErrSendInFlight, railtx.ErrSequenceAdvanced)
	}
	for _, confirmed := range []bool{false, true} {
		e := newLoopEnv()
		e.f.pending = true
		e.f.settle = []func() (bool, error){advanced}
		e.con.confirms = []bool{confirmed}
		e.ch.balances[testRecorder] = 500
		err := e.l.ensure(context.Background(), "recorder", testRecorder, 500)
		if confirmed {
			require.NoError(t, err)
			assert.Len(t, e.ab.hashes, 1)
		} else {
			require.ErrorIs(t, err, railtx.ErrSequenceAdvanced)
			assert.Empty(t, e.ab.hashes, "Enter, a wrong word or a timeout never abandons")
		}
	}
	e := newLoopEnv()
	b := uint64(41)
	e.f.binding = &b
	e.f.send = []func() ([32]byte, uint64, error){func() ([32]byte, uint64, error) { return [32]byte{}, 0, railtx.ErrSequenceBound }}
	e.con.confirms = []bool{false}
	require.ErrorIs(t, e.l.ensure(context.Background(), "recorder", testRecorder, 500), railtx.ErrSequenceBound)
	assert.Empty(t, e.ab.bindings)
}

func TestWaitForFundsAsksAfterTheTimeout(t *testing.T) {
	e := newLoopEnv()
	e.con.enters = []Answer{AnswerContinue, AnswerQuit}
	err := e.l.waitFor(context.Background(), testFunder, 1000)
	require.ErrorIs(t, err, ErrOperatorQuit)
	assert.Equal(t, ExitInconclusive, ExitCodeOf(err))
	assert.Len(t, e.con.prompts, 2, "keep waiting once, then quit")
	assert.Empty(t, e.f.sends)
	assert.Contains(t, e.text.String(), "waiting for funds...")
}

func TestBudgetIsShortfallsOnly(t *testing.T) {
	p := BudgetParams{MinGasPrice: big.NewRat(4, 1000), SendGas: 100000, PFBGas: 250000, Amount: 1000, MaxAmount: 200000}
	full, err := ComputeBudget(p, Balances{})
	require.NoError(t, err)
	assert.Equal(t, full.WantRecorder, full.Recorder)
	assert.Equal(t, full.WantExecutor, full.Executor)
	assert.EqualValues(t, 2*full.SendFee, full.FunderFees)
	assert.Equal(t, full.Recorder+full.Executor+full.FunderFees, full.Total)
	assert.GreaterOrEqual(t, full.Executor, uint64(2*1000+1), "the rogue attempt's amount + 1 is included")

	left, err := ComputeBudget(p, Balances{Recorder: full.WantRecorder, Executor: full.WantExecutor / 2})
	require.NoError(t, err)
	assert.Zero(t, left.Recorder)
	assert.Equal(t, full.WantExecutor-full.WantExecutor/2, left.Executor)
	assert.Equal(t, left.SendFee, left.FunderFees, "one send, one fee")

	none, err := ComputeBudget(p, Balances{Recorder: full.WantRecorder, Executor: full.WantExecutor})
	require.NoError(t, err)
	assert.Zero(t, none.Total)

	p.MaxAmount = 10
	_, err = ComputeBudget(p, Balances{})
	require.ErrorIs(t, err, ErrShortfallAboveMax)
}

var _ = errors.New
