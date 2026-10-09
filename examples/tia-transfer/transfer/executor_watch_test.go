package transfer_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/examples/tia-transfer/bankaction"
	"github.com/vgonkivs/edicta/examples/tia-transfer/transfer"
)

const graceS = uint64(600)

// timeoutHeightOf reads the timeout_height the executor signed. It is only
// valid once Sign has run.
func timeoutHeightOf(r *rig, action []byte, h commitment.Hash) uint64 {
	a, err := bankaction.Decode(action)
	if err != nil {
		panic(err)
	}
	th, err := bankaction.CheckBody(a, h, r.rail.bodies[0])
	if err != nil {
		panic(err)
	}
	return th
}

// chainAt makes the head and the Status node report headH until the wall clock
// passes expires + 60 s, then timeout_height + delta.
func chainAt(r *rig, action []byte, h commitment.Hash, delta uint64) {
	fn := func(clk uint64) uint64 {
		if clk < expiresAt+60 {
			return headH
		}
		return timeoutHeightOf(r, action, h) + delta
	}
	r.rail.heightFn = fn
}

func TestNoBroadcastOnceExpiresPassedEvenWhenTheTurnWasSlow(t *testing.T) {
	cases := map[string]struct {
		hook  func(r *rig)
		clock uint64
	}{
		"head slow past expires": {func(r *rig) {
			r.rail.onHeight = func(n int) {
				if n == 1 {
					r.clock.set(expiresAt + 1)
				}
			}
		}, 0},
		"status slow past expires": {func(r *rig) {
			r.rail.onStatus = func(n int) {
				if n == 1 {
					r.clock.set(expiresAt + 1)
				}
			}
		}, 0},
		"status slow to exactly expires minus skew": {func(r *rig) {
			r.rail.onStatus = func(n int) {
				if n == 1 {
					r.clock.set(expiresAt - skew)
				}
			}
		}, 0},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			r := newRig(t)
			action := actionBytes(t, chainID, validMsg())
			h := chash(11)
			chainAt(r, action, h, 10)
			c.hook(r)
			ctx, cancel := context.WithTimeout(bg, 10*time.Second)
			defer cancel()
			_, err := r.exec.Execute(ctx, goodAuth(t, h, action), action, testSalt)
			require.ErrorIs(t, err, transfer.ErrHandedOff)
			assert.Zero(t, r.rail.broadcastCalls(), "now + skew >= expires before the send")
			assert.Equal(t, 1, r.rail.signCalls())
		})
	}
}

func TestFailedHeightReadAfterExpiryDoesNotEndTheWatch(t *testing.T) {
	boom := errors.New("head unreadable")
	t.Run("a window of failures", func(t *testing.T) {
		r := newRig(t)
		action := actionBytes(t, chainID, validMsg())
		h := chash(12)
		chainAt(r, action, h, 10)
		r.rail.heightErrFn = func(clk uint64) error {
			if clk >= expiresAt+5 && clk < expiresAt+200 {
				return boom
			}
			return nil
		}
		ctx := r.cancelOnStatus(5000)
		_, err := r.exec.Execute(ctx, goodAuth(t, h, action), action, testSalt)
		require.NoError(t, ctx.Err())
		require.ErrorIs(t, err, transfer.ErrHandedOff)
		rec, gerr := r.store.Get(bg, h)
		require.NoError(t, gerr)
		assert.Equal(t, transfer.StateHandedOff, rec.State)
		var after int
		for _, ts := range r.rail.statusTimes {
			if ts > expiresAt+5 {
				after++
			}
		}
		assert.Greater(t, after, 3, "the loop went on after the failed reads")
	})
	t.Run("failing for good: only the grace bound ends it", func(t *testing.T) {
		r := newRig(t)
		r.rail.frozen = true
		r.rail.heightErrFn = func(clk uint64) error {
			if clk >= expiresAt {
				return boom
			}
			return nil
		}
		ctx := r.cancelOnStatus(5000)
		action := actionBytes(t, chainID, validMsg())
		_, err := r.exec.Execute(ctx, goodAuth(t, chash(13), action), action, testSalt)
		require.NoError(t, ctx.Err())
		require.ErrorIs(t, err, transfer.ErrHandedOff)
		assert.GreaterOrEqual(t, r.clock.unix(), expiresAt+graceS)
	})
}

// wantDeadline is the rule for every per-call deadline, against the clock
// reading the executor saw: now + every while the send is not live, and
// min(now + every, stop) while it is.
func wantDeadline(c callInfo, every time.Duration, stop time.Time) time.Time {
	d := c.clockNow.Add(every)
	if c.clockNow.Before(stop) && stop.Before(d) {
		return stop
	}
	return d
}

func TestEveryCallHasABoundedDeadline(t *testing.T) {
	const every = 100 * time.Millisecond
	r := newRig(t, func(c *transfer.Config) { c.RebroadcastEvery = every })
	realNow := time.Now()
	r.clock.followRealTime()
	expires := uint64(realNow.Unix()) + 600
	r.rail.frozen = true
	r.rail.hang = map[string]int{"height": 1, "status": 1, "broadcast": 1}
	action := actionBytes(t, chainID, validMsg())
	h := chash(14)
	auth := goodAuth(t, h, action, func(a *commitment.Authorization) { a.Expires = expires })
	// No parent deadline: a hung call may be cut only by its own.
	_, err := r.exec.Execute(bg, auth, action, testSalt)
	require.ErrorIs(t, err, transfer.ErrHandedOff)
	stop := time.Unix(int64(expires-skew), 0)
	for _, kind := range []string{"height", "status", "broadcast"} {
		calls := r.rail.calls(kind)
		require.NotEmpty(t, calls, kind)
		var hung int
		for _, c := range calls {
			require.True(t, c.hasDeadline, "%s call without a deadline", kind)
			// The clock follows real time, so the executor's reading is a little
			// earlier than the one recorded at call entry.
			assert.InDelta(t, 0, float64(c.deadline.Sub(wantDeadline(c, every, stop))), float64(20*time.Millisecond), "%s deadline %s, clock %s", kind, c.deadline, c.clockNow)
			if c.blocked > 0 {
				hung++
				assert.GreaterOrEqual(t, c.blocked, every/2, "%s hung call was cut before its own deadline", kind)
				assert.Less(t, c.blocked, 5*time.Second, "%s hung call outlived its deadline", kind)
			}
		}
		assert.Equal(t, 1, hung, kind)
	}
}

func TestDeadlineAfterExpiryIsTheRebroadcastInterval(t *testing.T) {
	const every = 7 * time.Second
	r := newRig(t, func(c *transfer.Config) { c.RebroadcastEvery = every })
	r.rail.frozen = true
	action := actionBytes(t, chainID, validMsg())
	_, err := r.exec.Execute(bg, goodAuth(t, chash(15), action), action, testSalt)
	require.ErrorIs(t, err, transfer.ErrHandedOff)
	stop := time.Unix(int64(expiresAt-skew), 0)
	var live, expired int
	for _, c := range append(r.rail.calls("height"), r.rail.calls("status")...) {
		require.True(t, c.hasDeadline)
		assert.True(t, c.deadline.Equal(wantDeadline(c, every, stop)), "deadline %s, clock %s", c.deadline, c.clockNow)
		if c.clockNow.Before(stop) {
			live++
			assert.False(t, c.deadline.After(stop), "live call outlives the send stop")
			continue
		}
		expired++
		assert.True(t, c.deadline.Equal(c.clockNow.Add(every)), "deadline %s after expiry, clock %s", c.deadline, c.clockNow)
	}
	assert.Positive(t, live)
	assert.Positive(t, expired)
}

func TestAfterExpiryHeightAndStatusDeadlinesAreNeverInThePast(t *testing.T) {
	r := newRig(t)
	r.rail.frozen = true
	action := actionBytes(t, chainID, validMsg())
	_, err := r.exec.Execute(bg, goodAuth(t, chash(17), action), action, testSalt)
	require.ErrorIs(t, err, transfer.ErrHandedOff)
	var checked int
	for _, kind := range []string{"height", "status"} {
		for _, c := range r.rail.calls(kind) {
			if c.clockNow.Unix() < int64(expiresAt) {
				continue
			}
			checked++
			assert.True(t, c.deadline.After(c.clockNow), "%s deadline %s is not after the clock %s", kind, c.deadline, c.clockNow)
		}
	}
	assert.Positive(t, checked)
}

func TestTimeoutBoundNeedsTheStatusNodeHeightPastTheLagMargin(t *testing.T) {
	cases := map[string]struct {
		lag   int
		delta uint64
		early bool
	}{
		"default margin, th+3 is not enough":  {0, 3, false},
		"default margin, th+4 hands off":      {0, 4, true},
		"explicit default, th+3 not enough":   {3, 3, false},
		"custom margin 10, th+10 not enough":  {10, 10, false},
		"custom margin 10, th+11 hands off":   {10, 11, true},
		"custom margin 1, th+2 hands off":     {1, 2, true},
		"custom margin 1, th+1 is not enough": {1, 1, false},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			r := newRig(t, func(cfg *transfer.Config) { cfg.IndexerLagBlocks = c.lag })
			action := actionBytes(t, chainID, validMsg())
			h := chash(16)
			chainAt(r, action, h, c.delta)
			ctx := r.cancelOnStatus(5000)
			_, err := r.exec.Execute(ctx, goodAuth(t, h, action), action, testSalt)
			require.NoError(t, ctx.Err())
			require.ErrorIs(t, err, transfer.ErrHandedOff)
			if c.early {
				assert.Less(t, r.clock.unix(), expiresAt+graceS, "handed off on the timeout bound")
				n := len(r.rail.statusHeight)
				require.GreaterOrEqual(t, n, 2)
				assert.Greater(t, r.rail.statusTimes[n-1], r.rail.statusTimes[n-2], "second check after a delay")
			} else {
				assert.GreaterOrEqual(t, r.clock.unix(), expiresAt+graceS, "only the grace bound applies")
			}
		})
	}
}

func TestHeadFarPastTimeoutDoesNotCountWhenTheStatusNodeLags(t *testing.T) {
	r := newRig(t)
	r.rail.heightFn = func(clk uint64) uint64 {
		if clk < expiresAt {
			return headH
		}
		return headH + 1000
	}
	r.rail.nodeHeightFn = func(uint64) uint64 { return headH }
	ctx := r.cancelOnStatus(5000)
	action := actionBytes(t, chainID, validMsg())
	_, err := r.exec.Execute(ctx, goodAuth(t, chash(17), action), action, testSalt)
	require.NoError(t, ctx.Err())
	require.ErrorIs(t, err, transfer.ErrHandedOff)
	assert.GreaterOrEqual(t, r.clock.unix(), expiresAt+graceS, "the bridge head alone is not enough")
}

func TestTxVisibleOnTheSecondCheckFinishes(t *testing.T) {
	r := newRig(t)
	action := actionBytes(t, chainID, validMsg())
	h := chash(18)
	chainAt(r, action, h, 10)
	qualified := false
	r.rail.statusOverride = func(_ int, nodeH uint64) (transfer.TxStatus, bool) {
		if qualified {
			return transfer.TxStatus{State: transfer.TxCommitted, Height: headH + 2}, true
		}
		qualified = nodeH > timeoutHeightOf(r, action, h)+3
		return transfer.TxStatus{}, false
	}
	ctx := r.cancelOnStatus(5000)
	res, err := r.exec.Execute(ctx, goodAuth(t, h, action), action, testSalt)
	require.NoError(t, ctx.Err())
	require.NoError(t, err, "indexed late: finished, not handed off")
	assert.Equal(t, headH+2, res.Height)
	assert.True(t, r.store.has("finish"))
	assert.False(t, r.store.has("handoff"))
}

func TestNegativeIndexerLagIsInvalid(t *testing.T) {
	c := newClock()
	_, err := transfer.NewExecutor(transfer.Config{
		GatePubKey: gatePub(), GateID: gateID, IndexerLagBlocks: -1,
	}, transfer.Domain{ChainID: chainID, Denom: denom, HRP: hrp, Sender: sender},
		newRail(c), transfer.NewMemStore(), c)
	require.ErrorIs(t, err, transfer.ErrInvalidConfig)
}
