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
			_, err := r.exec.Execute(ctx, goodAuth(t, h, action), action)
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
		_, err := r.exec.Execute(ctx, goodAuth(t, h, action), action)
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
		_, err := r.exec.Execute(ctx, goodAuth(t, chash(13), action), action)
		require.NoError(t, ctx.Err())
		require.ErrorIs(t, err, transfer.ErrHandedOff)
		assert.GreaterOrEqual(t, r.clock.unix(), expiresAt+graceS)
	})
}

func TestEveryCallHasABoundedDeadline(t *testing.T) {
	r := newRig(t, func(c *transfer.Config) { c.RebroadcastEvery = 50 * time.Millisecond })
	r.rail.frozen = true
	r.rail.hang = map[string]int{"height": 1, "status": 1, "broadcast": 1}
	ctx, cancel := context.WithTimeout(bg, 20*time.Second)
	defer cancel()
	action := actionBytes(t, chainID, validMsg())
	h := chash(14)
	_, err := r.exec.Execute(ctx, goodAuth(t, h, action), action)
	require.NoError(t, ctx.Err(), "a hanging call blocked past its bound")
	require.ErrorIs(t, err, transfer.ErrHandedOff)
	for _, kind := range []string{"height", "status", "broadcast"} {
		calls := r.rail.calls(kind)
		require.NotEmpty(t, calls, kind)
		for _, c := range calls {
			assert.True(t, c.hasDeadline, "%s call without a deadline", kind)
			assert.LessOrEqual(t, c.remaining, 50*time.Millisecond, kind)
		}
	}
}

func TestDeadlineAfterExpiryIsTheRebroadcastInterval(t *testing.T) {
	r := newRig(t, func(c *transfer.Config) { c.RebroadcastEvery = 7 * time.Second })
	r.rail.frozen = true
	action := actionBytes(t, chainID, validMsg())
	_, err := r.exec.Execute(bg, goodAuth(t, chash(15), action), action)
	require.ErrorIs(t, err, transfer.ErrHandedOff)
	var checked int
	for _, c := range append(r.rail.calls("height"), r.rail.calls("status")...) {
		require.True(t, c.hasDeadline)
		assert.LessOrEqual(t, c.remaining, 7*time.Second)
		checked++
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
			_, err := r.exec.Execute(ctx, goodAuth(t, h, action), action)
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
	_, err := r.exec.Execute(ctx, goodAuth(t, chash(17), action), action)
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
	res, err := r.exec.Execute(ctx, goodAuth(t, h, action), action)
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
