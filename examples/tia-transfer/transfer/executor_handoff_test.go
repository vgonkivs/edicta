package transfer_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/examples/tia-transfer/bankaction"
	"github.com/vgonkivs/edicta/examples/tia-transfer/transfer"
)

// These tests use the existing Executor API and assume that
//   - MemStore.Finish accepts a record in StateHandedOff (HandedOff -> Finished),
//   - Resume and Execute-after-hand-off look the tx up once and Finish it.

const expiresAt = nowUnix + 600

// timeoutOf is the timeout_height the executor signed into the first tx.
func timeoutOf(t *testing.T, r *rig, action []byte, h commitment.Hash) uint64 {
	t.Helper()
	a, err := bankaction.Decode(action)
	require.NoError(t, err)
	require.NotEmpty(t, r.rail.bodies)
	th, err := bankaction.CheckBody(a, h, r.rail.bodies[0])
	require.NoError(t, err)
	return th
}

// stalledPastExpiry makes a chain whose head stays at headH (below
// timeout_height) until the wall clock passes expires + 120 s, then jumps
// past timeout_height.
func stalledPastExpiry(t *testing.T, r *rig, action []byte, h commitment.Hash) {
	t.Helper()
	a, err := bankaction.Decode(action)
	require.NoError(t, err)
	r.rail.heightFn = func(clk uint64) uint64 {
		if clk < expiresAt+120 {
			return headH
		}
		th, err := bankaction.CheckBody(a, h, r.rail.bodies[0])
		if err != nil {
			panic(err)
		}
		return th + 1
	}
	ctx := r.cancelOnStatus(5000)
	_ = ctx
}

// cancelOnStatus is a guard: a loop that never ends fails instead of hanging.
func (r *rig) cancelOnStatus(n int) context.Context {
	ctx, cancel := context.WithCancel(bg)
	r.t.Cleanup(cancel)
	r.rail.onStatus = func(c int) {
		if c > n {
			cancel()
		}
	}
	r.guard = ctx
	return ctx
}

func TestKeepsCheckingStatusAfterExpiresAndHandsOffOnlyPastTimeoutHeight(t *testing.T) {
	r := newRig(t)
	action := actionBytes(t, chainID, validMsg())
	h := chash(5)
	stalledPastExpiry(t, r, action, h)
	_, err := r.exec.Execute(r.guard, goodAuth(t, h, action), action)
	require.ErrorIs(t, err, transfer.ErrHandedOff)
	require.NoError(t, r.guard.Err(), "the loop ended on its own")
	th := timeoutOf(t, r, action, h)

	for _, ts := range r.rail.bcastTimes {
		assert.Less(t, ts+skew, expiresAt, "no broadcast once now + skew >= expires")
	}
	after := 0
	for _, ts := range r.rail.statusTimes {
		if ts >= expiresAt {
			after++
		}
	}
	assert.GreaterOrEqual(t, after, 2, "status keeps being checked after expires")
	last := len(r.rail.statusHeight) - 1
	assert.Greater(t, r.rail.statusHeight[last], th, "the last status check is past timeout_height")
	for i, hh := range r.rail.statusHeight {
		if r.rail.statusTimes[i] >= expiresAt && hh <= th {
			assert.False(t, i == last, "no hand-off while the head is at or below timeout_height")
		}
	}
	assert.Equal(t, 1, r.rail.signCalls())
	assert.True(t, r.store.has("handoff"))
	rec, err := r.store.Get(bg, h)
	require.NoError(t, err)
	assert.Equal(t, transfer.StateHandedOff, rec.State)
}

func TestTxLandingBetweenExpiresAndTimeoutHeightIsFinished(t *testing.T) {
	r := newRig(t)
	action := actionBytes(t, chainID, validMsg())
	h := chash(6)
	stalledPastExpiry(t, r, action, h)
	r.rail.commitAtClock = expiresAt + 30 // head still at headH <= timeout_height
	r.rail.commitHeight = headH
	res, err := r.exec.Execute(r.guard, goodAuth(t, h, action), action)
	require.NoError(t, err, "included before timeout_height: success, not a hand-off")
	assert.Equal(t, headH, res.Height)
	assert.Equal(t, sha256.Sum256(r.rail.signed[0]), res.TxHash)
	assert.True(t, r.store.has("finish"))
	assert.False(t, r.store.has("handoff"))
	for _, ts := range r.rail.bcastTimes {
		assert.Less(t, ts+skew, expiresAt)
	}
	assert.Equal(t, 1, r.rail.signCalls())
}

func TestUnreadableHeadAfterExpiryDoesNotHandOff(t *testing.T) {
	r := newRig(t)
	action := actionBytes(t, chainID, validMsg())
	h := chash(7)
	r.rail.frozen = true
	ctx := r.cancelOnStatus(5000)
	r.rail.onBroadcast = func(n int) {
		if n == 1 {
			r.rail.headErr = errors.New("head unreadable")
		}
	}
	_, err := r.exec.Execute(ctx, goodAuth(t, h, action), action)
	require.Error(t, err)
	require.NotErrorIs(t, err, transfer.ErrHandedOff, "without a head we cannot say the timeout passed")
	require.NoError(t, ctx.Err(), "the loop ended on its own")
	assert.False(t, r.store.has("handoff"))
	rec, gerr := r.store.Get(bg, h)
	require.NoError(t, gerr)
	assert.Equal(t, transfer.StatePrepared, rec.State, "left for Resume")
}

func handOff(t *testing.T, r *rig, h commitment.Hash) []byte {
	t.Helper()
	action := actionBytes(t, chainID, validMsg())
	_, err := r.exec.Execute(bg, goodAuth(t, h, action), action)
	require.ErrorIs(t, err, transfer.ErrHandedOff)
	return action
}

func TestResumeOfHandedOffRecordFindsTheTxAndNeverSigns(t *testing.T) {
	r := newRig(t)
	h := chash(8)
	handOff(t, r, h)
	signs, bcasts := r.rail.signCalls(), r.rail.broadcastCalls()

	// Still not on chain: stays handed off.
	_, err := r.exec.Resume(bg, h)
	require.ErrorIs(t, err, transfer.ErrHandedOff)

	// The tx is found later.
	r.rail.includeAt = 1
	res, err := r.exec.Resume(bg, h)
	require.NoError(t, err)
	assert.Equal(t, uint64(1), res.Height)
	assert.Equal(t, sha256.Sum256(r.rail.signed[0]), res.TxHash)
	rec, err := r.store.Get(bg, h)
	require.NoError(t, err)
	assert.Equal(t, transfer.StateFinished, rec.State)
	assert.Equal(t, signs, r.rail.signCalls(), "Resume never signs")
	assert.Equal(t, bcasts, r.rail.broadcastCalls(), "Resume of a handed-off record never sends")

	again, err := r.exec.Resume(bg, h)
	require.NoError(t, err)
	assert.Equal(t, res, again)
}

func TestExecuteOfAHandedOffDecisionAlsoReconciles(t *testing.T) {
	r := newRig(t)
	h := chash(9)
	action := handOff(t, r, h)
	r.rail.includeAt = 1
	res, err := r.exec.Execute(bg, goodAuth(t, h, action), action)
	require.ErrorIs(t, err, transfer.ErrSeen)
	require.NotErrorIs(t, err, transfer.ErrHandedOff)
	assert.Equal(t, uint64(1), res.Height)
	assert.Equal(t, 1, r.rail.signCalls())
}

func TestFinalRejectionOfATxAlreadyCommittedIsSuccess(t *testing.T) {
	r := newRig(t)
	r.rail.includeAt = headH // committed as soon as something was broadcast
	r.rail.broadcastErrs = []error{fmt.Errorf("%w: sdk code 5: insufficient funds", transfer.ErrRejected)}
	action := actionBytes(t, chainID, validMsg())
	res, err := r.exec.Execute(bg, goodAuth(t, chash(1), action), action)
	require.NoError(t, err, "the tx is on chain: not a hand-off")
	assert.Equal(t, headH, res.Height)
	assert.Equal(t, sha256.Sum256(r.rail.signed[0]), res.TxHash)
	assert.True(t, r.store.has("finish"))
	assert.False(t, r.store.has("handoff"))
	assert.Equal(t, 1, r.rail.broadcastCalls())
}

func TestFinalRejectionStoresTheRealReason(t *testing.T) {
	cause := "codespace \"sdk\" code 13: insufficient fee; got: 500utia required: 600utia"
	r := newRig(t)
	r.rail.broadcastErrs = []error{fmt.Errorf("%w: %s", transfer.ErrRejected, cause)}
	action := actionBytes(t, chainID, validMsg())
	h := chash(2)
	_, err := r.exec.Execute(bg, goodAuth(t, h, action), action)
	require.ErrorIs(t, err, transfer.ErrHandedOff)
	require.ErrorIs(t, err, transfer.ErrRejected)
	assert.Contains(t, err.Error(), cause)
	assert.NotContains(t, err.Error(), "not included by timeout_height")
	assert.GreaterOrEqual(t, r.rail.statusCalls(), 2, "one status check before the send, one after the rejection")
	rec, gerr := r.store.Get(bg, h)
	require.NoError(t, gerr)
	assert.Equal(t, transfer.StateHandedOff, rec.State)
	assert.Contains(t, rec.Reason, "code 13")
	assert.Contains(t, rec.Reason, "insufficient fee")
	assert.NotContains(t, rec.Reason, "not included by timeout_height")
}

// Mempool full (sdk code 20) is not final: the Rail reports it as an ordinary
// transient error (not ErrRejected), so the same bytes keep being sent.
func TestMempoolFullKeepsRetryingButOtherFinalCodesStayFinal(t *testing.T) {
	r := newRig(t)
	r.rail.includeAt = headH + 5
	full := errors.New("codespace sdk code 20: mempool is full")
	r.rail.broadcastErrs = []error{full, full, full}
	action := actionBytes(t, chainID, validMsg())
	_, err := r.exec.Execute(bg, goodAuth(t, chash(3), action), action)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, r.rail.broadcastCalls(), 3)
	assert.Equal(t, 1, r.rail.signCalls())

	r2 := newRig(t)
	r2.rail.broadcastErrs = []error{fmt.Errorf("%w: codespace \"sdk\" code 5: insufficient funds", transfer.ErrRejected)}
	_, err = r2.exec.Execute(bg, goodAuth(t, chash(4), action), action)
	require.ErrorIs(t, err, transfer.ErrHandedOff)
	assert.Equal(t, 1, r2.rail.broadcastCalls())
}
