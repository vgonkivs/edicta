package transfer_test

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/examples/tia-transfer/transfer"
)

// transfer.ErrRejected is the Rail's final answer to a
// broadcast: the node checked the transaction and refused it (insufficient
// fee, signature, out of gas, sequence); resending the same bytes cannot help.
// The executor stops at once, hands off, and returns an error that wraps both
// ErrHandedOff and the Rail's error (node code and log). Every failure Result
// carries the real tx hash (sha256 of the signed bytes), never zeros.

func TestFinalRejectionStopsRebroadcastAndHandsOff(t *testing.T) {
	for name, cause := range map[string]string{
		"insufficient fee": "code 13: insufficient fee; got: 500utia required: 600utia",
		"signature":        "code 4: signature verification failed",
		"out of gas":       "code 11: out of gas in location: ReadFlat",
		"sequence":         "code 32: account sequence mismatch, expected 5, got 4",
	} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t)
			r.rail.includeAt = headH + 50
			r.rail.broadcastErrs = []error{fmt.Errorf("%w: %s", transfer.ErrRejected, cause)}
			action := actionBytes(t, chainID, validMsg())
			res, err := r.exec.Execute(bg, goodAuth(t, chash(1), action), action)
			require.ErrorIs(t, err, transfer.ErrHandedOff)
			require.ErrorIs(t, err, transfer.ErrRejected)
			assert.Contains(t, err.Error(), cause, "node code and log reach the caller")
			assert.Equal(t, 1, r.rail.broadcastCalls(), "no rebroadcast after a final rejection")
			assert.Equal(t, 1, r.rail.broadcastCalls(), "a delay before the last status check is fine, a resend is not")
			assert.True(t, r.store.has("handoff"))
			assert.False(t, r.store.has("finish"))
			require.Equal(t, 1, r.rail.signCalls())
			assert.Equal(t, sha256.Sum256(r.rail.signed[0]), res.TxHash, "the real tx hash, not zeros")
			assert.NotEqual(t, [32]byte{}, res.TxHash)
		})
	}
}

func TestTransientBroadcastErrorsKeepRetrying(t *testing.T) {
	r := newRig(t)
	r.rail.includeAt = headH + 5
	r.rail.broadcastErrs = []error{errors.New("unavailable"), errors.New("timeout"), errors.New("unavailable")}
	action := actionBytes(t, chainID, validMsg())
	res, err := r.exec.Execute(bg, goodAuth(t, chash(1), action), action)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, r.rail.broadcastCalls(), 3, "all three transient errors were retried past")
	assert.Equal(t, sha256.Sum256(r.rail.signed[0]), res.TxHash)
}

// On a halted chain (head never passes timeout_height) the
// executor hands off once the wall clock passes expires + HandOffGrace.
// HandOffGrace defaults to 10m.
// The hand-off error names the bound that fired ("grace") and carries the hash.
func TestTransientErrorsUntilGraceAreSurfacedWithTheHash(t *testing.T) {
	for name, grace := range map[string]time.Duration{"default 10m": 0, "configured 2m": 2 * time.Minute} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t, func(c *transfer.Config) { c.HandOffGrace = grace })
			want := grace
			if want == 0 {
				want = 10 * time.Minute
			}
			r.rail.frozen = true
			r.rail.broadcastErrs = make([]error, 100000)
			for i := range r.rail.broadcastErrs {
				r.rail.broadcastErrs[i] = errors.New("node unreachable: dial refused")
			}
			ctx := r.cancelOnStatus(5000)
			action := actionBytes(t, chainID, validMsg())
			h := chash(1)
			res, err := r.exec.Execute(ctx, goodAuth(t, h, action), action)
			require.NoError(t, ctx.Err(), "the grace bound ends the loop")
			require.ErrorIs(t, err, transfer.ErrHandedOff)
			assert.Contains(t, err.Error(), "node unreachable: dial refused", "the last broadcast error is not swallowed")
			assert.Contains(t, strings.ToLower(err.Error()), "grace", "the error says which bound fired")
			assert.Greater(t, r.rail.broadcastCalls(), 1)
			assert.Equal(t, sha256.Sum256(r.rail.signed[0]), res.TxHash, "hand-off also carries the hash")
			for _, ts := range r.rail.bcastTimes {
				assert.Less(t, ts+skew, expiresAt, "no send once the authorization has run out")
			}
			last := r.rail.statusTimes[len(r.rail.statusTimes)-1]
			assert.GreaterOrEqual(t, last, expiresAt+uint64(want.Seconds()), "not handed off before the grace has passed")
			rec, gerr := r.store.Get(bg, h)
			require.NoError(t, gerr)
			assert.Equal(t, transfer.StateHandedOff, rec.State)
			assert.Contains(t, strings.ToLower(rec.Reason), "grace")

			// The tx lands later: Resume finishes the record and never signs.
			signs, bcasts := r.rail.signCalls(), r.rail.broadcastCalls()
			r.rail.commitAtClock, r.rail.commitHeight = 1, headH
			res2, err := r.exec.Resume(bg, h)
			require.NoError(t, err)
			assert.Equal(t, headH, res2.Height)
			assert.Equal(t, res.TxHash, res2.TxHash)
			assert.Equal(t, signs, r.rail.signCalls())
			assert.Equal(t, bcasts, r.rail.broadcastCalls())
			rec, gerr = r.store.Get(bg, h)
			require.NoError(t, gerr)
			assert.Equal(t, transfer.StateFinished, rec.State)
		})
	}
}

func TestRejectionOnALaterTurnAlsoStops(t *testing.T) {
	r := newRig(t)
	r.rail.frozen = true
	r.rail.broadcastErrs = []error{errors.New("blip"), fmt.Errorf("%w: code 13: insufficient fee", transfer.ErrRejected)}
	action := actionBytes(t, chainID, validMsg())
	res, err := r.exec.Execute(bg, goodAuth(t, chash(1), action), action)
	require.ErrorIs(t, err, transfer.ErrRejected)
	require.ErrorIs(t, err, transfer.ErrHandedOff)
	assert.Equal(t, 2, r.rail.broadcastCalls())
	assert.Equal(t, sha256.Sum256(r.rail.signed[0]), res.TxHash)
}
