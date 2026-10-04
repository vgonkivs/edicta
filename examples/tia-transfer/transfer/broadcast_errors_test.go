package transfer_test

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/examples/tia-transfer/transfer"
)

// Assumed symbol: transfer.ErrRejected, the Rail's final answer to a
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
			assert.Empty(t, r.clock.waited(), "no waiting for another turn")
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

func TestTransientErrorsUntilDeadlineAreSurfacedWithTheHash(t *testing.T) {
	r := newRig(t)
	r.rail.frozen = true
	r.rail.broadcastErrs = make([]error, 100000)
	for i := range r.rail.broadcastErrs {
		r.rail.broadcastErrs[i] = errors.New("node unreachable: dial refused")
	}
	action := actionBytes(t, chainID, validMsg())
	res, err := r.exec.Execute(bg, goodAuth(t, chash(1), action), action)
	require.ErrorIs(t, err, transfer.ErrHandedOff)
	assert.Contains(t, err.Error(), "node unreachable: dial refused", "the last broadcast error is not swallowed")
	assert.Greater(t, r.rail.broadcastCalls(), 1)
	assert.Equal(t, sha256.Sum256(r.rail.signed[0]), res.TxHash, "hand-off at the deadline also carries the hash")
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
