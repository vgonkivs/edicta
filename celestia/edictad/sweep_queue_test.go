package edictad_test

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/archive"
)

func eventually(t *testing.T, cond func() bool, msg string) {
	t.Helper()
	require.Eventually(t, cond, 10*time.Second, 5*time.Millisecond, msg)
}

// A record the gate decided on but the archive refused is queued and written
// by the background sweep: with its K2 inputs, which a registry scan could not
// supply.
func TestQueuedAuthorizationRecordIsRetriedWithItsK2Inputs(t *testing.T) {
	e, fs, real, base := archiveEnv(t)
	tick := make(chan time.Time)
	e.deps.SweepTick = tick
	e.start()
	d := e.decision(base, 1)

	fs.failKind(archive.KindAuthorization, errArchiveDown)
	st, _, _ := e.authorizeRaw(d)
	require.Equal(t, 200, st)

	tick <- t0 // still failing: the record stays queued
	tick <- t0 // returns once the first run is over
	_, err := real.Authorization(bg, d.hash)
	require.ErrorIs(t, err, archive.ErrNotFound)

	fs.failKind(archive.KindAuthorization, nil)
	tick <- t0
	eventually(t, func() bool { _, err := real.Authorization(bg, d.hash); return err == nil }, "the queue is drained")
	auth, err := real.Authorization(bg, d.hash)
	require.NoError(t, err)
	require.NotNil(t, auth.K2, "the queued record keeps the inputs the gate used")
	assert.EqualValues(t, t0.Unix(), auth.K2.CheckedAt)

	// Drained: further ticks write nothing.
	n := fs.putCount(archive.KindAuthorization)
	tick <- t0
	tick <- t0
	assert.Equal(t, n, fs.putCount(archive.KindAuthorization))
}

func TestQueuedMarkerIsRetried(t *testing.T) {
	e, fs, real, base := archiveEnv(t)
	tick := make(chan time.Time)
	e.deps.SweepTick = tick
	e.start()
	st, _, _ := e.authorizeRaw(e.decision(base, 1))
	require.Equal(t, 200, st)

	fs.failKind(archive.KindRejection, errArchiveDown)
	d := e.decisionAct(base, 1, []byte{0xa1, 1, 1, 9})
	st, _, _ = e.authorizeRaw(d)
	require.Equal(t, 409, st)
	_, err := real.Rejection(bg, d.hash, "ErrNonceUsed")
	require.ErrorIs(t, err, archive.ErrNotFound)

	fs.failKind(archive.KindRejection, nil)
	tick <- t0
	eventually(t, func() bool { _, err := real.Rejection(bg, d.hash, "ErrNonceUsed"); return err == nil }, "the marker is written")
}

// A queued record whose decision record is gone is dropped and counted, not
// retried for ever.
func TestQueuedRecordWithoutItsDecisionIsDropped(t *testing.T) {
	e, fs, real, base := archiveEnv(t)
	tick := make(chan time.Time)
	e.deps.SweepTick = tick
	e.start()
	d := e.decision(base, 1)
	fs.failKind(archive.KindAuthorization, errArchiveDown)
	st, _, _ := e.authorizeRaw(d)
	require.Equal(t, 200, st)
	require.NoError(t, removeFile(decisionFile(e, d.hash)))

	fs.failKind(archive.KindAuthorization, nil)
	tick <- t0
	tick <- t0
	n := fs.putCount(archive.KindAuthorization)
	tick <- t0
	tick <- t0
	assert.Equal(t, n, fs.putCount(archive.KindAuthorization), "no further attempts")
	_, err := real.Authorization(bg, d.hash)
	require.ErrorIs(t, err, archive.ErrNotFound)
	assert.NotEmpty(t, e.logs.String())
}

// At most 64 archive calls are in flight; one more is a retryable 503, and the
// slots come back when the calls finish.
func TestArchiveInFlightLimitIs503(t *testing.T) {
	const limit = 64
	e, fs, real, base := archiveEnv(t)
	entered := make(chan struct{}, limit+8)
	release := make(chan struct{})
	fs.onPut(archive.KindDecision, func() { entered <- struct{}{}; <-release })
	e.start()

	statuses := make([]int, limit)
	errs := make([]error, limit)
	var wg sync.WaitGroup
	for i := range limit {
		d := e.decision(base, byte(i+1))
		wg.Add(1)
		go func() {
			defer wg.Done()
			statuses[i], errs[i] = e.authorizeStatus(d)
		}()
	}
	for range limit {
		<-entered
	}

	extra := e.decision(base, byte(limit+1))
	st, ra, body := e.authorizeRaw(extra)
	require.Equal(t, 503, st)
	assert.NotEmpty(t, ra)
	assert.True(t, hasCode(body, "ErrArchiveUnavailable"))
	assert.Equal(t, limit, fs.putCount(archive.KindDecision), "the refused call never reached the store")

	close(release)
	wg.Wait()
	for i := range limit {
		require.NoError(t, errs[i])
		assert.Equal(t, 200, statuses[i])
	}
	fs.onPut(archive.KindDecision, nil)
	st, _, _ = e.authorizeRaw(extra)
	assert.Equal(t, 200, st, "the slots are free again")
	_, err := real.Decision(bg, extra.hash)
	require.NoError(t, err)
}
