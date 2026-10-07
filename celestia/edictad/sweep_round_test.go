package edictad_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/archive"
)

// A record that fails for good is not retried, but the Authorization is in the
// registry, so the next tick repairs the archive from there.
func TestPermanentlyFailedAuthorizationRecordIsRepairedFromTheRegistry(t *testing.T) {
	e, fs, real, base := archiveEnv(t)
	tick := make(chan time.Time)
	e.deps.SweepTick = tick
	e.start()
	d := e.decision(base, 1)

	fs.failKind(archive.KindAuthorization, fmt.Errorf("put: %w", archive.ErrCorrupt))
	st, _, _ := e.authorizeRaw(d)
	require.Equal(t, 200, st)
	_, err := real.Authorization(bg, d.hash)
	require.ErrorIs(t, err, archive.ErrNotFound)

	fs.failKind(archive.KindAuthorization, nil)
	tick <- t0
	eventually(t, func() bool { _, err := real.Authorization(bg, d.hash); return err == nil }, "the scan repairs the record")
	auth, err := real.Authorization(bg, d.hash)
	require.NoError(t, err)
	assert.Nil(t, auth.K2, "repaired from the registry, without the retention inputs")
}

// Shutdown makes a last attempt to write what is still queued.
func TestShutdownDrainWritesTheQueuedRecord(t *testing.T) {
	e, fs, real, base := archiveEnv(t)
	e.deps.SweepTick = make(chan time.Time)
	srv := e.start()
	d := e.decision(base, 1)

	fs.failKind(archive.KindAuthorization, errArchiveDown)
	st, _, _ := e.authorizeRaw(d)
	require.Equal(t, 200, st)
	fs.failKind(archive.KindAuthorization, nil)

	require.NoError(t, srv.Shutdown(bg))
	auth, err := real.Authorization(bg, d.hash)
	require.NoError(t, err)
	assert.NotNil(t, auth.K2, "the queued record keeps the inputs the gate used")
}

// The drain ends with the caller's deadline, not after the archive write
// timeout.
func TestShutdownDrainStopsAtTheCallersDeadline(t *testing.T) {
	e, fs, _, base := archiveEnv(t)
	e.deps.SweepTick = make(chan time.Time)
	srv := e.start()
	d := e.decision(base, 1)

	fs.failKind(archive.KindAuthorization, errArchiveDown)
	st, _, _ := e.authorizeRaw(d)
	require.Equal(t, 200, st)
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	fs.onPut(archive.KindAuthorization, func() { <-release })

	ctx, cancel := context.WithTimeout(bg, 200*time.Millisecond)
	defer cancel()
	begin := time.Now()
	_ = srv.Shutdown(ctx)
	assert.Less(t, time.Since(begin), 5*time.Second, "the write timeout is 10 s")
}
