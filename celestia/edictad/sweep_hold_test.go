package edictad_test

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/archive"
)

// A scan that runs while the issuing request's Authorization write is blocked
// leaves the entry to that request, so the record keeps the retention inputs
// only the request has.
func TestScanLeavesAnEntryWhoseAuthorizationWriteIsBlocked(t *testing.T) {
	e, fs, real, base := archiveEnv(t)
	tick := make(chan time.Time)
	e.deps.SweepTick = tick
	e.start()
	a, b := e.decision(base, 1), e.decision(base, 2)

	// A record that fails for good raises the dropped flag, so the next tick
	// scans the registry.
	fs.failKind(archive.KindAuthorization, fmt.Errorf("put: %w", archive.ErrCorrupt))
	st, _, _ := e.authorizeRaw(a)
	require.Equal(t, 200, st)
	fs.failKind(archive.KindAuthorization, nil)

	var armed atomic.Bool
	armed.Store(true)
	entered, release := make(chan struct{}), make(chan struct{})
	fs.onPut(archive.KindAuthorization, func() {
		if armed.CompareAndSwap(true, false) {
			close(entered)
			<-release
		}
	})
	done := make(chan int, 1)
	go func() { s, _ := e.authorizeStatus(b); done <- s }()
	<-entered

	tick <- t0
	eventually(t, func() bool { _, err := real.Authorization(bg, a.hash); return err == nil }, "the scan ran and repaired the other entry")
	_, err := real.Authorization(bg, b.hash)
	require.ErrorIs(t, err, archive.ErrNotFound, "the scan left the held entry alone")

	close(release)
	require.Equal(t, 200, <-done)
	auth, err := real.Authorization(bg, b.hash)
	require.NoError(t, err)
	assert.NotNil(t, auth.K2, "the request's own record, with its retention inputs")
}

// When the drain is cut short, Shutdown says so.
func TestShutdownReturnsTheDrainsContextError(t *testing.T) {
	e, fs, _, base := archiveEnv(t)
	e.deps.SweepTick = make(chan time.Time)
	srv := e.start()
	d := e.decision(base, 1)

	fs.failKind(archive.KindAuthorization, errArchiveDown)
	st, _, _ := e.authorizeRaw(d)
	require.Equal(t, 200, st)

	ctx, cancel := context.WithCancel(bg)
	defer cancel()
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	fs.onPut(archive.KindAuthorization, func() { cancel(); <-release })

	err := srv.Shutdown(ctx)
	require.ErrorIs(t, err, context.Canceled, "the queued record was left because ctx ended")
	e.registryReopens()
}
