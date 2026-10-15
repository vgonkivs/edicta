package execcapture_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/archive/fsarchive"
	"github.com/vgonkivs/edicta/celestia/execcapture"
)

// slowArchive is an archive whose writes of the listed references hang
// until released or until the call's context ends.
type slowArchive struct {
	*fsarchive.Store
	hang    map[string]bool
	release chan struct{}
	entered chan struct{}
	once    sync.Once

	mu        sync.Mutex
	deadlines []bool
}

func newSlowArchive(t *testing.T, hang ...string) *slowArchive {
	t.Helper()
	st, err := fsarchive.Open(t.TempDir(), nil)
	require.NoError(t, err)
	s := &slowArchive{Store: st, hang: map[string]bool{}, release: make(chan struct{}), entered: make(chan struct{})}
	for _, h := range hang {
		s.hang[h] = true
	}
	return s
}

func (s *slowArchive) Put(ctx context.Context, r archive.Record) (archive.Outcome, error) {
	_, has := ctx.Deadline()
	s.mu.Lock()
	s.deadlines = append(s.deadlines, has)
	s.mu.Unlock()
	if rec, ok := r.(*archive.ExecutionResultRecord); ok && s.hang[hex.EncodeToString(rec.RailRef)] {
		s.once.Do(func() { close(s.entered) })
		select {
		case <-s.release:
		case <-ctx.Done():
			return 0, ctx.Err()
		}
	}
	return s.Store.Put(ctx, r)
}

func within(t *testing.T, d time.Duration, f func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		f()
	}()
	select {
	case <-done:
	case <-time.After(d):
		require.FailNow(t, "the call did not return in time")
	}
}

// A move into the archive that hangs does not hold up new captures: Pass
// captures and moves a new reference while Migrate waits on the archive.
func TestSlowArchiveDoesNotStallNewCaptures(t *testing.T) {
	r := newRig(t)
	refs := r.chain.block(50, 2, func(int) uint32 { return 0 })
	r.chain.setHead(52)
	_, err := r.cap.Track(context.Background(), refs[0], hashA, false)
	require.NoError(t, err)
	r.cap.Pass(context.Background())

	slow := newSlowArchive(t, refs[0])
	c, err := execcapture.New(execcapture.Config{ChainID: chainID, PruneWindowBlocks: 1000}, r.chain, r.store,
		slog.New(slog.NewTextHandler(&syncWriter{w: &bytes.Buffer{}}, nil)), execcapture.WithArchive(slow))
	require.NoError(t, err)

	migrated := make(chan []execcapture.Migrated, 1)
	go func() { migrated <- c.Migrate(context.Background()) }()
	select {
	case <-slow.entered:
	case <-time.After(10 * time.Second):
		require.FailNow(t, "Migrate never reached the archive")
	}

	_, err = c.Track(context.Background(), refs[1], hashA, false)
	require.NoError(t, err)
	within(t, 10*time.Second, func() { c.Pass(context.Background()) })
	ref1, err := hex.DecodeString(refs[1])
	require.NoError(t, err)
	_, err = slow.ExecutionResult(context.Background(), chainID, ref1)
	require.NoError(t, err, "the new capture moved into the archive while the old one hangs")
	assert.Nil(t, c.Migrate(context.Background()), "a second run does not overlap the one in progress")

	close(slow.release)
	var got []execcapture.Migrated
	select {
	case got = <-migrated:
	case <-time.After(10 * time.Second):
		require.FailNow(t, "Migrate did not finish after the archive answered")
	}
	require.Len(t, got, 1)
	assert.Equal(t, refs[0], got[0].RailRef)
	assert.Equal(t, execcapture.MigrationWritten, got[0].Result, "%v", got[0].Err)
	b, err := r.store.Blocks(context.Background())
	require.NoError(t, err)
	assert.Empty(t, b, "both captures are dropped once archived")
}

// Every archive call is bounded: an archive that never answers costs one
// timeout, the capture stays, and the warning is not repeated every run.
func TestArchiveCallsAreBounded(t *testing.T) {
	r := newRig(t)
	refs := r.chain.block(50, 1, func(int) uint32 { return 0 })
	r.chain.setHead(52)
	_, err := r.cap.Track(context.Background(), refs[0], hashA, false)
	require.NoError(t, err)
	r.cap.Pass(context.Background())

	slow := newSlowArchive(t, refs[0])
	logs := &bytes.Buffer{}
	w := &syncWriter{w: logs}
	c, err := execcapture.New(execcapture.Config{ChainID: chainID, PruneWindowBlocks: 1000}, r.chain, r.store,
		slog.New(slog.NewTextHandler(w, nil)), execcapture.WithArchive(slow), execcapture.WithArchiveTimeout(50*time.Millisecond))
	require.NoError(t, err)

	for range 2 {
		var got []execcapture.Migrated
		within(t, 10*time.Second, func() { got = c.Migrate(context.Background()) })
		require.Len(t, got, 1)
		assert.Equal(t, execcapture.MigrationRetry, got[0].Result)
		require.ErrorIs(t, got[0].Err, context.DeadlineExceeded)
	}
	slow.mu.Lock()
	assert.Equal(t, []bool{true, true}, slow.deadlines, "each archive call carries its own deadline")
	slow.mu.Unlock()
	blk, err := r.store.Block(context.Background(), chainID, 50)
	require.NoError(t, err)
	assert.Len(t, blk.Txs, 1, "the capture stays")
	w.mu.Lock()
	assert.Equal(t, 1, strings.Count(logs.String(), "retried on the next run"))
	w.mu.Unlock()
}

func TestArchiveTimeoutMustBePositive(t *testing.T) {
	r := newRig(t)
	_, err := execcapture.New(execcapture.Config{ChainID: chainID, PruneWindowBlocks: 1000}, r.chain, r.store, nil,
		execcapture.WithArchiveTimeout(0))
	require.ErrorIs(t, err, execcapture.ErrInvalid)
}
