package execcapture_test

import (
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/celestia/execcapture"
)

// A capture still missing after the whole prune window can no longer
// succeed: it is marked lost, logged once at error level, no longer counted
// as overdue (health recovers), and never tracked again.
func TestCaptureLostAfterThePruneWindow(t *testing.T) {
	r := newRig(t)
	refs := r.chain.block(1000, 1, func(int) uint32 { return 0 })
	r.chain.resErr = errors.New("pruned")
	ctx := t.Context()

	r.chain.setHead(1000 + 600)
	_, err := r.cap.Track(ctx, refs[0], hashA, false)
	require.NoError(t, err)
	r.cap.Pass(ctx)
	assert.EqualValues(t, 1, r.cap.Overdue())

	r.chain.setHead(1000 + 999)
	r.cap.Pass(ctx)
	assert.EqualValues(t, 1, r.cap.Overdue(), "one block short of the window")

	r.chain.setHead(1000 + 1000)
	r.cap.Pass(ctx)
	assert.Zero(t, r.cap.Overdue(), "a lost capture does not keep health degraded")
	lost, err := r.store.Lost(ctx, refs[0])
	require.NoError(t, err)
	assert.True(t, lost)
	pend, err := r.store.ListPending(ctx)
	require.NoError(t, err)
	assert.Empty(t, pend)

	r.cap.Pass(ctx)
	assert.Equal(t, 1, strings.Count(r.logs.String(), "capture is lost"), "logged once")

	added, err := r.cap.Track(ctx, refs[0], hashA, true)
	require.NoError(t, err)
	assert.False(t, added, "a lost reference is not tracked again")
}

// A rail_ref that never shows up on the chain ages from the head at which it
// was first seen.
func TestCaptureNeverFoundIsLost(t *testing.T) {
	r := newRig(t)
	r.chain.setHead(5000)
	ref := strings.Repeat("ab", 32)
	_, err := r.cap.Track(t.Context(), ref, hashA, false)
	require.NoError(t, err)
	r.cap.Pass(t.Context())
	r.chain.setHead(6000)
	r.cap.Pass(t.Context())
	lost, err := r.store.Lost(t.Context(), ref)
	require.NoError(t, err)
	assert.True(t, lost)
	assert.Zero(t, r.cap.Overdue())
}

// One pending file that does not decode is quarantined and reported once; it
// blocks neither new tracking nor the other captures.
func TestCorruptPendingFileIsQuarantined(t *testing.T) {
	dir := t.TempDir()
	st, err := execcapture.OpenDir(dir)
	require.NoError(t, err)
	bad := strings.Repeat("cd", 32)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "pending", bad+".json"), []byte("{not json"), 0o600))

	r := newRig(t)
	r.store = st
	c, err := execcapture.New(r.cap.Config(), r.chain, st, slog.New(slog.NewTextHandler(&syncWriter{w: r.logs}, nil)))
	require.NoError(t, err)
	r.cap = c

	refs := r.chain.block(40, 1, func(int) uint32 { return 0 })
	r.chain.setHead(41)
	added, err := r.cap.Track(t.Context(), refs[0], hashA, false)
	require.NoError(t, err)
	assert.True(t, added)
	_, err = os.Stat(filepath.Join(dir, "quarantine", bad+".json"))
	require.NoError(t, err, "the bad file is moved aside")
	_, err = r.cap.Track(t.Context(), strings.Repeat("ef", 32), hashA, false)
	require.NoError(t, err)
	assert.Equal(t, 1, strings.Count(r.logs.String(), "moved to quarantine"), "reported once")

	r.cap.Pass(t.Context())
	r.cap.Pass(t.Context())
	done, err := st.Captured(t.Context(), refs[0])
	require.NoError(t, err)
	assert.True(t, done)
	pend, err := st.ListPending(t.Context())
	require.NoError(t, err)
	require.Len(t, pend, 1, "only the reference not on the chain yet")
	assert.Equal(t, strings.Repeat("ef", 32), pend[0].RailRef)
}
