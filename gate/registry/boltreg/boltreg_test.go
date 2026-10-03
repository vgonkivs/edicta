package boltreg_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/prior/commitment"
	"github.com/vgonkivs/prior/gate/registry"
	"github.com/vgonkivs/prior/gate/registry/boltreg"
	"github.com/vgonkivs/prior/gate/registry/regtest"
)

var ctx = context.Background()

func TestConformance(t *testing.T) {
	regtest.Run(t, func(t *testing.T, epoch uint64) registry.Registry {
		r, err := boltreg.Open(filepath.Join(t.TempDir(), "nonces.db"), epoch)
		require.NoError(t, err)
		t.Cleanup(func() { _ = r.Close() })
		return r
	})
}

func entry(i byte) registry.Entry {
	var k registry.Key
	k.PubKey[0], k.Nonce[0] = i, i
	return registry.Entry{Key: k, CommitmentHash: commitment.Hash{i}, State: registry.StateReserved,
		Path: registry.PathArchive, ReservedAt: 5000, ValidUntil: 6000}
}

func TestDurableWrites(t *testing.T) {
	r, err := boltreg.Open(filepath.Join(t.TempDir(), "n.db"), 100)
	require.NoError(t, err)
	defer r.Close()
	require.False(t, r.NoSync(), "NoSync is set: a Reserve could be lost on a crash")
}

func TestSecondOpenFailsWhileLocked(t *testing.T) {
	path := filepath.Join(t.TempDir(), "n.db")
	r, err := boltreg.Open(path, 100)
	require.NoError(t, err)
	if r2, err := boltreg.Open(path, 100); err == nil {
		_ = r2.Close()
		require.FailNow(t, "a second process-level open of the same file succeeded")
	}
	err = r.Close()
	require.NoError(t, err)
	r3, err := boltreg.Open(path, 100)
	require.NoError(t, err, "reopen after Close")
	_ = r3.Close()
}

// TestReopenKeepsEverything simulates a crash by closing and reopening: the
// entry, the history and the epoch persist, and a reopen never rewrites the
// epoch even when it is given a later time.
func TestReopenKeepsEverything(t *testing.T) {
	path := filepath.Join(t.TempDir(), "n.db")
	r, err := boltreg.Open(path, 100)
	require.NoError(t, err)
	e := entry(1)
	err = r.Reserve(ctx, e, regtest.Tolerance)
	require.NoError(t, err)
	u := e
	u.State = registry.StateUnknown
	u.History = []registry.Resolution{{Source: registry.SourceRail, By: "gate", At: 5100, PrevState: registry.StateReserved}}
	err = r.Resolve(ctx, e.Key, registry.StateReserved, u)
	require.NoError(t, err)
	e2 := entry(2)
	err = r.Reserve(ctx, e2, regtest.Tolerance)
	require.NoError(t, err)
	want1, _ := r.Get(ctx, e.Key)
	want2, _ := r.Get(ctx, e2.Key)
	err = r.Close()
	require.NoError(t, err)

	r, err = boltreg.Open(path, 99999)
	require.NoError(t, err)
	defer r.Close()
	m, err := r.Meta(ctx)
	require.NoErrorf(t, err, "meta %+v", m)
	require.EqualValuesf(t, 100, m.Epoch, "meta %+v %v", m, err)
	require.EqualValuesf(t, 5000, m.Watermark, "meta %+v %v", m, err)
	got1, err := r.Get(ctx, e.Key)
	require.NoErrorf(t, err, "entry 1 after reopen: %+v", got1)
	require.Equalf(t, want1, got1, "entry 1 after reopen: %+v %v", got1, err)
	got2, err := r.Get(ctx, e2.Key)
	require.NoErrorf(t, err, "entry 2 after reopen: %+v", got2)
	require.Equalf(t, want2, got2, "entry 2 after reopen: %+v %v", got2, err)
	err = r.Reserve(ctx, e, regtest.Tolerance)
	require.ErrorIs(t, err, registry.ErrExists, "reserve after reopen")
	n, err := r.Recover(ctx, 7000)
	require.NoErrorf(t, err, "Recover = %d", n)
	require.EqualValuesf(t, 1, n, "Recover = %d, %v", n, err)
}

func TestOpenRejectsGarbageFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "n.db")
	err := writeFile(path, []byte("not a bbolt file, but long enough to be read as a page header.........."))
	require.NoError(t, err)
	if r, err := boltreg.Open(path, 100); err == nil {
		_ = r.Close()
		require.FailNow(t, "opened a garbage file")
	}
}

func TestPruneCutoffSurvivesReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "n.db")
	r, err := boltreg.Open(path, 100)
	require.NoError(t, err)
	e := entry(1)
	e.ValidUntil = 400
	require.NoError(t, r.Reserve(ctx, e, regtest.Tolerance))
	u := e
	u.State = registry.StateExecuted
	u.Receipt = []byte("r")
	u.History = []registry.Resolution{{Source: registry.SourceRail, By: "gate", At: 5100, PrevState: registry.StateReserved}}
	require.NoError(t, r.Resolve(ctx, e.Key, registry.StateReserved, u))
	n, err := r.Prune(ctx, 500)
	require.NoError(t, err)
	require.Equal(t, 1, n)
	require.NoError(t, r.Close())

	r, err = boltreg.Open(path, 99999)
	require.NoError(t, err)
	defer r.Close()
	m, err := r.Meta(ctx)
	require.NoError(t, err)
	require.EqualValues(t, 500, m.PruneCutoff)
	old := entry(2)
	old.ValidUntil = 499
	require.ErrorIs(t, r.Reserve(ctx, old, regtest.Tolerance), registry.ErrPrunedWindow)
	_, err = r.Get(ctx, old.Key)
	require.ErrorIs(t, err, registry.ErrNotFound)
}

// A damaged meta value must never read as zero: a zero prune cutoff would
// allow reserving inside the pruned window again, a zero watermark would
// disable the clock check, and a zero epoch the registry-age check.
func TestCorruptMetaIsRefused(t *testing.T) {
	for _, key := range []string{"epoch", "watermark", "prune_cutoff"} {
		for name, val := range map[string][]byte{
			"empty":    {},
			"1 byte":   {1},
			"7 bytes":  make([]byte, 7),
			"9 bytes":  make([]byte, 9),
			"32 bytes": make([]byte, 32),
		} {
			t.Run(key+"/"+name, func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "n.db")
				r, err := boltreg.Open(path, 100)
				require.NoError(t, err)
				require.NoError(t, r.SetMetaRaw(key, val))
				require.NoError(t, r.Close())

				r, err = boltreg.Open(path, 100)
				if err == nil {
					defer r.Close()
					err = r.Reserve(ctx, entry(1), regtest.Tolerance)
				}
				require.ErrorIs(t, err, registry.ErrCorruptMeta)
				if r != nil {
					_, gerr := r.Get(ctx, entry(1).Key)
					require.ErrorIs(t, gerr, registry.ErrNotFound, "a refused reservation must not write")
				}
			})
		}
	}
}
