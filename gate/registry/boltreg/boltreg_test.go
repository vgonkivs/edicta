package boltreg_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/gate/registry"
	"github.com/vgonkivs/edicta/gate/registry/boltreg"
	"github.com/vgonkivs/edicta/gate/registry/regtest"
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
	return registry.Entry{Key: k, CommitmentHash: commitment.Hash{i}, ActionHash: commitment.Hash{i, 2},
		Path: registry.PathArchive, AuthorizedAt: 5000, ValidUntil: 6000, Authorization: []byte{0xa2, i}}
}

func TestDurableWrites(t *testing.T) {
	r, err := boltreg.Open(filepath.Join(t.TempDir(), "n.db"), 100)
	require.NoError(t, err)
	defer r.Close()
	require.False(t, r.NoSync(), "NoSync is set: a Consume could be lost on a crash")
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
// entries, the receipt and the epoch persist, and a reopen never rewrites the
// epoch even when it is given a later time.
func TestReopenKeepsEverything(t *testing.T) {
	path := filepath.Join(t.TempDir(), "n.db")
	r, err := boltreg.Open(path, 100)
	require.NoError(t, err)
	e := entry(1)
	require.NoError(t, r.Consume(ctx, e, regtest.Tolerance))
	require.NoError(t, r.AttachReceipt(ctx, e.Key, e.CommitmentHash, []byte("receipt")))
	e2 := entry(2)
	require.NoError(t, r.Consume(ctx, e2, regtest.Tolerance))
	want1, _ := r.Get(ctx, e.Key)
	want2, _ := r.Get(ctx, e2.Key)
	require.NoError(t, r.Close())

	r, err = boltreg.Open(path, 99999)
	require.NoError(t, err)
	defer r.Close()
	m, err := r.Meta(ctx)
	require.NoError(t, err)
	require.Equal(t, registry.Meta{Epoch: 100, Watermark: 5000}, m)
	got1, err := r.Get(ctx, e.Key)
	require.NoError(t, err)
	require.Equal(t, want1, got1)
	require.Equal(t, []byte("receipt"), got1.Receipt)
	got2, err := r.Get(ctx, e2.Key)
	require.NoError(t, err)
	require.Equal(t, want2, got2)
	require.ErrorIs(t, r.Consume(ctx, e, regtest.Tolerance), registry.ErrExists, "consume after reopen")
	require.ErrorIs(t, r.AttachReceipt(ctx, e.Key, e.CommitmentHash, []byte("again")), registry.ErrStateConflict)
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
	require.NoError(t, r.Consume(ctx, e, regtest.Tolerance))
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
	require.ErrorIs(t, r.Consume(ctx, old, regtest.Tolerance), registry.ErrPrunedWindow)
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
					err = r.Consume(ctx, entry(1), regtest.Tolerance)
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

// A file written by the earlier gate (no schema version, entries with a state
// machine) must be refused, never read as an empty or valid registry.
func TestOldSchemaFileIsRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "n.db")
	r, err := boltreg.Open(path, 100)
	require.NoError(t, err)
	require.NoError(t, r.DeleteMetaRaw("schema_version"))
	require.NoError(t, r.Close())

	r, err = boltreg.Open(path, 100)
	if err == nil {
		defer r.Close()
		err = r.Consume(ctx, entry(1), regtest.Tolerance)
	}
	require.ErrorIs(t, err, registry.ErrCorruptMeta)
}

func TestUnknownSchemaVersionIsRefused(t *testing.T) {
	for name, val := range map[string][]byte{
		"empty": {}, "one byte": {0xff}, "nine bytes": make([]byte, 9),
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "n.db")
			r, err := boltreg.Open(path, 100)
			require.NoError(t, err)
			require.NoError(t, r.SetMetaRaw("schema_version", val))
			require.NoError(t, r.Close())
			r, err = boltreg.Open(path, 100)
			if err == nil {
				defer r.Close()
				err = r.Consume(ctx, entry(1), regtest.Tolerance)
			}
			require.ErrorIs(t, err, registry.ErrCorruptMeta)
		})
	}
}
