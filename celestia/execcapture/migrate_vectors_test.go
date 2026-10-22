package execcapture_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/celestia/execcapture"
	"github.com/vgonkivs/edicta/engine/archive"
	"github.com/vgonkivs/edicta/engine/archive/fsarchive"
	"github.com/vgonkivs/edicta/test/execresultfix"
)

// migrationRig is a capture store holding one block file and an archive
// that may already hold records.
type migrationRig struct {
	dir   string
	arch  *fsarchive.Store
	store *execcapture.Dir
	cap   *execcapture.Capturer
	logs  *bytes.Buffer
	block execcapture.Block
}

func newMigrationRig(t *testing.T, m execresultfix.Migration) *migrationRig {
	t.Helper()
	r := &migrationRig{dir: t.TempDir(), logs: &bytes.Buffer{}}
	var err error
	r.arch, err = fsarchive.Open(r.dir, nil)
	require.NoError(t, err)
	for path, raw := range m.Stored {
		p := filepath.Join(r.dir, filepath.FromSlash(path))
		require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o755))
		require.NoError(t, os.WriteFile(p, execresultfix.Hex(t, raw), 0o644))
	}
	require.NoError(t, json.Unmarshal(m.Capture, &r.block))
	r.store, err = execcapture.OpenDir(t.TempDir())
	require.NoError(t, err)
	require.NoError(t, r.store.PutBlock(context.Background(), r.block))
	r.cap, err = execcapture.New(execcapture.Config{ChainID: r.block.ChainID, PruneWindowBlocks: 1000}, newFakeChain(), r.store,
		slog.New(slog.NewTextHandler(&syncWriter{w: r.logs}, nil)), execcapture.WithArchive(r.arch))
	require.NoError(t, err)
	return r
}

func (r *migrationRig) stored(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(r.dir, filepath.FromSlash(path)))
	if os.IsNotExist(err) {
		return nil
	}
	require.NoError(t, err)
	return b
}

func (r *migrationRig) inBlockFile(t *testing.T, railRef string) bool {
	t.Helper()
	b, err := r.store.Block(context.Background(), r.block.ChainID, r.block.Height)
	if err != nil {
		require.ErrorIs(t, err, os.ErrNotExist)
		return false
	}
	return slices.ContainsFunc(b.Txs, func(x execcapture.Tx) bool { return x.RailRef == railRef })
}

func TestMigrationVectors(t *testing.T) {
	f := execresultfix.Load(t)
	require.NotEmpty(t, f.Migration)
	for _, m := range f.Migration {
		t.Run(m.ID, func(t *testing.T) {
			r := newMigrationRig(t, m)
			before := map[string][]byte{}
			for path := range m.Stored {
				before[path] = r.stored(t, path)
			}
			got := r.cap.Migrate(context.Background())
			require.Len(t, got, len(m.Expect))
			kept := 0
			for i, want := range m.Expect {
				g := got[i]
				require.Equal(t, want.RailRef, g.RailRef)
				assert.Equal(t, want.Result, g.Result, "%v", g.Err)
				if want.Rule != "" {
					assert.Equal(t, want.Rule, g.Rule, "%v", g.Err)
				}
				if want.Result == execcapture.MigrationAlreadyStored {
					assert.Equal(t, want.Equivalence, g.Equivalence)
				}
				if want.Path != "" {
					assert.Equal(t, want.Path, g.Path)
				}
				if want.CBORHex != "" {
					assert.Equal(t, want.CBORHex, hex.EncodeToString(g.Record), "the record built from the capture")
				}

				captured, err := r.store.Captured(context.Background(), want.RailRef)
				require.NoError(t, err)
				assert.True(t, captured, "a reference stays captured, here or in the archive")
				switch want.Result {
				case execcapture.MigrationWritten:
					assert.Equal(t, want.CBORHex, hex.EncodeToString(r.stored(t, want.Path)))
					assert.False(t, r.inBlockFile(t, want.RailRef), "dropped once archived")
				case execcapture.MigrationAlreadyStored:
					assert.Equal(t, before[want.Path], r.stored(t, want.Path), "the first write stays")
					assert.False(t, r.inBlockFile(t, want.RailRef), "dropped once an equivalent record is archived")
				case execcapture.MigrationKept:
					kept++
					assert.Equal(t, before[want.Path], r.stored(t, want.Path), "the squatted record stays")
					assert.True(t, r.inBlockFile(t, want.RailRef), "the capture stays the gate's copy")
					assert.Contains(t, r.logs.String(), "level=ERROR")
					assert.Contains(t, r.logs.String(), want.Path)
				case execcapture.MigrationRefused:
					assert.True(t, r.inBlockFile(t, want.RailRef), "a refused capture stays")
					p, err := archive.ExecResultPath(r.block.ChainID, execresultfix.Hex(t, want.RailRef))
					require.NoError(t, err)
					assert.Nil(t, r.stored(t, p), "nothing broken reaches the archive")
				default:
					t.Fatalf("unknown result %s", want.Result)
				}
			}
			assert.EqualValues(t, kept, r.cap.Conflicts())

			// A later run changes nothing, and reports the conflict again.
			again := r.cap.Migrate(context.Background())
			for _, g := range again {
				want := m.Expect[slices.IndexFunc(m.Expect, func(e execresultfix.MigrationExpect) bool { return e.RailRef == g.RailRef })]
				require.Contains(t, []string{execcapture.MigrationKept, execcapture.MigrationRefused}, want.Result, g.RailRef)
				assert.Equal(t, want.Result, g.Result)
			}
			assert.EqualValues(t, kept, r.cap.Conflicts())
		})
	}
}
