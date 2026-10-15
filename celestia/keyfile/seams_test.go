package keyfile

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func replace[T any](t *testing.T, p *T, v T) {
	t.Helper()
	old := *p
	t.Cleanup(func() { *p = old })
	*p = v
}

func TestWriteNewKeepsTheTargetOnceLinked(t *testing.T) {
	data := []byte("0123456789abcdef0123456789abcdef")
	cases := map[string]struct {
		remove func(string) error
		sync   func(string) error
		wantOK bool
	}{
		// Another run removed the temporary file between the link and the
		// unlink: the key is in place, so that is success.
		"temp already gone": {
			remove: func(p string) error {
				_ = os.Remove(p)
				return &fs.PathError{Op: "remove", Path: p, Err: fs.ErrNotExist}
			},
			sync: SyncDir, wantOK: true,
		},
		"temp removal fails": {
			remove: func(string) error { return syscall.EIO },
			sync:   SyncDir,
		},
		"directory sync fails": {
			remove: os.Remove,
			sync:   func(string) error { return syscall.EIO },
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			replace(t, &removeFile, tc.remove)
			replace(t, &syncDir, tc.sync)
			path := filepath.Join(t.TempDir(), "k")
			err := WriteNew(path, data)
			if tc.wantOK {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.NotErrorIs(t, err, ErrExists)
			}
			got, rerr := os.ReadFile(path)
			require.NoError(t, rerr, "a linked key is never removed")
			assert.Equal(t, data, got)
		})
	}
}

func TestMkdirSyncSyncsTheParentOfEachNewDirectory(t *testing.T) {
	root := t.TempDir()
	var synced []string
	replace(t, &syncDir, func(d string) error { synced = append(synced, d); return SyncDir(d) })

	target := filepath.Join(root, "a", "b", "c")
	require.NoError(t, MkdirSync(target))
	assert.Equal(t, []string{root, filepath.Join(root, "a"), filepath.Join(root, "a", "b")}, synced)
	for _, d := range []string{"a", "a/b", "a/b/c"} {
		fi, err := os.Stat(filepath.Join(root, d))
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0o700), fi.Mode().Perm(), d)
	}

	synced = nil
	require.NoError(t, MkdirSync(target))
	assert.Empty(t, synced, "an existing directory needs no sync")
}

func TestMkdirSyncReportsAFailedSync(t *testing.T) {
	replace(t, &syncDir, func(string) error { return syscall.EIO })
	err := MkdirSync(filepath.Join(t.TempDir(), "new"))
	require.ErrorIs(t, err, syscall.EIO)
}

func TestMkdirSyncRefusesAFileOnThePath(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "f"), nil, 0o600))
	err := MkdirSync(filepath.Join(root, "f", "d"))
	require.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "not a directory"), err.Error())
}

func TestWriteNewSyncsTheNewKeysDirectoryIntoItsParent(t *testing.T) {
	home := t.TempDir()
	var synced []string
	replace(t, &syncDir, func(d string) error { synced = append(synced, d); return SyncDir(d) })
	require.NoError(t, WriteNew(filepath.Join(home, "keys", "k"), []byte("x")))
	assert.Contains(t, synced, home, "the keys entry in the home")
	assert.Contains(t, synced, filepath.Join(home, "keys"), "the key entry in keys")
}
