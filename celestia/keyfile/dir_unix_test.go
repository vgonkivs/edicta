//go:build darwin || linux

package keyfile_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/celestia/keyfile"
)

func TestCheckDir(t *testing.T) {
	root := t.TempDir()
	good := filepath.Join(root, "good")
	require.NoError(t, os.Mkdir(good, 0o700))
	require.NoError(t, keyfile.CheckDir(good))

	readable := filepath.Join(root, "readable")
	require.NoError(t, os.Mkdir(readable, 0o755))
	require.NoError(t, keyfile.CheckDir(readable), "others may read the names, not change them")

	for _, mode := range []os.FileMode{0o770, 0o707, 0o777, 0o720} {
		d := filepath.Join(root, mode.String())
		require.NoError(t, os.Mkdir(d, 0o700))
		require.NoError(t, os.Chmod(d, mode))
		err := keyfile.CheckDir(d)
		require.ErrorIs(t, err, keyfile.ErrUnsafeDir, mode)
		assert.Contains(t, err.Error(), "chmod 700 "+d)
	}

	link := filepath.Join(root, "link")
	require.NoError(t, os.Symlink(good, link))
	require.ErrorIs(t, keyfile.CheckDir(link), keyfile.ErrUnsafeDir)

	file := filepath.Join(root, "file")
	require.NoError(t, os.WriteFile(file, nil, 0o600))
	require.ErrorIs(t, keyfile.CheckDir(file), keyfile.ErrUnsafeDir)

	require.Error(t, keyfile.CheckDir(filepath.Join(root, "missing")))
}

func TestCheckDirRefusesAnotherUsersDirectory(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root owns the probe directory")
	}
	// The root directory belongs to root and is not writable by others.
	err := keyfile.CheckDir("/")
	require.ErrorIs(t, err, keyfile.ErrUnsafeDir)
	assert.Contains(t, err.Error(), "not by you")
}

func TestLockDirIsExclusive(t *testing.T) {
	dir := t.TempDir()
	unlock, err := keyfile.LockDir(dir, ".lock")
	require.NoError(t, err)

	_, err = keyfile.LockDir(dir, ".lock")
	require.ErrorIs(t, err, keyfile.ErrLocked)

	unlock()
	unlock2, err := keyfile.LockDir(dir, ".lock")
	require.NoError(t, err)
	unlock2()

	fi, err := os.Stat(filepath.Join(dir, ".lock"))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), fi.Mode().Perm())
}

func TestLockDirDoesNotFollowASymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "elsewhere")
	require.NoError(t, os.Symlink(target, filepath.Join(dir, ".lock")))
	_, err := keyfile.LockDir(dir, ".lock")
	require.Error(t, err)
	assert.NoFileExists(t, target)
}
