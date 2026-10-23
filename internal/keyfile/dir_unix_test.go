//go:build darwin || linux

package keyfile_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/internal/keyfile"
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

// realDir is dir with its symlinks resolved, as ResolveDir returns it.
func realDir(t *testing.T, dir string) string {
	t.Helper()
	r, err := filepath.EvalSymlinks(dir)
	require.NoError(t, err)
	return r
}

func TestResolveDirReturnsThePathWithoutSymlinks(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home")
	require.NoError(t, os.Mkdir(home, 0o700))
	got, err := keyfile.ResolveDir(home)
	require.NoError(t, err)
	assert.Equal(t, realDir(t, home), got)

	abs := filepath.Join(root, "abs")
	require.NoError(t, os.Symlink(home, abs))
	got, err = keyfile.ResolveDir(abs)
	require.NoError(t, err)
	assert.Equal(t, realDir(t, home), got)

	sub := filepath.Join(root, "sub")
	require.NoError(t, os.Mkdir(sub, 0o700))
	rel := filepath.Join(sub, "rel")
	require.NoError(t, os.Symlink("../home", rel))
	chain := filepath.Join(root, "chain")
	require.NoError(t, os.Symlink(rel, chain))
	got, err = keyfile.ResolveDir(chain + "/./")
	require.NoError(t, err)
	assert.Equal(t, realDir(t, home), got)
}

func TestResolveDirRefusesAWritableDirectoryAbove(t *testing.T) {
	root := t.TempDir()
	shared := filepath.Join(root, "shared")
	require.NoError(t, os.Mkdir(shared, 0o700))
	home := filepath.Join(shared, "home")
	require.NoError(t, os.Mkdir(home, 0o700))

	require.NoError(t, os.Chmod(shared, 0o777))
	_, err := keyfile.ResolveDir(home)
	require.ErrorIs(t, err, keyfile.ErrUnsafeDir)
	assert.Contains(t, err.Error(), "not sticky")

	require.NoError(t, os.Chmod(shared, 0o770))
	_, err = keyfile.ResolveDir(home)
	require.ErrorIs(t, err, keyfile.ErrUnsafeDir, "group-writable counts too")

	// Others cannot move what they do not own out of a sticky directory.
	require.NoError(t, os.Chmod(shared, 0o777|os.ModeSticky))
	got, err := keyfile.ResolveDir(home)
	require.NoError(t, err)
	assert.Equal(t, realDir(t, home), got)
}

func TestResolveDirChecksTheDirectoryOfEachSymlink(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home")
	require.NoError(t, os.Mkdir(home, 0o700))
	shared := filepath.Join(root, "shared")
	require.NoError(t, os.Mkdir(shared, 0o700))
	link := filepath.Join(shared, "edicta")
	require.NoError(t, os.Symlink(home, link))
	require.NoError(t, os.Chmod(shared, 0o777))

	// The target is safe, but anyone can replace the link.
	_, err := keyfile.ResolveDir(link)
	require.ErrorIs(t, err, keyfile.ErrUnsafeDir)
	assert.Contains(t, err.Error(), shared)
}

func TestResolveDirChecksTheTargetItself(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home")
	require.NoError(t, os.Mkdir(home, 0o700))
	require.NoError(t, os.Chmod(home, 0o777|os.ModeSticky))
	_, err := keyfile.ResolveDir(home)
	require.ErrorIs(t, err, keyfile.ErrUnsafeDir, "sticky is enough above the home, not for the home")

	file := filepath.Join(root, "file")
	require.NoError(t, os.WriteFile(file, nil, 0o600))
	_, err = keyfile.ResolveDir(filepath.Join(file, "home"))
	require.ErrorIs(t, err, keyfile.ErrUnsafeDir)
}

func TestResolveDirErrors(t *testing.T) {
	root := t.TempDir()
	_, err := keyfile.ResolveDir("relative/home")
	require.Error(t, err)

	_, err = keyfile.ResolveDir(filepath.Join(root, "missing"))
	require.ErrorIs(t, err, os.ErrNotExist)

	a, b := filepath.Join(root, "a"), filepath.Join(root, "b")
	require.NoError(t, os.Symlink(b, a))
	require.NoError(t, os.Symlink(a, b))
	_, err = keyfile.ResolveDir(a)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "too many symlinks")
}
