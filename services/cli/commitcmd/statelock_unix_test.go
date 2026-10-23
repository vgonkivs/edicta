// SPDX-License-Identifier: Apache-2.0

//go:build unix

package commitcmd_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/services/cli/commitcmd"
)

// lockChildEnv names the state directory a child copy of the test binary
// tries to lock.
const lockChildEnv = "EDICTA_TEST_STATE_LOCK_DIR"

func TestMain(m *testing.M) {
	if dir := os.Getenv(lockChildEnv); dir != "" {
		unlock, err := commitcmd.LockStateDir(dir)
		if err != nil {
			os.Stdout.WriteString(err.Error())
			os.Exit(3)
		}
		unlock()
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func lockInChild(t *testing.T, dir string) (string, int) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(), lockChildEnv+"="+dir)
	out, err := cmd.Output()
	if err != nil {
		var ee *exec.ExitError
		require.ErrorAs(t, err, &ee)
		return string(out), ee.ExitCode()
	}
	return string(out), 0
}

func TestLockStateDirRefusesASecondProcess(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	unlock, err := commitcmd.LockStateDir(dir)
	require.NoError(t, err)

	out, code := lockInChild(t, dir)
	assert.Equal(t, 3, code, "a second process on the same state directory must not start")
	assert.Contains(t, out, "held by another process")

	unlock()
	out, code = lockInChild(t, dir)
	assert.Equal(t, 0, code, "the directory is free once the holder lets go: %s", out)
}

func TestLockStateDirRefusesASecondHolderInProcess(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	unlock, err := commitcmd.LockStateDir(dir)
	require.NoError(t, err)
	_, err = commitcmd.LockStateDir(dir)
	require.ErrorIs(t, err, commitcmd.ErrStateDirInUse)
	unlock()
	again, err := commitcmd.LockStateDir(dir)
	require.NoError(t, err)
	again()
}

func TestLockStateDirKeepsTheStoreRules(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	unlock, err := commitcmd.LockStateDir(dir)
	require.NoError(t, err)
	defer unlock()
	info, err := os.Stat(dir)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o700), info.Mode().Perm(), "the directory is created as the store creates it")

	st, err := commitcmd.NewFileStateStore(dir)
	require.NoError(t, err)
	_, ok, err := st.Load(strings.Repeat("ab", 32))
	require.NoError(t, err)
	assert.False(t, ok, "the lock file is never read as a run")

	open := filepath.Join(t.TempDir(), "open")
	require.NoError(t, os.Mkdir(open, 0o755))
	require.NoError(t, os.Chmod(open, 0o755))
	_, err = commitcmd.LockStateDir(open)
	require.Error(t, err, "a directory others can read is refused before any lock")
	assert.NotErrorIs(t, err, commitcmd.ErrStateDirInUse)
	_, err = os.Stat(filepath.Join(open, commitcmd.StateLockFile))
	assert.ErrorIs(t, err, os.ErrNotExist)
}

func TestLockStateDirRefusesASymlinkedLockFile(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	require.NoError(t, os.Mkdir(dir, 0o700))
	require.NoError(t, os.Symlink(filepath.Join(t.TempDir(), "elsewhere"), filepath.Join(dir, commitcmd.StateLockFile)))
	_, err := commitcmd.LockStateDir(dir)
	require.Error(t, err)
	assert.NotErrorIs(t, err, commitcmd.ErrStateDirInUse)
}
