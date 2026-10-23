package initcmd

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Another run that finished its keyring first owns the name: the loser
// reports the winner's keyring as existing instead of failing.
func TestKeyringRenameLostToAnotherRun(t *testing.T) {
	home := t.TempDir()
	old := renameDir
	t.Cleanup(func() { renameDir = old })
	var winner string
	renameDir = func(from, to string) error {
		require.NoError(t, os.Rename(from, to))
		winner = to
		return &os.LinkError{Op: "rename", Old: from, New: to, Err: syscall.ENOTEMPTY}
	}
	a, err := ensureAccount(home, "recorder")
	require.NoError(t, err)
	assert.Equal(t, Exists, a.Status)
	assert.Equal(t, filepath.Join(home, "keyring-recorder"), winner)
	assert.Contains(t, a.Address, "celestia1")
}

func TestKeyringRenameFailureWithoutAWinnerIsAnError(t *testing.T) {
	home := t.TempDir()
	old := renameDir
	t.Cleanup(func() { renameDir = old })
	renameDir = func(string, string) error { return syscall.EXDEV }
	_, err := ensureAccount(home, "recorder")
	require.ErrorIs(t, err, syscall.EXDEV)
	assert.NoDirExists(t, filepath.Join(home, "keyring-recorder"))
}
