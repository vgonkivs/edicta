//go:build darwin || linux

package keyfile

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResolveDirRefusesADirectoryOfAnotherUser(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root may use any directory")
	}
	home := filepath.Join(t.TempDir(), "home")
	require.NoError(t, os.Mkdir(home, 0o700))
	// Seen as another user, the test's own directories above the home
	// belong to someone else; the root-owned ones stay acceptable.
	replace(t, &geteuid, func() int { return os.Geteuid() + 1 })
	_, err := ResolveDir(home)
	require.ErrorIs(t, err, ErrUnsafeDir)
	assert.Contains(t, err.Error(), "neither root nor you")
}
