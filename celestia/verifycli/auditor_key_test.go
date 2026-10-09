package verifycli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/celestia/secret"
)

func TestAuditorKeyFlag(t *testing.T) {
	dir := t.TempDir()
	keyHex := strings.Repeat("07", 32)
	good := filepath.Join(dir, "auditor.key")
	require.NoError(t, os.WriteFile(good, []byte(keyHex+"\n"), 0o600))
	open := filepath.Join(dir, "open.key")
	require.NoError(t, os.WriteFile(open, []byte(keyHex), 0o644))
	short := filepath.Join(dir, "short.key")
	require.NoError(t, os.WriteFile(short, []byte("0707"), 0o600))

	base := []string{"verify", strings.Repeat("ab", 32), "--gate-key", strings.Repeat("cd", 32), "--archive", dir}
	var out bytes.Buffer
	f, err := parseFlags(append(base[:len(base):len(base)], "--auditor-key", good, "--auditor-key", good), &out)
	require.NoError(t, err)
	assert.Equal(t, []string{good, good}, f.auditorKeys)

	k, err := loadAuditorKey(good)
	require.NoError(t, err)
	require.NotNil(t, k.PublicKey())
	assert.NotContains(t, k.String(), keyHex, "a key never prints")

	_, err = loadAuditorKey(open)
	require.ErrorIs(t, err, secret.ErrPermissions)
	_, err = loadAuditorKey(short)
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "0707", "an error never shows key bytes")
}
