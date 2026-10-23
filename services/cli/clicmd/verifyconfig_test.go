package clicmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/config"
)

const verifyCfg = `
[network]
celestia = "mocha"

[agent]
id = "a"
key_file = "/k/agent"

[gate]
gate_id = "g"
key_file = "/k/gate"
registry_path = "/r"
allowlist_file = "/l"
action_types = ["application/x402+json"]
executor_keys = ["%s"]

[archive]
dir = "/archive"

[verify]
headers_rpc = "https://h.example.org"
checkpoint_rpc = ["https://c.example.org"]
tx_rpc = "https://tx.example.org"
exclude_host = ["gate.example.org"]
`

func writeVerifyCfg(t *testing.T) string {
	t.Helper()
	key := "0100000000000000000000000000000000000000000000000000000000000000"
	p := filepath.Join(t.TempDir(), config.FileName)
	require.NoError(t, os.WriteFile(p, []byte(fmt.Sprintf(verifyCfg, key)), 0o600))
	return p
}

func TestVerifyDefaultsReadTheConfig(t *testing.T) {
	d, err := verifyDefaults(writeVerifyCfg(t))
	require.NoError(t, err)
	assert.Equal(t, "/archive", d.ArchiveDir)
	assert.Equal(t, "https://h.example.org", d.HeadersRPC)
	assert.Equal(t, []string{"https://c.example.org"}, d.CheckpointRPC)
	assert.Equal(t, []string{"https://tx.example.org"}, d.TxRPC)
	assert.Equal(t, []string{"gate.example.org"}, d.ExcludeHosts)
	assert.Equal(t, 1, d.Quorum)
}

func TestVerifyDefaultsMissingDefaultFileIsSkipped(t *testing.T) {
	t.Setenv(config.EnvHome, t.TempDir())
	d, err := verifyDefaults("")
	require.NoError(t, err)
	assert.Empty(t, d.ArchiveDir)
}

func TestVerifyDefaultsMissingExplicitFileIsAnError(t *testing.T) {
	_, err := verifyDefaults(filepath.Join(t.TempDir(), "nope.toml"))
	require.Error(t, err)
}

func TestVerifyDefaultsReadTheHomeConfig(t *testing.T) {
	p := writeVerifyCfg(t)
	t.Setenv(config.EnvHome, filepath.Dir(p))
	d, err := verifyDefaults("")
	require.NoError(t, err)
	assert.Equal(t, "/archive", d.ArchiveDir)
}

func TestVerifyConfigFlagReachesTheCommand(t *testing.T) {
	code, out := edicta(t, "verify", strings.Repeat("00", 32), "--config", filepath.Join(t.TempDir(), "nope.toml"))
	assert.Equal(t, exitUsage, code)
	assert.Contains(t, out, "nope.toml")
}
