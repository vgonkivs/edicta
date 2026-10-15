package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/celestia/edictad"
)

func edictaTOML(t *testing.T, dir string) []byte {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	return []byte(fmt.Sprintf(`
[network]
celestia = "mocha"

[agent]
id = "a"
key_file = %[1]q

[gate]
gate_id = "g"
key_file = %[2]q
registry_path = %[3]q
allowlist_file = %[4]q
action_types = ["application/x402+json"]
executor_keys = [%[5]q]

[archive]
dir = %[6]q
`, dir+"/agent.key", dir+"/gate.key", dir+"/registry", dir+"/allow.toml", hex.EncodeToString(pub), dir+"/archive"))
}

func TestLoadConfigReadsEdictaToml(t *testing.T) {
	cfg, err := loadConfig(edictaTOML(t, t.TempDir()))
	require.NoError(t, err)
	assert.Equal(t, "g", cfg.Gate.GateID)
	assert.False(t, cfg.Recorder.Enabled)
}

func TestLoadConfigRefusesFastMode(t *testing.T) {
	data := strings.Replace(string(edictaTOML(t, t.TempDir())), "[archive]", "[archive]\n", 1)
	data = strings.Replace(data, "action_types", "fast_mode = true\naction_types", 1)
	_, err := loadConfig([]byte(data))
	require.ErrorIs(t, err, edictad.ErrNotAvailable)
}

func TestLoadConfigKeepsTheLegacyPath(t *testing.T) {
	legacy := []byte(`
[network]
da = "celestia_blob"
[archive]
dir = "/tmp/a"
[gate]
gate_id = "g"
key_file = "/k"
registry_path = "/r"
allowlist_file = "/l"
action_types = ["application/x402+json"]
executor_keys = ["` + strings.Repeat("00", 32) + `"]
anchor_verifier = "self"
[http]
listen = "127.0.0.1:8080"
`)
	want, wantErr := edictad.ParseConfig(legacy)
	got, err := loadConfig(legacy)
	assert.Equal(t, wantErr, err)
	assert.Equal(t, want, got)
}
