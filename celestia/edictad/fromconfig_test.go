package edictad_test

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/celestia/config"
	"github.com/vgonkivs/edicta/celestia/edictad"
	"github.com/vgonkivs/edicta/examples/tia-transfer/bankaction"
)

// starterTOML has the shape `edicta init` writes for the Mocha preset.
func starterTOML(t *testing.T, home string, extra string) []byte {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	p := func(name string) string { return filepath.Join(home, name) }
	return []byte(fmt.Sprintf(`
[network]
celestia = "mocha"
settlement = "base-sepolia"

[agent]
id = "agent-1"
key_file = %q
gate_url = "http://127.0.0.1:8080"

[gate]
gate_id = "gate-1"
key_file = %q
registry_path = %q
allowlist_file = %q
mandate_file = %q
action_types = ["application/x402+json"]
executor_keys = [%q]
%s

[recorder]
keyring_dir = %q
key_name = "recorder"
passphrase_file = %q
namespace = %q

[publisher]
keyring_dir = %q
key_name = "publisher"
passphrase_file = %q
namespace = %q

[archive]
dir = %q
`, p("agent.key"), p("gate.key"), p("registry"), p("allow.toml"), p("mandate.cbor"),
		hex.EncodeToString(pub), extra,
		p("rec"), p("rec.pass"), ns("ab"),
		p("pub"), p("pub.pass"), ns("cd"), p("archive")))
}

// ns is a version 0 namespace: 19 zero bytes, then 10 bytes.
func ns(b string) string { return strings.Repeat("00", 19) + strings.Repeat(b, 10) }

func load(t *testing.T, data []byte) config.Config {
	t.Helper()
	c, err := config.Parse(data, nil)
	require.NoError(t, err)
	require.NoError(t, c.ApplyDefaults(config.Builtin{}))
	require.NoError(t, c.ValidateBasic())
	return c
}

func TestFromEdictaMapsAStarterConfig(t *testing.T) {
	home := t.TempDir()
	in := load(t, starterTOML(t, home, ""))
	out, err := edictad.FromEdicta(in)
	require.NoError(t, err)
	require.NoError(t, out.ValidateBasic())

	assert.Equal(t, edictad.DAConfigBlob, out.Network.DA)
	assert.Equal(t, in.Network.ChainID, out.Network.ChainID)
	assert.Equal(t, in.Network.ConsensusGRPC.Addr, out.Network.ConsensusGRPC.Addr)
	assert.Equal(t, in.Archive.Dir, out.Archive.Dir)
	g := in.Gate
	assert.Equal(t, g.GateID, out.Gate.GateID)
	assert.Equal(t, g.KeyFile, out.Gate.KeyFile)
	assert.Equal(t, g.RegistryPath, out.Gate.RegistryPath)
	assert.Equal(t, g.AllowlistFile, out.Gate.AllowlistFile)
	assert.Equal(t, g.ActionTypes, out.Gate.ActionTypes)
	assert.Equal(t, g.ExecutorKeys, out.Gate.ExecutorKeys)
	assert.Equal(t, g.MandateFile, out.Policy.MandateFile)
	assert.Equal(t, g.Listen, out.HTTP.Listen)
	assert.True(t, out.Recorder.Enabled)
	assert.Equal(t, in.Recorder.Namespace, out.Recorder.Namespace)
	assert.Equal(t, in.Recorder.KeyringDir, out.Recorder.KeyringDir)
	assert.Equal(t, in.Recorder.KeyName, out.Recorder.KeyName)
	assert.Equal(t, in.Recorder.PassphraseFile, out.Recorder.PassphraseFile)
	assert.Equal(t, "file", out.Recorder.KeyringBackend)
	assert.NotZero(t, out.Recorder.Quota.BlobsPerHour)
	assert.GreaterOrEqual(t, out.Recorder.Quota.BytesPerDay, in.Recorder.MaxBlobBytes)
	assert.False(t, out.Capture.Enabled)
}

func TestFromEdictaMapsCapture(t *testing.T) {
	home := t.TempDir()
	data := append(starterTOML(t, home, ""), []byte(fmt.Sprintf(`
[capture]
dir = %q
comet_rpc = "https://rpc.example.org"
`, filepath.Join(home, "capture")))...)
	in := load(t, data)
	in.Gate.ActionTypes = []string{bankaction.ActionType}
	out, err := edictad.FromEdicta(in)
	require.NoError(t, err)
	assert.True(t, out.Capture.Enabled)
	assert.Equal(t, in.Capture.Dir, out.Capture.Dir)
	assert.Equal(t, in.Capture.CometRPC, out.Capture.CometRPC)
	assert.Equal(t, in.Capture.NodePruneWindowBlocks, out.Capture.NodePruneWindowBlocks)
	assert.Equal(t, in.Capture.RetryEveryS, out.Capture.RetryEveryS)
}

func TestFromEdictaRefusesWhatThisBuildLacks(t *testing.T) {
	for _, key := range []string{"fast_mode", "sessions"} {
		t.Run(key, func(t *testing.T) {
			in := load(t, starterTOML(t, t.TempDir(), key+" = true"))
			_, err := edictad.FromEdicta(in)
			require.ErrorIs(t, err, edictad.ErrNotAvailable)
			require.ErrorIs(t, err, edictad.ErrConfig)
			assert.Contains(t, err.Error(), "gate."+key)
		})
	}
}

func TestFromEdictaNeedsTheGate(t *testing.T) {
	in := load(t, starterTOML(t, t.TempDir(), ""))
	in.Gate = nil
	_, err := edictad.FromEdicta(in)
	require.ErrorIs(t, err, edictad.ErrConfig)
}

func TestFromEdictaWithoutRecorderDisablesIt(t *testing.T) {
	in := load(t, starterTOML(t, t.TempDir(), ""))
	in.Recorder, in.Publisher = nil, nil
	out, err := edictad.FromEdicta(in)
	require.NoError(t, err)
	assert.False(t, out.Recorder.Enabled)
}

func TestFromEdictaFibreNeedsOwnNode(t *testing.T) {
	in := load(t, starterTOML(t, t.TempDir(), ""))
	in.Recorder.DA = config.DAFibre
	in.Recorder.OwnNode = true
	in.Recorder.EscrowHeadroomUtia = 5
	out, err := edictad.FromEdicta(in)
	require.NoError(t, err)
	assert.Equal(t, edictad.DAConfigFibre, out.Network.DA)
	assert.True(t, out.Recorder.OwnNode)
	assert.Equal(t, uint64(5), out.Recorder.EscrowMarginUtia)

	in.Recorder.OwnNode = false
	_, err = edictad.FromEdicta(in)
	require.ErrorIs(t, err, edictad.ErrConfig)
}

func TestFromEdictaFibreWithoutOwnNodeNamesTheKey(t *testing.T) {
	in := load(t, starterTOML(t, t.TempDir(), ""))
	in.Recorder.DA = config.DAFibre
	in.Recorder.OwnNode = false
	_, err := edictad.FromEdicta(in)
	require.ErrorIs(t, err, edictad.ErrConfig)
	assert.Contains(t, err.Error(), "own_node")
}
