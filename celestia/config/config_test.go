package config_test

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/celestia/config"
)

func pub(b byte) string { return hex.EncodeToString(append(make([]byte, 31), b)) }

// ns and ns2 are valid user namespaces.
var (
	ns  = strings.Repeat("00", 19) + "ab" + strings.Repeat("00", 9)
	ns2 = strings.Repeat("00", 19) + "cd" + strings.Repeat("00", 9)
)

var selfHosted = `
[network]
celestia = "mocha"
settlement = "base-sepolia"

[agent]
id = "agent-1"
key_file = "/h/keys/agent.ed25519"

[gate]
gate_id = "gate-1"
key_file = "/h/keys/gate.ed25519"
registry_path = "/h/registry.db"
allowlist_file = "/h/agents.toml"
action_types = ["application/vnd.edicta.x402.exact-evm.v1+cbor"]
executor_keys = ["` + pub(1) + `"]

[recorder]
keyring_dir = "/h/keyring/recorder"
key_name = "recorder"
passphrase_file = "/h/keyring/recorder/recorder.pass"
namespace = "` + ns + `"

[archive]
dir = "/h/archive"
`

func loadValid(t *testing.T, data string, ov map[string]string) config.Config {
	t.Helper()
	c, err := config.Parse([]byte(data), ov)
	require.NoError(t, err)
	require.NoError(t, c.ApplyDefaults(config.Builtin{}))
	require.NoError(t, c.ValidateBasic())
	return c
}

func TestPresetsFillTheNetwork(t *testing.T) {
	c := loadValid(t, selfHosted, nil)
	assert.Equal(t, "mocha-5", c.Network.ChainID)
	assert.Equal(t, "grpc-mocha.pops.one:9090", c.Network.ConsensusGRPC.Addr)
	assert.False(t, c.Network.ConsensusGRPC.TLS)
	assert.True(t, c.Network.Bridge.TLS)
	assert.Equal(t, uint64(84532), c.Network.EVM.ChainID)
	assert.Equal(t, "https://x402.org/facilitator", c.Network.EVM.FacilitatorURL)
	assert.Equal(t, config.ModeSelfHosted, c.Network.Mode)
	assert.Equal(t, config.DABlob, c.Recorder.DA)
	assert.Equal(t, config.BackendFile, c.Gate.KeyBackend)
}

func TestFileKeysWinOverThePreset(t *testing.T) {
	c := loadValid(t, selfHosted+"\n", map[string]string{
		"network.chain_id":            "mocha-5",
		"network.consensus_grpc.addr": "10.0.0.1:9090",
	})
	assert.Equal(t, "10.0.0.1:9090", c.Network.ConsensusGRPC.Addr)
	assert.False(t, c.Network.ConsensusGRPC.TLS, "the preset's TLS flag does not attach to another address")
}

func TestUnknownKeysAreRefused(t *testing.T) {
	for name, data := range map[string]string{
		"top level":  selfHosted + "\nwat = 1\n",
		"in section": strings.Replace(selfHosted, `id = "agent-1"`, "id = \"agent-1\"\npassphrase = \"hunter2\"", 1),
		"table":      selfHosted + "\n[nope]\nx = 1\n",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := config.Parse([]byte(data), nil)
			require.ErrorIs(t, err, config.ErrConfig)
			assert.Contains(t, err.Error(), "unknown keys")
			assert.NotContains(t, err.Error(), "hunter2")
		})
	}
}

func TestOverridesChangeSingleKeys(t *testing.T) {
	c := loadValid(t, selfHosted, map[string]string{
		"agent.id":                "agent-2",
		"recorder.max_blob_bytes": "4096",
		"gate.sessions":           "true",
		"gate.listen":             "127.0.0.1:9000",
	})
	assert.Equal(t, "agent-2", c.Agent.ID)
	assert.Equal(t, uint64(4096), c.Recorder.MaxBlobBytes)
	assert.True(t, c.Gate.Sessions)
	assert.Equal(t, "mocha-5", c.Network.ChainID)
}

func TestOverrideOfAnUnknownKeyIsRefused(t *testing.T) {
	_, err := config.Parse([]byte(selfHosted), map[string]string{"agent.nope": "1"})
	require.ErrorIs(t, err, config.ErrConfig)
	_, err = config.Parse([]byte(selfHosted), map[string]string{"agent.id.deeper": "1"})
	require.ErrorIs(t, err, config.ErrConfig)
	_, err = config.Parse([]byte(selfHosted), map[string]string{"": "1"})
	require.ErrorIs(t, err, config.ErrConfig)
}

func TestOverrideBuildsAMissingSection(t *testing.T) {
	c, err := config.Parse([]byte(selfHosted), map[string]string{"verify.tx_rpc": "https://rpc.example.org"})
	require.NoError(t, err)
	require.NotNil(t, c.Verify)
	assert.Equal(t, "https://rpc.example.org", c.Verify.TxRPC)
}

func TestMainnetPresetsAreNotAvailableYet(t *testing.T) {
	for _, tc := range []struct{ celestia, settlement string }{
		{"celestia-mainnet", "none"}, {"mocha", "base"}, {"nope", "none"}, {"mocha", "nope"},
	} {
		c, err := config.Parse([]byte(selfHosted), map[string]string{"network.celestia": tc.celestia, "network.settlement": tc.settlement})
		require.NoError(t, err)
		err = c.ApplyDefaults(config.Builtin{})
		require.ErrorIs(t, err, config.ErrPreset, "%v", tc)
	}
}

func TestCustomNeedsEveryEndpoint(t *testing.T) {
	c, err := config.Parse([]byte(selfHosted), map[string]string{"network.celestia": "custom", "network.settlement": "none"})
	require.NoError(t, err)
	require.NoError(t, c.ApplyDefaults(nil))
	err = c.ValidateBasic()
	require.ErrorIs(t, err, config.ErrConfig)
	assert.Contains(t, err.Error(), "network.chain_id")
}

func TestApplyDefaultsBeforeValidateBasic(t *testing.T) {
	c, err := config.Parse([]byte(selfHosted), nil)
	require.NoError(t, err)
	require.ErrorIs(t, c.ValidateBasic(), config.ErrConfig, "ValidateBasic applies no defaults")
}

func TestValidateBasicRefusals(t *testing.T) {
	tests := []struct {
		name string
		ov   map[string]string
		want string
	}{
		{"bad namespace length", map[string]string{"recorder.namespace": `"00ab"`}, "recorder.namespace"},
		{"reserved namespace", map[string]string{"recorder.namespace": `"` + strings.Repeat("00", 28) + `ab"`}, "reserved"},
		{"version 1 namespace", map[string]string{"recorder.namespace": `"01` + strings.Repeat("00", 18) + `ab` + strings.Repeat("00", 9) + `"`}, "version 0"},
		{"da", map[string]string{"recorder.da": "blob"}, "recorder.da"},
		{"fibre needs own node", map[string]string{"recorder.da": "fibre"}, "own_node"},
		{"own node with blob", map[string]string{"recorder.own_node": "true"}, "own_node"},
		{"kms gate key", map[string]string{"gate.key_backend": "kms"}, "kms"},
		{"executor key", map[string]string{"gate.executor_keys": `["zz"]`}, "gate.executor_keys"},
		{"gate id", map[string]string{"gate.gate_id": `"a b"`}, "gate.gate_id"},
		{"mode", map[string]string{"network.mode": "cloud"}, "network.mode"},
		{"scheme", map[string]string{"archive.url": "ftp://x.example"}, "archive.url"},
		{"url credentials", map[string]string{"archive.url": "https://u:p@x.example"}, "credentials"},
		{"role overlap", map[string]string{"gate.key_file": `"/h/keys/agent.ed25519"`}, "signing roles"},
		{"capture without rpc", map[string]string{"capture.dir": `"/h/c"`}, "capture.comet_rpc"},
		{"quorum", map[string]string{"verify.checkpoint_rpc": `["https://a.example"]`, "verify.quorum": "2"}, "verify.quorum"},
		{"signer without settlement", map[string]string{"network.settlement": "none", "signer.pinned_gate_keys": `["` + pub(1) + `"]`}, "signer"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c, err := config.Parse([]byte(selfHosted), tc.ov)
			require.NoError(t, err)
			require.NoError(t, c.ApplyDefaults(config.Builtin{}))
			err = c.ValidateBasic()
			require.ErrorIs(t, err, config.ErrConfig)
			assert.Contains(t, err.Error(), tc.want)
		})
	}
}

func TestRecorderAndPublisherNeedSeparateAccounts(t *testing.T) {
	data := selfHosted + `
[publisher]
keyring_dir = "/h/keyring/recorder"
key_name = "recorder"
passphrase_file = "/h/keyring/recorder/recorder.pass"
namespace = "` + ns2 + `"
`
	c, err := config.Parse([]byte(data), nil)
	require.NoError(t, err)
	require.NoError(t, c.ApplyDefaults(nil))
	err = c.ValidateBasic()
	require.ErrorIs(t, err, config.ErrConfig)
	assert.Contains(t, err.Error(), "separate accounts")
}

func TestHostedModeHoldsOnlyAgentAndSigner(t *testing.T) {
	hosted := `
[network]
celestia = "mocha"
settlement = "base-sepolia"
mode = "hosted"

[agent]
id = "agent-1"
key_file = "/h/keys/agent.ed25519"
recorder_url = "https://relay.example.org"
gate_url = "https://gate.example.org"

[signer]
pinned_gate_keys = ["` + pub(7) + `"]
payer_key_file = "/h/keys/payer.secp256k1"
[signer.risk]
max_per_payment = 1000000
max_per_hour = 10000000
`
	c := loadValid(t, hosted, nil)
	assert.Equal(t, uint64(84532), c.Signer.PinnedChainID)
	assert.Equal(t, "0x036cbd53842c5426634e7929541ec2318f3dcf7e", c.Signer.PinnedUSDC)

	c2, err := config.Parse([]byte(hosted+"\n"+`[gate]
gate_id = "g"
`), nil)
	require.NoError(t, err)
	require.NoError(t, c2.ApplyDefaults(nil))
	require.ErrorIs(t, c2.ValidateBasic(), config.ErrConfig)

	c3, err := config.Parse([]byte(strings.Replace(hosted, "[signer]", "[nosigner]", 1)), nil)
	require.Error(t, err)
	_ = c3
}

func TestSelfHostedNeedsAGateAndAnArchive(t *testing.T) {
	for _, drop := range []string{"[gate]", "[archive]"} {
		data := strings.Replace(selfHosted, drop, "[x"+drop[1:], 1)
		_, err := config.Parse([]byte(data), nil)
		require.Error(t, err, "renamed %s is an unknown table", drop)
	}
	c, err := config.Parse([]byte(selfHosted), map[string]string{"archive.dir": `""`})
	require.NoError(t, err)
	require.NoError(t, c.ApplyDefaults(nil))
	require.ErrorIs(t, c.ValidateBasic(), config.ErrConfig)
}

func TestSignerRiskLimits(t *testing.T) {
	ov := map[string]string{
		"signer.pinned_gate_keys":     `["` + pub(1) + `"]`,
		"signer.payer_key_file":       `"/h/keys/payer"`,
		"signer.risk.max_per_hour":    "10",
		"signer.risk.max_per_payment": "11",
	}
	c, err := config.Parse([]byte(selfHosted), ov)
	require.NoError(t, err)
	require.NoError(t, c.ApplyDefaults(nil))
	err = c.ValidateBasic()
	require.ErrorIs(t, err, config.ErrConfig)
	assert.Contains(t, err.Error(), "max_per_payment above")
}

func TestPresetDrift(t *testing.T) {
	c := loadValid(t, selfHosted, nil)
	d, err := c.Drift(nil)
	require.NoError(t, err)
	assert.Empty(t, d, "an unrecorded version has nothing to compare")

	v, err := c.Versions(config.Builtin{})
	require.NoError(t, err)
	c.Network.CelestiaPresetVersion = v.Celestia
	c.Network.SettlementPresetVersion = v.Settlement
	d, err = c.Drift(nil)
	require.NoError(t, err)
	assert.Empty(t, d)

	c.Network.CelestiaPresetVersion = v.Celestia + 1
	c.Network.SettlementPresetVersion = v.Settlement + 1
	d, err = c.Drift(nil)
	require.NoError(t, err)
	assert.Len(t, d, 2)
}

func TestLoadAndHome(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(config.EnvHome, dir)
	p, err := config.DefaultPath()
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(dir, "edicta.toml"), p)
	require.NoError(t, os.WriteFile(p, []byte(selfHosted), 0o600))
	c, err := config.LoadValid(p, nil, nil)
	require.NoError(t, err)
	assert.Equal(t, "agent-1", c.Agent.ID)

	_, err = config.Load(filepath.Join(dir, "missing.toml"), nil)
	require.ErrorIs(t, err, config.ErrConfig)
}

func TestInvalidTOMLIsRefused(t *testing.T) {
	_, err := config.Parse([]byte("[network\ncelestia = "), nil)
	require.ErrorIs(t, err, config.ErrConfig)
	_, err = config.Parse([]byte("[network]\ncelestia = 5\n"), nil)
	require.ErrorIs(t, err, config.ErrConfig)
}

func TestIsEdictaConfig(t *testing.T) {
	assert.True(t, config.IsEdictaConfig([]byte(selfHosted)))
	assert.False(t, config.IsEdictaConfig([]byte("[network]\nda = \"fibre\"\n")))
	assert.False(t, config.IsEdictaConfig([]byte("not toml [")))
}

func TestSecretsAreNeverValues(t *testing.T) {
	// Every secret-bearing key is a path; a key named like a value is unknown.
	for _, k := range []string{"passphrase", "token", "private_key", "seed"} {
		_, err := config.Parse([]byte(selfHosted), map[string]string{"recorder." + k: `"x"`})
		require.ErrorIs(t, err, config.ErrConfig, k)
	}
}

func TestApplyOverridesOnATree(t *testing.T) {
	tree := map[string]any{"network": map[string]any{"celestia": "mocha"}}
	require.NoError(t, config.ApplyOverrides(tree, map[string]string{
		"network.consensus_grpc.addr": "localhost:9090",
		"network.consensus_grpc.tls":  "true",
	}))
	assert.Equal(t, map[string]any{"network": map[string]any{
		"celestia":       "mocha",
		"consensus_grpc": map[string]any{"addr": "localhost:9090", "tls": true},
	}}, tree)

	err := config.ApplyOverrides(tree, map[string]string{"network.celestia.x": "1"})
	require.ErrorIs(t, err, config.ErrConfig)
}
