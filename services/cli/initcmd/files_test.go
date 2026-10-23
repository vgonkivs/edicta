package initcmd_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/pelletier/go-toml/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/config"
	"github.com/vgonkivs/edicta/engine/policy"
	"github.com/vgonkivs/edicta/internal/keyfile"
	"github.com/vgonkivs/edicta/services/cli/doctor"
	"github.com/vgonkivs/edicta/services/cli/initcmd"
)

func readMandate(t *testing.T, path string) *policy.SignedMandate {
	t.Helper()
	b, err := os.ReadFile(path)
	require.NoError(t, err)
	sm, _, err := policy.VerifyMandate(b)
	require.NoError(t, err)
	return sm
}

func TestEmptyHomeWritesALoadableStack(t *testing.T) {
	home := t.TempDir()
	res, err := run(t, home, healthyEnv("mocha-5"))
	require.NoError(t, err)
	assert.Equal(t, initcmd.Created, res.Config.Status)
	assert.Equal(t, initcmd.Created, res.Allowlist.Status)
	assert.Equal(t, initcmd.Created, res.Principal.Status)
	require.NotNil(t, res.Mandate)
	assert.Equal(t, initcmd.Created, res.Mandate.Status)

	cfg, err := config.LoadValid(res.Config.Path, nil, nil)
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(home, config.FileName), res.Config.Path)

	n := cfg.Network
	assert.Equal(t, config.CelestiaMocha, n.Celestia)
	assert.Equal(t, config.SettlementBaseSepolia, n.Settlement)
	assert.Equal(t, res.Network.CelestiaPresetVersion, n.CelestiaPresetVersion)
	assert.Equal(t, res.Network.SettlementPresetVersion, n.SettlementPresetVersion)
	drift, err := cfg.Drift(config.Builtin{})
	require.NoError(t, err)
	assert.Empty(t, drift)

	assert.Equal(t, res.Agent.Path, cfg.Agent.KeyFile)
	assert.Equal(t, res.AgentID, cfg.Agent.ID)
	g := cfg.Gate
	require.NotNil(t, g)
	assert.Equal(t, res.GateID, g.GateID)
	assert.Equal(t, res.Gate.Path, g.KeyFile)
	assert.Equal(t, res.Allowlist.Path, g.AllowlistFile)
	assert.Equal(t, res.Mandate.Path, g.MandateFile)
	assert.Equal(t, []string{initcmd.X402ActionType}, g.ActionTypes)
	assert.Equal(t, []string{hex.EncodeToString(res.Executor.Public)}, g.ExecutorKeys)
	assert.False(t, g.FastMode)
	assert.False(t, g.Sessions)

	require.NotNil(t, cfg.Recorder)
	require.NotNil(t, cfg.Publisher)
	assert.Equal(t, res.RecorderNamespace, cfg.Recorder.Namespace)
	assert.Equal(t, res.PublisherNamespace, cfg.Publisher.Namespace)
	assert.Equal(t, res.Recorder.KeyringDir, cfg.Recorder.KeyringDir)
	assert.Equal(t, res.Recorder.PassphraseFile, cfg.Recorder.PassphraseFile)
	assert.Equal(t, res.Publisher.KeyringDir, cfg.Publisher.KeyringDir)
	assert.Equal(t, config.DABlob, cfg.Recorder.DA)
	assert.Equal(t, res.ArchiveDir, cfg.Archive.Dir)
	assert.DirExists(t, res.ArchiveDir)

	s := cfg.Signer
	require.NotNil(t, s)
	assert.Equal(t, []string{hex.EncodeToString(res.Gate.Public)}, s.PinnedGateKeys)
	assert.Equal(t, res.Payer.Path, s.PayerKeyFile)
	assert.Equal(t, res.Payer.Address, s.PayerAddress)
	assert.Equal(t, uint64(84532), s.PinnedChainID)
	assert.Equal(t, initcmd.DefaultMaxPerPayment, s.Risk.MaxPerPayment)
	assert.Equal(t, initcmd.DefaultMaxPerHour, s.Risk.MaxPerHour)

	var allow struct {
		Agents []struct {
			AgentID string `toml:"agent_id"`
			PubKey  string `toml:"pubkey"`
		} `toml:"agents"`
	}
	b, err := os.ReadFile(res.Allowlist.Path)
	require.NoError(t, err)
	require.NoError(t, toml.NewDecoder(bytes.NewReader(b)).DisallowUnknownFields().Decode(&allow))
	require.Len(t, allow.Agents, 1)
	assert.Equal(t, res.AgentID, allow.Agents[0].AgentID)
	assert.Equal(t, hex.EncodeToString(res.Agent.Public), allow.Agents[0].PubKey)

	// The checks doctor runs on these files pass.
	rep := doctor.Run(context.Background(), cfg, doctor.Checks(healthyEnv("mocha-5"), doctor.ConfigCheck{}))
	for _, it := range rep.Items {
		if it.Name == "gate" || it.Name == "keydirs" || it.Name == "archive" {
			assert.Equal(t, doctor.OK, it.Status, "%s: %s", it.Name, it.Cause)
		}
	}
}

func TestStarterMandateVerifiesWithThePrincipalKey(t *testing.T) {
	res, err := run(t, t.TempDir(), healthyEnv("mocha-5"))
	require.NoError(t, err)

	priv, err := keyfile.ReadSeed(res.Principal.Path, "principal")
	require.NoError(t, err)
	principal := priv.Public().(ed25519.PublicKey)
	sm := readMandate(t, res.Mandate.Path)
	m := &sm.Mandate

	assert.Equal(t, []byte(principal), m.Principal)
	assert.Zero(t, m.SigType, "an Ed25519 principal")
	canon, err := policy.EncodeMandate(m)
	require.NoError(t, err)
	h := policy.HashMandate(canon)
	assert.Equal(t, hex.EncodeToString(h[:]), res.Mandate.Hash)
	assert.True(t, ed25519.Verify(principal, policy.MandateSigningMessage(h), sm.Signature), "signed by the principal key")

	assert.Equal(t, res.GateID, m.GateID)
	assert.True(t, m.Covers(res.Agent.Public))
	assert.Len(t, m.Agents, 1)
	assert.Equal(t, []string{initcmd.X402Kind}, m.Kinds)
	assert.Zero(t, m.FastModeMaxDelay, "fast mode needs the principal's explicit consent")
	assert.LessOrEqual(t, m.NotBefore, uint64(testNow.Unix()))
	assert.Greater(t, m.NotAfter, uint64(testNow.Unix()))
	require.Len(t, m.Assets, 1)
	a := m.Assets[0]
	assert.Equal(t, "eip155:84532/erc20:0x036cbd53842c5426634e7929541ec2318f3dcf7e", a.Asset)
	assert.Equal(t, uint64(initcmd.USDCScale), a.Scale)
	assert.Equal(t, policy.AmountFromUint64(initcmd.DefaultMaxPerPayment), a.PerActionMax)
	assert.Equal(t, []policy.PeriodLimit{{Hours: 1, Max: policy.AmountFromUint64(initcmd.DefaultMaxPerHour)}}, a.Periods)
	assert.Nil(t, a.Recipients)

	assert.Equal(t, policy.Render(m), res.Mandate.Text)
	var out bytes.Buffer
	require.NoError(t, res.WriteText(&out))
	assert.Contains(t, out.String(), res.Mandate.Text, "the mandate is shown in full")
}

func TestLimitsReachTheMandateAndTheSigner(t *testing.T) {
	home := t.TempDir()
	res, err := initcmd.Run(context.Background(), initcmd.Config{Home: home, MaxPerPayment: 250_000, MaxPerHour: 2_000_000}, healthyEnv("mocha-5"), nil)
	require.NoError(t, err)
	m := readMandate(t, res.Mandate.Path).Mandate
	assert.Equal(t, policy.AmountFromUint64(250_000), m.Assets[0].PerActionMax)
	assert.Equal(t, policy.AmountFromUint64(2_000_000), m.Assets[0].Periods[0].Max)
	cfg, err := config.LoadValid(res.Config.Path, nil, nil)
	require.NoError(t, err)
	assert.Equal(t, config.SignerRisk{MaxPerPayment: 250_000, MaxPerHour: 2_000_000}, cfg.Signer.Risk)
}

func TestRolesNeverShareAKey(t *testing.T) {
	res, err := run(t, t.TempDir(), healthyEnv("mocha-5"))
	require.NoError(t, err)
	keys := []initcmd.Ed25519Key{res.Agent, res.Gate, res.Executor, res.Principal}
	paths := map[string]bool{res.Payer.Path: true}
	for i, a := range keys {
		require.Len(t, a.Public, ed25519.PublicKeySize, a.Role)
		assert.False(t, paths[a.Path], "%s shares a file", a.Role)
		paths[a.Path] = true
		for _, b := range keys[i+1:] {
			assert.NotEqual(t, a.Public, b.Public, "%s and %s", a.Role, b.Role)
		}
	}
	assert.NotEqual(t, res.Recorder.KeyringDir, res.Publisher.KeyringDir)
	assert.NotEqual(t, res.Recorder.Address, res.Publisher.Address)

	m := readMandate(t, res.Mandate.Path).Mandate
	for _, k := range []initcmd.Ed25519Key{res.Gate, res.Executor} {
		assert.False(t, m.Covers(k.Public), "the %s key is no agent of the mandate", k.Role)
	}
	cfg, err := config.LoadValid(res.Config.Path, nil, nil)
	require.NoError(t, err)
	assert.NotContains(t, cfg.Gate.ExecutorKeys, hex.EncodeToString(res.Gate.Public))
	assert.NotContains(t, cfg.Gate.ExecutorKeys, hex.EncodeToString(res.Agent.Public))
}

func TestMissingConfigIsWrittenOnceWithTheNamesOnDisk(t *testing.T) {
	home := t.TempDir()
	first, err := run(t, home, healthyEnv("mocha-5"))
	require.NoError(t, err)
	require.NoError(t, os.Remove(first.Config.Path))

	second, err := run(t, home, healthyEnv("mocha-5"))
	require.NoError(t, err)
	assert.Equal(t, initcmd.Created, second.Config.Status)
	assert.Equal(t, initcmd.Exists, second.Mandate.Status)
	assert.Equal(t, first.GateID, second.GateID, "the gate id comes from the existing mandate")
	cfg, err := config.LoadValid(second.Config.Path, nil, nil)
	require.NoError(t, err)
	assert.Equal(t, readMandate(t, second.Mandate.Path).Mandate.GateID, cfg.Gate.GateID)
	assert.Equal(t, second.RecorderNamespace, cfg.Recorder.Namespace)
	written, err := os.ReadFile(second.Config.Path)
	require.NoError(t, err)

	third, err := run(t, home, healthyEnv("mocha-5"))
	require.NoError(t, err)
	assert.Equal(t, initcmd.Exists, third.Config.Status)
	assert.Equal(t, second.RecorderNamespace, third.RecorderNamespace)
	assert.Equal(t, second.PublisherNamespace, third.PublisherNamespace)
	again, err := os.ReadFile(third.Config.Path)
	require.NoError(t, err)
	assert.Equal(t, written, again)
}

func TestMissingMandateIsSignedForTheConfiguredGate(t *testing.T) {
	home := t.TempDir()
	first, err := run(t, home, healthyEnv("mocha-5"))
	require.NoError(t, err)
	require.NoError(t, os.Remove(first.Mandate.Path))

	second, err := run(t, home, healthyEnv("mocha-5"))
	require.NoError(t, err)
	assert.Equal(t, initcmd.Created, second.Mandate.Status)
	assert.NotEqual(t, first.Mandate.Hash, second.Mandate.Hash)
	assert.Equal(t, first.GateID, readMandate(t, second.Mandate.Path).Mandate.GateID)
}

func TestUnusableConfigIsLeftAloneAndStopsTheRun(t *testing.T) {
	home := t.TempDir()
	path := filepath.Join(home, config.FileName)
	require.NoError(t, os.WriteFile(path, []byte("[network]\ncelestia = \"mocha\"\nbogus = 1\n"), 0o600))

	_, err := run(t, home, healthyEnv("mocha-5"))
	require.ErrorIs(t, err, initcmd.ErrExisting)
	entries, err := os.ReadDir(home)
	require.NoError(t, err)
	require.Len(t, entries, 1, "nothing is written next to it")
}

func TestConfigForAnotherPresetStopsTheRun(t *testing.T) {
	home := t.TempDir()
	_, err := run(t, home, healthyEnv("mocha-5"))
	require.NoError(t, err)
	before := tree(t, home)

	_, err = initcmd.Run(context.Background(), initcmd.Config{Home: home, Preset: "mocha+none"}, healthyEnv("mocha-5"), nil)
	require.ErrorIs(t, err, initcmd.ErrConfig)
	assert.Contains(t, err.Error(), "mocha+base-sepolia")
	assert.Equal(t, before, tree(t, home))
}

func TestUnusableMandateIsLeftAlone(t *testing.T) {
	home := t.TempDir()
	first, err := run(t, home, healthyEnv("mocha-5"))
	require.NoError(t, err)
	require.NoError(t, os.Remove(first.Mandate.Path))
	require.NoError(t, os.WriteFile(first.Mandate.Path, []byte("not a mandate"), 0o600))

	_, err = run(t, home, healthyEnv("mocha-5"))
	require.ErrorIs(t, err, initcmd.ErrExisting)
	got, err := os.ReadFile(first.Mandate.Path)
	require.NoError(t, err)
	assert.Equal(t, "not a mandate", string(got))
}

func TestNoSettlementWritesNoMandateOrSigner(t *testing.T) {
	home := t.TempDir()
	res, err := initcmd.Run(context.Background(), initcmd.Config{Home: home, Preset: "mocha+none"}, healthyEnv("mocha-5"), nil)
	require.NoError(t, err)
	assert.Nil(t, res.Mandate)
	assert.Empty(t, res.Principal.Path)
	assert.NoFileExists(t, filepath.Join(home, initcmd.MandateFile))
	assert.NoFileExists(t, filepath.Join(home, "keys", "principal.ed25519"))

	cfg, err := config.LoadValid(res.Config.Path, nil, nil)
	require.NoError(t, err)
	assert.Nil(t, cfg.Signer)
	assert.Empty(t, cfg.Gate.MandateFile)
	assert.Equal(t, "gate-"+hex.EncodeToString(res.Gate.Public[:8]), cfg.Gate.GateID)
}

func TestNextCommand(t *testing.T) {
	home := t.TempDir()
	t.Setenv(config.EnvHome, home)
	res, err := run(t, home, healthyEnv("mocha-5"))
	require.NoError(t, err)
	assert.Equal(t, "edicta doctor", res.NextCommand)
	var out bytes.Buffer
	require.NoError(t, res.WriteText(&out))
	assert.Contains(t, out.String(), "next: edicta doctor\n")

	other := filepath.Join(t.TempDir(), "my home")
	res, err = initcmd.Run(context.Background(), initcmd.Config{Home: other, Preset: "mocha+none"}, healthyEnv("mocha-5"), nil)
	require.NoError(t, err)
	assert.Equal(t, "edicta doctor --config '"+filepath.Join(other, config.FileName)+"'", res.NextCommand)
}
