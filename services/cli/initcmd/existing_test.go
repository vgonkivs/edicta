package initcmd_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/config"
	"github.com/vgonkivs/edicta/internal/keyfile"
	"github.com/vgonkivs/edicta/services/cli/initcmd"
)

func noSettlement(t *testing.T, home string) (initcmd.Result, error) {
	t.Helper()
	return initcmd.Run(context.Background(), initcmd.Config{Home: home, Preset: "mocha+none"}, healthyEnv("mocha-5"), nil)
}

func TestHomeUnderAWritableParentIsRefused(t *testing.T) {
	shared := filepath.Join(t.TempDir(), "shared")
	require.NoError(t, os.Mkdir(shared, 0o700))
	require.NoError(t, os.Chmod(shared, 0o777))
	home := filepath.Join(shared, "edicta")

	_, err := noSettlement(t, home)
	require.ErrorIs(t, err, keyfile.ErrUnsafeDir)
	assert.Contains(t, err.Error(), shared)
	assert.NoDirExists(t, filepath.Join(home, "keys"))

	// Others cannot move what they do not own out of a sticky directory.
	require.NoError(t, os.Chmod(shared, 0o777|os.ModeSticky))
	_, err = noSettlement(t, home)
	require.NoError(t, err)
	assert.FileExists(t, filepath.Join(home, "keys", "agent.ed25519"))
}

func TestSymlinkInAWritableDirectoryIsRefused(t *testing.T) {
	realDir := t.TempDir()
	shared := filepath.Join(t.TempDir(), "shared")
	require.NoError(t, os.Mkdir(shared, 0o700))
	home := filepath.Join(shared, "edicta")
	require.NoError(t, os.Symlink(realDir, home))
	require.NoError(t, os.Chmod(shared, 0o777))

	_, err := noSettlement(t, home)
	require.ErrorIs(t, err, keyfile.ErrUnsafeDir)
	entries, err := os.ReadDir(realDir)
	require.NoError(t, err)
	assert.Empty(t, entries)
}

func TestSymlinkedHomeIsUsedThroughItsTarget(t *testing.T) {
	realDir, other := t.TempDir(), t.TempDir()
	home := filepath.Join(t.TempDir(), "edicta")
	require.NoError(t, os.Symlink(realDir, home))

	// Once the keys are written, the link is pointed elsewhere: the rest of
	// the run must still land in the directory it checked.
	env := healthyEnv("mocha-5")
	var moved bool
	env.Now = func() time.Time {
		if _, err := os.Stat(filepath.Join(realDir, "keys", "agent.ed25519")); err == nil && !moved {
			require.NoError(t, os.Remove(home))
			require.NoError(t, os.Symlink(other, home))
			moved = true
		}
		return testNow
	}
	res, err := initcmd.Run(context.Background(), initcmd.Config{Home: home}, env, nil)
	require.NoError(t, err)
	require.True(t, moved, "the link was moved during the run")

	entries, err := os.ReadDir(other)
	require.NoError(t, err)
	assert.Empty(t, entries)
	for _, name := range []string{initcmd.MandateFile, initcmd.AllowlistFile, config.FileName} {
		assert.FileExists(t, filepath.Join(realDir, name), name)
	}
	assert.DirExists(t, filepath.Join(realDir, initcmd.ArchiveDir))
	// What the user reads names the home as given.
	assert.Equal(t, filepath.Join(home, "keys", "agent.ed25519"), res.Agent.Path)
	assert.Equal(t, filepath.Join(home, config.FileName), res.Config.Path)
	assert.Equal(t, filepath.Join(home, "keyring-recorder"), res.Recorder.KeyringDir)
}

// failingPresets answers like the built-in presets until it has answered
// limit times, then fails.
type failingPresets struct {
	config.Builtin
	calls atomic.Int32
	limit int32
}

var errPresetGone = errors.New("preset gone")

func (p *failingPresets) Celestia(name string) (config.Preset, error) {
	if p.calls.Add(1) > p.limit {
		return config.Preset{}, errPresetGone
	}
	return p.Builtin.Celestia(name)
}

func (p *failingPresets) Settlement(name string) (config.Preset, error) {
	if p.calls.Add(1) > p.limit {
		return config.Preset{}, errPresetGone
	}
	return p.Builtin.Settlement(name)
}

func TestConfigFileThatCannotBeBuiltStopsTheRunBeforeAnyWrite(t *testing.T) {
	home := filepath.Join(t.TempDir(), "edicta")
	// The network section and the preflight use the presets four times;
	// building the config file is the next use.
	p := &failingPresets{limit: 4}
	res, err := initcmd.Run(context.Background(), initcmd.Config{Home: home}, healthyEnv("mocha-5"), p)
	require.ErrorIs(t, err, errPresetGone)
	require.NotEmpty(t, res.Preflight.Items, "the preflight ran")

	entries, err := os.ReadDir(home)
	require.NoError(t, err)
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	assert.Equal(t, []string{initcmd.LockFile}, names, "no key, mandate or allowlist is written")
}

func TestExistingMandateKeepsItsPrincipal(t *testing.T) {
	home := t.TempDir()
	first, err := run(t, home, healthyEnv("mocha-5"))
	require.NoError(t, err)
	assert.Equal(t, "ed25519:"+hex.EncodeToString(first.Principal.Public), first.PrincipalID)
	keyPath := first.Principal.Path
	require.NoError(t, os.Remove(keyPath))

	// The key was moved off the machine: no new principal is made.
	second, err := run(t, home, healthyEnv("mocha-5"))
	require.NoError(t, err)
	assert.NoFileExists(t, keyPath)
	assert.Equal(t, initcmd.Offline, second.Principal.Status)
	assert.Empty(t, second.Principal.Path)
	assert.Equal(t, first.Principal.Public, second.Principal.Public)
	assert.Equal(t, first.PrincipalID, second.PrincipalID)
	assert.Equal(t, first.Mandate.Hash, second.Mandate.Hash)
	var out bytes.Buffer
	require.NoError(t, second.WriteText(&out))
	assert.Contains(t, out.String(), "offline  principal "+first.PrincipalID)
	assert.Contains(t, out.String(), "signed by principal "+first.PrincipalID)
	assert.NotContains(t, out.String(), "move it off this machine")

	// A key file that did not sign the mandate is reported, not used.
	_, err = keyfile.NewSeed(keyPath)
	require.NoError(t, err)
	stray, err := os.ReadFile(keyPath)
	require.NoError(t, err)
	third, err := run(t, home, healthyEnv("mocha-5"))
	require.NoError(t, err)
	assert.Equal(t, initcmd.Mismatch, third.Principal.Status)
	assert.Equal(t, keyPath, third.Principal.Path)
	assert.Equal(t, first.Principal.Public, third.Principal.Public)
	assert.Equal(t, first.Mandate.Hash, third.Mandate.Hash)
	got, err := os.ReadFile(keyPath)
	require.NoError(t, err)
	assert.Equal(t, stray, got)
	out.Reset()
	require.NoError(t, third.WriteText(&out))
	assert.Contains(t, out.String(), "mismatch principal key "+keyPath)
}

func TestSharedKeyFilesAreRefused(t *testing.T) {
	for _, pair := range [][2]string{{"agent", "gate"}, {"gate", "executor"}, {"agent", "executor"}, {"gate", "principal"}, {"executor", "principal"}} {
		t.Run(pair[0]+"="+pair[1], func(t *testing.T) {
			home := t.TempDir()
			keys := filepath.Join(home, "keys")
			require.NoError(t, os.Mkdir(keys, 0o700))
			a := filepath.Join(keys, pair[0]+".ed25519")
			_, err := keyfile.NewSeed(a)
			require.NoError(t, err)
			seed, err := os.ReadFile(a)
			require.NoError(t, err)
			b := filepath.Join(keys, pair[1]+".ed25519")
			require.NoError(t, os.WriteFile(b, seed, 0o600))

			_, err = run(t, home, healthyEnv("mocha-5"))
			require.ErrorIs(t, err, initcmd.ErrKeyRole)
			assert.Contains(t, err.Error(), a)
			assert.Contains(t, err.Error(), b)
			entries, err := os.ReadDir(keys)
			require.NoError(t, err)
			assert.Len(t, entries, 2, "no other key is made")
			assert.NoDirExists(t, filepath.Join(home, "keyring-recorder"))
		})
	}
}

func TestMandatePrincipalSharedWithARoleIsRefused(t *testing.T) {
	home := t.TempDir()
	first, err := run(t, home, healthyEnv("mocha-5"))
	require.NoError(t, err)
	// The principal key is moved off the machine and, by mistake, kept as
	// the executor key.
	seed, err := os.ReadFile(first.Principal.Path)
	require.NoError(t, err)
	require.NoError(t, os.Remove(first.Principal.Path))
	require.NoError(t, os.Remove(first.Executor.Path))
	require.NoError(t, os.WriteFile(first.Executor.Path, seed, 0o600))

	_, err = run(t, home, healthyEnv("mocha-5"))
	require.ErrorIs(t, err, initcmd.ErrKeyRole)
	assert.Contains(t, err.Error(), first.Executor.Path)
	assert.Contains(t, err.Error(), initcmd.MandateFile)
}

func TestConfigForAnotherModeStopsTheRun(t *testing.T) {
	home := t.TempDir()
	hosted := `[network]
celestia = "mocha"
settlement = "base-sepolia"
mode = "hosted"

[agent]
id = "agent-1"
key_file = "/k/agent.ed25519"

[signer]
pinned_gate_keys = ["` + strings.Repeat("ab", 32) + `"]
payer_key_file = "/k/payer.secp256k1"

[signer.risk]
max_per_payment = 1
max_per_hour = 1
`
	path := filepath.Join(home, config.FileName)
	require.NoError(t, os.WriteFile(path, []byte(hosted), 0o600))
	_, err := config.LoadValid(path, nil, nil)
	require.NoError(t, err, "the hosted config is valid")
	before := tree(t, home)

	res, err := run(t, home, healthyEnv("mocha-5"))
	require.ErrorIs(t, err, initcmd.ErrConfig)
	assert.Contains(t, err.Error(), "hosted")
	assert.Empty(t, res.Preflight.Items, "refused before the preflight")
	assert.Equal(t, before, tree(t, home))
}

func TestOversizedConfigIsNotRead(t *testing.T) {
	home := t.TempDir()
	line := "# " + strings.Repeat("x", 1021) + "\n"
	big := strings.Repeat(line, 1025)
	require.NoError(t, os.WriteFile(filepath.Join(home, config.FileName), []byte(big), 0o600))

	_, err := run(t, home, healthyEnv("mocha-5"))
	require.ErrorIs(t, err, initcmd.ErrExisting)
	assert.Contains(t, err.Error(), "longer than")
}

func TestConfigOfAnUnsafeHomeIsNotRead(t *testing.T) {
	home := filepath.Join(t.TempDir(), "edicta")
	require.NoError(t, os.Mkdir(home, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(home, config.FileName), []byte("not toml ["), 0o600))
	require.NoError(t, os.Chmod(home, 0o777))

	_, err := run(t, home, healthyEnv("mocha-5"))
	require.ErrorIs(t, err, keyfile.ErrUnsafeDir)
	assert.NotErrorIs(t, err, initcmd.ErrExisting)
}

func TestConfigValidateBasicRefusesTheStarterAssetAndMode(t *testing.T) {
	for _, k := range []string{
		"network.mode", "network.Mode", "network.celestia_preset_version", "network.settlement_preset_version",
		"network.evm", "network.evm.chain_id", "network.EVM.Chain_ID", "network.evm.usdc", "network.evm.usdc.address",
		"network.evm.usdc.name",
	} {
		c := initcmd.Config{Home: "/h", Overrides: map[string]string{k: "1"}}
		c.ApplyDefaults()
		assert.ErrorIs(t, c.ValidateBasic(), initcmd.ErrConfig, k)
	}
	c := initcmd.Config{Home: "/h", Overrides: map[string]string{"network.evm.rpc": `["https://rpc.example"]`}}
	c.ApplyDefaults()
	assert.NoError(t, c.ValidateBasic(), "an endpoint may be overridden")
}

func TestConfigValidateBasicCapsTheLimits(t *testing.T) {
	c := initcmd.Config{Home: "/h", MaxPerPayment: 1, MaxPerHour: initcmd.MaxLimit}
	c.ApplyDefaults()
	require.NoError(t, c.ValidateBasic())

	c.MaxPerHour = initcmd.MaxLimit + 1
	err := c.ValidateBasic()
	require.ErrorIs(t, err, initcmd.ErrConfig)
	assert.Contains(t, err.Error(), "at most 1000000 USDC")

	// The largest uint64 cannot be written to edicta.toml; it never gets
	// that far.
	c = initcmd.Config{Home: t.TempDir(), MaxPerPayment: ^uint64(0), MaxPerHour: ^uint64(0)}
	_, err = initcmd.Run(context.Background(), c, healthyEnv("mocha-5"), nil)
	require.ErrorIs(t, err, initcmd.ErrConfig)
	entries, err := os.ReadDir(c.Home)
	require.NoError(t, err)
	assert.Empty(t, entries)
}
