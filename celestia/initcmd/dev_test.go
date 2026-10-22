// SPDX-License-Identifier: Apache-2.0

//go:build edictadev

package initcmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/celestia/config"
	"github.com/vgonkivs/edicta/celestia/edictad"
	"github.com/vgonkivs/edicta/engine/policy"
)

func runDev(t *testing.T, home string) DevResult {
	t.Helper()
	res, err := RunDev(DevConfig{Home: home, Now: time.Unix(1_800_000_000, 0)})
	require.NoError(t, err)
	return res
}

func TestRunDevCreatesTheStack(t *testing.T) {
	home := filepath.Join(t.TempDir(), "dev")
	res := runDev(t, home)

	for _, f := range []string{
		DevMarkerFile, DevEdictadFile, config.FileName, AllowlistFile, MandateFile, DevTokenFile, DevAccountsFile,
		"keys/agent.ed25519", "keys/gate.ed25519", "keys/executor.ed25519", "keys/principal.ed25519",
		"keys/payer.secp256k1", "keys/facilitator.secp256k1",
	} {
		fi, err := os.Stat(filepath.Join(res.Home, f))
		require.NoError(t, err, f)
		assert.Zero(t, fi.Mode().Perm()&0o077, "%s is private", f)
	}

	marker, err := os.ReadFile(filepath.Join(res.Home, DevMarkerFile))
	require.NoError(t, err)
	assert.Contains(t, string(marker), "DEV ONLY")

	accounts, err := os.ReadFile(filepath.Join(res.Home, DevAccountsFile))
	require.NoError(t, err)
	for _, want := range []string{res.Recorder.Address, res.Funder.Address, res.Payer.Address, res.Facilitator.Address} {
		assert.Contains(t, string(accounts), want)
	}
	assert.True(t, strings.HasPrefix(res.Recorder.Address, CelestiaHRP+"1"))
	assert.NotEqual(t, res.Recorder.Address, res.Funder.Address)
	assert.NotEqual(t, res.Payer.Address, res.Facilitator.Address)
}

func TestRunDevIsIdempotent(t *testing.T) {
	home := filepath.Join(t.TempDir(), "dev")
	first := runDev(t, home)
	cfgBefore, err := os.ReadFile(filepath.Join(first.Home, DevEdictadFile))
	require.NoError(t, err)

	second := runDev(t, home)
	assert.Equal(t, first.Recorder.Address, second.Recorder.Address)
	assert.Equal(t, first.Funder.Address, second.Funder.Address)
	assert.Equal(t, first.Payer.Address, second.Payer.Address)
	assert.Equal(t, first.Facilitator.Address, second.Facilitator.Address)
	assert.Equal(t, first.MandateHash, second.MandateHash)
	assert.Equal(t, first.Agent.Public, second.Agent.Public)
	assert.Equal(t, Exists, second.Agent.Status)
	assert.Equal(t, Exists, second.EdictadConfig.Status)

	cfgAfter, err := os.ReadFile(filepath.Join(second.Home, DevEdictadFile))
	require.NoError(t, err)
	assert.Equal(t, cfgBefore, cfgAfter, "a re-run does not rewrite the configuration")
}

func TestDevEdictadConfigIsFastMode(t *testing.T) {
	res := runDev(t, filepath.Join(t.TempDir(), "dev"))
	raw, err := os.ReadFile(filepath.Join(res.Home, DevEdictadFile))
	require.NoError(t, err)
	cfg, err := edictad.ParseConfig(raw)
	require.NoError(t, err)

	assert.Equal(t, DevCelestiaChainID, cfg.Network.ChainID)
	assert.Equal(t, edictad.DAConfigBlob, cfg.Network.DA)
	assert.EqualValues(t, 10, cfg.Network.MinAppVersion)
	assert.EqualValues(t, 10, cfg.Network.MaxAppVersion)
	assert.True(t, cfg.Recorder.Fast)
	assert.True(t, cfg.Recorder.FastDedicatedAccount)
	assert.True(t, cfg.Gate.Fast.Enabled)
	assert.True(t, cfg.Gate.Fast.OwnNode)
	assert.Equal(t, []string{DevNamespace()}, cfg.Gate.Fast.PendingNamespaces)
	assert.Equal(t, DevNamespace(), cfg.Recorder.Namespace)
	assert.Equal(t, DevGateID, cfg.Gate.GateID)
	assert.NotEmpty(t, cfg.Policy.MandateFile)
}

func TestDevMandateConsentsToFastMode(t *testing.T) {
	res := runDev(t, filepath.Join(t.TempDir(), "dev"))
	raw, err := os.ReadFile(filepath.Join(res.Home, MandateFile))
	require.NoError(t, err)
	sm, _, err := policy.VerifyMandate(raw)
	require.NoError(t, err)

	assert.Equal(t, DevGateID, sm.Mandate.GateID)
	assert.EqualValues(t, 20, sm.Mandate.FastModeMaxDelay)
	assert.Equal(t, [][]byte{res.Agent.Public}, sm.Mandate.Agents)
	assert.Equal(t, []byte(res.Principal.Public), sm.Mandate.Principal)
	assert.Equal(t, "cosmos:"+DevCelestiaChainID+"/utia", sm.Mandate.Assets[0].Asset)
}

func TestDevEdictaConfigValidates(t *testing.T) {
	res := runDev(t, filepath.Join(t.TempDir(), "dev"))
	cfg, err := config.LoadValid(filepath.Join(res.Home, config.FileName), nil, config.Builtin{})
	require.NoError(t, err)

	assert.Equal(t, DevCelestiaChainID, cfg.Network.ChainID)
	assert.Equal(t, DevEdenChainID, cfg.Network.EVM.ChainID)
	assert.Equal(t, res.Payer.Address, cfg.Signer.PayerAddress)
	assert.Equal(t, DevNamespace(), cfg.Recorder.Namespace)
}

func TestDevNamespaceIsAValidUserNamespace(t *testing.T) {
	require.NoError(t, config.CheckNamespace("namespace", DevNamespace()))
}

func TestDevKeysDifferAcrossHomes(t *testing.T) {
	a := runDev(t, filepath.Join(t.TempDir(), "a"))
	b := runDev(t, filepath.Join(t.TempDir(), "b"))
	assert.NotEqual(t, a.Payer.Address, b.Payer.Address, "dev keys are generated per volume, never shared")
	assert.NotEqual(t, a.Agent.Public, b.Agent.Public)
}

func TestRunDevRefusesAMandateOfAnotherGate(t *testing.T) {
	home := filepath.Join(t.TempDir(), "dev")
	res := runDev(t, home)
	// A mandate bound to another gate is somebody else's file, not ours to use.
	b, err := signStarterMandate(mandateParams{
		principalPath: filepath.Join(res.Home, "keys", "principal.ed25519"),
		principal:     res.Principal.Public,
		gateID:        "some-other-gate",
		agent:         res.Agent.Public,
		asset:         "eip155:1/erc20:0x0000000000000000000000000000000000000001",
		perPayment:    1, perHour: 1,
		now: time.Unix(1_800_000_000, 0),
	})
	require.NoError(t, err)
	path := filepath.Join(res.Home, MandateFile)
	require.NoError(t, os.Remove(path))
	require.NoError(t, os.WriteFile(path, b, 0o600))

	_, err = RunDev(DevConfig{Home: home})
	require.ErrorIs(t, err, ErrExisting)
}

func TestDevConfigValidateBasic(t *testing.T) {
	assert.ErrorIs(t, DevConfig{}.ValidateBasic(), ErrConfig)
	assert.ErrorIs(t, DevConfig{Home: "x", FastDelay: 3}.ValidateBasic(), ErrConfig)
	assert.ErrorIs(t, DevConfig{Home: "x", FastDelay: 101}.ValidateBasic(), ErrConfig)
	assert.NoError(t, DevConfig{Home: "x", FastDelay: 20}.ValidateBasic())
}

func TestRunDevRefusesAForeignHomeBeforeWriting(t *testing.T) {
	home := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(home, "edicta.toml"), []byte("x"), 0o600))

	_, err := RunDev(DevConfig{Home: home})
	require.ErrorIs(t, err, ErrConfig)
	entries, err := os.ReadDir(home)
	require.NoError(t, err)
	assert.Len(t, entries, 1, "nothing was written")
}

func TestRunDevNeverSignsWithAnExistingPrincipalKey(t *testing.T) {
	home := filepath.Join(t.TempDir(), "dev")
	res := runDev(t, home)
	require.NoError(t, os.Remove(filepath.Join(res.Home, MandateFile)))

	_, err := RunDev(DevConfig{Home: home})
	require.ErrorIs(t, err, ErrExisting)
	_, err = os.Stat(filepath.Join(res.Home, MandateFile))
	assert.True(t, os.IsNotExist(err))
}
