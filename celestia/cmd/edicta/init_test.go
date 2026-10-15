package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/celestia/config"
	"github.com/vgonkivs/edicta/celestia/doctor"
	"github.com/vgonkivs/edicta/celestia/initcmd"
)

// useInitEnv gives init an environment with no probes, so every preflight
// check fails without touching the network.
func useInitEnv(t *testing.T) {
	t.Helper()
	old := initEnv
	t.Cleanup(func() { initEnv = old })
	initEnv = func() *doctor.Env { return &doctor.Env{} }
}

func TestInitFailedPreflightCreatesNoHome(t *testing.T) {
	useInitEnv(t)
	home := filepath.Join(t.TempDir(), "edicta")
	code, out := edicta(t, "init", "--home", home)
	assert.Equal(t, exitInvalid, code)
	assert.Contains(t, out, "preflight")
	assert.Contains(t, out, "fail")
	assert.NoDirExists(t, home)
}

func TestInitPassesTheFlags(t *testing.T) {
	useInitEnv(t)
	old := initRun
	t.Cleanup(func() { initRun = old })
	var got initcmd.Config
	initRun = func(_ context.Context, c initcmd.Config, _ *doctor.Env, _ config.Presets) (initcmd.Result, error) {
		got = c
		return initcmd.Result{
			Home:  c.Home,
			Payer: &initcmd.Payer{Path: "/k/payer", Address: "0xabc", Status: initcmd.Created},
		}, nil
	}
	code, out := edicta(t, "init", "--home", "/h", "--preset", "mocha+none", "--set", "network.consensus_grpc.addr=localhost:9090")
	require.Equal(t, 0, code, out)
	assert.Equal(t, initcmd.Config{Home: "/h", Preset: "mocha+none", Overrides: map[string]string{"network.consensus_grpc.addr": "localhost:9090"}}, got)
	assert.Contains(t, out, "0xabc")
}

func TestInitDefaultsToTheEdictaHome(t *testing.T) {
	useInitEnv(t)
	home := filepath.Join(t.TempDir(), "h")
	t.Setenv(config.EnvHome, home)
	old := initRun
	t.Cleanup(func() { initRun = old })
	var got initcmd.Config
	initRun = func(_ context.Context, c initcmd.Config, _ *doctor.Env, _ config.Presets) (initcmd.Result, error) {
		got = c
		return initcmd.Result{}, nil
	}
	code, out := edicta(t, "init")
	require.Equal(t, 0, code, out)
	assert.Equal(t, home, got.Home)
	assert.Equal(t, initcmd.DefaultPreset, got.Preset)
}

func TestInitUsageErrors(t *testing.T) {
	useInitEnv(t)
	home := filepath.Join(t.TempDir(), "edicta")
	for name, args := range map[string][]string{
		"unknown flag":       {"init", "--bogus"},
		"extra argument":     {"init", "--home", home, "extra"},
		"set without equals": {"init", "--home", home, "--set", "network.chain_id"},
		"bad preset":         {"init", "--home", home, "--preset", "mocha"},
		"non-network set":    {"init", "--home", home, "--set", "recorder.key_name=x"},
		"unavailable preset": {"init", "--home", home, "--preset", "celestia-mainnet+base"},
	} {
		code, out := edicta(t, args...)
		assert.Equal(t, exitUsage, code, name+": "+out)
	}
	_, err := os.Stat(home)
	assert.True(t, os.IsNotExist(err))
}

func TestParseUSDC(t *testing.T) {
	for in, want := range map[string]uint64{
		"1": 1_000_000, "0.10": 100_000, ".5": 500_000, "0.000001": 1, "12.345678": 12_345_678, "007": 7_000_000, "1.": 1_000_000,
	} {
		got, err := parseUSDC(in)
		require.NoError(t, err, in)
		assert.Equal(t, want, got, in)
	}
	for _, in := range []string{"", ".", "0", "0.0", "0.0000001", "-1", "1e3", "1,5", " 1", "99999999999999999999"} {
		_, err := parseUSDC(in)
		assert.Error(t, err, in)
	}
}

func TestInitPassesTheLimits(t *testing.T) {
	useInitEnv(t)
	old := initRun
	t.Cleanup(func() { initRun = old })
	var got initcmd.Config
	initRun = func(_ context.Context, c initcmd.Config, _ *doctor.Env, _ config.Presets) (initcmd.Result, error) {
		got = c
		return initcmd.Result{Home: c.Home}, nil
	}
	code, out := edicta(t, "init", "--home", "/h", "--max-per-payment", "0.25", "--max-per-hour", "3")
	require.Equal(t, 0, code, out)
	assert.Equal(t, uint64(250_000), got.MaxPerPayment)
	assert.Equal(t, uint64(3_000_000), got.MaxPerHour)

	code, out = edicta(t, "init", "--home", "/h", "--max-per-payment", "lots")
	assert.Equal(t, exitUsage, code, out)
	assert.Contains(t, out, "--max-per-payment")
}
