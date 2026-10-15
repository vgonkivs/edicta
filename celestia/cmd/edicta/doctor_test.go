package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/celestia/config"
	"github.com/vgonkivs/edicta/celestia/doctor"
)

const doctorNS = "0000000000000000000000000000000000000000ab000000000000000000"

func doctorConfig(t *testing.T, extra string) string {
	t.Helper()
	h := t.TempDir()
	body := `
[network]
celestia = "mocha"
settlement = "base-sepolia"

[agent]
id = "agent-1"
key_file = "` + h + `/agent.ed25519"

[gate]
gate_id = "gate-1"
key_file = "` + h + `/gate.ed25519"
registry_path = "` + h + `/registry.db"
allowlist_file = "` + h + `/agents.toml"
action_types = ["application/vnd.edicta.x402.exact-evm.v1+cbor"]
executor_keys = ["` + strings.Repeat("00", 31) + `01"]

[recorder]
keyring_dir = "` + h + `/keyring"
key_name = "recorder"
passphrase_file = "` + h + `/keyring/recorder.pass"
namespace = "` + strings.Repeat("00", 19) + "ab" + strings.Repeat("00", 9) + `"

[archive]
dir = "` + h + `/archive"
` + extra
	p := filepath.Join(h, "edicta.toml")
	require.NoError(t, os.WriteFile(p, []byte(body), 0o600))
	return p
}

// probeCheck records the config the checks of a run saw.
type probeCheck struct {
	seen *config.Config
	res  doctor.Result
}

func (probeCheck) Name() string { return "probe" }
func (p probeCheck) Run(_ context.Context, c config.Config) doctor.Result {
	*p.seen = c
	return p.res
}

// useFakeChecks replaces the network checks with one recording check.
func useFakeChecks(t *testing.T, res doctor.Result) *config.Config {
	t.Helper()
	oldEnv, oldChecks := doctorEnv, doctorChecks
	t.Cleanup(func() { doctorEnv, doctorChecks = oldEnv, oldChecks })
	seen := new(config.Config)
	doctorEnv = func() *doctor.Env { return &doctor.Env{} }
	doctorChecks = func(_ *doctor.Env, cc doctor.Check) []doctor.Check {
		return []doctor.Check{cc, probeCheck{seen: seen, res: res}}
	}
	return seen
}

func TestDoctorGoodConfigExitsZero(t *testing.T) {
	seen := useFakeChecks(t, doctor.Result{Status: doctor.OK, Cause: "fine"})
	p := doctorConfig(t, "")
	code, out := edicta(t, "doctor", "--config", p)
	assert.Equal(t, exitValid, code, out)
	assert.Contains(t, out, "config")
	assert.Contains(t, out, "mocha")
	assert.Equal(t, "agent-1", seen.Agent.ID)
}

func TestDoctorFailedCheckExitsNonZero(t *testing.T) {
	useFakeChecks(t, doctor.Result{Status: doctor.Fail, Cause: "broken", Fix: "repair"})
	code, out := edicta(t, "doctor", "--config", doctorConfig(t, ""))
	assert.Equal(t, exitInvalid, code)
	assert.Contains(t, out, "repair")
}

func TestDoctorLoadErrorRunsOnlyTheConfigCheck(t *testing.T) {
	seen := useFakeChecks(t, doctor.Result{Status: doctor.OK})
	p := filepath.Join(t.TempDir(), "edicta.toml")
	require.NoError(t, os.WriteFile(p, []byte("[network]\ncelestia = \"nowhere\"\n"), 0o600))
	code, out := edicta(t, "doctor", "--config", p, "--json")
	assert.Equal(t, exitInvalid, code)
	var doc struct {
		OK     bool `json:"ok"`
		Checks []struct{ Name, Status string }
	}
	require.NoError(t, json.Unmarshal([]byte(out), &doc), out)
	require.Len(t, doc.Checks, 1)
	assert.Equal(t, "config", doc.Checks[0].Name)
	assert.Equal(t, "fail", doc.Checks[0].Status)
	assert.False(t, doc.OK)
	assert.Empty(t, seen.Agent, "no other check ran")
}

func TestDoctorMissingConfigFileFails(t *testing.T) {
	useFakeChecks(t, doctor.Result{Status: doctor.OK})
	code, out := edicta(t, "doctor", "--config", filepath.Join(t.TempDir(), "absent.toml"))
	assert.Equal(t, exitInvalid, code)
	assert.Contains(t, out, "config")
}

func TestDoctorSetOverridesAKey(t *testing.T) {
	seen := useFakeChecks(t, doctor.Result{Status: doctor.OK})
	code, out := edicta(t, "doctor", "--config", doctorConfig(t, ""), "--set", `agent.id="other"`)
	assert.Equal(t, exitValid, code, out)
	assert.Equal(t, "other", seen.Agent.ID)
}

func TestDoctorSetUnknownKeyIsRefused(t *testing.T) {
	seen := useFakeChecks(t, doctor.Result{Status: doctor.OK})
	code, out := edicta(t, "doctor", "--config", doctorConfig(t, ""), "--set", "agent.nonsense=1")
	assert.Equal(t, exitInvalid, code)
	assert.Contains(t, out, "nonsense")
	assert.Empty(t, seen.Agent)
}

func TestDoctorUsageErrors(t *testing.T) {
	useFakeChecks(t, doctor.Result{Status: doctor.OK})
	for _, args := range [][]string{
		{"doctor", "--set", "novalue"},
		{"doctor", "--set", "=x"},
		{"doctor", "--bogus"},
		{"doctor", "extra"},
	} {
		code, out := edicta(t, args...)
		assert.Equal(t, exitUsage, code, "%v: %s", args, out)
		assert.Contains(t, out, "edicta doctor:")
	}
}

func TestDoctorJSONParses(t *testing.T) {
	useFakeChecks(t, doctor.Result{Status: doctor.Warn, Cause: "slow", Fix: "wait"})
	code, out := edicta(t, "doctor", "--json", "--config", doctorConfig(t, ""))
	assert.Equal(t, exitValid, code, "a warning does not fail the run")
	var doc struct {
		OK     bool `json:"ok"`
		Checks []struct{ Name, Status string }
	}
	require.NoError(t, json.Unmarshal([]byte(out), &doc), out)
	assert.True(t, doc.OK)
	require.Len(t, doc.Checks, 2)
	assert.Equal(t, "warn", doc.Checks[1].Status)
}
