package verifycli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVerifyOnAReadOnlyArchiveLeavesItUntouched(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("directory permissions do not bind root")
	}
	s := newScenario(t, scenarioOpts{})
	trusted := s.chain.trustedFile(t, checkpointH, nil)

	old := filepath.Join(s.archiveDir, ".tmp-old")
	require.NoError(t, os.WriteFile(old, []byte("x"), 0o644))
	past := time.Now().Add(-2 * time.Hour)
	require.NoError(t, os.Chtimes(old, past, past))

	var dirs []string
	require.NoError(t, filepath.WalkDir(s.archiveDir, func(p string, e os.DirEntry, err error) error {
		if err == nil && e.IsDir() {
			dirs = append(dirs, p)
		}
		return err
	}))
	for i := len(dirs) - 1; i >= 0; i-- {
		require.NoError(t, os.Chmod(dirs[i], 0o555))
	}
	t.Cleanup(func() {
		for _, d := range dirs {
			_ = os.Chmod(d, 0o755)
		}
	})
	before := listing(t, s.archiveDir)

	for _, cmd := range []string{"verify", "replay"} {
		code, out := exec(t, s.args(cmd, "--trusted", trusted))
		assert.Equal(t, exitValid, code, out)
	}
	assert.FileExists(t, old)
	assert.Equal(t, before, listing(t, s.archiveDir), "no file was created, removed or touched")
}

func listing(t *testing.T, dir string) []string {
	t.Helper()
	var out []string
	require.NoError(t, filepath.WalkDir(dir, func(p string, e os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := e.Info()
		if err != nil {
			return err
		}
		out = append(out, p+" "+info.ModTime().String()+" "+info.Mode().String())
		return nil
	}))
	return out
}

func TestJSONErrorsAreJSON(t *testing.T) {
	s := newScenario(t, scenarioOpts{})
	hex := strings.Repeat("ab", 32)
	tests := []struct {
		name string
		args []string
	}{
		{"no hash", []string{"verify", "--json", "--archive", s.archiveDir, "--gate-key", s.gateKey}},
		{"missing archive", []string{"verify", "--json", "--archive", s.archiveDir + "/nope", "--gate-key", s.gateKey, hex}},
		{"bad flag", []string{"verify", "--json", "--frob", "--archive", s.archiveDir, "--gate-key", s.gateKey, hex}},
		{"json flag last", []string{"verify", "--archive", s.archiveDir, "--gate-key", "00", "--json", hex}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			code, out := exec(t, tc.args)
			assert.Equal(t, exitUsage, code, out)
			var doc map[string]any
			require.NoError(t, json.Unmarshal([]byte(out), &doc), "the output is one JSON document: %q", out)
			msg, ok := doc["error"].(string)
			require.True(t, ok)
			assert.NotEmpty(t, msg)
		})
	}
	t.Run("without the flag the error stays text", func(t *testing.T) {
		code, out := exec(t, []string{"verify"})
		assert.Equal(t, exitUsage, code)
		assert.NotEmpty(t, out)
		assert.False(t, strings.HasPrefix(strings.TrimSpace(out), "{"), "a plain message, not JSON: %q", out)
	})
}

func TestParametersFlagsAndReport(t *testing.T) {
	s := newScenario(t, scenarioOpts{})
	trusted := s.chain.trustedFile(t, checkpointH, nil)

	t.Run("defaults are printed", func(t *testing.T) {
		code, out := exec(t, s.args("verify", "--trusted", trusted))
		require.Equal(t, exitValid, code, out)
		assert.Contains(t, out, "skew 30s")
		assert.Contains(t, out, "blob retention 14400s")
		assert.Contains(t, out, "fibre retention 14400s")
	})
	t.Run("flags reach the report", func(t *testing.T) {
		code, out := exec(t, s.args("verify", "--json", "--skew", "60", "--blob-retention", "7200", "--trusted", trusted))
		require.Equal(t, exitValid, code, out)
		var rep struct {
			Params map[string]uint64 `json:"params"`
		}
		require.NoError(t, json.Unmarshal([]byte(out), &rep))
		assert.Equal(t, uint64(60), rep.Params["skew_s"])
		assert.Equal(t, uint64(7200), rep.Params["blob_retention_s"])
		assert.Equal(t, uint64(14400), rep.Params["fibre_retention_s"])
	})
	t.Run("a blob retention the gate did not use fails the replay", func(t *testing.T) {
		code, out := exec(t, s.args("replay", "--blob-retention", "7200", "--trusted", trusted))
		assert.Equal(t, exitInvalid, code, out)
		assert.Contains(t, out, "retention replay")
		assert.NotContains(t, out, "verdict: valid")
	})
	t.Run("values the gate would refuse are usage errors", func(t *testing.T) {
		for _, a := range [][]string{{"--skew", "301"}, {"--blob-retention", "0"}, {"--skew", "-1"}, {"--blob-retention", "x"}} {
			code, out := exec(t, s.args("verify", a[0], a[1]))
			assert.Equal(t, exitUsage, code, "%v: %s", a, out)
		}
	})
}

func TestReplayJSONFoldsInconsistencyIntoTheVerdict(t *testing.T) {
	s := newScenario(t, scenarioOpts{})
	trusted := s.chain.trustedFile(t, checkpointH, nil)
	code, out := exec(t, s.args("replay", "--json", "--blob-retention", "7200", "--trusted", trusted))
	assert.Equal(t, exitInvalid, code, out)
	var rep map[string]any
	require.NoError(t, json.Unmarshal([]byte(out), &rep))
	assert.Equal(t, "invalid", rep["verdict"])
	var found bool
	for _, c := range rep["checks"].([]any) {
		if m := c.(map[string]any); m["name"] == "retention_replay" {
			found = true
			assert.Equal(t, "fail", m["status"])
		}
	}
	assert.True(t, found)
}

func TestJSONHeaderTrustFieldsAreAlwaysThere(t *testing.T) {
	s := newScenario(t, scenarioOpts{})
	code, out := exec(t, s.args("verify", "--json"))
	require.Equal(t, exitUnchecked, code, out)
	var rep map[string]any
	require.NoError(t, json.Unmarshal([]byte(out), &rep))
	ht, ok := rep["header_trust"].(map[string]any)
	require.True(t, ok)
	for _, k := range []string{"status", "checkpoint_height", "checkpoint_hash", "cross_check"} {
		assert.Contains(t, ht, k)
	}
}
