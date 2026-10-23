package verifycli

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Exit codes: 0 valid, 1 invalid, 2 unchecked (inconclusive: a source or an
// input did not let a check run to a result), 3 not authorized (pending or
// rejected), 4 usage or unreadable input.
const (
	exitValid         = 0
	exitInvalid       = 1
	exitUnchecked     = 2
	exitNotAuthorized = 3
	exitUsage         = 4
)

func TestVerifyOfflineWithTrustedHeaderFile(t *testing.T) {
	s := newScenario(t, scenarioOpts{})
	trusted := s.chain.trustedFile(t, checkpointH, nil)
	code, out := exec(t, s.args("verify", "--trusted", trusted))

	assert.Equal(t, exitValid, code, out)
	for _, line := range []string{
		"[ok] envelope", "[ok] action", "[ok] authorization", "[ok] payload", "[ok] anchor", "[ok] header_trust",
	} {
		assert.Contains(t, out, line)
	}
	assert.Contains(t, out, "verdict: valid")
	assert.NotContains(t, out, "[FAIL]")
	assert.NotContains(t, out, "\x1b[", "no colour codes when stdout is not a terminal")
}

func TestVerifyWithoutTrustedHeaderIsUnchecked(t *testing.T) {
	s := newScenario(t, scenarioOpts{})
	code, out := exec(t, s.args("verify"))
	assert.Equal(t, exitUnchecked, code, out)
	assert.Contains(t, out, "[unchecked] header_trust")
	assert.Contains(t, out, "reason: no_trusted_header")
	assert.Contains(t, out, "advice: supply a trusted header")
	assert.Contains(t, out, "verdict: unchecked")
	assert.NotContains(t, out, "verdict: valid")
}

// A damaged copy is a source problem: the verdict is inconclusive, and the
// report says which check, why, and what to try.
func TestVerifyTamperIsInconclusive(t *testing.T) {
	s := newScenario(t, scenarioOpts{tamperBlob: true})
	trusted := s.chain.trustedFile(t, checkpointH, nil)
	code, out := exec(t, s.args("verify", "--trusted", trusted))

	assert.Equal(t, exitUnchecked, code, out)
	assert.Contains(t, out, "[unchecked] payload")
	assert.Contains(t, out, "reason: source_corrupt")
	assert.Contains(t, out, "advice: another copy")
	assert.Contains(t, out, "verdict: unchecked")
	assert.NotContains(t, out, "[FAIL]")
	assert.NotContains(t, out, "verdict: valid")
	assert.NotContains(t, out, "verdict: invalid")
}

// What verified data proves about the decision still fails.
func TestVerifyAGateSignedContradictionIsInvalid(t *testing.T) {
	s := newScenario(t, scenarioOpts{outlivingAuth: true})
	trusted := s.chain.trustedFile(t, checkpointH, nil)
	code, out := exec(t, s.args("verify", "--trusted", trusted))

	assert.Equal(t, exitInvalid, code, out)
	assert.Contains(t, out, "[FAIL] authorization")
	assert.Contains(t, out, "verdict: invalid")
}

func TestVerifyPendingIsNotAuthorized(t *testing.T) {
	s := newScenario(t, scenarioOpts{pending: true})
	trusted := s.chain.trustedFile(t, checkpointH, nil)
	code, out := exec(t, s.args("verify", "--trusted", trusted))
	assert.Equal(t, exitNotAuthorized, code, out)
	assert.Contains(t, out, "pending")
	assert.NotContains(t, out, "verdict: valid")
	assert.NotContains(t, strings.ToLower(out), "authorized: true")
}

func TestVerifyHeaderTrustFailures(t *testing.T) {
	t.Run("bundled header substituted", func(t *testing.T) {
		s := newScenario(t, scenarioOpts{})
		trusted := s.chain.trustedFile(t, checkpointH, func(hs [][]byte) {
			hd := s.chain.hdrs[anchorHeight+4]
			hd.AppHash = filler("forged", 1)
			hs[4] = encodeHeader(t, hd)
		})
		code, out := exec(t, s.args("verify", "--trusted", trusted))
		assert.Equal(t, exitUnchecked, code, out)
		assert.Contains(t, out, "[unchecked] header_trust")
		assert.Contains(t, out, "reason: chain_mismatch")
		assert.NotContains(t, out, "[FAIL]")
	})
	t.Run("checkpoint below the anchor height", func(t *testing.T) {
		s := newScenario(t, scenarioOpts{})
		trusted := s.chain.trustedFile(t, anchorHeight-1, nil)
		code, out := exec(t, s.args("verify", "--trusted", trusted))
		assert.Equal(t, exitUnchecked, code, out)
		assert.Contains(t, out, "[unchecked] header_trust")
		assert.Contains(t, out, "reason: header_above_checkpoint")
		assert.Contains(t, out, "checkpoint")
	})
}

func TestVerifyUnknownDecision(t *testing.T) {
	s := newScenario(t, scenarioOpts{})
	s.hash[0] ^= 1
	code, out := exec(t, s.args("verify"))
	assert.Equal(t, exitUnchecked, code, out)
	assert.Contains(t, out, "[unchecked] decision")
	assert.Contains(t, out, "reason: decision_unavailable")
	assert.Contains(t, out, "advice: another archive copy")
	assert.Contains(t, out, "state: unknown")
	assert.NotContains(t, out, "[FAIL]")
}

func TestUsageErrors(t *testing.T) {
	s := newScenario(t, scenarioOpts{})
	trusted := s.chain.trustedFile(t, checkpointH, nil)
	hex := strings.Repeat("ab", 32)
	tests := []struct {
		name string
		args []string
	}{
		{"no command", nil},
		{"unknown command", []string{"frobnicate"}},
		{"no hash", []string{"verify", "--archive", s.archiveDir, "--gate-key", s.gateKey}},
		{"bad hash", []string{"verify", "--archive", s.archiveDir, "--gate-key", s.gateKey, "zz"}},
		{"no archive", []string{"verify", "--gate-key", s.gateKey, hex}},
		{"no gate key", []string{"verify", "--archive", s.archiveDir, hex}},
		{"bad gate key", []string{"verify", "--archive", s.archiveDir, "--gate-key", "00", hex}},
		{"missing archive dir", []string{"verify", "--archive", s.archiveDir + "/nope", "--gate-key", s.gateKey, hex}},
		{"missing trusted file", []string{"verify", "--archive", s.archiveDir, "--gate-key", s.gateKey, "--trusted", trusted + ".missing", hex}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			code, out := exec(t, tc.args)
			assert.Equal(t, exitUsage, code, out)
			assert.NotEmpty(t, out)
		})
	}
	t.Run("malformed trusted file", func(t *testing.T) {
		bad := t.TempDir() + "/bad.json"
		require.NoError(t, writeFile(bad, "{not json"))
		code, out := exec(t, s.args("verify", "--trusted", bad))
		assert.Equal(t, exitUsage, code, out)
	})
}

func TestVerifyJSON(t *testing.T) {
	s := newScenario(t, scenarioOpts{})
	trusted := s.chain.trustedFile(t, checkpointH, nil)
	code, out := exec(t, s.args("verify", "--json", "--trusted", trusted))
	require.Equal(t, exitValid, code, out)

	var rep map[string]any
	require.NoError(t, json.Unmarshal([]byte(out), &rep), "the output is one JSON document")
	assert.Equal(t, "valid", rep["verdict"])
	assert.Equal(t, "authorized", rep["state"])
	assert.Equal(t, true, rep["authorization_verified"])
	assert.Equal(t, hexOf(s.hash[:]), rep["commitment_hash"])
	checks, ok := rep["checks"].([]any)
	require.True(t, ok)
	status := map[string]string{}
	for _, c := range checks {
		m := c.(map[string]any)
		status[m["name"].(string)] = m["status"].(string)
	}
	for _, n := range []string{"envelope", "action", "authorization", "payload", "anchor", "header_trust"} {
		assert.Equal(t, "pass", status[n], n)
	}
	ht, ok := rep["header_trust"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "valid", ht["status"])
	assert.EqualValues(t, checkpointH, ht["checkpoint_height"])
	assert.Equal(t, "off", ht["cross_check"])
}

func TestVerifyJSONReportsTheReasonAndTheAdvice(t *testing.T) {
	s := newScenario(t, scenarioOpts{tamperBlob: true})
	trusted := s.chain.trustedFile(t, checkpointH, nil)
	code, out := exec(t, s.args("verify", "--json", "--trusted", trusted))
	assert.Equal(t, exitUnchecked, code)
	var rep map[string]any
	require.NoError(t, json.Unmarshal([]byte(out), &rep))
	assert.Equal(t, "unchecked", rep["verdict"])
	found := false
	for _, c := range rep["checks"].([]any) {
		m := c.(map[string]any)
		if m["name"] == "payload" {
			found = true
			assert.Equal(t, "unchecked", m["status"])
			assert.Equal(t, "source_corrupt", m["reason"])
			assert.Equal(t, "another copy", m["advice"])
			assert.NotEmpty(t, m["error"])
		}
	}
	assert.True(t, found)
}

func TestVerifyJSONOfAFailureKeepsTheExitCode(t *testing.T) {
	s := newScenario(t, scenarioOpts{outlivingAuth: true})
	trusted := s.chain.trustedFile(t, checkpointH, nil)
	code, out := exec(t, s.args("verify", "--json", "--trusted", trusted))
	assert.Equal(t, exitInvalid, code)
	var rep map[string]any
	require.NoError(t, json.Unmarshal([]byte(out), &rep))
	assert.Equal(t, "invalid", rep["verdict"])
	for _, c := range rep["checks"].([]any) {
		m := c.(map[string]any)
		if m["name"] == "authorization" {
			assert.Equal(t, "fail", m["status"])
			assert.NotContains(t, m, "reason", "a finding has no reason of the closed set, only the rule that failed")
			assert.NotEmpty(t, m["error"])
		}
	}
}

func TestReplay(t *testing.T) {
	s := newScenario(t, scenarioOpts{})
	trusted := s.chain.trustedFile(t, checkpointH, nil)

	code, out := exec(t, s.args("replay", "--trusted", trusted))
	assert.Equal(t, exitValid, code, out)
	assert.Contains(t, out, "[ok] retention replay")
	assert.Contains(t, out, "consistent")

	code, out = exec(t, s.args("replay", "--json", "--trusted", trusted))
	require.Equal(t, exitValid, code, out)
	var rep map[string]any
	require.NoError(t, json.Unmarshal([]byte(out), &rep))
	k2, ok := rep["retention_replay"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, true, k2["replayable"])
	assert.Equal(t, true, k2["consistent"])
}
