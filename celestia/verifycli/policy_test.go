package verifycli

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/verifier"
)

func violatedReport(v verifier.Verdict) verifier.Report {
	var h commitment.Hash
	h[0] = 7
	return verifier.Report{
		Verdict: v,
		GateIntegrity: verifier.GateIntegrity{
			Status: verifier.IntegrityViolated, Reason: verifier.ReasonGateEquivocation,
			Evidence: [][]byte{{1, 2}}, EvidenceHashes: []commitment.Hash{h},
		},
		Checks: []verifier.Check{{Name: verifier.CheckPolicy, Status: verifier.StatusUnchecked, Reason: verifier.ReasonBlocked}},
	}
}

func TestExitCodePrecedence(t *testing.T) {
	assert.Equal(t, codeGateIntegrity, codeFor(violatedReport(verifier.VerdictUnchecked)))
	assert.Equal(t, codeInvalid, codeFor(violatedReport(verifier.VerdictInvalid)), "an invalid decision stays 1")
	assert.Equal(t, codeUnchecked, codeFor(verifier.Report{Verdict: verifier.VerdictUnchecked}))
	assert.Equal(t, codeValid, codeFor(verifier.Report{Verdict: verifier.VerdictValid}))
	assert.Equal(t, codeNotAuthorized, codeFor(verifier.Report{Verdict: verifier.VerdictNotAuthorized}))
}

func TestBannerIsFirstLineAlsoWithExit1(t *testing.T) {
	for _, v := range []verifier.Verdict{verifier.VerdictUnchecked, verifier.VerdictInvalid} {
		var out bytes.Buffer
		writeText(&out, viewOf(violatedReport(v)), false)
		first, _, _ := strings.Cut(out.String(), "\n")
		assert.Equal(t, "GATE INTEGRITY VIOLATED (gate_equivocation)", first)
	}
	var out bytes.Buffer
	writeText(&out, viewOf(verifier.Report{Verdict: verifier.VerdictValid}), false)
	assert.NotContains(t, out.String(), "GATE INTEGRITY VIOLATED")
}

func TestJSONAlwaysCarriesGateIntegrity(t *testing.T) {
	var out bytes.Buffer
	require.NoError(t, writeJSON(&out, viewOf(verifier.Report{Verdict: verifier.VerdictValid})))
	var m map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(out.Bytes(), &m))
	var gi integrityView
	require.NoError(t, json.Unmarshal(m["gate_integrity"], &gi))
	assert.Equal(t, "not_checked", gi.Status)

	out.Reset()
	require.NoError(t, writeJSON(&out, viewOf(violatedReport(verifier.VerdictUnchecked))))
	require.NoError(t, json.Unmarshal(out.Bytes(), &m))
	require.NoError(t, json.Unmarshal(m["gate_integrity"], &gi))
	assert.Equal(t, "violated", gi.Status)
	assert.Equal(t, "gate_equivocation", gi.Reason)
	assert.Equal(t, []string{"0102"}, gi.Evidence)
	assert.Len(t, gi.EvidenceHashes, 1)
}

func TestPolicyFlags(t *testing.T) {
	hash := strings.Repeat("ab", 32)
	key := strings.Repeat("cd", 32)
	var out bytes.Buffer
	f, err := parseFlags([]string{
		"verify", hash, "--gate-key", key, "--archive", t.TempDir(), "--require-policy", "--policy-full",
		"--principal-key", key + "," + strings.Repeat("ef", 32), "--policy-evidence", "a.bin", "--policy-evidence", "b.bin",
	}, &out)
	require.NoError(t, err)
	assert.True(t, f.requirePolicy)
	assert.True(t, f.policyFull)
	assert.Len(t, f.principalKeys, 2)
	assert.Equal(t, []string{"a.bin", "b.bin"}, f.evidencePaths)

	_, err = parseFlags([]string{"verify", hash, "--gate-key", key, "--archive", t.TempDir(), "--principal-key", "zz"}, &out)
	var ue usageError
	require.ErrorAs(t, err, &ue)
}

func TestPrincipalKeyRepeatsAndMaxWalkSteps(t *testing.T) {
	hash := strings.Repeat("ab", 32)
	key := strings.Repeat("cd", 32)
	base := []string{"verify", hash, "--gate-key", key, "--archive", t.TempDir()}
	var out bytes.Buffer
	f, err := parseFlags(append(base[:len(base):len(base)],
		"--max-walk-steps", "50",
		"--principal-key", strings.Repeat("01", 32), "--principal-key", strings.Repeat("02", 32)+","+strings.Repeat("03", 32),
	), &out)
	require.NoError(t, err)
	assert.Len(t, f.principalKeys, 3)
	assert.Equal(t, 50, f.maxWalkSteps)

	f, err = parseFlags(base, &out)
	require.NoError(t, err)
	assert.Equal(t, verifier.DefaultMaxWalkSteps, f.maxWalkSteps)
}

func TestMaxWalkStepsBelowOneIsAUsageError(t *testing.T) {
	hash := strings.Repeat("ab", 32)
	key := strings.Repeat("cd", 32)
	for _, flag := range []string{"--max-walk-steps", "--policy-depth"} {
		for _, n := range []string{"0", "-1"} {
			t.Run(flag+" "+n, func(t *testing.T) {
				var out bytes.Buffer
				_, err := parseFlags([]string{"verify", hash, "--gate-key", key, "--archive", t.TempDir(), flag, n}, &out)
				var ue usageError
				require.ErrorAs(t, err, &ue)
				assert.Contains(t, err.Error(), "--max-walk-steps")
			})
		}
	}
}

func TestPolicyDepthIsAnAliasOfMaxWalkSteps(t *testing.T) {
	hash := strings.Repeat("ab", 32)
	key := strings.Repeat("cd", 32)
	var out bytes.Buffer
	f, err := parseFlags([]string{"verify", hash, "--gate-key", key, "--archive", t.TempDir(), "--policy-depth", "7"}, &out)
	require.NoError(t, err)
	assert.Equal(t, 7, f.maxWalkSteps)
}

func walkReport(end verifier.WalkEnd, status verifier.IntegrityStatus, reason verifier.Reason) verifier.Report {
	return verifier.Report{
		Verdict: verifier.VerdictValid,
		GateIntegrity: verifier.GateIntegrity{
			Status: status, Reason: reason,
			Walk: &verifier.WalkInfo{MaxSteps: 2, Steps: 2, FromSeq: 1, ToSeq: 3, Total: 4, End: end},
		},
	}
}

func TestWalkTextLineAndTruncationAdvice(t *testing.T) {
	var out bytes.Buffer
	writeText(&out, viewOf(walkReport(verifier.WalkEndMaxSteps, verifier.IntegrityUnchecked, verifier.ReasonPolicyWalkTruncated)), false)
	assert.Contains(t, out.String(),
		"gate integrity walk: last 3 of 4 verdicts checked (seq 1 to 3, 2 of at most 2 steps, ended at max_steps)\n")
	assert.Contains(t, out.String(), "    advice: raise --max-walk-steps above 3 to walk to genesis\n")
	assert.Equal(t, codeValid, codeFor(walkReport(verifier.WalkEndMaxSteps, verifier.IntegrityUnchecked, verifier.ReasonPolicyWalkTruncated)))

	out.Reset()
	writeText(&out, viewOf(walkReport(verifier.WalkEndGenesis, verifier.IntegrityOK, "")), false)
	assert.Contains(t, out.String(), "ended at genesis)")
	assert.NotContains(t, out.String(), "advice:")

	out.Reset()
	writeText(&out, viewOf(verifier.Report{Verdict: verifier.VerdictValid}), false)
	assert.NotContains(t, out.String(), "gate integrity walk")
}

func TestJSONWalkFieldIsOmittedWithoutAWalk(t *testing.T) {
	gi := func(r verifier.Report) map[string]json.RawMessage {
		var out bytes.Buffer
		require.NoError(t, writeJSON(&out, viewOf(r)))
		var m map[string]json.RawMessage
		require.NoError(t, json.Unmarshal(out.Bytes(), &m))
		var g map[string]json.RawMessage
		require.NoError(t, json.Unmarshal(m["gate_integrity"], &g))
		return g
	}
	assert.NotContains(t, gi(verifier.Report{Verdict: verifier.VerdictValid}), "walk")

	g := gi(walkReport(verifier.WalkEndMaxSteps, verifier.IntegrityUnchecked, verifier.ReasonPolicyWalkTruncated))
	assert.JSONEq(t, `{"max_steps":2,"steps":2,"from_seq":1,"to_seq":3,"total":4,"end":"max_steps"}`, string(g["walk"]))
	assert.JSONEq(t, `"policy_walk_truncated"`, string(g["reason"]))
}
