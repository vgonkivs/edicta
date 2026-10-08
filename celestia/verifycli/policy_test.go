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
