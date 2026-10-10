package verifycli

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/verifier"
)

func policyJSON(t *testing.T, info *verifier.PolicyInfo) map[string]json.RawMessage {
	t.Helper()
	var out bytes.Buffer
	require.NoError(t, writeJSON(&out, viewOf(verifier.Report{Verdict: verifier.VerdictUnchecked, Policy: info})))
	var top map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(out.Bytes(), &top))
	var pol map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(top["policy"], &pol))
	return pol
}

// A private verdict that was not opened prints no seq, times or facts, and
// its state hashes are the public ones.
func TestKeylessPrivateReportLeavesOutWhatItCannotKnow(t *testing.T) {
	prev, next := commitment.Hash{1, 2}, commitment.Hash{3, 4}
	pol := policyJSON(t, &verifier.PolicyInfo{
		Mode: verifier.PolicyModePrivate, ContentPrivate: true, PrevStateHash: prev, NewStateHash: next,
	})
	for _, k := range []string{"seq", "anchor_time", "eval_time", "extractor", "kind", "asset", "amount", "scale"} {
		assert.NotContains(t, pol, k)
	}
	assert.JSONEq(t, `"`+hex.EncodeToString(prev[:])+`"`, string(pol["prev_state_hash"]))
	assert.JSONEq(t, `"`+hex.EncodeToString(next[:])+`"`, string(pol["new_state_hash"]))

	var text bytes.Buffer
	writeText(&text, viewOf(verifier.Report{Verdict: verifier.VerdictUnchecked, Policy: &verifier.PolicyInfo{
		Mode: verifier.PolicyModePrivate, ContentPrivate: true, MandateID: []byte{1}, Version: 2,
	}}), false)
	assert.Contains(t, text.String(), "private part was not opened")
	assert.NotContains(t, text.String(), "counter position")

	// An opened or public verdict prints seq 0 at genesis.
	pol = policyJSON(t, &verifier.PolicyInfo{Mode: verifier.PolicyModePublic})
	assert.JSONEq(t, "0", string(pol["seq"]))
	assert.JSONEq(t, "0", string(pol["anchor_time"]))
}
