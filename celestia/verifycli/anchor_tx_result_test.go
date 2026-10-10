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

const anchorTxResultLine = "Informational: anchor tx result: code 0, node-reported, not part of the claim"

func renderReport(t *testing.T, r verifier.Report) (string, map[string]any) {
	t.Helper()
	v := viewOf(r)
	var text bytes.Buffer
	writeText(&text, v, false)
	var js bytes.Buffer
	require.NoError(t, writeJSON(&js, v))
	var m map[string]any
	require.NoError(t, json.Unmarshal(js.Bytes(), &m))
	return text.String(), m
}

func fastValid(da commitment.DA, txResult string) verifier.Report {
	return verifier.Report{
		Verdict:        verifier.VerdictValid,
		DA:             da,
		Settlement:     "node-attested",
		AnchorTxResult: txResult,
		Authorization:  &verifier.AuthorizationInfo{Version: commitment.Version, Mode: commitment.ModeFast},
		Fast:           &verifier.FastInfo{H0: 10, AnchorDeadline: 13, AnchorHeight: 11, Publication: verifier.PublicationAnchored},
	}
}

func TestAnchorTxResultReport(t *testing.T) {
	t.Run("fibre, fast: after the Proven line, not under assumptions", func(t *testing.T) {
		out, m := renderReport(t, fastValid(commitment.DAFibre, verifier.AnchorTxResultText))
		assert.Equal(t, "code 0, node-reported, not part of the claim", m["anchor_tx_result"])
		as, ok := m["assumptions"].([]any)
		require.True(t, ok)
		for _, a := range as {
			assert.NotContains(t, a, "anchor tx result")
		}
		assert.Equal(t, 1, strings.Count(out, anchorTxResultLine), out)
		proven := strings.Index(out, "Proven: payload bytes match the commitment; anchored on L1 no later than T_H (anchor inclusion proven);")
		info := strings.Index(out, anchorTxResultLine)
		attested := strings.Index(out, "Attested by the gate (not proven)")
		require.GreaterOrEqual(t, proven, 0, out)
		assert.Less(t, proven, info)
		assert.Less(t, info, attested)
		assert.NotContains(t, out, "Assumptions: anchor tx result")
	})
	t.Run("fibre, strict", func(t *testing.T) {
		r := fastValid(commitment.DAFibre, verifier.AnchorTxResultText)
		r.Fast, r.Authorization.Mode = nil, commitment.ModeStrict
		out, m := renderReport(t, r)
		assert.Equal(t, verifier.AnchorTxResultText, m["anchor_tx_result"])
		assert.NotContains(t, m, "assumptions")
		assert.Equal(t, 1, strings.Count(out, anchorTxResultLine), out)
	})
	t.Run("blob, fast: no field, no line", func(t *testing.T) {
		out, m := renderReport(t, fastValid(commitment.DACelestiaBlob, ""))
		assert.NotContains(t, m, "anchor_tx_result")
		assert.NotContains(t, out, "anchor tx result")
		assert.Contains(t, out, "(anchor inclusion proven)")
	})
}
