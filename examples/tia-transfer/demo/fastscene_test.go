package demo

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/celestia/verifycli"
)

// The fast-mode scene: the gate authorizes a pending decision in the block
// of h0, the anchor never lands, and the verifier first cannot decide
// (inside the window), then proves the absence (after the deadline).
func TestFastSceneVerdicts(t *testing.T) {
	var screen bytes.Buffer
	out, err := RunFastScene(t.Context(), FastSceneConfig{Dir: t.TempDir()}, NewScreen(&screen, false, false), verifycli.Run)
	require.NoError(t, err, screen.String())
	assert.Equal(t, ExitOK, out.Code)
	assert.Equal(t, out.H0+fastDelay, out.Deadline)

	w := out.Window
	assert.Equal(t, VerdictInconclusive, w.Verdict, screen.String())
	assert.Equal(t, 2, w.Code)
	assert.Equal(t, "unchecked", w.AnchorStatus)
	assert.Equal(t, "anchor_pending", w.AnchorReason)

	f := out.Final
	assert.Equal(t, VerdictInvalid, f.Verdict, screen.String())
	assert.Equal(t, 1, f.Code)
	assert.Equal(t, "fail", f.AnchorStatus)
	assert.Equal(t, "anchor_absent", f.AnchorReason)
	assert.Equal(t, "failed", f.Publication)
	assert.Equal(t, "absent", f.Absence)
	assert.Equal(t, fastDelay+1, f.Heights)
	require.Len(t, out.RecorderSigner, 20)
	assert.Equal(t, hex.EncodeToString(out.RecorderSigner), f.IntentSigner, "the anchor intent is attributed to the Recorder's account")
	assert.Empty(t, w.IntentSigner, "no attribution while the window is open")

	assert.Contains(t, screen.String(), "VERDICT: INVALID")
}
