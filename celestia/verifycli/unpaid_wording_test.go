package verifycli

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/internal/testkit"
)

// The text and JSON output of anchor_unpaid carry the wording of
// reasons_v1.1.json: a valid verdict needs a paid anchor, so nothing may
// still promise that a later verifier confirms inclusion without the code.
func TestUnpaidOutputWordingIsV11(t *testing.T) {
	raw, err := os.ReadFile(testkit.SpecPath(t, "vectors/verifier/reasons_v1.1.json"))
	require.NoError(t, err)
	var words struct {
		Reasons []struct {
			Name     string `json:"name"`
			Meaning  string `json:"meaning"`
			Advice   string `json:"advice"`
			Replaces struct {
				Meaning string `json:"meaning"`
				Advice  string `json:"advice"`
			} `json:"replaces"`
		} `json:"reasons"`
	}
	require.NoError(t, json.Unmarshal(raw, &words))
	require.Len(t, words.Reasons, 1)
	w := words.Reasons[0]
	require.Equal(t, "anchor_unpaid", w.Name)

	ac := loadAbsenceCase(t, "window_three_heights_proven")
	gk := gatePubHex(t)
	dir, h := ac.pendingArchive(t, ac.ref.Height, ac.ref.Height+1, ac.deadline)
	args := []string{"verify", hex.EncodeToString(h[:]), "--archive", dir, "--gate-key", gk, "--trusted", ac.trustedAt(t)}

	code, v := runFast(t, args...)
	require.Equal(t, codeUnchecked, code)
	c := v.check("anchor")
	require.Equal(t, "anchor_unpaid", c.Reason, c.Error)
	assert.Equal(t, w.Advice, c.Advice)

	code, text := exec(t, args)
	require.Equal(t, codeUnchecked, code, text)
	assert.Contains(t, text, "    reason: anchor_unpaid: "+w.Meaning+"\n")
	assert.Contains(t, text, "    advice: "+w.Advice+"\n")
	assert.NotContains(t, text, w.Replaces.Meaning)
	assert.NotContains(t, text, w.Replaces.Advice)
	assert.NotContains(t, text, "without the code")
}
