package edictad_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/celestia/edictad"
	"github.com/vgonkivs/edicta/commitment"
)

// An archived anchor intent the fast Recorder cannot follow may be a lost
// intent whose decision later reads as anchor_missing, so /v1/health reports
// degraded once the boot recovery has skipped one, and the record is logged
// at error level by its path.
func TestRecorderFastSkippedIntentDegradesHealth(t *testing.T) {
	for name, corrupt := range map[string]bool{"clean archive": false, "corrupt intent": true} {
		t.Run(name, func(t *testing.T) {
			p := newPolicyEnv(t)
			p.mandate.FastModeMaxDelay = fastDelay
			p.file = p.sign(p.principal, p.mandate)
			signer, _ := keyringSigner(t, "testchain-7")
			p.deps.Archive = p.real
			p.deps.RecorderFast = &edictad.RecorderFastDeps{Signer: signer}
			head, err := p.chain.Head(bg)
			require.NoError(t, err)
			rel, err := archive.IntentPath(commitment.DACelestiaBlob, bytes.Repeat([]byte{7}, 32), head.Height)
			require.NoError(t, err)
			if corrupt {
				path := filepath.Join(p.path("archive"), filepath.FromSlash(rel))
				require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o700))
				require.NoError(t, os.WriteFile(path, []byte("not a record"), 0o600))
			}
			p.start(p.edits(gateFastFor(), recFast())...)

			if !corrupt {
				h, err := p.client("").Health(bg)
				require.NoError(t, err)
				assert.EqualValues(t, 1, h.Status)
				return
			}
			require.Eventually(t, func() bool {
				h, err := p.client("").Health(bg)
				return err == nil && h.Status == 2
			}, 20*time.Second, 20*time.Millisecond, "health is degraded while an intent is skipped")
			lines := p.logLines("level=ERROR", "does not decode and is not followed", rel)
			assert.Len(t, lines, 1, "logged once, by its path")
		})
	}
}
