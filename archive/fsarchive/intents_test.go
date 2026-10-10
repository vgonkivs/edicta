package fsarchive_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/test/archivefix"
)

func TestIntentsListsByDAAndHeight(t *testing.T) {
	fx := archivefix.Load(t)
	s, dir := open(t, fx)
	none, err := s.Intents(bg, commitment.DACelestiaBlob, 0)
	require.NoError(t, err)
	assert.Empty(t, none, "no intent directory yet")

	var stored []*archive.AnchorIntentRecord
	for _, c := range loadV1(t).Cases {
		if c.Kind != "13" {
			continue
		}
		rec := archivefix.Build(t, c.Input).(*archive.AnchorIntentRecord)
		_, err := s.Put(bg, rec)
		require.NoError(t, err)
		stored = append(stored, rec)
		// A temp file of a write in progress is not a key.
		p, err := archive.IntentPath(rec.DA, rec.Commitment, rec.RefHeight)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(dir, filepath.Dir(p), ".tmp-1"), []byte("x"), 0o644))
	}
	require.NotEmpty(t, stored)

	for _, da := range []commitment.DA{commitment.DAFibre, commitment.DACelestiaBlob} {
		var want []*archive.AnchorIntentRecord
		for _, r := range stored {
			if r.DA == da {
				want = append(want, r)
			}
		}
		got, err := s.Intents(bg, da, 0)
		require.NoError(t, err)
		assert.ElementsMatch(t, want, got, "da %d", da)
		for _, r := range want {
			got, err := s.Intents(bg, da, r.RefHeight+1)
			require.NoError(t, err)
			assert.NotContains(t, got, r, "below the from height")
		}
	}
}
