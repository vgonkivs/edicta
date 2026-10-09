package absence_test

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/celestia/absence"
)

// FuzzDecodeRecord: any input either decodes to a record that re-encodes to
// the same bytes, or fails as a corrupt record.
func FuzzDecodeRecord(f *testing.F) {
	b, err := os.ReadFile(archivePath)
	require.NoError(f, err)
	var af archiveFile
	require.NoError(f, json.Unmarshal(b, &af))
	for _, c := range af.Cases {
		if raw, err := hex.DecodeString(c.Record); err == nil {
			f.Add(raw)
		}
	}
	f.Fuzz(func(t *testing.T, in []byte) {
		r, err := absence.DecodeRecord(in)
		if err != nil {
			require.ErrorIs(t, err, archive.ErrCorrupt)
			return
		}
		again, err := absence.EncodeRecord(r)
		require.NoError(t, err)
		require.Equal(t, in, again)
	})
}
