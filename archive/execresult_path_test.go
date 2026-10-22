package archive_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/engine/commitment"
	"github.com/vgonkivs/edicta/test/archivefix"
	"github.com/vgonkivs/edicta/test/execresultfix"
)

// The reader is chosen by the path: kind 19 is read only under exec/, and
// nothing but kind 19 is read there.
func TestDecodeAtDispatchesByPath(t *testing.T) {
	hash := strings.Repeat("ab", 32)
	for _, p := range []string{
		"decision/" + hash,
		"authorization/" + hash,
		"payload/1/" + hash,
		"evidence/2/" + hash,
		"reveal/" + hash,
		"private/1/" + hash,
		"intent/1/" + hash + "/7",
		"anything/else",
	} {
		t.Run("kind 19 under "+p, func(t *testing.T) {
			_, raw := execRecord(t)
			_, err := archive.DecodeAt(p, raw)
			require.ErrorIs(t, err, archive.ErrCorrupt)
			require.ErrorIs(t, err, commitment.ErrInvalidEnum)
		})
	}

	r := execresultfix.Load(t).Records[0]
	t.Run("kind 19 under its own path", func(t *testing.T) {
		rec, err := archive.DecodeAt(r.Path, execresultfix.Hex(t, r.CBORHex))
		require.NoError(t, err)
		require.Equal(t, r.Build(t), rec)
	})

	fx := archivefix.Load(t)
	n := 0
	for _, c := range fx.Cases {
		if c.CBOR == nil {
			continue
		}
		n++
		t.Run("non-19 "+c.ID+" under exec/", func(t *testing.T) {
			_, err := archive.DecodeAt(r.Path, c.CBOR)
			require.ErrorIs(t, err, archive.ErrCorrupt)
			require.ErrorIs(t, err, commitment.ErrInvalidEnum)
			// Under its own key it still reads with the general reader.
			_, err = archive.DecodeAt(c.Key, c.CBOR)
			require.NoError(t, err)
		})
	}
	require.Positive(t, n)
}
