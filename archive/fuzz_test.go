package archive_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/test/archivefix"
)

func FuzzDecode(f *testing.F) {
	fx := archivefix.Load(f)
	for _, c := range fx.Cases {
		if c.CBOR != nil {
			f.Add(c.CBOR)
		}
	}
	for _, r := range fx.Rejects {
		f.Add(r.CBOR)
	}
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		rec, err := archive.Decode(b)
		if err != nil {
			require.Nil(t, rec)
			require.ErrorIs(t, err, archive.ErrCorrupt)
			return
		}
		again, err := archive.Encode(rec)
		require.NoError(t, err)
		require.Equal(t, b, again)
	})
}
