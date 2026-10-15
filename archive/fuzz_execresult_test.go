package archive_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/test/execresultfix"
)

func FuzzDecodeExecutionResult(f *testing.F) {
	fx := execresultfix.Load(f)
	for _, r := range fx.Records {
		f.Add(execresultfix.Hex(f, r.CBORHex))
	}
	for _, r := range fx.Reject {
		f.Add(execresultfix.Hex(f, r.CBORHex))
	}
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		rec, err := archive.DecodeExecutionResult(b)
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
