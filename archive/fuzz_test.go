package archive_test

import (
	"encoding/hex"
	"encoding/json"
	"os"
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
	addV1Seeds(f)
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

// addV1Seeds seeds every format 1 record and reject, the anchor intent and
// absence proof kinds included.
func addV1Seeds(f *testing.F) {
	raw, err := os.ReadFile("../spec/vectors/v1/archive.json")
	require.NoError(f, err)
	var v struct {
		Cases []struct {
			CBOR string `json:"record_cbor_hex"`
		} `json:"cases"`
		Reject []struct {
			CBOR string `json:"record_cbor_hex"`
		} `json:"reject"`
	}
	require.NoError(f, json.Unmarshal(raw, &v))
	for _, c := range append(v.Cases, v.Reject...) {
		b, err := hex.DecodeString(c.CBOR)
		require.NoError(f, err)
		f.Add(b)
	}
}
