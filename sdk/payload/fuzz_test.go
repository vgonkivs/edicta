package payload_test

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/sdk/payload"
	"github.com/vgonkivs/edicta/test/sdkfix"
)

// FuzzDecode: no panic, only the package sentinels, and whatever is accepted
// encodes back to the same bytes.
func FuzzDecode(f *testing.F) {
	v := sdkfix.Load(f)
	for _, c := range v.Cases {
		f.Add(c.Plaintext)
	}
	f.Add([]byte{})
	f.Add([]byte{0xa0})
	f.Add([]byte{0xbf, 0xff})
	f.Fuzz(func(t *testing.T, in []byte) {
		p, err := payload.Decode(in)
		if err != nil {
			require.Nil(t, p)
			ok := errors.Is(err, payload.ErrMalformed) || errors.Is(err, payload.ErrVersion) || errors.Is(err, payload.ErrTooLarge)
			require.Truef(t, ok, "unexpected error %v", err)
			return
		}
		out, err := payload.Encode(p)
		require.NoError(t, err)
		require.Equal(t, in, out)
	})
}
