package blob_test

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/sdk/blob"
	"github.com/vgonkivs/edicta/test/sdkfix"
)

func isBlobError(err error) bool {
	for _, s := range sdkfix.BlobSentinels() {
		if errors.Is(err, s) {
			return true
		}
	}
	return false
}

func seeds(f *testing.F) {
	v := sdkfix.Load(f)
	for _, c := range v.Cases {
		f.Add(c.Blob)
	}
	for _, r := range v.Rejects {
		f.Add(r.Blob)
	}
	f.Add([]byte{})
	f.Add([]byte{0xa4, 0x01, 0x00})
}

// FuzzDecode: no panic, only the package sentinels, and whatever is accepted
// is canonical (it encodes back to the same bytes) and within the bounds.
func FuzzDecode(f *testing.F) {
	seeds(f)
	f.Fuzz(func(t *testing.T, in []byte) {
		b, err := blob.Decode(in)
		if err != nil {
			require.Nil(t, b)
			require.Truef(t, isBlobError(err), "unexpected error %v", err)
			return
		}
		require.GreaterOrEqual(t, len(b.Recipients), blob.MinRecipients)
		require.LessOrEqual(t, len(b.Recipients), blob.MaxRecipients)
		require.GreaterOrEqual(t, len(b.Ciphertext), blob.MinCiphertextSize)
		out, err := blob.Encode(b)
		require.NoError(t, err)
		require.Equal(t, in, out)
	})
}

// FuzzOpen: random bytes against fixed keys never panic and fail with a blob
// sentinel; a success implies the input decodes canonically.
func FuzzOpen(f *testing.F) {
	seeds(f)
	v := sdkfix.Load(f)
	keys := []sdkfix.Key{v.Keys["gate-paper-1"], v.Keys["auditor-1"]}
	f.Fuzz(func(t *testing.T, in []byte) {
		for _, k := range keys {
			for _, withKID := range []bool{true, false} {
				_, _, err := blob.Open(in, k.OpenKey(withKID))
				if err != nil {
					require.Truef(t, isBlobError(err), "unexpected error %v", err)
					continue
				}
				b, derr := blob.Decode(in)
				require.NoError(t, derr, "Open accepted what Decode rejects")
				out, eerr := blob.Encode(b)
				require.NoError(t, eerr)
				require.Equal(t, in, out)
			}
		}
	})
}
