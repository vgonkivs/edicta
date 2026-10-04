package commitment_test

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/commitment"
)

// FuzzDecodeSignedAuthorization: never panics, every rejection carries a
// package sentinel, accepted input is canonical, and verification agrees with
// decoding.
func FuzzDecodeSignedAuthorization(f *testing.F) {
	var af authorizationFile
	loadJSON(f, "authorization.json", &af)
	for _, c := range af.Cases {
		f.Add(mustHex(f, c.SignedAuthorizationHex))
	}
	for _, c := range af.Reject {
		f.Add(mustHex(f, c.SignedAuthorizationHex))
	}
	var rf receiptFile
	loadJSON(f, "receipt.json", &rf)
	f.Add(mustHex(f, rf.Cases[0].SignedReceiptHex))
	f.Add([]byte{})
	f.Add([]byte{0xa2, 0x01, 0xa0})

	chk := toAuthorizationCheck(f, af.Cases[0].Check)

	f.Fuzz(func(t *testing.T, data []byte) {
		sa, h, err := commitment.DecodeSignedAuthorization(data)
		if err != nil {
			require.Truef(t, matchesAnySentinel(err), "rejection without a sentinel: %v", err)
		} else {
			require.LessOrEqual(t, len(data), commitment.MaxAuthorizationSize)
			enc, eerr := commitment.EncodeSignedAuthorization(sa)
			require.NoError(t, eerr)
			require.Equalf(t, hex.EncodeToString(data), hex.EncodeToString(enc), "accepted input is not canonical")
			canon, cerr := commitment.EncodeAuthorization(&sa.Authorization)
			require.NoError(t, cerr)
			require.Equal(t, h, commitment.HashAuthorization(canon), "hash differs from the hash of the canonical Authorization")
		}
		va, vh, verr := commitment.VerifyAuthorization(data, chk)
		if verr != nil {
			require.Truef(t, matchesAnySentinel(verr), "verification failure without a sentinel: %v", verr)
			return
		}
		require.NoError(t, err, "verified input that does not decode")
		require.Equal(t, h, vh)
		require.NotNil(t, va)
	})
}
