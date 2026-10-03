package commitment_test

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/prior/commitment"
)

// FuzzDecodeSignedReceipt: never panics, every rejection carries a package
// sentinel, accepted input is canonical, and verification agrees with decoding.
func FuzzDecodeSignedReceipt(f *testing.F) {
	var rf receiptFile
	loadJSON(f, "receipt.json", &rf)
	for _, c := range rf.Cases {
		f.Add(mustHex(f, c.SignedReceiptHex))
	}
	for _, c := range rf.Reject {
		f.Add(mustHex(f, c.SignedReceiptHex))
	}
	vf := loadValid(f)
	f.Add(mustHex(f, vf.Cases[0].EnvelopeHex))
	f.Add([]byte{})
	f.Add([]byte{0xa2, 0x01, 0xa0})

	f.Fuzz(func(t *testing.T, data []byte) {
		sr, h, err := commitment.DecodeSignedReceipt(data)
		if err != nil {
			require.Truef(t, matchesAnySentinel(err), "rejection without a sentinel: %v", err)
		} else {
			require.LessOrEqualf(t, len(data), commitment.MaxReceiptSize, "accepted %d bytes", len(data))
			enc, eerr := commitment.EncodeSignedReceipt(sr)
			require.NoErrorf(t, eerr, "accepted input is not canonical: %v\n in  %x\n out %x", eerr, data, enc)
			require.Equalf(t, hex.EncodeToString(data), hex.EncodeToString(enc), "accepted input is not canonical: %v\n in  %x\n out %x", eerr, data, enc)
			canon, cerr := commitment.EncodeReceipt(&sr.Receipt)
			require.NoError(t, cerr, "hash differs from the hash of the canonical receipt")
			require.Equalf(t, h, commitment.HashReceipt(canon), "hash differs from the hash of the canonical receipt: %v", cerr)
		}
		vr, vh, verr := commitment.VerifyReceipt(data)
		if verr != nil {
			require.Truef(t, matchesAnySentinel(verr), "verification failure without a sentinel: %v", verr)
			return
		}
		require.NoError(t, err, "verified input that does not decode")
		require.Equalf(t, h, vh, "verified input that does not decode: %v", err)
		require.NotNilf(t, vr, "verified input that does not decode: %v", err)
	})
}
