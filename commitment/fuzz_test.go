package commitment_test

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/prior/commitment"
)

// FuzzDecode exercises the strict decoder. Properties:
//   - never panics;
//   - input above MaxSignedSize is rejected;
//   - every rejection carries a package sentinel;
//   - every accepted input re-encodes to identical bytes (the ErrNonCanonical guard);
//   - the commitment inside an accepted envelope also round-trips alone.
func FuzzDecode(f *testing.F) {
	var vf validFile
	var rf rejectFile
	loadJSON(f, "valid.json", &vf)
	loadJSON(f, "reject.json", &rf)
	for _, c := range vf.Cases {
		f.Add(mustHex(f, c.EnvelopeHex))
		f.Add(mustHex(f, c.CommitmentCBORHex))
	}
	for _, c := range rf.Cases {
		f.Add(mustHex(f, c.EnvelopeHex))
	}
	f.Add([]byte{})
	f.Add([]byte{0xa0})

	f.Fuzz(func(t *testing.T, data []byte) {
		s, err := commitment.DecodeSigned(data)
		if err != nil {
			require.Truef(t, matchesAnySentinel(err), "rejection without a sentinel: %v", err)
		} else {
			require.LessOrEqualf(t, len(data), commitment.MaxSignedSize, "accepted %d bytes, above MaxSignedSize", len(data))
			enc, eerr := commitment.EncodeSigned(s)
			require.NoError(t, eerr, "EncodeSigned of accepted input")
			require.Equalf(t, hex.EncodeToString(data), hex.EncodeToString(enc), "accepted input is not canonical\n in  %x\n out %x", data, enc)
			canon, cerr := commitment.Encode(&s.Commitment)
			require.NoError(t, cerr, "Encode of accepted commitment")
			require.LessOrEqualf(t, len(canon), commitment.MaxCommitmentSize, "accepted commitment of %d bytes", len(canon))
		}

		c, err := commitment.Decode(data)
		if err != nil {
			require.Truef(t, matchesAnySentinel(err), "Decode rejection without a sentinel: %v", err)
			return
		}
		enc, err := commitment.Encode(c)
		require.NoError(t, err, "Encode of accepted commitment")
		require.Equalf(t, hex.EncodeToString(data), hex.EncodeToString(enc), "accepted commitment is not canonical\n in  %x\n out %x", data, enc)
	})
}
