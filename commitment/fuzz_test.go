package commitment_test

import (
	"bytes"
	"testing"

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
			if !matchesAnySentinel(err) {
				t.Fatalf("rejection without a sentinel: %v", err)
			}
		} else {
			if len(data) > commitment.MaxSignedSize {
				t.Fatalf("accepted %d bytes, above MaxSignedSize", len(data))
			}
			enc, eerr := commitment.EncodeSigned(s)
			if eerr != nil {
				t.Fatalf("EncodeSigned of accepted input: %v", eerr)
			}
			if !bytes.Equal(enc, data) {
				t.Fatalf("accepted input is not canonical\n in  %x\n out %x", data, enc)
			}
			canon, cerr := commitment.Encode(&s.Commitment)
			if cerr != nil {
				t.Fatalf("Encode of accepted commitment: %v", cerr)
			}
			if len(canon) > commitment.MaxCommitmentSize {
				t.Fatalf("accepted commitment of %d bytes", len(canon))
			}
		}

		c, err := commitment.Decode(data)
		if err != nil {
			if !matchesAnySentinel(err) {
				t.Fatalf("Decode rejection without a sentinel: %v", err)
			}
			return
		}
		enc, err := commitment.Encode(c)
		if err != nil {
			t.Fatalf("Encode of accepted commitment: %v", err)
		}
		if !bytes.Equal(enc, data) {
			t.Fatalf("accepted commitment is not canonical\n in  %x\n out %x", data, enc)
		}
	})
}
