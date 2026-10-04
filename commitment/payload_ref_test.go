package commitment_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/commitment"
)

func refBlob() commitment.PayloadRef {
	ns := append(make([]byte, 19), []byte("edicta/d01")...)
	return commitment.PayloadRef{
		DA: commitment.DACelestiaBlob, Namespace: ns, Commitment: bytes.Repeat([]byte{0xab}, 32),
		Height: 4_200_000, Signer: bytes.Repeat([]byte{0x11}, 20),
	}
}

func refFibre() commitment.PayloadRef {
	r := refBlob()
	r.DA, r.Signer = commitment.DAFibre, nil
	return r
}

func TestPayloadRefRoundTrip(t *testing.T) {
	for name, ref := range map[string]commitment.PayloadRef{"celestia_blob": refBlob(), "fibre": refFibre()} {
		t.Run(name, func(t *testing.T) {
			raw, err := commitment.EncodePayloadRef(ref)
			require.NoError(t, err)
			got, err := commitment.DecodePayloadRef(raw)
			require.NoError(t, err)
			assert.Equal(t, ref, got)
			again, err := commitment.EncodePayloadRef(got)
			require.NoError(t, err)
			assert.Equal(t, raw, again)
		})
	}
}

// The bytes are the ones the commitment encoder emits under key 10.
func TestPayloadRefIsTheCommitmentKey10Bytes(t *testing.T) {
	raw, err := os.ReadFile(vectorDir + "/valid.json")
	require.NoError(t, err)
	var v struct {
		Cases []struct {
			ID             string `json:"id"`
			CommitmentCBOR string `json:"commitment_cbor_hex"`
		} `json:"cases"`
	}
	require.NoError(t, json.Unmarshal(raw, &v))
	require.NotEmpty(t, v.Cases)
	for _, c := range v.Cases {
		cb, err := hex.DecodeString(c.CommitmentCBOR)
		require.NoError(t, err)
		com, err := commitment.Decode(cb)
		require.NoError(t, err, c.ID)
		enc, err := commitment.EncodePayloadRef(com.PayloadRef)
		require.NoError(t, err, c.ID)
		assert.Truef(t, bytes.Contains(cb, append([]byte{0x0a}, enc...)), "%s: key 10 holds the exported encoding", c.ID)
		back, err := commitment.DecodePayloadRef(enc)
		require.NoError(t, err, c.ID)
		assert.Equal(t, com.PayloadRef, back, c.ID)
	}
}

func TestPayloadRefAPIVector(t *testing.T) {
	raw, err := os.ReadFile("../spec/vectors/api/publish_request.json")
	require.NoError(t, err)
	var v struct {
		Response []struct {
			ID  string `json:"id"`
			Ref string `json:"payload_ref_cbor_hex"`
		} `json:"response"`
	}
	require.NoError(t, json.Unmarshal(raw, &v))
	require.NotEmpty(t, v.Response)
	for _, r := range v.Response {
		b, err := hex.DecodeString(r.Ref)
		require.NoError(t, err)
		ref, err := commitment.DecodePayloadRef(b)
		require.NoError(t, err, r.ID)
		enc, err := commitment.EncodePayloadRef(ref)
		require.NoError(t, err, r.ID)
		assert.Equal(t, b, enc, r.ID)
	}
}

func TestEncodePayloadRefRejectsInvalid(t *testing.T) {
	bad := map[string]func(*commitment.PayloadRef){
		"da zero":             func(r *commitment.PayloadRef) { r.DA = 0 },
		"da unknown":          func(r *commitment.PayloadRef) { r.DA = 9 },
		"short namespace":     func(r *commitment.PayloadRef) { r.Namespace = r.Namespace[:28] },
		"short commitment":    func(r *commitment.PayloadRef) { r.Commitment = r.Commitment[:31] },
		"zero height":         func(r *commitment.PayloadRef) { r.Height = 0 },
		"missing signer da 2": func(r *commitment.PayloadRef) { r.Signer = nil },
		"short signer":        func(r *commitment.PayloadRef) { r.Signer = r.Signer[:19] },
		"signer on fibre":     func(r *commitment.PayloadRef) { r.DA = commitment.DAFibre },
		"height above 2^63-1": func(r *commitment.PayloadRef) { r.Height = 1 << 63 },
	}
	for name, mod := range bad {
		t.Run(name, func(t *testing.T) {
			ref := refBlob()
			mod(&ref)
			raw, err := commitment.EncodePayloadRef(ref)
			require.Error(t, err)
			assert.Nil(t, raw)
		})
	}
}

func TestDecodePayloadRefIsStrict(t *testing.T) {
	good, err := commitment.EncodePayloadRef(refBlob())
	require.NoError(t, err)
	goodFibre, err := commitment.EncodePayloadRef(refFibre())
	require.NoError(t, err)
	// The map head is 0xa5 for da 2 and 0xa4 for da 1.
	require.Equal(t, byte(0xa5), good[0])
	require.Equal(t, byte(0xa4), goodFibre[0])

	with := func(f func([]byte) []byte) []byte { return f(bytes.Clone(good)) }
	tests := []struct {
		name string
		in   []byte
		want error
	}{
		{"empty", nil, commitment.ErrMalformed},
		{"truncated", good[:len(good)-1], commitment.ErrMalformed},
		{"trailing byte", append(bytes.Clone(good), 0), commitment.ErrTrailingData},
		{"not a map", []byte{0x80}, commitment.ErrWrongType},
		{"indefinite map", with(func(b []byte) []byte { b[0] = 0xbf; return append(b, 0xff) }), commitment.ErrIndefiniteLength},
		{"unknown key 6", with(func(b []byte) []byte { b[0] = 0xa6; return append(b, 0x06, 0x00) }), commitment.ErrUnknownKey},
		{"signer on fibre", append([]byte{0xa5}, append(goodFibre[1:], append([]byte{0x05, 0x54}, bytes.Repeat([]byte{1}, 20)...)...)...), commitment.ErrUnknownKey},
		{"duplicate key", []byte{0xa2, 0x01, 0x01, 0x01, 0x01}, commitment.ErrDuplicateKey},
		{"unsorted keys", []byte{0xa2, 0x02, 0x00, 0x01, 0x01}, commitment.ErrUnsortedMap},
		{"non minimal da", []byte{0xa1, 0x01, 0x18, 0x02}, commitment.ErrNonMinimalInt},
		{"text key", []byte{0xa1, 0x61, 'a', 0x01}, commitment.ErrKeyType},
		{"float da", []byte{0xa1, 0x01, 0xf9, 0x40, 0x00}, commitment.ErrFloat},
		{"tagged", append([]byte{0xc1}, good...), commitment.ErrTag},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ref, err := commitment.DecodePayloadRef(tt.in)
			require.ErrorIs(t, err, tt.want)
			assert.Equal(t, commitment.PayloadRef{}, ref)
		})
	}

	t.Run("missing signer for da 2", func(t *testing.T) {
		raw := bytes.Clone(good[:len(good)-22])
		raw[0] = 0xa4
		_, err := commitment.DecodePayloadRef(raw)
		require.ErrorIs(t, err, commitment.ErrMissingField)
	})
	t.Run("short commitment", func(t *testing.T) {
		ref := refBlob()
		raw, err := commitment.EncodePayloadRef(ref)
		require.NoError(t, err)
		i := bytes.Index(raw, []byte{0x03, 0x58, 0x20})
		require.Positive(t, i)
		raw[i+1], raw[i+2] = 0x58, 0x1f
		raw = append(raw[:i+3+31], raw[i+3+32:]...)
		_, err = commitment.DecodePayloadRef(raw)
		require.ErrorIs(t, err, commitment.ErrFieldSize)
	})
	t.Run("oversized input", func(t *testing.T) {
		_, err := commitment.DecodePayloadRef(bytes.Repeat([]byte{0}, 1<<20))
		require.Error(t, err)
	})
}

func TestDecodePayloadRefDoesNotAlias(t *testing.T) {
	raw, err := commitment.EncodePayloadRef(refBlob())
	require.NoError(t, err)
	ref, err := commitment.DecodePayloadRef(raw)
	require.NoError(t, err)
	before := bytes.Clone(ref.Commitment)
	clear(raw)
	assert.Equal(t, before, ref.Commitment)
}

func FuzzDecodePayloadRef(f *testing.F) {
	for _, r := range []commitment.PayloadRef{refBlob(), refFibre()} {
		b, err := commitment.EncodePayloadRef(r)
		require.NoError(f, err)
		f.Add(b)
	}
	f.Add([]byte{})
	f.Add([]byte{0xa0})
	f.Fuzz(func(t *testing.T, in []byte) {
		ref, err := commitment.DecodePayloadRef(in)
		if err != nil {
			return
		}
		enc, err := commitment.EncodePayloadRef(ref)
		require.NoError(t, err)
		assert.Equal(t, in, enc, "anything accepted is canonical")
	})
}
