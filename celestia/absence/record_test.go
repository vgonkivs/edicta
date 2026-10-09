package absence_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/celestia/absence"
	"github.com/vgonkivs/edicta/commitment"
)

const archivePath = "../../spec/vectors/v1/archive.json"

var causes = map[string]error{
	"ErrTooLarge":         commitment.ErrTooLarge,
	"ErrUnknownKey":       commitment.ErrUnknownKey,
	"ErrMissingField":     commitment.ErrMissingField,
	"ErrZeroValue":        commitment.ErrZeroValue,
	"ErrFieldSize":        commitment.ErrFieldSize,
	"ErrWrongType":        commitment.ErrWrongType,
	"ErrInvalidEnum":      commitment.ErrInvalidEnum,
	"ErrInvalidNamespace": commitment.ErrInvalidNamespace,
}

type archiveFile struct {
	Cases []struct {
		ID     string `json:"id"`
		Kind   string `json:"kind"`
		Path   string `json:"path"`
		Record string `json:"record_cbor_hex"`
	} `json:"cases"`
	Reject []struct {
		ID     string `json:"id"`
		Record string `json:"record_cbor_hex"`
		Expect string `json:"expect_error"`
		Cause  string `json:"cause"`
	} `json:"reject"`
	RejectLarge []struct {
		ID         string  `json:"id"`
		BaseCase   string  `json:"base_case"`
		Field      string  `json:"field"`
		Label      string  `json:"placeholder_label"`
		FieldSize  string  `json:"field_size"`
		RecordSize string  `json:"record_size"`
		SHA256     string  `json:"record_sha256_hex"`
		Expect     *string `json:"expect_error"`
		Cause      *string `json:"cause"`
	} `json:"reject_large"`
	Reads []struct {
		ID     string  `json:"id"`
		Path   string  `json:"path"`
		Record string  `json:"record_cbor_hex"`
		Expect *string `json:"expect_error"`
	} `json:"reads"`
}

func loadArchive(t *testing.T) archiveFile {
	t.Helper()
	b, err := os.ReadFile(archivePath)
	require.NoError(t, err)
	var f archiveFile
	require.NoError(t, json.Unmarshal(b, &f))
	return f
}

func placeholder(label string, size int) []byte {
	out := make([]byte, 0, size+32)
	for i := 0; len(out) < size; i++ {
		s := sha256.Sum256([]byte(fmt.Sprintf("edicta/v0 test archive placeholder|%s|%d", label, i)))
		out = append(out, s[:]...)
	}
	return out[:size]
}

func TestRecordVectors(t *testing.T) {
	f := loadArchive(t)
	base := map[string]absence.Record{}
	n := 0
	for _, c := range f.Cases {
		if c.Kind != strconv.Itoa(absence.KindAbsenceProof) {
			continue
		}
		n++
		b := unhex(t, c.Record)
		r, err := absence.DecodeRecordAt(c.Path, b)
		require.NoError(t, err, c.ID)
		again, err := absence.EncodeRecord(r)
		require.NoError(t, err, c.ID)
		assert.Equal(t, b, again, c.ID)
		base[c.ID] = r
	}
	require.Equal(t, 3, n)

	n = 0
	for _, c := range f.Reject {
		if !strings.HasPrefix(c.ID, "absence_") {
			continue
		}
		n++
		_, err := absence.DecodeRecord(unhex(t, c.Record))
		require.Equal(t, "archive.ErrCorrupt", c.Expect)
		require.ErrorIs(t, err, archive.ErrCorrupt, c.ID)
		require.Contains(t, causes, c.Cause, c.ID)
		require.ErrorIs(t, err, causes[c.Cause], c.ID)
	}
	require.Equal(t, 4, n)

	for _, c := range f.RejectLarge {
		t.Run(c.ID, func(t *testing.T) {
			r, ok := base[c.BaseCase]
			require.True(t, ok)
			size, err := strconv.Atoi(c.FieldSize)
			require.NoError(t, err)
			p := placeholder(c.Label, size)
			switch c.Field {
			case "7":
				r.Header = p
			case "9":
				r.NamespaceData = p
			default:
				require.Fail(t, "field "+c.Field)
			}
			b := rawEncode(r)
			require.Equal(t, c.RecordSize, strconv.Itoa(len(b)))
			sum := sha256.Sum256(b)
			require.Equal(t, c.SHA256, hex.EncodeToString(sum[:]))
			_, err = absence.DecodeRecord(b)
			if c.Cause == nil {
				require.NoError(t, err)
				return
			}
			require.ErrorIs(t, err, archive.ErrCorrupt)
			require.ErrorIs(t, err, causes[*c.Cause])
		})
	}

	n = 0
	for _, c := range f.Reads {
		if !strings.HasPrefix(c.Path, absence.PathPrefix+"/") {
			continue
		}
		n++
		_, err := absence.DecodeRecordAt(c.Path, unhex(t, c.Record))
		if c.Expect == nil {
			require.NoError(t, err, c.ID)
			continue
		}
		require.ErrorIs(t, err, archive.ErrCorrupt, c.ID)
	}
	require.Positive(t, n)
}

// rawEncode writes the record bytes without the validity check of
// EncodeRecord, for inputs that must be rejected.
func rawEncode(r absence.Record) []byte {
	var b []byte
	head := func(major byte, n uint64) {
		m := major << 5
		switch {
		case n < 24:
			b = append(b, m|byte(n))
		case n <= 0xff:
			b = append(b, m|24, byte(n))
		case n <= 0xffff:
			b = append(b, m|25, byte(n>>8), byte(n))
		case n <= 0xffffffff:
			b = append(b, m|26, byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
		default:
			b = append(b, m|27, byte(n>>56), byte(n>>48), byte(n>>40), byte(n>>32), byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
		}
	}
	u := func(k, v uint64) { head(0, k); head(0, v) }
	bs := func(k uint64, v []byte) { head(0, k); head(2, uint64(len(v))); b = append(b, v...) }
	n := uint64(9)
	if r.Results != nil {
		n = 11
	}
	head(5, n)
	u(1, 0)
	u(2, absence.KindAbsenceProof)
	u(3, r.DA)
	bs(4, r.Commitment)
	bs(5, r.Namespace)
	u(6, r.Height)
	bs(7, r.Header)
	bs(8, r.DAH)
	bs(9, r.NamespaceData)
	if n == 11 {
		bs(10, r.Results)
		bs(11, r.NextHeader)
	}
	return b
}

func TestDecodeRecordStrict(t *testing.T) {
	f := loadArchive(t)
	var good []byte
	for _, c := range f.Cases {
		if c.ID == "absence_blob" {
			good = unhex(t, c.Record)
		}
	}
	require.NotNil(t, good)
	r, err := absence.DecodeRecord(good)
	require.NoError(t, err)

	cases := []struct {
		name  string
		mut   func([]byte) []byte
		cause error
	}{
		{"trailing byte", func(b []byte) []byte { return append(b, 0) }, commitment.ErrTrailingData},
		{"truncated", func(b []byte) []byte { return b[:len(b)-1] }, commitment.ErrMalformed},
		{"not a map", func([]byte) []byte { return []byte{0x01} }, commitment.ErrWrongType},
		{"indefinite map", func([]byte) []byte { return []byte{0xbf, 0xff} }, commitment.ErrIndefiniteLength},
		{"tag", func([]byte) []byte { return []byte{0xc0, 0x00} }, commitment.ErrTag},
		{"float", func([]byte) []byte { return []byte{0xf9, 0, 0} }, commitment.ErrFloat},
		{"non-minimal head", func([]byte) []byte { return []byte{0xb8, 0x01, 0x01, 0x00} }, commitment.ErrNonMinimalInt},
		{"unsorted", func([]byte) []byte { return []byte{0xa2, 0x02, 0x0e, 0x01, 0x00} }, commitment.ErrUnsortedMap},
		{"duplicate", func([]byte) []byte { return []byte{0xa2, 0x01, 0x00, 0x01, 0x00} }, commitment.ErrDuplicateKey},
		{"text key", func([]byte) []byte { return []byte{0xa1, 0x61, 0x61, 0x00} }, commitment.ErrKeyType},
		{"format 1", func([]byte) []byte { return []byte{0xa2, 0x01, 0x01, 0x02, 0x0e} }, commitment.ErrUnsupportedVersion},
		{"another kind", func([]byte) []byte { return []byte{0xa2, 0x01, 0x00, 0x02, 0x0d} }, commitment.ErrInvalidEnum},
		{"no kind", func([]byte) []byte { return []byte{0xa1, 0x01, 0x00} }, commitment.ErrMissingField},
		{"da 3", func([]byte) []byte { x := r; x.DA = 3; return rawEncode(x) }, commitment.ErrInvalidEnum},
		{"reserved namespace", func([]byte) []byte {
			x := r
			x.Namespace = make([]byte, 29)
			return rawEncode(x)
		}, commitment.ErrInvalidNamespace},
		{"short commitment", func([]byte) []byte { x := r; x.Commitment = x.Commitment[:31]; return rawEncode(x) }, commitment.ErrFieldSize},
		{"empty header", func([]byte) []byte { x := r; x.Header = []byte{}; return rawEncode(x) }, commitment.ErrFieldSize},
		{"huge height", func([]byte) []byte { x := r; x.Height = 1 << 63; return rawEncode(x) }, commitment.ErrIntRange},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := absence.DecodeRecord(c.mut(append([]byte(nil), good...)))
			require.ErrorIs(t, err, archive.ErrCorrupt)
			require.ErrorIs(t, err, c.cause)
		})
	}

	_, err = absence.EncodeRecord(absence.Record{DA: 2, Commitment: r.Commitment, Namespace: r.Namespace, Height: 1,
		Header: r.Header, DAH: r.DAH, Results: []byte("{}")})
	require.Error(t, err)
}
