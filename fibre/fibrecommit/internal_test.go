package fibrecommit

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/gate"
)

func TestWrongDAWrapsBoth(t *testing.T) {
	cm, err := New(DefaultMaxDataSize)
	require.NoError(t, err)
	r := commitment.PayloadRef{DA: commitment.DACelestiaBlob, Commitment: make([]byte, 32)}

	err = cm.Check(r, []byte{0x65})
	require.ErrorIs(t, err, gate.ErrDACommitmentMismatch)
	require.ErrorIs(t, err, errWrongDA)
}

func TestEmptyDataWrapsMismatch(t *testing.T) {
	cm, err := New(DefaultMaxDataSize)
	require.NoError(t, err)
	r := commitment.PayloadRef{DA: commitment.DAFibre, Commitment: make([]byte, 32)}

	for _, data := range [][]byte{nil, {}} {
		err = cm.Check(r, data)
		require.ErrorIs(t, err, gate.ErrDACommitmentMismatch)
		require.ErrorIs(t, err, errEmpty)
	}
}

// commitmentString accepts the hex string or the raw bytes form of an
// embedded commitment.
func commitmentString(t *testing.T, v any) string {
	t.Helper()
	switch c := v.(type) {
	case string:
		return c
	case [32]byte:
		return hex.EncodeToString(c[:])
	case []byte:
		return hex.EncodeToString(c)
	}
	require.FailNow(t, "unexpected commitment type", "%T", v)
	return ""
}

// The self-test table is embedded in the binary, so it must stay equal to the
// shared vector file.
func TestSelfTestCasesMatchVectors(t *testing.T) {
	type vec struct {
		ID            string `json:"id"`
		Size          string `json:"size"`
		CommitmentHex string `json:"commitment_hex"`
		UploadSize    string `json:"upload_size"`
		RowSize       string `json:"row_size"`
	}
	var f struct {
		Cases []vec `json:"cases"`
	}
	readJSON(t, "../../spec/vectors/da/fibre_commit.json", &f)
	byID := map[string]vec{}
	for _, c := range f.Cases {
		byID[c.ID] = c
	}

	require.NotEmpty(t, selfTestCases)
	names := map[string]bool{}
	bigRow := false
	for _, sc := range selfTestCases {
		names[sc.name] = true
		v, ok := byID[sc.name]
		require.True(t, ok, "self-test case %q is not in the vector file", sc.name)
		assert.Equal(t, v.Size, fmt.Sprint(sc.size), sc.name)
		assert.Equal(t, v.UploadSize, fmt.Sprint(sc.uploadSize), sc.name)
		assert.Equal(t, v.CommitmentHex, commitmentString(t, sc.commitment), sc.name)
		var row int
		_, err := fmt.Sscan(v.RowSize, &row)
		require.NoError(t, err)
		bigRow = bigRow || row > 128
	}
	for _, id := range []string{"fibre_live_mocha_popsmin1", "fibre_size_262139", "fibre_size_262140"} {
		assert.True(t, names[id], "self-test must cover %s", id)
	}
	assert.True(t, bigRow, "self-test must cover a row size above 128")
}

func readJSON(t *testing.T, path string, v any) {
	t.Helper()
	b, err := os.ReadFile(path)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(b, v))
}
