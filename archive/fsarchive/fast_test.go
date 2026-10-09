package fsarchive_test

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/test/archivefix"
)

type v1Vectors struct {
	Cases []struct {
		ID      string         `json:"id"`
		Kind    string         `json:"kind"`
		Path    string         `json:"path"`
		Input   map[string]any `json:"input"`
		CBORHex string         `json:"record_cbor_hex"`
	} `json:"cases"`
	Reads []struct {
		ID      string `json:"id"`
		Path    string `json:"path"`
		CBORHex string `json:"record_cbor_hex"`
		Expect  string `json:"expect_error"`
	} `json:"reads"`
}

func loadV1(t *testing.T) v1Vectors {
	t.Helper()
	raw, err := os.ReadFile("../../spec/vectors/v1/archive.json")
	require.NoError(t, err)
	var v v1Vectors
	require.NoError(t, json.Unmarshal(raw, &v))
	return v
}

func TestIntentAndAbsenceRoundTrip(t *testing.T) {
	fx := archivefix.Load(t)
	v := loadV1(t)
	ran := 0
	for _, c := range v.Cases {
		if c.Kind != "13" && c.Kind != "14" {
			continue
		}
		ran++
		t.Run(c.ID, func(t *testing.T) {
			s, _ := open(t, fx)
			rec := archivefix.Build(t, c.Input)
			out, err := s.Put(bg, rec)
			require.NoError(t, err)
			assert.Equal(t, archive.Written, out)
			out, err = s.Put(bg, rec)
			require.NoError(t, err)
			assert.Equal(t, archive.Unchanged, out)

			switch r := rec.(type) {
			case *archive.AnchorIntentRecord:
				got, err := s.Intent(bg, r.DA, r.Commitment, r.RefHeight)
				require.NoError(t, err)
				assert.Equal(t, r, got)
				_, err = s.Intent(bg, r.DA, r.Commitment, r.RefHeight+1)
				require.ErrorIs(t, err, archive.ErrNotFound)
				other := *r
				other.Tx = append([]byte{0x01}, r.Tx...)
				_, err = s.Put(bg, &other)
				require.ErrorIs(t, err, archive.ErrConflict, "a second tx under one reference")
			case *archive.AbsenceProofRecord:
				got, err := s.Absence(bg, r.DA, r.Commitment, r.Height)
				require.NoError(t, err)
				assert.Equal(t, r, got)
				other := *r
				other.Header = append([]byte{0x01}, r.Header...)
				out, err := s.Put(bg, &other)
				require.NoError(t, err, "the first absence proof of a key stays")
				assert.Equal(t, archive.Unchanged, out)
			}
		})
	}
	require.Equal(t, 5, ran)
}

func TestIntentAndAbsenceReadsCheckTheKey(t *testing.T) {
	fx := archivefix.Load(t)
	v := loadV1(t)
	ran := 0
	for _, r := range v.Reads {
		kind, err := archive.ParseKey(r.Path)
		if err != nil || kind != archive.KindAnchorIntent && kind != archive.KindAbsenceProof {
			continue
		}
		ran++
		t.Run(r.ID, func(t *testing.T) {
			s, dir := open(t, fx)
			b, err := hex.DecodeString(r.CBORHex)
			require.NoError(t, err)
			plant(t, dir, r.Path, b)
			rec, err := archive.Decode(b)
			require.NoError(t, err)
			switch x := rec.(type) {
			case *archive.AnchorIntentRecord:
				_, err = s.Intent(bg, x.DA, x.Commitment, heightOf(t, r.Path))
			case *archive.AbsenceProofRecord:
				_, err = s.Absence(bg, x.DA, x.Commitment, heightOf(t, r.Path))
			}
			if r.Expect == "None" || r.Expect == "" {
				require.NoError(t, err)
				return
			}
			require.ErrorIs(t, err, archive.ErrCorrupt)
		})
	}
	require.GreaterOrEqual(t, ran, 3)
}

func heightOf(t *testing.T, path string) uint64 {
	t.Helper()
	var n uint64
	i := len(path) - 1
	for i >= 0 && path[i] != '/' {
		i--
	}
	for _, c := range path[i+1:] {
		n = n*10 + uint64(c-'0')
	}
	require.NotZero(t, n)
	return n
}
