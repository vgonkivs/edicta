package archive_test

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/test/archivefix"
)

type v1ArchiveFile struct {
	MarkerNames []string `json:"marker_names"`
	Unassigned  []string `json:"unassigned_kinds"`
	Cases       []struct {
		ID      string         `json:"id"`
		Kind    json.Number    `json:"kind"`
		Path    string         `json:"path"`
		Input   map[string]any `json:"input"`
		CBORHex string         `json:"record_cbor_hex"`
	} `json:"cases"`
	Reject []struct {
		ID      string `json:"id"`
		CBORHex string `json:"record_cbor_hex"`
		Cause   string `json:"cause"`
	} `json:"reject"`
}

func loadV1Archive(t *testing.T) v1ArchiveFile {
	t.Helper()
	raw, err := os.ReadFile("../spec/vectors/v1/archive.json")
	require.NoError(t, err)
	var f v1ArchiveFile
	require.NoError(t, json.Unmarshal(raw, &f))
	return f
}

func TestV1ArchiveCases(t *testing.T) {
	f := loadV1Archive(t)
	require.NotEmpty(t, f.Cases)
	for _, c := range f.Cases {
		t.Run(c.ID, func(t *testing.T) {
			want, err := hex.DecodeString(c.CBORHex)
			require.NoError(t, err)
			rec, err := archive.Decode(want)
			require.NoError(t, err)
			assert.EqualValues(t, c.Kind.String(), fmt.Sprint(uint64(rec.Kind())))
			assert.Equal(t, archivefix.Build(t, c.Input), rec)
			got, err := archive.Encode(rec)
			require.NoError(t, err)
			assert.Equal(t, c.CBORHex, hex.EncodeToString(got))
			path, err := archive.KeyPath(rec)
			require.NoError(t, err)
			assert.Equal(t, c.Path, path)
			kind, err := archive.ParseKey(path)
			require.NoError(t, err)
			assert.Equal(t, rec.Kind(), kind)
		})
	}
}

func TestV1ArchiveReject(t *testing.T) {
	f := loadV1Archive(t)
	require.NotEmpty(t, f.Reject)
	for _, r := range f.Reject {
		t.Run(r.ID, func(t *testing.T) {
			cause, ok := archivefix.Causes[r.Cause]
			require.True(t, ok, "unmapped cause %s", r.Cause)
			b, err := hex.DecodeString(r.CBORHex)
			require.NoError(t, err)
			rec, err := archive.Decode(b)
			require.Nil(t, rec)
			require.ErrorIs(t, err, archive.ErrCorrupt)
			require.ErrorIs(t, err, cause)
		})
	}
}

func TestV1MarkerNames(t *testing.T) {
	f := loadV1Archive(t)
	require.NotEmpty(t, f.MarkerNames)
	for _, n := range f.MarkerNames {
		assert.True(t, archive.IsVerdict(n), n)
	}
	for _, n := range []string{"ErrMandateMismatch", "ErrAnchorPending", "ErrNamespaceNotAllowed", "ErrAnchorIntentUnavailable"} {
		assert.False(t, archive.IsVerdict(n), "%s writes no marker", n)
	}
	for _, k := range f.Unassigned {
		b, err := archive.Encode(&archive.RejectionRecord{Error: "ErrExpired", GateID: "g", RejectedAt: 1})
		require.NoError(t, err)
		// Same record with the kind replaced by the unassigned one.
		b[4] = byte(mustUint(t, k))
		_, err = archive.Decode(b)
		require.ErrorIs(t, err, archive.ErrCorrupt, "kind %s", k)
	}
}

func mustUint(t *testing.T, s string) uint64 {
	t.Helper()
	var n uint64
	_, err := fmt.Sscan(s, &n)
	require.NoError(t, err)
	return n
}
