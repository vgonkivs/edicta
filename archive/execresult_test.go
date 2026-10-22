package archive_test

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/engine/commitment"
	"github.com/vgonkivs/edicta/test/archivefix"
	"github.com/vgonkivs/edicta/test/execresultfix"
)

func TestExecutionResultRecords(t *testing.T) {
	f := execresultfix.Load(t)
	require.NotEmpty(t, f.Records)
	for _, r := range f.Records {
		t.Run(r.ID, func(t *testing.T) {
			raw := execresultfix.Hex(t, r.CBORHex)
			sum := sha256.Sum256(raw)
			require.Equal(t, r.SHA256Hex, hex.EncodeToString(sum[:]))

			rec, err := archive.DecodeExecutionResult(raw)
			require.NoError(t, err)
			assert.Equal(t, r.Build(t), rec)
			again, err := archive.Encode(rec)
			require.NoError(t, err)
			assert.Equal(t, r.CBORHex, hex.EncodeToString(again))

			path, err := archive.KeyPath(rec)
			require.NoError(t, err)
			assert.Equal(t, r.Path, path)
			kind, err := archive.ParseKey(path)
			require.NoError(t, err)
			assert.Equal(t, archive.KindExecutionResult, kind)
			want, err := archive.ExecResultPath(r.Key.ChainID, execresultfix.Hex(t, r.Key.RailRef))
			require.NoError(t, err)
			assert.Equal(t, r.Path, want)

			at, err := archive.DecodeAt(path, raw)
			require.NoError(t, err)
			assert.Equal(t, rec, at)

			// The general reader is the v1.0 one: it refuses the kind.
			require.Equal(t, "ErrInvalidEnum", r.V10ReaderCause)
			_, err = archive.Decode(raw)
			require.ErrorIs(t, err, archive.ErrCorrupt)
			require.ErrorIs(t, err, commitment.ErrInvalidEnum)
		})
	}
}

func TestExecutionResultRejects(t *testing.T) {
	f := execresultfix.Load(t)
	require.NotEmpty(t, f.Reject)
	for _, r := range f.Reject {
		t.Run(r.ID, func(t *testing.T) {
			require.Equal(t, "archive.ErrCorrupt", r.ExpectError)
			cause, ok := archivefix.Causes[r.Cause]
			require.True(t, ok, "unmapped cause %s", r.Cause)
			raw := execresultfix.Hex(t, r.CBORHex)
			_, err := archive.DecodeExecutionResult(raw)
			require.ErrorIs(t, err, archive.ErrCorrupt)
			require.ErrorIs(t, err, cause)
			_, err = archive.DecodeAt("exec/mocha-5/"+strings.Repeat("00", 32), raw)
			require.ErrorIs(t, err, cause)
		})
	}
}

// The cases with rule decode fail strict decoding: the verifier sets them
// aside before any XR rule.
func TestExecutionResultDecodeCases(t *testing.T) {
	f := execresultfix.Load(t)
	n := 0
	for _, c := range f.Cases {
		raw := execresultfix.Hex(t, c.CBORHex)
		_, err := archive.DecodeExecutionResult(raw)
		if c.Expect.Rule == "decode" {
			n++
			require.ErrorIs(t, err, archive.ErrCorrupt, c.ID)
			continue
		}
		require.NoError(t, err, c.ID)
	}
	require.Positive(t, n)
}

func execRecord(t *testing.T) (*archive.ExecutionResultRecord, []byte) {
	t.Helper()
	r := execresultfix.Load(t).Records[0]
	return r.Build(t), execresultfix.Hex(t, r.CBORHex)
}

func TestExecutionResultReaderIsolation(t *testing.T) {
	rec, raw := execRecord(t)

	// The kind 19 reader takes no other kind.
	fx := archivefix.Load(t)
	for _, c := range fx.Cases {
		if c.CBOR == nil {
			continue
		}
		_, err := archive.DecodeExecutionResult(c.CBOR)
		require.ErrorIs(t, err, archive.ErrCorrupt, c.ID)
		require.ErrorIs(t, err, commitment.ErrInvalidEnum, c.ID)
	}

	// Under any other path the general reader refuses it.
	_, err := archive.DecodeAt("decision/"+strings.Repeat("00", 32), raw)
	require.ErrorIs(t, err, commitment.ErrInvalidEnum)

	// Encode checks the record with its own reader.
	b, err := archive.Encode(rec)
	require.NoError(t, err)
	assert.Equal(t, raw, b)
	bad := *rec
	bad.ResultsTotal = 0
	_, err = archive.Encode(&bad)
	require.ErrorIs(t, err, commitment.ErrZeroValue)
	bad = *rec
	bad.ResultPath = make([]byte, 33)
	_, err = archive.Encode(&bad)
	require.ErrorIs(t, err, commitment.ErrFieldSize)
}

func TestExecutionResultIdentityIsTheKey(t *testing.T) {
	rec, _ := execRecord(t)
	other := *rec
	other.Height++
	other.Result = []byte{0x08, 0x01}
	assert.True(t, archive.SameIdentity(rec, &other))
	other.RailRef = make([]byte, 32)
	assert.False(t, archive.SameIdentity(rec, &other))
	other = *rec
	other.ChainID = "mocha-4"
	assert.False(t, archive.SameIdentity(rec, &other))
	assert.False(t, archive.SameIdentity(rec, &archive.DecisionRecord{}))
}

func TestExecResultPathAndParseKey(t *testing.T) {
	ref := make([]byte, 32)
	hexRef := strings.Repeat("00", 32)
	for _, ok := range []string{"mocha-5", "A", "a.b_c-d", strings.Repeat("x", 50)} {
		p, err := archive.ExecResultPath(ok, ref)
		require.NoError(t, err, ok)
		assert.Equal(t, "exec/"+ok+"/"+hexRef, p)
		k, err := archive.ParseKey(p)
		require.NoError(t, err, ok)
		assert.Equal(t, archive.KindExecutionResult, k)
	}
	for _, bad := range []string{"", ".", "..", ".hidden", "a/b", "a b", strings.Repeat("x", 51), "mé"} {
		_, err := archive.ExecResultPath(bad, ref)
		require.Error(t, err, bad)
		_, err = archive.ParseKey("exec/" + bad + "/" + hexRef)
		require.Error(t, err, bad)
	}
	_, err := archive.ExecResultPath("mocha-5", ref[:31])
	require.ErrorIs(t, err, commitment.ErrFieldSize)
	for _, bad := range []string{
		"exec/mocha-5/" + strings.ToUpper(strings.Repeat("ab", 32)),
		"exec/mocha-5/" + strings.Repeat("00", 31),
		"exec/mocha-5",
		"exec/mocha-5/" + hexRef + "/x",
		"exec//" + hexRef,
	} {
		_, err := archive.ParseKey(bad)
		require.Error(t, err, bad)
	}
}
