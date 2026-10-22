package fsarchive_test

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/engine/archive"
	"github.com/vgonkivs/edicta/engine/archive/fsarchive"
	"github.com/vgonkivs/edicta/engine/commitment"
	"github.com/vgonkivs/edicta/test/archivefix"
	"github.com/vgonkivs/edicta/test/execresultfix"
)

func TestExecutionResultWriteOnceByKey(t *testing.T) {
	ctx := context.Background()
	f := execresultfix.Load(t)
	s, err := fsarchiveOpen(t.TempDir(), archivefix.Load(t))
	require.NoError(t, err)

	r := f.Records[0]
	rec := r.Build(t)
	ref := execresultfix.Hex(t, r.Key.RailRef)

	_, err = s.ExecutionResult(ctx, r.Key.ChainID, ref)
	require.ErrorIs(t, err, archive.ErrNotFound)

	// No other record is needed first.
	out, err := s.Put(ctx, rec)
	require.NoError(t, err)
	assert.Equal(t, archive.Written, out)

	got, err := s.ExecutionResult(ctx, r.Key.ChainID, ref)
	require.NoError(t, err)
	assert.Equal(t, rec, got)
	rc, err := s.Raw(ctx, r.Path)
	require.NoError(t, err)
	raw, err := io.ReadAll(rc)
	require.NoError(t, rc.Close())
	require.NoError(t, err)
	assert.Equal(t, execresultfix.Hex(t, r.CBORHex), raw)

	// The identity is the key: another record under it is not written, and
	// the first one stays.
	other := *rec
	other.ResultPath = append(bytes.Clone(rec.ResultPath), make([]byte, 32)...)
	out, err = s.Put(ctx, &other)
	require.NoError(t, err)
	assert.Equal(t, archive.Unchanged, out)
	got, err = s.ExecutionResult(ctx, r.Key.ChainID, ref)
	require.NoError(t, err)
	assert.Equal(t, rec, got)

	// Impossible keys are absent.
	_, err = s.ExecutionResult(ctx, ".x", ref)
	require.ErrorIs(t, err, archive.ErrNotFound)
	_, err = s.ExecutionResult(ctx, r.Key.ChainID, ref[:31])
	require.ErrorIs(t, err, archive.ErrNotFound)
}

func TestExecutionResultReaderChecksTheKey(t *testing.T) {
	ctx := context.Background()
	f := execresultfix.Load(t)
	dir := t.TempDir()
	s, err := fsarchiveOpen(dir, archivefix.Load(t))
	require.NoError(t, err)
	a, b := f.Records[0], f.Records[1]
	require.NotEqual(t, a.Path, b.Path)

	// The record of another key under a's path is corrupt, never a's.
	p := filepath.Join(dir, filepath.FromSlash(a.Path))
	require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o755))
	require.NoError(t, os.WriteFile(p, execresultfix.Hex(t, b.CBORHex), 0o644))
	_, err = s.ExecutionResult(ctx, a.Key.ChainID, execresultfix.Hex(t, a.Key.RailRef))
	require.ErrorIs(t, err, archive.ErrCorrupt)

	// A write over a corrupt record is refused and leaves it.
	_, err = s.Put(ctx, a.Build(t))
	require.ErrorIs(t, err, archive.ErrCorrupt)

	// A record that fails strict decoding is corrupt with its cause.
	reject := f.Reject[0]
	require.NoError(t, os.WriteFile(p, execresultfix.Hex(t, reject.CBORHex), 0o644))
	_, err = s.ExecutionResult(ctx, a.Key.ChainID, execresultfix.Hex(t, a.Key.RailRef))
	require.ErrorIs(t, err, archive.ErrCorrupt)
	require.ErrorIs(t, err, archivefix.Causes[reject.Cause])
}

func TestExecutionResultOnAReadOnlyStore(t *testing.T) {
	ctx := context.Background()
	f := execresultfix.Load(t)
	dir := t.TempDir()
	s, err := fsarchiveOpen(dir, archivefix.Load(t))
	require.NoError(t, err)
	r := f.Records[0]
	_, err = s.Put(ctx, r.Build(t))
	require.NoError(t, err)

	ro, err := fsarchive.OpenReadOnly(dir, nil)
	require.NoError(t, err)
	got, err := ro.ExecutionResult(ctx, r.Key.ChainID, execresultfix.Hex(t, r.Key.RailRef))
	require.NoError(t, err)
	assert.Equal(t, r.Build(t), got)
	_, err = ro.Put(ctx, r.Build(t))
	require.ErrorIs(t, err, fsarchive.ErrReadOnly)
}

func TestExecutionResultReaderPaths(t *testing.T) {
	ctx := context.Background()
	f := execresultfix.Load(t)
	fx := archivefix.Load(t)
	dir := t.TempDir()
	s, err := fsarchiveOpen(dir, fx)
	require.NoError(t, err)
	r := f.Records[0]
	put := func(rel string, b []byte) {
		p := filepath.Join(dir, filepath.FromSlash(rel))
		require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o755))
		require.NoError(t, os.WriteFile(p, b, 0o644))
	}

	// Kind 19 bytes under a decision path are refused by the general reader.
	var h commitment.Hash
	h[0] = 0x42
	put("decision/"+archive.HashPath(archive.KindDecision, h)[len("decision/"):], execresultfix.Hex(t, r.CBORHex))
	_, err = s.Decision(ctx, h)
	require.ErrorIs(t, err, archive.ErrCorrupt)
	require.ErrorIs(t, err, commitment.ErrInvalidEnum)

	// A record of another kind under exec/ is refused by the kind 19 reader.
	var other []byte
	for _, c := range fx.Cases {
		if c.CBOR != nil {
			other = c.CBOR
			break
		}
	}
	require.NotNil(t, other)
	put(r.Path, other)
	_, err = s.ExecutionResult(ctx, r.Key.ChainID, execresultfix.Hex(t, r.Key.RailRef))
	require.ErrorIs(t, err, archive.ErrCorrupt)
	require.ErrorIs(t, err, commitment.ErrInvalidEnum)
}
