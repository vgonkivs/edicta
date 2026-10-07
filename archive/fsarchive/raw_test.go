package fsarchive_test

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/archive/fsarchive"
	"github.com/vgonkivs/edicta/test/archivefix"
)

var _ interface {
	Raw(ctx context.Context, key string) (io.ReadCloser, error)
} = (*fsarchive.Store)(nil)

func readRaw(t *testing.T, s *fsarchive.Store, key string) ([]byte, error) {
	t.Helper()
	rc, err := s.Raw(bg, key)
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	b, rerr := io.ReadAll(rc)
	require.NoError(t, rerr)
	return b, nil
}

func TestRawServesTheStoredBytesVerbatim(t *testing.T) {
	fx := archivefix.Load(t)
	for _, ids := range [][]string{
		{"payload_da2_minimal_lmt", "evidence_da2_minimal_lmt", "decision_minimal_lmt", "authorization_minimal_lmt_da"},
		{"payload_da2_minimal_lmt", "evidence_da2_minimal_lmt", "decision_minimal_lmt", "rejection_minimal_lmt_not_yet_valid"},
	} {
		s, dir := open(t, fx)
		for _, id := range ids {
			c := fx.Cases[id]
			_, err := s.Put(bg, c.Record)
			require.NoError(t, err, id)

			got, err := readRaw(t, s, c.Key)
			require.NoError(t, err, id)
			onDisk, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(c.Key)))
			require.NoError(t, err)
			assert.Equal(t, onDisk, got, id)

			rec, err := archive.Decode(got)
			require.NoError(t, err)
			assert.True(t, archive.SameIdentity(c.Record, rec), id)
		}
	}
}

func TestRawDoesNotDecodeOrCheckTheRecord(t *testing.T) {
	fx := archivefix.Load(t)
	s, dir := open(t, fx)
	c := fx.Cases["decision_minimal_lmt"]
	_, err := s.Put(bg, c.Record)
	require.NoError(t, err)
	path := filepath.Join(dir, filepath.FromSlash(c.Key))
	require.NoError(t, os.WriteFile(path, []byte("not a record"), 0o644))

	got, err := readRaw(t, s, c.Key)
	require.NoError(t, err)
	assert.Equal(t, []byte("not a record"), got, "the client's reader checks decide, not the server's")
}

func TestRawAbsentAndImpossibleKeysAreNotFound(t *testing.T) {
	fx := archivefix.Load(t)
	s, dir := open(t, fx)
	c := fx.Cases["decision_minimal_lmt"]
	_, err := s.Put(bg, c.Record)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "outside"), []byte("x"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".hidden"), []byte("x"), 0o644))

	for _, key := range []string{
		fx.Cases["decision_fibre_small_payload"].Key,
		fx.Cases["payload_da2_minimal_lmt"].Key,
		"",
		"decision",
		"decision/",
		"../outside",
		"decision/../../outside",
		"decision/../outside",
		"outside",
		".hidden",
		"/decision/e2ea62234c504e4df72e172c8e0da5f02a1eeb784ccd39ac9e20f6dd4c7c8f1d",
		"decision/E2EA62234C504E4DF72E172C8E0DA5F02A1EEB784CCD39AC9E20F6DD4C7C8F1D",
	} {
		rc, err := s.Raw(bg, key)
		if rc != nil {
			rc.Close()
		}
		require.ErrorIs(t, err, archive.ErrNotFound, "%q", key)
	}
}

func TestRawFollowsNoLinkOutOfTheTree(t *testing.T) {
	fx := archivefix.Load(t)
	s, dir := open(t, fx)
	c := fx.Cases["decision_minimal_lmt"]
	outside := filepath.Join(t.TempDir(), "secret")
	require.NoError(t, os.WriteFile(outside, []byte("secret"), 0o644))
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "decision"), 0o755))
	if err := os.Symlink(outside, filepath.Join(dir, filepath.FromSlash(c.Key))); err != nil {
		t.Skipf("no symlinks: %v", err)
	}
	rc, err := s.Raw(bg, c.Key)
	if rc != nil {
		b, _ := io.ReadAll(rc)
		rc.Close()
		assert.NotEqual(t, []byte("secret"), b)
	}
	require.Error(t, err)
}

func TestRawWorksOnAReadOnlyStore(t *testing.T) {
	fx := archivefix.Load(t)
	w, dir := open(t, fx)
	c := fx.Cases["decision_minimal_lmt"]
	_, err := w.Put(bg, c.Record)
	require.NoError(t, err)

	ro, err := fsarchive.OpenReadOnly(dir, committers(fx))
	require.NoError(t, err)
	got, err := readRaw(t, ro, c.Key)
	require.NoError(t, err)
	want, err := archive.Encode(c.Record)
	require.NoError(t, err)
	assert.Equal(t, want, got)
}
