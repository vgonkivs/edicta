package fsarchive_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/archive/fsarchive"
	"github.com/vgonkivs/edicta/test/archivefix"
)

// absenceRecord is the first kind 14 vector record.
func absenceRecord(t *testing.T) *archive.AbsenceProofRecord {
	t.Helper()
	for _, c := range loadV1(t).Cases {
		if c.Kind == "14" {
			return archivefix.Build(t, c.Input).(*archive.AbsenceProofRecord)
		}
	}
	require.Fail(t, "no kind 14 case")
	return nil
}

// Put keeps the first absence proof of a key whatever its bytes; only
// ReplaceAbsence swaps a stored one, and an equal one is left untouched.
func TestReplaceAbsence(t *testing.T) {
	fx := archivefix.Load(t)
	rec := absenceRecord(t)
	other := *rec
	other.Header = append([]byte{0x01}, rec.Header...)
	key, err := archive.KeyPath(rec)
	require.NoError(t, err)

	for _, tc := range []struct {
		name  string
		setup func(t *testing.T, s *fsarchive.Store, dir string)
		put   *archive.AbsenceProofRecord
		want  archive.Outcome
	}{
		{"no record yet", func(*testing.T, *fsarchive.Store, string) {}, rec, archive.Written},
		{"byte-equal record", func(t *testing.T, s *fsarchive.Store, _ string) {
			_, err := s.Put(bg, rec)
			require.NoError(t, err)
		}, rec, archive.Unchanged},
		{"another record under the key", func(t *testing.T, s *fsarchive.Store, _ string) {
			_, err := s.Put(bg, &other)
			require.NoError(t, err)
		}, rec, archive.Written},
		{"a corrupt file under the key", func(t *testing.T, _ *fsarchive.Store, dir string) {
			plant(t, dir, key, []byte{0xff, 0x00, 0x01})
		}, rec, archive.Written},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, dir := open(t, fx)
			tc.setup(t, s, dir)
			out, err := s.ReplaceAbsence(bg, tc.put)
			require.NoError(t, err)
			assert.Equal(t, tc.want, out)
			got, err := s.Absence(bg, rec.DA, rec.Commitment, rec.Height)
			require.NoError(t, err)
			assert.Equal(t, tc.put, got)
			assert.Equal(t, []string{key}, archivefix.Files(t, dir), "no temp file is left")
		})
	}

	t.Run("read-only store", func(t *testing.T) {
		s, dir := open(t, fx)
		_, err := s.Put(bg, &other)
		require.NoError(t, err)
		before, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(key)))
		require.NoError(t, err)
		ro, err := fsarchive.OpenReadOnly(dir, committers(fx))
		require.NoError(t, err)
		_, err = ro.ReplaceAbsence(bg, rec)
		require.ErrorIs(t, err, fsarchive.ErrReadOnly)
		after, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(key)))
		require.NoError(t, err)
		assert.True(t, bytes.Equal(before, after))
	})
	t.Run("a record that does not encode", func(t *testing.T) {
		s, dir := open(t, fx)
		bad := *rec
		bad.Commitment = nil
		_, err := s.ReplaceAbsence(bg, &bad)
		require.Error(t, err)
		assert.Empty(t, archivefix.Files(t, dir))
	})
}
