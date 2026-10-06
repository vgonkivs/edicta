package fsarchive_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/archive/fsarchive"
	"github.com/vgonkivs/edicta/test/archivefix"
)

func TestOpenReadOnlyReadsAndNeverWrites(t *testing.T) {
	fx := archivefix.Load(t)
	writer, dir := open(t, fx)
	p := fx.Cases["payload_da2_minimal_lmt"].Record.(*archive.PayloadRecord)
	d := fx.Cases["decision_minimal_lmt"].Record.(*archive.DecisionRecord)
	for _, r := range []archive.Record{p, d} {
		_, err := writer.Put(bg, r)
		require.NoError(t, err)
	}
	old := filepath.Join(dir, ".tmp-old")
	require.NoError(t, os.WriteFile(old, []byte("x"), 0o644))
	past := time.Now().Add(-2 * time.Hour)
	require.NoError(t, os.Chtimes(old, past, past))

	before := archivefix.Files(t, dir)

	ro, err := fsarchive.OpenReadOnly(dir, committers(fx))
	require.NoError(t, err)

	got, err := ro.Payload(bg, p.DA, p.Commitment)
	require.NoError(t, err)
	assert.Equal(t, p.Blob, got.Blob)

	_, err = ro.Put(bg, fx.Cases["evidence_da2_minimal_lmt"].Record)
	require.ErrorIs(t, err, fsarchive.ErrReadOnly)
	_, err = ro.Put(bg, p)
	require.ErrorIs(t, err, fsarchive.ErrReadOnly, "even a record that is already stored")

	assert.FileExists(t, old, "an old temp file is not cleaned up")
	assert.Equal(t, before, archivefix.Files(t, dir), "no record appeared and the old temp file is still listed")
}

func TestOpenReadOnlyDoesNotCreateTheDirectory(t *testing.T) {
	fx := archivefix.Load(t)
	missing := filepath.Join(t.TempDir(), "nope")
	_, err := fsarchive.OpenReadOnly(missing, committers(fx))
	require.Error(t, err)
	assert.NoDirExists(t, missing)

	file := filepath.Join(t.TempDir(), "f")
	require.NoError(t, os.WriteFile(file, nil, 0o644))
	_, err = fsarchive.OpenReadOnly(file, committers(fx))
	require.Error(t, err)
}

func TestOpenReadOnlyOnAReadOnlyDirectory(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("directory permissions do not bind root")
	}
	fx := archivefix.Load(t)
	writer, dir := open(t, fx)
	p := fx.Cases["payload_da2_minimal_lmt"].Record.(*archive.PayloadRecord)
	_, err := writer.Put(bg, p)
	require.NoError(t, err)

	var dirs []string
	require.NoError(t, filepath.WalkDir(dir, func(path string, e os.DirEntry, err error) error {
		if err == nil && e.IsDir() {
			dirs = append(dirs, path)
		}
		return err
	}))
	for i := len(dirs) - 1; i >= 0; i-- {
		require.NoError(t, os.Chmod(dirs[i], 0o555))
	}
	t.Cleanup(func() {
		for _, d := range dirs {
			_ = os.Chmod(d, 0o755)
		}
	})

	ro, err := fsarchive.OpenReadOnly(dir, committers(fx))
	require.NoError(t, err)
	got, err := ro.Payload(bg, p.DA, p.Commitment)
	require.NoError(t, err)
	assert.Equal(t, p.Blob, got.Blob)
	_, err = ro.Put(bg, p)
	require.ErrorIs(t, err, fsarchive.ErrReadOnly)
}
