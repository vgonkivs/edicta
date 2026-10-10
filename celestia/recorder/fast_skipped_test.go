package recorder_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/archive"
)

// Every archived intent the recovery leaves out is counted and logged once at
// error level with its path: one that does not decode and one that decodes
// but cannot be followed. A later Publish does not count them again.
func TestFastBlobRecoveryCountsSkippedIntents(t *testing.T) {
	f := newBlobFast(t)
	dir := t.TempDir()
	f.st = openArchive(t, dir)
	clean := f.recSlow(f.st, nil)
	_, err := clean.Publish(bg, f.blob)
	require.NoError(t, err)
	assert.Zero(t, clean.SkippedIntents())
	require.NoError(t, clean.Close(bg))

	bad := f.plantIntent(7)
	badPath, err := archive.IntentPath(bad.DA, bad.Commitment, bad.RefHeight)
	require.NoError(t, err)
	junkPath, err := archive.IntentPath(bad.DA, bad.Commitment, bad.RefHeight+1)
	require.NoError(t, err)
	junk := filepath.Join(dir, filepath.FromSlash(junkPath))
	require.NoError(t, os.WriteFile(junk, []byte("not a record"), 0o600))

	log := &logBuf{}
	r := f.recSlow(f.st, log)
	_, err = r.Publish(bg, []byte("blob B"))
	require.NoError(t, err)
	_, err = r.Publish(bg, []byte("blob C"))
	require.NoError(t, err)

	assert.EqualValues(t, 2, r.SkippedIntents())
	assert.Equal(t, 1, log.count("does not decode and is not followed"))
	assert.Equal(t, 1, log.count("cannot be followed and is skipped"))
	assert.Equal(t, 2, log.count("level=ERROR"), "one error line per record")
	assert.Equal(t, 1, log.count(junkPath), "the undecodable record is named by its path")
	assert.Equal(t, 1, log.count(badPath), "the unfollowable record is named by its path")
}
