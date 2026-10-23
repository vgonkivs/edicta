package edictad

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCaptureDirOverlapsArchiveDir(t *testing.T) {
	root := t.TempDir()
	archive := filepath.Join(root, "archive")
	require.NoError(t, os.MkdirAll(archive, 0o700))
	wd, err := os.Getwd()
	require.NoError(t, err)
	relArchive, err := filepath.Rel(wd, archive)
	require.NoError(t, err)

	for name, tc := range map[string]struct {
		capture, archive string
		overlap          bool
	}{
		"same":                     {archive, archive, true},
		"same, trailing slash":     {archive + "/", archive, true},
		"inside":                   {filepath.Join(archive, "cap"), archive, true},
		"inside through ..":        {filepath.Join(root, "x", "..", "archive", "cap"), archive, true},
		"a child named ..x":        {filepath.Join(archive, "..x"), archive, true},
		"archive inside capture":   {root, archive, true},
		"relative archive, inside": {filepath.Join(archive, "cap"), relArchive, true},
		"relative capture, same":   {relArchive, archive, true},
		"sibling":                  {filepath.Join(root, "capture"), archive, false},
		"sibling sharing a prefix": {archive + "2", archive, false},
		"sibling named ..archive":  {filepath.Join(root, "..archive"), archive, false},
		"no archive dir":           {filepath.Join(root, "capture"), "", false},
	} {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tc.overlap, dirsOverlap(tc.capture, tc.archive, lexicalDir))
			assert.Equal(t, tc.overlap, dirsOverlap(tc.capture, tc.archive, realDir))
		})
	}

	t.Run("through a symlink", func(t *testing.T) {
		link := filepath.Join(root, "link")
		require.NoError(t, os.Symlink(archive, link))
		capture := filepath.Join(link, "cap", "deeper")
		assert.False(t, dirsOverlap(capture, archive, lexicalDir), "the lexical check cannot see it")
		assert.True(t, dirsOverlap(capture, archive, realDir))
		assert.True(t, dirsOverlap(root, link, realDir), "the archive behind a link inside capture.dir")
	})
}
