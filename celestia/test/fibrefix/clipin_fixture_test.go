// SPDX-License-Identifier: Apache-2.0

//go:build clipin

package fibrefix_test

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/celestia/test/fibrefix"
)

// TestWriteCLIPinArchive regenerates the archive fixture the CLI pin replays
// `verify` against. The root module cannot import this package, so the
// fixture is checked in and only rebuilt on demand:
//
//	EDICTA_CLIPIN_ARCHIVE_OUT=$PWD/test/clipin/testdata/verify \
//	  go -C celestia test -tags clipin -run TestWriteCLIPinArchive ./test/fibrefix
func TestWriteCLIPinArchive(t *testing.T) {
	out := os.Getenv("EDICTA_CLIPIN_ARCHIVE_OUT")
	if out == "" {
		t.Skip("EDICTA_CLIPIN_ARCHIVE_OUT is not set")
	}
	l := fibrefix.LoadLive(t)
	d := l.WriteDecision(t, l.Evidence(t))
	trusted := l.TrustedFile(t, nil)

	require.NoError(t, os.RemoveAll(out))
	require.NoError(t, os.CopyFS(filepath.Join(out, "archive"), os.DirFS(d.Dir)))
	b, err := os.ReadFile(trusted)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(out, "trusted.json"), b, 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(out, "hash"), []byte(hex.EncodeToString(d.Hash[:])+"\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(out, "gate-key"), []byte(d.GateKeyHex+"\n"), 0o644))
}
