package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// A private mandate carries the secret state_salt: the unsigned and the
// signed file are owner-only, also when the file existed with a wider mode.
func TestPrivateMandateFileMode(t *testing.T) {
	cases, seeds := vectors(t)
	c := cases["m_full"]
	dir := t.TempDir()
	priv := filepath.Join(dir, "private.cbor")
	require.NoError(t, os.WriteFile(priv, nil, 0o644))
	code, _, errOut := call("private", "--mandate", file(t, "m.hex", c.Cbor),
		"--auditor", "Bob:"+strings.Repeat("09", 32), "--new-id", "--out", priv)
	require.Equal(t, exitOK, code, errOut)
	requireMode(t, priv, 0o600)

	signed := filepath.Join(dir, "signed.cbor")
	key := file(t, "key.hex", seeds[c.Signer]+"\n")
	code, _, errOut = call("sign", "--mandate", priv, "--scheme", "ed25519", "--key", key,
		"--book", filepath.Join(dir, "book.json"), "--out", signed)
	require.Equal(t, exitOK, code, errOut)
	requireMode(t, signed, 0o600)

}

func requireMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	fi, err := os.Stat(path)
	require.NoError(t, err)
	require.Equal(t, want, fi.Mode().Perm())
}
