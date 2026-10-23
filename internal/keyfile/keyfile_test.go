package keyfile_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/internal/keyfile"
	"github.com/vgonkivs/edicta/internal/secret"
)

func write(t *testing.T, data []byte, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "key")
	require.NoError(t, os.WriteFile(p, data, mode))
	require.NoError(t, os.Chmod(p, mode))
	return p
}

func seq(n int, last byte) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i + 1)
	}
	b[n-1] = last
	return b
}

func TestNewSeedWritesA0600FileItReadsBack(t *testing.T) {
	p := filepath.Join(t.TempDir(), "sub", "dir", "agent.ed25519")
	pub, err := keyfile.NewSeed(p)
	require.NoError(t, err)

	fi, err := os.Stat(p)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), fi.Mode().Perm())
	assert.Equal(t, int64(keyfile.SeedLen), fi.Size())
	di, err := os.Stat(filepath.Dir(p))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o700), di.Mode().Perm())

	priv, err := keyfile.ReadSeed(p, "agent")
	require.NoError(t, err)
	assert.Equal(t, pub, priv.Public().(ed25519.PublicKey))
}

func TestWriteNewNeverOverwrites(t *testing.T) {
	p := write(t, []byte("old"), 0o600)
	err := keyfile.WriteNew(p, []byte("new"))
	require.ErrorIs(t, err, keyfile.ErrExists)
	got, err := os.ReadFile(p)
	require.NoError(t, err)
	assert.Equal(t, "old", string(got))

	_, err = keyfile.NewSeed(p)
	require.ErrorIs(t, err, keyfile.ErrExists)
}

func TestWriteNewLeavesNoTemporaryFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "payer.secp256k1")
	require.NoError(t, keyfile.WriteNew(p, []byte("key")))
	require.ErrorIs(t, keyfile.WriteNew(p, []byte("other")), keyfile.ErrExists)

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	require.Len(t, entries, 1, "only the key file, no temporary file")
	assert.Equal(t, "payer.secp256k1", entries[0].Name())
	got, err := os.ReadFile(p)
	require.NoError(t, err)
	assert.Equal(t, "key", string(got))
	fi, err := os.Stat(p)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), fi.Mode().Perm())
}

func TestWriteNewRefusesASymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	link := filepath.Join(dir, "link")
	require.NoError(t, os.Symlink(target, link))
	require.ErrorIs(t, keyfile.WriteNew(link, []byte("k")), keyfile.ErrExists, "a dangling symlink is not followed")
	_, err := os.Lstat(target)
	assert.True(t, os.IsNotExist(err), "nothing is created through the link")
}

func TestReadSeedDoesNotTrim(t *testing.T) {
	for _, last := range []byte{'\n', '\r', ' '} {
		seed := seq(keyfile.SeedLen, last)
		priv, err := keyfile.ReadSeed(write(t, seed, 0o600), "gate")
		require.NoError(t, err)
		assert.Equal(t, seed, priv.Seed())
	}
}

func TestReadSeedRefusals(t *testing.T) {
	t.Run("too short", func(t *testing.T) {
		_, err := keyfile.ReadSeed(write(t, seq(31, 1), 0o600), "gate")
		require.ErrorIs(t, err, keyfile.ErrBadKeyFile)
	})
	t.Run("too long", func(t *testing.T) {
		_, err := keyfile.ReadSeed(write(t, append(seq(32, 1), '\n'), 0o600), "gate")
		require.ErrorIs(t, err, keyfile.ErrBadKeyFile)
	})
	t.Run("large file", func(t *testing.T) {
		_, err := keyfile.ReadSeed(write(t, make([]byte, 1<<20), 0o600), "gate")
		require.ErrorIs(t, err, keyfile.ErrBadKeyFile)
	})
	t.Run("group readable", func(t *testing.T) {
		_, err := keyfile.ReadSeed(write(t, seq(32, 1), 0o640), "gate")
		require.ErrorIs(t, err, secret.ErrPermissions)
	})
	t.Run("other readable", func(t *testing.T) {
		_, err := keyfile.ReadSeed(write(t, seq(32, 1), 0o604), "gate")
		require.ErrorIs(t, err, secret.ErrPermissions)
	})
	t.Run("directory", func(t *testing.T) {
		d := filepath.Join(t.TempDir(), "d")
		require.NoError(t, os.Mkdir(d, 0o700))
		_, err := keyfile.ReadSeed(d, "gate")
		require.ErrorIs(t, err, keyfile.ErrBadKeyFile)
	})
	t.Run("missing", func(t *testing.T) {
		_, err := keyfile.ReadSeed(filepath.Join(t.TempDir(), "none"), "gate")
		require.ErrorIs(t, err, os.ErrNotExist)
	})
}

func TestReadSecp256k1(t *testing.T) {
	for _, last := range []byte{'\n', '\r', ' ', 0x01} {
		k := seq(32, last)
		got, err := keyfile.ReadSecp256k1(write(t, k, 0o600), "payer")
		require.NoError(t, err, "raw key ending in %#x", last)
		assert.Equal(t, k, got, "a raw key is read whole, its last byte %#x included", last)
	}

	k := seq(32, 0x0a)
	h := []byte(hex.EncodeToString(k))
	for name, data := range map[string][]byte{
		"hex":                  h,
		"hex with newline":     append(bytes.Clone(h), '\n'),
		"upper-case hex":       bytes.ToUpper(h),
		"upper-case hex + \\n": append(bytes.ToUpper(h), '\n'),
	} {
		got, err := keyfile.ReadSecp256k1(write(t, data, 0o600), "payer")
		require.NoError(t, err, name)
		assert.Equal(t, k, got, name)
	}

	for name, data := range map[string][]byte{
		"31 bytes":            seq(31, 1),
		"33 bytes":            seq(33, 1),
		"hex with CRLF":       append(bytes.Clone(h), '\r', '\n'),
		"hex with space":      append(bytes.Clone(h), ' '),
		"not hex":             bytes.Repeat([]byte("zz"), 32),
		"65 bytes, no \\n":    append(bytes.Clone(h), 'a'),
		"large":               make([]byte, 4096),
		"empty":               {},
		"62 hex + newline(s)": append([]byte(hex.EncodeToString(k[:31])), '\n', '\n', '\n'),
	} {
		_, err := keyfile.ReadSecp256k1(write(t, data, 0o600), "payer")
		require.ErrorIs(t, err, keyfile.ErrBadKeyFile, name)
	}

	_, err := keyfile.ReadSecp256k1(write(t, k, 0o644), "payer")
	require.ErrorIs(t, err, secret.ErrPermissions)
}
