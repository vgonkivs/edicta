//go:build darwin || linux

package railtx_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/term"

	"github.com/vgonkivs/edicta/celestia/node"
	"github.com/vgonkivs/edicta/celestia/nodefake"
	"github.com/vgonkivs/edicta/celestia/railtx"
	"github.com/vgonkivs/edicta/celestia/secret"
)

const (
	fixturePass = "fixture-passphrase"
	fixtureAddr = "celestia13hzxpm30m23tfp90sv767u0fhc9xj0qk82ytnd"
)

// fixtureDir copies the checked-in keyring so a test never modifies it.
func fixtureDir(t *testing.T) string {
	t.Helper()
	dst := t.TempDir()
	src := "testdata/file-keyring/keyring-file"
	require.NoError(t, os.MkdirAll(filepath.Join(dst, "keyring-file"), 0o700))
	ents, err := os.ReadDir(src)
	require.NoError(t, err)
	for _, e := range ents {
		b, err := os.ReadFile(filepath.Join(src, e.Name()))
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(dst, "keyring-file", e.Name()), b, 0o600))
	}
	return dst
}

// withTTYStdin makes os.Stdin a terminal for the duration of f. Nothing is
// ever typed on it, so any read blocks until the timeout.
func withTTYStdin(t *testing.T, f func() error) error {
	t.Helper()
	m, s := openPTY(t)
	require.True(t, term.IsTerminal(int(s.Fd())))
	old := os.Stdin
	os.Stdin = s
	done := make(chan error, 1)
	go func() { done <- f() }()
	defer func() {
		_ = m.Close()
		_ = s.Close()
		os.Stdin = old
	}()
	select {
	case err := <-done:
		return err
	case <-time.After(5 * time.Second):
		// Hanging up the master wakes a blocked read; wait so neither the
		// slave nor os.Stdin is touched under a running goroutine.
		_ = m.Close()
		<-done
		t.Fatal("blocked on the terminal: it read os.Stdin")
		return nil
	}
}

func TestKeyFromKeyringOnTerminalNeverPrompts(t *testing.T) {
	dir := fixtureDir(t)
	var sender string
	err := withTTYStdin(t, func() error {
		r, err := railtx.New(railtx.Config{
			Consensus: nodefake.NewConsensus("mocha-4"), Reader: nodefake.NewChain(nil), GasLimit: 1,
			Key: railtx.KeyFromKeyring(dir, "executor", secret.New([]byte(fixturePass))),
		})
		if err != nil {
			return err
		}
		d, err := r.Domain(bg)
		sender = d.Sender
		return err
	})
	require.NoError(t, err)
	assert.Equal(t, fixtureAddr, sender)
}

func TestKeyFromKeyringWrongPassphraseOnTerminalIsBadPassphrase(t *testing.T) {
	dir := fixtureDir(t)
	err := withTTYStdin(t, func() error {
		_, err := railtx.New(railtx.Config{
			Consensus: nodefake.NewConsensus("mocha-4"), Reader: nodefake.NewChain(nil), GasLimit: 1,
			Key: railtx.KeyFromKeyring(dir, "executor", secret.New([]byte("not-the-passphrase"))),
		})
		return err
	})
	require.ErrorIs(t, err, node.ErrBadPassphrase)
	assert.NotContains(t, err.Error(), "not-the-passphrase")
}

func TestImportKeyringOnTerminalNeverPrompts(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "kr")
	err := withTTYStdin(t, func() error {
		return railtx.ImportKeyring(dir, "executor", secret.New([]byte(fixturePass)), secret.New(scalar(5)))
	})
	require.NoError(t, err)
}
