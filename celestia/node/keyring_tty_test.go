//go:build darwin || linux

package node

import (
	"encoding/hex"
	"os"
	"testing"
	"time"

	"github.com/cosmos/cosmos-sdk/types/tx/signing"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/term"
)

const (
	fixturePass = "fixture-passphrase"
	fixtureAddr = "celestia13hzxpm30m23tfp90sv767u0fhc9xj0qk82ytnd"
	fixtureSig  = "e9542c22e7777ed3c364a98dce16fafb570dbd249160a2fca68ad955c82c52f5" +
		"399aed1b380c2393646805db8c5d05e8a7358c337089683d794b1fe83e50d1a0"
	fixtureMsg = "edicta keyring fixture message"
)

// fixtureDir copies the fixture keyring made by the SDK file backend, so a
// test can never modify the checked-in files.
func fixtureDir(t *testing.T) string {
	t.Helper()
	dst := t.TempDir()
	src := "testdata/file-keyring/keyring-file"
	require.NoError(t, os.MkdirAll(dst+"/keyring-file", 0o700))
	ents, err := os.ReadDir(src)
	require.NoError(t, err)
	for _, e := range ents {
		b, err := os.ReadFile(src + "/" + e.Name())
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(dst+"/keyring-file/"+e.Name(), b, 0o600))
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
		t.Fatal("OpenKeyring blocked on the terminal: it read os.Stdin")
		return nil
	}
}

func TestOpenKeyringOnTerminalNeverPrompts(t *testing.T) {
	dir := fixtureDir(t)
	err := withTTYStdin(t, func() error {
		kr, err := OpenKeyring(KeyringConfig{Dir: dir, Name: "executor", Backend: "file", Passphrase: []byte(fixturePass)})
		if err != nil {
			return err
		}
		_, err = kr.Key("executor")
		return err
	})
	require.NoError(t, err)
}

func TestOpenKeyringWrongPassphraseOnTerminalIsBadPassphrase(t *testing.T) {
	dir := fixtureDir(t)
	err := withTTYStdin(t, func() error {
		_, err := OpenKeyring(KeyringConfig{Dir: dir, Name: "executor", Backend: "file", Passphrase: []byte("not-the-passphrase")})
		return err
	})
	require.ErrorIs(t, err, ErrBadPassphrase)
	assert.NotContains(t, err.Error(), "not-the-passphrase")
}

func TestFixtureKeyringSameAddressAndSignature(t *testing.T) {
	dir := fixtureDir(t)
	kr, err := OpenKeyring(KeyringConfig{Dir: dir, Name: "executor", Backend: "file", Passphrase: []byte(fixturePass)})
	require.NoError(t, err)
	k, err := kr.Key("executor")
	require.NoError(t, err)
	addr, err := k.GetAddress()
	require.NoError(t, err)
	assert.Equal(t, fixtureAddr, addr.String())
	sig, _, err := kr.Sign("executor", []byte(fixtureMsg), signing.SignMode_SIGN_MODE_DIRECT)
	require.NoError(t, err)
	assert.Equal(t, fixtureSig, hex.EncodeToString(sig))
}
