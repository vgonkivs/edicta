package node

import (
	"os"
	"testing"
	"time"

	"github.com/cosmos/cosmos-sdk/crypto/keyring"
	"github.com/stretchr/testify/require"
)

// ErrBadPassphrase wraps ErrKeyring and is returned by OpenKeyring when the file backend cannot decrypt with the given passphrase.
func TestOpenKeyringWrongPassphraseFailsWithoutReadingStdin(t *testing.T) {
	dir := t.TempDir()
	makeKey(t, dir, keyring.BackendFile, "executor", "right-passphrase")

	// A stdin nobody writes to or closes: any read blocks forever.
	r, w, err := os.Pipe()
	require.NoError(t, err)
	t.Cleanup(func() { _ = r.Close(); _ = w.Close() })
	old := os.Stdin
	os.Stdin = r
	t.Cleanup(func() { os.Stdin = old })

	done := make(chan error, 1)
	go func() {
		_, err := OpenKeyring(KeyringConfig{Dir: dir, Name: "executor", Backend: "file", Passphrase: []byte("wrong-passphrase")})
		done <- err
	}()
	select {
	case err := <-done:
		require.ErrorIs(t, err, ErrBadPassphrase)
		require.ErrorIs(t, err, ErrKeyring)
		require.NotContains(t, err.Error(), "wrong-passphrase")
	case <-time.After(10 * time.Second):
		t.Fatal("OpenKeyring blocked: it read os.Stdin")
	}
}
