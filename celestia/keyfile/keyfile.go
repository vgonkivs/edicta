// Package keyfile reads and creates the raw key files of the Edicta binaries:
// a 32-byte Ed25519 seed, mode 0600, never overwritten. The format is the one
// edicta-live and edictad read.
package keyfile

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/vgonkivs/edicta/celestia/secret"
)

// SeedLen is the length of a raw Ed25519 seed file.
const SeedLen = ed25519.SeedSize

// ErrExists means the file is already there; files are never overwritten.
var ErrExists = errors.New("keyfile: file exists")

// ReadSeed reads a raw Ed25519 seed. It does not trim: a trailing newline may
// be a seed byte. The file must be a regular file of mode 0600 or tighter.
func ReadSeed(path, what string) (ed25519.PrivateKey, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("%s key file: %w", what, err)
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s key file is not a regular file", what)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s key file: %w", what, secret.ErrPermissions)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("%s key file: %w", what, err)
	}
	defer clear(b)
	if len(b) != SeedLen {
		return nil, fmt.Errorf("%s key file must hold exactly %d bytes", what, SeedLen)
	}
	return ed25519.NewKeyFromSeed(b), nil
}

// WriteNew creates path (and its parent directories, mode 0700) with mode
// 0600 and writes data. It fails with ErrExists if path exists, and removes
// the file again if the write fails.
func WriteNew(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, os.ErrExist) {
		return fmt.Errorf("%w: %s", ErrExists, path)
	}
	if err != nil {
		return err
	}
	_, werr := f.Write(data)
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		_ = os.Remove(path)
	}
	return werr
}

// RandomBytes returns n bytes from the system random source.
func RandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("keyfile: randomness: %w", err)
	}
	return b, nil
}

// NewSeed creates a fresh Ed25519 seed file at path and returns its public
// key. An existing file is never touched.
func NewSeed(path string) (ed25519.PublicKey, error) {
	seed, err := RandomBytes(SeedLen)
	if err != nil {
		return nil, err
	}
	defer clear(seed)
	if err := WriteNew(path, seed); err != nil {
		return nil, err
	}
	return ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey), nil
}
