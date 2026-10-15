// Package keyfile reads and creates the raw key files of the Edicta binaries:
// a 32-byte Ed25519 seed or a secp256k1 scalar, mode 0600, never overwritten.
// The seed format is the one edicta-live and edictad read.
package keyfile

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/vgonkivs/edicta/celestia/secret"
)

// SeedLen is the length of a raw Ed25519 seed file.
const SeedLen = ed25519.SeedSize

// Secp256k1Len is the length of a raw secp256k1 scalar.
const Secp256k1Len = 32

// ErrExists means the file is already there; files are never overwritten.
var ErrExists = errors.New("keyfile: file exists")

// ErrBadKeyFile means a key file is not a regular file or does not hold a key
// of the expected form.
var ErrBadKeyFile = errors.New("keyfile: bad key file")

// readKeyFile reads at most max bytes of a regular file of mode 0600 or
// tighter. The checks run on the open descriptor, so the file read is the
// file checked. It never trims: the last byte of a raw key may be a newline.
func readKeyFile(path, what string, max int) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("%s key file: %w", what, err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("%s key file: %w", what, err)
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: %s key file is not a regular file", ErrBadKeyFile, what)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s key file: %w", what, secret.ErrPermissions)
	}
	b, err := io.ReadAll(io.LimitReader(f, int64(max)+1))
	if err != nil {
		clear(b)
		return nil, fmt.Errorf("%s key file: %w", what, err)
	}
	if len(b) > max {
		clear(b)
		return nil, fmt.Errorf("%w: %s key file is longer than %d bytes", ErrBadKeyFile, what, max)
	}
	return b, nil
}

// ReadSeed reads a raw Ed25519 seed. The file must be a regular file of mode
// 0600 or tighter holding exactly SeedLen bytes.
func ReadSeed(path, what string) (ed25519.PrivateKey, error) {
	b, err := readKeyFile(path, what, SeedLen)
	if err != nil {
		return nil, err
	}
	defer clear(b)
	if len(b) != SeedLen {
		return nil, fmt.Errorf("%w: %s key file must hold exactly %d bytes", ErrBadKeyFile, what, SeedLen)
	}
	return ed25519.NewKeyFromSeed(b), nil
}

// ReadSecp256k1 reads a secp256k1 scalar: exactly 32 raw bytes, or 64 hex
// characters with at most one trailing newline. A 32-byte file is always raw,
// so a raw key that ends in a newline or carriage return byte is read whole.
// The scalar is not checked against the curve order; the signer does that.
func ReadSecp256k1(path, what string) ([]byte, error) {
	b, err := readKeyFile(path, what, 2*Secp256k1Len+1)
	if err != nil {
		return nil, err
	}
	defer clear(b)
	switch len(b) {
	case Secp256k1Len:
		return bytes.Clone(b), nil
	case 2*Secp256k1Len + 1:
		if b[len(b)-1] != '\n' {
			break
		}
		b = b[:len(b)-1]
		fallthrough
	case 2 * Secp256k1Len:
		k := make([]byte, Secp256k1Len)
		if _, err := hex.Decode(k, b); err == nil {
			return k, nil
		}
		clear(k)
	}
	return nil, fmt.Errorf("%w: %s key file must hold %d raw bytes or %d hex characters", ErrBadKeyFile, what, Secp256k1Len, 2*Secp256k1Len)
}

// WriteNew creates path (and its parent directories, mode 0700) with mode
// 0600, writes data and syncs the file and its directory, so a key whose
// public half was already shown survives a crash. It fails with ErrExists if
// path exists, and removes the file again if anything after the create
// fails.
func WriteNew(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
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
	if werr == nil {
		werr = f.Sync()
	}
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr == nil {
		werr = syncDir(dir)
	}
	if werr != nil {
		_ = os.Remove(path)
		return fmt.Errorf("keyfile: write %s: %w", path, werr)
	}
	return nil
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	err = d.Sync()
	// Some file systems cannot sync a directory; the file itself is synced.
	if errors.Is(err, syscall.EINVAL) || errors.Is(err, syscall.ENOTSUP) {
		err = nil
	}
	if cerr := d.Close(); err == nil {
		err = cerr
	}
	return err
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
