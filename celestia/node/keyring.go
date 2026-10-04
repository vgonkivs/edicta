package node

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/cosmos/cosmos-sdk/crypto/keyring"
	"golang.org/x/crypto/bcrypt"

	"github.com/celestiaorg/celestia-app/v10/app"
	"github.com/celestiaorg/celestia-app/v10/app/encoding"
)

// ErrKeyring wraps every refusal to open a keyring or find its key.
var ErrKeyring = errors.New("node: keyring")

// ErrBadPassphrase means the passphrase does not unlock the file keyring. It
// wraps ErrKeyring and is returned without ever prompting on stdin.
var ErrBadPassphrase = fmt.Errorf("%w: wrong passphrase", ErrKeyring)

// KeyringConfig locates one signing key. The Recorder and the executor each
// use their own Dir and KeyName; nothing here is shared between them.
type KeyringConfig struct {
	Dir  string
	Name string
	// Backend is "file" (encrypted, needs Passphrase) or "test" (plaintext).
	Backend string
	// AllowTest permits the plaintext test backend, for development only.
	AllowTest  bool
	Passphrase []byte
	Logger     *slog.Logger // nil means slog.Default()
}

// OpenKeyring opens an existing key; it never generates one. The test backend
// is refused unless AllowTest is set, and then logs a warning.
func OpenKeyring(c KeyringConfig) (keyring.Keyring, error) {
	log := c.Logger
	if log == nil {
		log = slog.Default()
	}
	switch {
	case c.Dir == "":
		return nil, fmt.Errorf("%w: no directory", ErrKeyring)
	case c.Name == "":
		return nil, fmt.Errorf("%w: no key name", ErrKeyring)
	}
	var in io.Reader
	switch c.Backend {
	case keyring.BackendFile:
		if len(c.Passphrase) == 0 {
			return nil, fmt.Errorf("%w: file backend needs a passphrase", ErrKeyring)
		}
		if err := checkPassphrase(c.Dir, c.Passphrase); err != nil {
			return nil, err
		}
		in = &repeatReader{line: append(append([]byte(nil), c.Passphrase...), '\n')}
	case keyring.BackendTest:
		if !c.AllowTest {
			return nil, fmt.Errorf("%w: test backend is refused without the explicit development flag", ErrKeyring)
		}
		log.Warn("node: plaintext test keyring backend, for development only", "key", c.Name)
		in = eofReader{}
	default:
		return nil, fmt.Errorf("%w: unsupported backend %q", ErrKeyring, c.Backend)
	}
	cfg := encoding.MakeConfig(app.ModuleEncodingRegisters...)
	kr, err := keyring.New(app.Name, c.Backend, c.Dir, in, cfg.Codec)
	if err != nil {
		return nil, fmt.Errorf("%w: open: %v", ErrKeyring, err)
	}
	if _, err := kr.Key(c.Name); err != nil {
		if errors.Is(err, keyring.ErrMaxPassPhraseAttempts) {
			return nil, ErrBadPassphrase
		}
		return nil, fmt.Errorf("%w: key %q: %v", ErrKeyring, c.Name, err)
	}
	return kr, nil
}

// repeatReader answers every passphrase prompt of the file backend.
type repeatReader struct {
	line []byte
	off  int
}

func (r *repeatReader) Read(p []byte) (int, error) {
	n := 0
	for n < len(p) {
		c := copy(p[n:], r.line[r.off:])
		n += c
		r.off = (r.off + c) % len(r.line)
	}
	return n, nil
}

type eofReader struct{}

func (eofReader) Read([]byte) (int, error) { return 0, io.EOF }

// checkPassphrase compares pass with the keyring's stored hash before the
// library can fall back to prompting on a terminal. A keyring without a hash
// file has no key yet; the later key lookup reports that.
func checkPassphrase(dir string, pass []byte) error {
	h, err := os.ReadFile(filepath.Join(dir, "keyhash"))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("%w: read keyhash: %v", ErrKeyring, err)
	}
	if bcrypt.CompareHashAndPassword(h, pass) != nil {
		return ErrBadPassphrase
	}
	return nil
}
