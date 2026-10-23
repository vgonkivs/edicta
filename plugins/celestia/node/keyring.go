package node

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"

	keyring99 "github.com/99designs/keyring"
	"github.com/cosmos/cosmos-sdk/codec"
	"github.com/cosmos/cosmos-sdk/crypto/keyring"
	"golang.org/x/crypto/bcrypt"

	"github.com/celestiaorg/celestia-app/v10/app"
	"github.com/celestiaorg/celestia-app/v10/app/encoding"
)

// ErrKeyring wraps every refusal to open a keyring or find its key.
var ErrKeyring = errors.New("node: keyring")

// ErrBadPassphrase means the passphrase does not unlock the file keyring. It
// wraps ErrKeyring and is returned without ever prompting.
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
	cfg := encoding.MakeConfig(app.ModuleEncodingRegisters...)
	var kr keyring.Keyring
	switch c.Backend {
	case keyring.BackendFile:
		var err error
		kr, err = OpenFileKeyring(c.Dir, c.Passphrase, cfg.Codec, false)
		if err != nil {
			return nil, err
		}
	case keyring.BackendTest:
		if !c.AllowTest {
			return nil, fmt.Errorf("%w: test backend is refused without the explicit development flag", ErrKeyring)
		}
		log.Warn("node: plaintext test keyring backend, for development only", "key", c.Name)
		// The test backend answers its own password callback; the empty
		// reader only guarantees nothing is read from stdin.
		var err error
		kr, err = keyring.New(app.Name, c.Backend, c.Dir, eofReader{}, cfg.Codec)
		if err != nil {
			return nil, fmt.Errorf("%w: open: %v", ErrKeyring, err)
		}
	default:
		return nil, fmt.Errorf("%w: unsupported backend %q", ErrKeyring, c.Backend)
	}
	if _, err := kr.Key(c.Name); err != nil {
		return nil, fmt.Errorf("%w: key %q: %v", ErrKeyring, c.Name, err)
	}
	return kr, nil
}

// OpenFileKeyring opens the SDK file backend keyring under dir without ever
// prompting or reading stdin; the SDK's own opener reads the terminal
// whenever stdin is one. An existing keyhash is checked against pass and
// never rewritten. With create, a missing store is created (mode 0700) and
// its keyhash written the way the SDK writes it, so the SDK and celestia-appd
// can open the store later.
func OpenFileKeyring(dir string, pass []byte, cdc codec.Codec, create bool) (keyring.Keyring, error) {
	if len(pass) == 0 {
		return nil, fmt.Errorf("%w: file backend needs a passphrase", ErrKeyring)
	}
	fileDir := filepath.Join(dir, fileKeyringDir)
	if create {
		if err := os.MkdirAll(fileDir, 0o700); err != nil {
			return nil, fmt.Errorf("%w: create dir: %v", ErrKeyring, err)
		}
		if err := writeKeyhash(fileDir, pass); err != nil {
			return nil, err
		}
	}
	if err := checkPassphrase(fileDir, pass); err != nil {
		return nil, err
	}
	p := string(pass)
	db, err := keyring99.Open(keyring99.Config{
		AllowedBackends:  []keyring99.BackendType{keyring99.FileBackend},
		ServiceName:      app.Name,
		FileDir:          fileDir,
		FilePasswordFunc: func(string) (string, error) { return p, nil },
	})
	if err != nil {
		return nil, fmt.Errorf("%w: open: %v", ErrKeyring, err)
	}
	return keyring.NewInMemoryWithKeyring(db, cdc), nil
}

// keyhashCost is the bcrypt cost the SDK uses for the keyhash file.
const keyhashCost = 2

// writeKeyhash creates keyhash if it does not exist; an existing one is left
// for checkPassphrase.
func writeKeyhash(fileDir string, pass []byte) error {
	path := filepath.Join(fileDir, "keyhash")
	h, err := bcrypt.GenerateFromPassword(pass, keyhashCost)
	if err != nil {
		return fmt.Errorf("%w: keyhash: %v", ErrKeyring, err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, os.ErrExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("%w: write keyhash: %v", ErrKeyring, err)
	}
	if _, err := f.Write(h); err != nil {
		_ = f.Close()
		return fmt.Errorf("%w: write keyhash: %v", ErrKeyring, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("%w: write keyhash: %v", ErrKeyring, err)
	}
	return nil
}

// fileKeyringDir is where the SDK file backend keeps its files under the
// keyring directory.
const fileKeyringDir = "keyring-file"

type eofReader struct{}

func (eofReader) Read([]byte) (int, error) { return 0, io.EOF }

// checkPassphrase compares pass with the hash stored in the file keyring
// directory, so a wrong passphrase is reported as such. A keyring without a
// hash file has no key yet; the later key lookup reports that.
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
