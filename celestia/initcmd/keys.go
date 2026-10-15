package initcmd

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/vgonkivs/edicta/celestia/config"
	"github.com/vgonkivs/edicta/celestia/doctor"
	"github.com/vgonkivs/edicta/celestia/keyfile"
	"github.com/vgonkivs/edicta/celestia/railtx"
	"github.com/vgonkivs/edicta/celestia/secret"
	"github.com/vgonkivs/edicta/principalsig"
)

// CelestiaHRP is the bech32 prefix of Celestia account addresses.
const CelestiaHRP = "celestia"

func exists(path string) (bool, error) {
	_, err := os.Lstat(path)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	return false, fmt.Errorf("init: %w", err)
}

func ensureSeed(path, role string) (Ed25519Key, error) {
	k := Ed25519Key{Role: role, Path: path}
	found, err := exists(path)
	if err != nil {
		return k, err
	}
	if !found {
		pub, err := keyfile.NewSeed(path)
		if err == nil {
			k.Public, k.Status = pub, Created
			return k, nil
		}
		if !errors.Is(err, keyfile.ErrExists) {
			return k, fmt.Errorf("init: %s key: %w", role, err)
		}
	}
	priv, err := keyfile.ReadSeed(path, role)
	if err != nil {
		return k, fmt.Errorf("%w: %s key %s: %w", ErrExisting, role, path, err)
	}
	pub, ok := priv.Public().(ed25519.PublicKey)
	clear(priv)
	if !ok {
		return k, fmt.Errorf("init: %s key: unexpected public key type", role)
	}
	k.Public, k.Status = pub, Exists
	return k, nil
}

// ensureAccount finds or creates the keyring directory of role. A new one is
// built and checked in a temporary directory and renamed into place, so the
// keyring directory is either absent or complete.
func ensureAccount(home, role string) (Account, error) {
	dir := filepath.Join(home, "keyring-"+role)
	a := Account{Role: role, KeyringDir: dir, KeyName: role, PassphraseFile: filepath.Join(dir, role+".pass")}
	found, err := exists(dir)
	if err != nil {
		return a, err
	}
	if found {
		if a.Address, err = accountAddress(dir, role, a.PassphraseFile); err != nil {
			return a, fmt.Errorf("%w: %s keyring %s: %w", ErrExisting, role, dir, err)
		}
		a.Status = Exists
		return a, nil
	}

	tmp, err := os.MkdirTemp(home, keyfile.TempPrefix)
	if err != nil {
		return a, fmt.Errorf("init: %s keyring: %w", role, err)
	}
	defer func() { _ = os.RemoveAll(tmp) }()
	tmpPass := filepath.Join(tmp, role+".pass")
	addr, err := createKeyring(tmp, role, tmpPass)
	if err != nil {
		return a, fmt.Errorf("init: %s keyring: %w", role, err)
	}
	if err := syncTree(tmp); err != nil {
		return a, fmt.Errorf("init: %s keyring: %w", role, err)
	}
	if err := os.Rename(tmp, dir); err != nil {
		return a, fmt.Errorf("init: %s keyring: %w", role, err)
	}
	if err := keyfile.SyncDir(home); err != nil {
		return a, fmt.Errorf("init: %s keyring: %w", role, err)
	}
	got, err := accountAddress(dir, role, a.PassphraseFile)
	if err != nil {
		return a, fmt.Errorf("init: %s keyring does not open after the move: %w", role, err)
	}
	if got != addr {
		return a, fmt.Errorf("init: %s keyring holds another key after the move", role)
	}
	a.Address, a.Status = addr, Created
	return a, nil
}

func createKeyring(dir, name, passFile string) (string, error) {
	pb, err := keyfile.RandomBytes(32)
	if err != nil {
		return "", err
	}
	passHex := []byte(hex.EncodeToString(pb) + "\n")
	clear(pb)
	err = keyfile.WriteNew(passFile, passHex)
	clear(passHex)
	if err != nil {
		return "", fmt.Errorf("passphrase file: %w", err)
	}
	pass, err := secret.FromFile(passFile)
	if err != nil {
		return "", err
	}
	defer pass.Zero()
	scalar, err := newScalar()
	if err != nil {
		return "", err
	}
	key := secret.New(scalar)
	clear(scalar)
	defer key.Zero()
	if err := railtx.ImportKeyring(dir, name, pass, key); err != nil {
		return "", err
	}
	return railtx.KeyFromKeyring(dir, name, pass).Address(CelestiaHRP)
}

// accountAddress opens the keyring with its passphrase file, which is the
// check that the account is usable without a prompt.
func accountAddress(dir, name, passFile string) (string, error) {
	pass, err := secret.FromFile(passFile)
	if err != nil {
		return "", err
	}
	defer pass.Zero()
	return railtx.KeyFromKeyring(dir, name, pass).Address(CelestiaHRP)
}

func ensurePayer(path string) (Payer, error) {
	p := Payer{Path: path}
	found, err := exists(path)
	if err != nil {
		return p, err
	}
	if !found {
		scalar, err := newScalar()
		if err != nil {
			return p, err
		}
		defer clear(scalar)
		addr, err := doctor.PayerAddressOf(scalar)
		if err != nil {
			return p, fmt.Errorf("init: payer key: %w", err)
		}
		err = keyfile.WriteNew(path, scalar)
		if err == nil {
			p.Address, p.Status = addr, Created
			return p, nil
		}
		if !errors.Is(err, keyfile.ErrExists) {
			return p, fmt.Errorf("init: payer key: %w", err)
		}
	}
	addr, err := doctor.PayerAddress(path)
	if err != nil {
		return p, fmt.Errorf("%w: payer key %s: %w", ErrExisting, path, err)
	}
	p.Address, p.Status = addr, Exists
	return p, nil
}

// newScalar returns a random secp256k1 private key in [1, n-1]; a draw
// outside that range is thrown away.
func newScalar() ([]byte, error) {
	for range 8 {
		b, err := keyfile.RandomBytes(keyfile.Secp256k1Len)
		if err != nil {
			return nil, err
		}
		if _, err := principalsig.NewSecp256k1Signer(principalsig.EIP712, b, ""); err == nil {
			return b, nil
		}
		clear(b)
	}
	return nil, errors.New("init: no valid secp256k1 key from the random source")
}

const namespaceLen = 29

// newNamespaces returns two distinct random version 0 user namespaces.
func newNamespaces() (string, string, error) {
	rec, err := newNamespace()
	if err != nil {
		return "", "", err
	}
	for range 8 {
		pub, err := newNamespace()
		if err != nil {
			return "", "", err
		}
		if pub != rec {
			return rec, pub, nil
		}
	}
	return "", "", errors.New("init: no distinct namespaces from the random source")
}

func newNamespace() (string, error) {
	for range 8 {
		id, err := keyfile.RandomBytes(10)
		if err != nil {
			return "", err
		}
		ns := make([]byte, namespaceLen)
		copy(ns[namespaceLen-len(id):], id)
		s := hex.EncodeToString(ns)
		if config.CheckNamespace("namespace", s) == nil {
			return s, nil
		}
	}
	return "", errors.New("init: no user namespace from the random source")
}

// syncTree syncs every file and directory under root, so that a rename of
// root publishes only complete content.
func syncTree(root string) error {
	return filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return keyfile.SyncDir(path)
		}
		if !d.Type().IsRegular() {
			return nil
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		err = f.Sync()
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		return err
	})
}
