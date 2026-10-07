package demo

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/vgonkivs/edicta/celestia/railtx"
	"github.com/vgonkivs/edicta/celestia/secret"
)

// writeNew creates path with mode 0600 and never overwrites.
func writeNew(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
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

func randBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("demo: randomness: %w", err)
	}
	return b, nil
}

type homeDirs struct{ home, chain, funding, runs string }

func prepareHome(home string) (homeDirs, error) {
	d := homeDirs{home: home, chain: filepath.Join(home, "chain"), funding: filepath.Join(home, "chain", "funding"), runs: filepath.Join(home, "runs")}
	for _, p := range []string{d.home, d.chain, d.funding, d.runs} {
		if err := os.MkdirAll(p, 0o700); err != nil {
			return d, fmt.Errorf("demo: %w", err)
		}
		if err := os.Chmod(p, 0o700); err != nil {
			return d, fmt.Errorf("demo: %w", err)
		}
	}
	return d, nil
}

func newRunDir(runs string, now time.Time) (string, error) {
	base := now.UTC().Format("20060102T150405")
	for i := 0; i < 100; i++ {
		p := filepath.Join(runs, base)
		if i > 0 {
			p = fmt.Sprintf("%s-%d", p, i)
		}
		err := os.Mkdir(p, 0o700)
		if err == nil {
			return p, nil
		}
		if !errors.Is(err, fs.ErrExist) {
			return "", fmt.Errorf("demo: run directory: %w", err)
		}
	}
	return "", errors.New("demo: no free run directory name")
}

// chainKey is one secp256k1 account kept in a file keyring.
type chainKey struct {
	dir, name string
	pass      secret.Secret
	addr      string
}

func (k chainKey) source() railtx.KeySource { return railtx.KeyFromKeyring(k.dir, k.name, k.pass) }

// loadOrCreateKey opens the demo's own key in dir, creating it (and its
// passphrase file, mode 0600) on the first run.
func loadOrCreateKey(dir, name, hrp string) (chainKey, error) {
	k := chainKey{dir: dir, name: name}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return k, fmt.Errorf("demo: %w", err)
	}
	passFile := filepath.Join(dir, name+".pass")
	if _, err := os.Lstat(passFile); errors.Is(err, fs.ErrNotExist) {
		pb, err := randBytes(32)
		if err != nil {
			return k, err
		}
		if err := writeNew(passFile, []byte(hex.EncodeToString(pb)+"\n")); err != nil {
			return k, fmt.Errorf("demo: passphrase file: %w", err)
		}
		pass, err := secret.FromFile(passFile)
		if err != nil {
			return k, err
		}
		scalar, err := randBytes(32)
		if err != nil {
			return k, err
		}
		err = railtx.ImportKeyring(dir, name, pass, secret.New(scalar))
		clear(scalar)
		if err != nil {
			return k, fmt.Errorf("demo: create %s key: %w", name, err)
		}
	}
	pass, err := secret.FromFile(passFile)
	if err != nil {
		return k, fmt.Errorf("demo: %s key: %w", name, err)
	}
	k.pass = pass
	if k.addr, err = k.source().Address(hrp); err != nil {
		return k, fmt.Errorf("demo: %s key: %w", name, err)
	}
	return k, nil
}
