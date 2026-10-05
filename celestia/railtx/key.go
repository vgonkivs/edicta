package railtx

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"

	"github.com/cosmos/cosmos-sdk/codec"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	"github.com/cosmos/cosmos-sdk/crypto"
	cryptocodec "github.com/cosmos/cosmos-sdk/crypto/codec"
	"github.com/cosmos/cosmos-sdk/crypto/keyring"
	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"

	"github.com/vgonkivs/edicta/celestia/node"
	"github.com/vgonkivs/edicta/celestia/secret"
)

const (
	keyringApp    = "edicta"
	redactedLabel = "railtx.KeySource[REDACTED]"
)

// KeySource says where the secp256k1 signing key comes from. The zero value
// is no key. It prints as a redaction marker under every fmt verb, slog and
// JSON.
type KeySource struct {
	raw        secret.Secret
	dir, name  string
	passphrase secret.Secret
	keyring    bool
}

// KeyFromSecret uses a raw 32-byte secp256k1 scalar.
func KeyFromSecret(s secret.Secret) KeySource { return KeySource{raw: s} }

// KeyFromKeyring uses the entry name of the cosmos-sdk "file" backend
// keyring in dir, unlocked with passphrase.
func KeyFromKeyring(dir, name string, passphrase secret.Secret) KeySource {
	return KeySource{dir: dir, name: name, passphrase: passphrase, keyring: true}
}

func (KeySource) String() string               { return redactedLabel }
func (KeySource) GoString() string             { return redactedLabel }
func (k KeySource) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, redactedLabel) }
func (KeySource) MarshalJSON() ([]byte, error) { return json.Marshal(redactedLabel) }
func (KeySource) LogValue() slog.Value         { return slog.StringValue(redactedLabel) }

// load returns the private key. The caller owns it.
func (k KeySource) load() (*secp256k1.PrivKey, error) {
	if k.keyring {
		return loadKeyring(k.dir, k.name, k.passphrase)
	}
	if !k.raw.IsSet() {
		return nil, errors.New("railtx: no signing key")
	}
	return privFromScalar(k.raw.Reveal())
}

func privFromScalar(b []byte) (*secp256k1.PrivKey, error) {
	defer clear(b)
	if len(b) != 32 {
		return nil, errors.New("railtx: secp256k1 key must be 32 bytes")
	}
	if allZero(b) {
		return nil, errors.New("railtx: zero secp256k1 key")
	}
	return &secp256k1.PrivKey{Key: bytes.Clone(b)}, nil
}

func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

func openKeyring(dir string, pass secret.Secret, create bool) (keyring.Keyring, error) {
	if !pass.IsSet() {
		return nil, errors.New("railtx: keyring passphrase not set")
	}
	reg := codectypes.NewInterfaceRegistry()
	cryptocodec.RegisterInterfaces(reg)
	p := pass.Reveal()
	defer clear(p)
	kr, err := node.OpenFileKeyring(dir, p, codec.NewProtoCodec(reg), create)
	if err != nil {
		return nil, fmt.Errorf("railtx: open keyring: %w", err)
	}
	return kr, nil
}

func loadKeyring(dir, name string, pass secret.Secret) (*secp256k1.PrivKey, error) {
	if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
		return nil, fmt.Errorf("railtx: keyring dir %q unusable: %w", dir, errOrNotDir(err))
	}
	kr, err := openKeyring(dir, pass, false)
	if err != nil {
		return nil, err
	}
	// A temporary armor passphrase, only to move the key within this process.
	const armorPass = "railtx-export"
	armor, err := kr.ExportPrivKeyArmor(name, armorPass)
	if err != nil {
		return nil, fmt.Errorf("railtx: keyring entry %q: %w", name, err)
	}
	pk, _, err := crypto.UnarmorDecryptPrivKey(armor, armorPass)
	if err != nil {
		return nil, fmt.Errorf("railtx: keyring entry %q: %w", name, err)
	}
	sk, ok := pk.(*secp256k1.PrivKey)
	if !ok {
		return nil, fmt.Errorf("railtx: keyring entry %q is not secp256k1", name)
	}
	return sk, nil
}

func errOrNotDir(err error) error {
	if err != nil {
		return err
	}
	return errors.New("not a directory")
}

// ImportKeyring stores a raw secp256k1 key as entry name in the "file"
// backend keyring in dir, creating dir (mode 0700) if needed.
func ImportKeyring(dir, name string, passphrase, key secret.Secret) error {
	sk, err := privFromScalar(key.Reveal())
	if err != nil {
		return err
	}
	defer clear(sk.Key)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("railtx: keyring dir: %w", err)
	}
	kr, err := openKeyring(dir, passphrase, true)
	if err != nil {
		return err
	}
	const armorPass = "railtx-export"
	armor := crypto.EncryptArmorPrivKey(sk, armorPass, sk.Type())
	if err := kr.ImportPrivKey(name, armor, armorPass); err != nil {
		return fmt.Errorf("railtx: import key %q: %w", name, err)
	}
	return nil
}
