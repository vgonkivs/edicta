package main

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"

	"golang.org/x/term"

	"github.com/vgonkivs/edicta/celestia/secret"
	"github.com/vgonkivs/edicta/sdk/blob"
)

const seedLen = 32

// readSeed reads a raw Ed25519 seed. It does not trim: a trailing newline may
// be a seed byte. The file must be mode 0600 or tighter.
func readSeed(path, what string) (ed25519.PrivateKey, error) {
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
	if len(b) != seedLen {
		return nil, fmt.Errorf("%s key file must hold exactly %d bytes", what, seedLen)
	}
	return ed25519.NewKeyFromSeed(b), nil
}

type keyBox struct{ priv ed25519.PrivateKey }

// publishSigner signs edictad publish requests for one agent. Every print
// path shows only a redaction marker.
type publishSigner struct {
	id  string
	box *keyBox
}

func newPublishSigner(id string, priv ed25519.PrivateKey) *publishSigner {
	return &publishSigner{id: id, box: &keyBox{priv: priv}}
}

func (s *publishSigner) AgentID() string { return s.id }

func (s *publishSigner) SignPublish(_ context.Context, msg []byte) ([]byte, error) {
	return ed25519.Sign(s.box.priv, msg), nil
}

func (*publishSigner) String() string               { return "[redacted]" }
func (*publishSigner) GoString() string             { return "[redacted]" }
func (*publishSigner) Format(f fmt.State, _ rune)   { _, _ = f.Write([]byte("[redacted]")) }
func (*publishSigner) LogValue() slog.Value         { return slog.StringValue("[redacted]") }
func (*publishSigner) MarshalJSON() ([]byte, error) { return []byte(`"[redacted]"`), nil }

// passphrase returns the executor keyring passphrase from a file or a no-echo
// prompt on the terminal.
func passphrase(c Config, in *os.File, prompt io.Writer) (secret.Secret, error) {
	if c.ExecPassFile != "" {
		return secret.FromFile(c.ExecPassFile)
	}
	fd := int(in.Fd())
	if !term.IsTerminal(fd) {
		return secret.Secret{}, errors.New("--executor-passphrase-prompt needs a terminal; use --executor-passphrase-file")
	}
	fmt.Fprint(prompt, "executor keyring passphrase: ")
	b, err := term.ReadPassword(fd)
	fmt.Fprintln(prompt)
	if err != nil {
		return secret.Secret{}, fmt.Errorf("reading passphrase: %w", err)
	}
	defer clear(b)
	if len(b) == 0 {
		return secret.Secret{}, errors.New("empty passphrase")
	}
	return secret.New(b), nil
}

// genRecipient creates a new X25519 recipient key at path (hex, mode 0600,
// never overwriting) and returns its sealing side.
func genRecipient(path string) (blob.Recipient, error) {
	sk, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return blob.Recipient{}, err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return blob.Recipient{}, fmt.Errorf("recipient key file: %w", err)
	}
	enc := []byte(hex.EncodeToString(sk.Bytes()) + "\n")
	_, werr := f.Write(enc)
	clear(enc)
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		_ = os.Remove(path)
		return blob.Recipient{}, fmt.Errorf("recipient key file: %w", werr)
	}
	return blob.Recipient{KID: []byte("edicta-live-1"), PublicKey: sk.PublicKey()}, nil
}

// reserveRecipientKey creates the recipient key file at path. The returned
// release removes the file unless keep is true: nothing is sealed to the key
// before the decision loop starts, so a startup failure need not burn the path.
func reserveRecipientKey(path string) (blob.Recipient, func(keep bool), error) {
	if _, err := os.Lstat(path); err == nil {
		return blob.Recipient{}, nil, fmt.Errorf("recipient key file %s already exists; it is never overwritten: %w", path, os.ErrExist)
	}
	rc, err := genRecipient(path)
	if err != nil {
		return blob.Recipient{}, nil, err
	}
	return rc, func(keep bool) {
		if !keep {
			_ = os.Remove(path)
		}
	}, nil
}

// readToken reads an optional bearer token file.
func readToken(path string) (string, error) {
	if path == "" {
		return "", nil
	}
	s, err := secret.FromFile(path)
	if err != nil {
		return "", err
	}
	defer s.Zero()
	return s.RevealString(), nil
}
