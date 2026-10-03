package gate

import (
	"context"
	"crypto/ed25519"
	"errors"
)

// Ed25519Signer signs with an in-memory key.
type Ed25519Signer struct {
	priv ed25519.PrivateKey
}

var _ Signer = (*Ed25519Signer)(nil)

func NewEd25519Signer(priv ed25519.PrivateKey) (*Ed25519Signer, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, errors.New("gate: ed25519 private key has the wrong size")
	}
	if !priv.Public().(ed25519.PublicKey).Equal(ed25519.NewKeyFromSeed(priv.Seed()).Public()) {
		return nil, errors.New("gate: ed25519 private key halves do not match")
	}
	return &Ed25519Signer{priv: append(ed25519.PrivateKey(nil), priv...)}, nil
}

func (s *Ed25519Signer) PublicKey() ed25519.PublicKey {
	return append(ed25519.PublicKey(nil), s.priv.Public().(ed25519.PublicKey)...)
}

func (s *Ed25519Signer) Sign(_ context.Context, msg []byte) ([]byte, error) {
	return ed25519.Sign(s.priv, msg), nil
}
