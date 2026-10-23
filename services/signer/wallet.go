// SPDX-License-Identifier: Apache-2.0

package signer

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"

	"github.com/vgonkivs/edicta/internal/evm"
)

// WalletBackend holds one payer key. An implementation may be remote.
type WalletBackend interface {
	Address(ctx context.Context) ([20]byte, error)
	// SignDigest returns r || s || y_parity: a deterministic (RFC 6979)
	// low-s secp256k1 signature, so that signing one digest twice gives one
	// signature.
	SignDigest(ctx context.Context, digest [32]byte) ([65]byte, error)
}

// KeyWallet is the file backend: the payer scalar in memory. It never prints
// the key.
type KeyWallet struct{ priv *secp256k1.PrivateKey }

var _ WalletBackend = (*KeyWallet)(nil)

// NewKeyWallet takes a 32-byte secp256k1 scalar in 1..n-1. The caller clears
// its copy.
func NewKeyWallet(scalar []byte) (*KeyWallet, error) {
	if len(scalar) != 32 {
		return nil, errors.New("signer: payer key must be 32 bytes")
	}
	var s secp256k1.ModNScalar
	if overflow := s.SetByteSlice(scalar); overflow || s.IsZero() {
		return nil, errors.New("signer: payer key is not a valid secp256k1 scalar")
	}
	return &KeyWallet{priv: secp256k1.NewPrivateKey(&s)}, nil
}

func (w *KeyWallet) String() string   { return "KeyWallet{[redacted]}" }
func (w *KeyWallet) GoString() string { return w.String() }

func (w *KeyWallet) Address(context.Context) ([20]byte, error) {
	return evm.Address(w.priv.PubKey()), nil
}

func (w *KeyWallet) SignDigest(_ context.Context, digest [32]byte) ([65]byte, error) {
	return evm.Sign(w.priv, digest)
}

// ExecutorKey is the executor's Ed25519 key: it signs record requests and
// nothing else.
type ExecutorKey interface {
	PublicKey() ed25519.PublicKey
	SignRecord(ctx context.Context, msg []byte) ([]byte, error)
}

// Ed25519Executor is a local executor key.
type Ed25519Executor struct{ priv ed25519.PrivateKey }

var _ ExecutorKey = (*Ed25519Executor)(nil)

// NewEd25519Executor takes the private key; the caller keeps no other copy.
func NewEd25519Executor(priv ed25519.PrivateKey) (*Ed25519Executor, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("signer: executor key of %d bytes", len(priv))
	}
	return &Ed25519Executor{priv: priv}, nil
}

func (e *Ed25519Executor) String() string   { return "Ed25519Executor{[redacted]}" }
func (e *Ed25519Executor) GoString() string { return e.String() }

func (e *Ed25519Executor) PublicKey() ed25519.PublicKey {
	pub := make(ed25519.PublicKey, ed25519.PublicKeySize)
	copy(pub, e.priv[ed25519.SeedSize:])
	return pub
}

func (e *Ed25519Executor) SignRecord(_ context.Context, msg []byte) ([]byte, error) {
	return ed25519.Sign(e.priv, msg), nil
}
