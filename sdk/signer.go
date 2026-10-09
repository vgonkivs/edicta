package sdk

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"sync"

	"github.com/vgonkivs/edicta/commitment"
)

// Ed25519Signer signs commitment hashes with an in-memory key. It never prints
// the key: every formatting verb, log value and marshaller shows only the
// public key or fails.
//
// The key lives behind a pointer to an unexported struct, so reflection-based
// printing of a copy, a slice, a map or an enclosing struct shows an address
// at most.
type Ed25519Signer struct {
	pub   ed25519.PublicKey
	state *signerState
}

// signerState holds the key one pointer deeper again: fmt prints the pointee
// of a pointer it cannot format when a bad verb is used, and that pointee must
// not contain the key bytes.
type signerState struct {
	mu     sync.RWMutex
	key    *keyBox
	closed bool
}

type keyBox struct{ priv ed25519.PrivateKey }

// NewEd25519Signer copies priv. The public key must pass the gate's own key
// check and belong to the seed.
func NewEd25519Signer(priv ed25519.PrivateKey) (*Ed25519Signer, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("sdk: private key of %d bytes", len(priv))
	}
	pub := bytes.Clone(priv[ed25519.SeedSize:])
	if err := commitment.CheckPublicKey(pub); err != nil {
		return nil, err
	}
	if !bytes.Equal(ed25519.NewKeyFromSeed(priv.Seed()).Public().(ed25519.PublicKey), pub) {
		return nil, fmt.Errorf("%w: public half does not belong to the seed", commitment.ErrInvalidPublicKey)
	}
	return &Ed25519Signer{pub: pub, state: &signerState{key: &keyBox{priv: bytes.Clone(priv)}}}, nil
}

func (s Ed25519Signer) PublicKey() ed25519.PublicKey { return bytes.Clone(s.pub) }

// SignCommitment signs the tagged commitment hash and nothing else.
func (s Ed25519Signer) SignCommitment(_ context.Context, h commitment.Hash) ([]byte, error) {
	return s.signMessage(commitment.SigningMessage(h))
}

func (s Ed25519Signer) signMessage(msg []byte) ([]byte, error) {
	st := s.state
	if st == nil {
		return nil, ErrSignerClosed
	}
	st.mu.RLock()
	defer st.mu.RUnlock()
	if st.closed {
		return nil, ErrSignerClosed
	}
	return ed25519.Sign(st.key.priv, msg), nil
}

// SignCommitmentV1 signs the v1-tagged commitment hash and nothing else.
func (s Ed25519Signer) SignCommitmentV1(_ context.Context, h commitment.Hash) ([]byte, error) {
	return s.signMessage(commitment.SignedMessage(commitment.VersionV1, h))
}

// Close zeroes the private key. Later signing calls fail.
func (s Ed25519Signer) Close() error {
	st := s.state
	if st == nil {
		return nil
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	clear(st.key.priv)
	st.closed = true
	return nil
}

func (s Ed25519Signer) String() string { return "Ed25519Signer(" + hex.EncodeToString(s.pub) + ")" }

// Format makes every fmt verb print the String form.
func (s Ed25519Signer) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte(s.String())) }

func (s Ed25519Signer) LogValue() slog.Value { return slog.StringValue(s.String()) }

var errNoMarshal = errors.New("sdk: a signer has no serialized form")

func (s Ed25519Signer) MarshalJSON() ([]byte, error) { return nil, errNoMarshal }
func (s Ed25519Signer) MarshalText() ([]byte, error) { return nil, errNoMarshal }
