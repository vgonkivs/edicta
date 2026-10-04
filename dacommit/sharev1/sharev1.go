// Package sharev1 recomputes the share commitment of a celestia_blob payload
// (da = 2, share version 1). The gate, the SDK and verifiers share it.
package sharev1

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/bits"

	"github.com/celestiaorg/go-square/v4/inclusion"
	"github.com/celestiaorg/go-square/v4/share"

	"github.com/vgonkivs/edicta/commitment"
)

const subtreeRootThreshold = 64

// ErrMismatch is returned for any difference, any malformed input and any da
// other than 2.
var ErrMismatch = errors.New("sharev1: share commitment mismatch")

// Commitment recomputes the share-version-1 commitment of blob in namespace
// with the embedded signer. Inputs are copied; a panic inside go-square is
// returned as an error.
func Commitment(namespace, signer, blob []byte) (out []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			out, err = nil, fmt.Errorf("%w: recompute panicked: %v", ErrMismatch, r)
		}
	}()
	ns, err := share.NewNamespaceFromBytes(bytes.Clone(namespace))
	if err != nil {
		return nil, fmt.Errorf("%w: namespace: %v", ErrMismatch, err)
	}
	b, err := share.NewV1Blob(ns, blob, bytes.Clone(signer))
	if err != nil {
		return nil, fmt.Errorf("%w: blob: %v", ErrMismatch, err)
	}
	got, err := inclusion.CreateCommitment(b, merkleRoot, subtreeRootThreshold)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMismatch, err)
	}
	return got, nil
}

// Check returns ErrMismatch unless ref is a da = 2 reference whose commitment
// equals the one recomputed from blob.
func Check(ref commitment.PayloadRef, blob []byte) error {
	if ref.DA != commitment.DACelestiaBlob {
		return fmt.Errorf("%w: da %d", ErrMismatch, ref.DA)
	}
	if len(ref.Commitment) != 32 {
		return fmt.Errorf("%w: commitment of %d bytes", ErrMismatch, len(ref.Commitment))
	}
	got, err := Commitment(ref.Namespace, ref.Signer, blob)
	if err != nil {
		return err
	}
	if !bytes.Equal(got, ref.Commitment) {
		return ErrMismatch
	}
	return nil
}

// merkleRoot is the RFC 6962 SHA-256 tree hash, the same function as
// CometBFT's merkle.HashFromByteSlices.
func merkleRoot(items [][]byte) []byte {
	switch len(items) {
	case 0:
		h := sha256.Sum256(nil)
		return h[:]
	case 1:
		h := sha256.Sum256(append([]byte{0}, items[0]...))
		return h[:]
	}
	k := 1 << (bits.Len(uint(len(items)-1)) - 1)
	l, r := merkleRoot(items[:k]), merkleRoot(items[k:])
	h := sha256.Sum256(append(append([]byte{1}, l...), r...))
	return h[:]
}
