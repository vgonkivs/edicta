// Package blobv1 recomputes the share commitment of a celestia_blob payload
// (da = 2, share version 1) so the gate can trust archive bytes.
package blobv1

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"math/bits"

	"github.com/celestiaorg/go-square/v4/inclusion"
	"github.com/celestiaorg/go-square/v4/share"

	"github.com/vgonkivs/prior/commitment"
	"github.com/vgonkivs/prior/gate"
)

const subtreeRootThreshold = 64

type committer struct{}

// New returns a stateless committer for da = 2. Every other da, and every
// malformed reference or blob, fails with gate.ErrDACommitmentMismatch.
func New() gate.DACommitter { return committer{} }

func (committer) Check(_ context.Context, ref commitment.PayloadRef, blob []byte) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("%w: recompute panicked: %v", gate.ErrDACommitmentMismatch, r)
		}
	}()
	if ref.DA != commitment.DACelestiaBlob {
		return fmt.Errorf("%w: da %d", gate.ErrDACommitmentMismatch, ref.DA)
	}
	if len(ref.Commitment) != 32 {
		return fmt.Errorf("%w: commitment of %d bytes", gate.ErrDACommitmentMismatch, len(ref.Commitment))
	}
	ns, err := share.NewNamespaceFromBytes(bytes.Clone(ref.Namespace))
	if err != nil {
		return fmt.Errorf("%w: namespace: %v", gate.ErrDACommitmentMismatch, err)
	}
	b, err := share.NewV1Blob(ns, blob, bytes.Clone(ref.Signer))
	if err != nil {
		return fmt.Errorf("%w: blob: %v", gate.ErrDACommitmentMismatch, err)
	}
	got, err := inclusion.CreateCommitment(b, merkleRoot, subtreeRootThreshold)
	if err != nil {
		return fmt.Errorf("%w: %v", gate.ErrDACommitmentMismatch, err)
	}
	if !bytes.Equal(got, ref.Commitment) {
		return gate.ErrDACommitmentMismatch
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
