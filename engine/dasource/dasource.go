// SPDX-License-Identifier: Apache-2.0

// Package dasource holds the interfaces through which the gate, the archive
// and the verifier read payloads and anchor intents and recompute DA
// commitments, with the sentinels those reads return. It lets storage and
// verification implement them without depending on the gate. The sentinels
// keep the gate's error texts: package gate exports the same values.
package dasource

import (
	"context"
	"errors"

	"github.com/vgonkivs/edicta/engine/commitment"
)

var (
	// ErrArchiveUnavailable means the decision record could not be written
	// durably, or the archive could not serve the payload record (unreadable
	// or damaged); nothing was signed and the nonce is unused.
	ErrArchiveUnavailable = errors.New("gate: archive unavailable")

	// ErrBlobNotFound is returned by a BlobSource, never by Authorize.
	ErrBlobNotFound = errors.New("gate: blob not found")

	ErrArchiveRecomputeUnsupported = errors.New("gate: archive path needs a DA commitment recompute that is not available")
	ErrDACommitmentMismatch        = errors.New("gate: DA commitment mismatch")
)

type BlobSource interface {
	// Fetch returns the blob bytes and reads at most maxSize+1 bytes. It
	// returns ErrBlobNotFound when the source knows the blob is absent.
	Fetch(ctx context.Context, ref commitment.PayloadRef, maxSize uint64) ([]byte, error)
}

type DACommitter interface {
	// Check recomputes the DA commitment of blob and compares it with
	// ref.Commitment; it returns ErrDACommitmentMismatch on any difference.
	Check(ref commitment.PayloadRef, blob []byte) error
}

// AnchorIntent is the archived anchor intent of a pending reference: the
// signed anchor tx, without the blob. Signer is set for da = 2 only.
// CreatedAt is floor(promise creation) for da = 1.
type AnchorIntent struct {
	DA         commitment.DA
	Commitment []byte
	Namespace  []byte
	RefHeight  uint64
	Tx         []byte
	Signer     []byte
	CreatedAt  uint64
}

// IntentSource reads the anchor intent of (da, commitment, ref_height). The
// gate answers any failure, an absent record included, with the retryable
// gate.ErrAnchorIntentUnavailable.
type IntentSource interface {
	Intent(ctx context.Context, da commitment.DA, commit []byte, refHeight uint64) (*AnchorIntent, error)
}
