// SPDX-License-Identifier: Apache-2.0

// Package recorder is what the gate daemon publishes payloads through,
// whatever the DA: the Recorder interface and the refusal reasons every
// implementation returns. API error codes name these sentinels as
// recorder.ErrX.
package recorder

import (
	"context"
	"errors"

	"github.com/vgonkivs/edicta/sdk"
)

var (
	ErrTooLarge       = errors.New("recorder: blob above MaxBlobBytes")
	ErrSignerMismatch = errors.New("recorder: anchored blob has another signer or share version")
	ErrNotVisible     = errors.New("recorder: anchor not visible on the read node in time")
	ErrOutcomeUnknown = errors.New("recorder: submit outcome unknown")
	// ErrNodeUnavailable means the read node failed for a reason other than
	// "not found"; the caller may retry.
	ErrNodeUnavailable = errors.New("recorder: node unavailable")
	ErrTooManyPending  = errors.New("recorder: too many blobs with an unresolved outcome")

	// ErrArchiveUnavailable means the archive write failed. Before a submit
	// nothing was submitted; after one, a retry resumes without paying again.
	ErrArchiveUnavailable = errors.New("recorder: archive unavailable")
	// ErrEscrowInsufficient means the escrow cannot pay for the upload;
	// nothing was submitted.
	ErrEscrowInsufficient = errors.New("recorder: escrow balance too low for this upload")
	// ErrSubmitMismatch means the node returned another blob id or promise
	// fields than computed locally; a fee may have been spent. It is sticky
	// per blob.
	ErrSubmitMismatch = errors.New("recorder: node returned another blob id than computed")
	// ErrAnchorRejected means a successful pay-for-fibre tx of the blob is on
	// chain but fails the certificate rule. It is sticky per blob: the escrow
	// was charged, so the blob is never submitted again.
	ErrAnchorRejected = errors.New("recorder: anchor on chain fails the certificate rule")
	// ErrClockSkew means the local clock, which dates the promise, is off the
	// chain head time by more than the allowed skew; nothing was submitted.
	ErrClockSkew = errors.New("recorder: local clock skewed against the chain")

	// ErrIntentStale means the anchor tx of an intent was signed for an
	// account sequence the chain has passed, so it can never land. The intent
	// stays archived and is never re-signed: the anchor tx is bound by its
	// exact bytes. This blob is not published again by this Recorder.
	ErrIntentStale = errors.New("recorder: anchor tx signed for a stale account sequence; publish a new blob")
	// ErrAnchorTxRejected means the node refused the anchor tx, or the chain
	// executed it with a nonzero code. It is sticky per blob.
	ErrAnchorTxRejected = errors.New("recorder: the node refused the anchor tx")
	// ErrAnchorExpired means the anchor of a pending reference did not land
	// before the chain stopped accepting it. It is sticky per blob.
	ErrAnchorExpired = errors.New("recorder: the anchor did not land in its window")
)

// Recorder is what the daemon publishes through, whatever the DA.
type Recorder interface {
	sdk.Publisher
	// Close waits for draining uploads until ctx ends, then cancels them.
	Close(ctx context.Context) error
	// SkippedIntents counts the archived anchor intents a fast Recorder
	// could not follow; health is degraded while it is not zero.
	SkippedIntents() uint64
}
