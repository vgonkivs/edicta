package gate

import (
	"errors"
	"fmt"
)

// Stateful rejection reasons. Decoding, validation, signature, time and scope reasons are sentinels of package
// commitment.
var (
	ErrAgentNotAllowed   = errors.New("gate: agent id not in the allowlist")
	ErrAgentKeyMismatch  = errors.New("gate: agent key differs from the allowlisted key")
	ErrAgentKeyIsGateKey = errors.New("gate: agent key is a gate key")

	ErrDANotAllowed = errors.New("gate: payload_ref.da not allowed by this gate")

	ErrPayloadAboveCap = errors.New("gate: payload above the Fibre payload limit")
	// ErrArchiveUnavailable means the decision record could not be written
	// durably, or the archive could not serve the payload record (unreadable
	// or damaged); nothing was signed and the nonce is unused.
	ErrArchiveUnavailable = errors.New("gate: archive unavailable")

	ErrNonceUsed           = errors.New("gate: nonce already used")
	ErrBeforeRegistryEpoch = errors.New("gate: issued_at not after the registry epoch")

	ErrAnchorNotFound       = errors.New("gate: anchor not found")
	ErrRetentionUnavailable = errors.New("gate: retention at the anchor height unreadable")

	ErrDACommitmentMismatch        = errors.New("gate: DA commitment mismatch")
	ErrArchiveRecomputeUnsupported = errors.New("gate: archive path needs a DA commitment recompute that is not available")
	ErrPayloadUnavailable          = errors.New("gate: payload unavailable")

	// ErrAnchorTooOld also matches ErrPayloadUnavailable.
	ErrAnchorTooOld = fmt.Errorf("gate: anchor too old, archive did not return the blob: %w", ErrPayloadUnavailable)

	// ErrBlobNotFound is returned by a BlobSource, never by Authorize.
	ErrBlobNotFound = errors.New("gate: blob not found")

	ErrChainUnavailable     = errors.New("gate: chain data unavailable")
	ErrRegistryUnavailable  = errors.New("gate: registry unavailable")
	ErrAllowlistUnavailable = errors.New("gate: allowlist unavailable")
	ErrRegistryInUse        = errors.New("gate: registry already used by another gate")
	ErrClockRegression      = errors.New("gate: clock before the registry watermark")

	// ErrExecutorNotAllowed is returned by Record for a key outside the executor allowlist.
	ErrExecutorNotAllowed = errors.New("gate: executor key not allowed")
	// ErrNotAuthorized is returned by Record when no Authorization of this commitment is stored.
	ErrNotAuthorized = errors.New("gate: no authorization for this commitment")
	// ErrReceiptExists is returned by Record when the receipt was already recorded; the stored receipt is returned with it.
	ErrReceiptExists = errors.New("gate: receipt already recorded")

	ErrClosed        = errors.New("gate: closed")
	ErrInvalidConfig = errors.New("gate: invalid configuration")
)

// Refusals of the reference form and of the mandate reference.
var (
	// ErrAnchorPending is a pending payload reference at a gate that does
	// not run fast mode.
	ErrAnchorPending = errors.New("gate: pending payload reference and fast mode is off")
	// ErrMandateRefMissing is a commitment without mandate_ref at a gate
	// with a mandate.
	ErrMandateRefMissing = errors.New("gate: commitment names no mandate")
	// ErrMandateMismatch is a mandate_ref other than the hash of the mandate
	// in force, or any mandate_ref at a gate without a mandate.
	ErrMandateMismatch = errors.New("gate: commitment names another mandate")
)

// Fast-mode refusals. This gate refuses every pending reference with
// ErrAnchorPending, so it never returns these; they exist so that every
// party maps the same codes.
var (
	ErrNamespaceNotAllowed     = errors.New("gate: namespace not allowed for a pending reference")
	ErrAnchorIntentUnavailable = errors.New("gate: anchor intent unavailable")
	ErrAnchorIntentInvalid     = errors.New("gate: anchor intent invalid")
	ErrCertInvalid             = errors.New("gate: availability certificate invalid")
	ErrH0TooOld                = errors.New("gate: reference height too old")
	ErrAnchorWindowClosed      = errors.New("gate: anchor window closed")
	ErrAnchorIntentRejected    = errors.New("gate: anchor intent rejected by the node")
)
