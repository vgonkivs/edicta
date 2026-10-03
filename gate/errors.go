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

	ErrNonceUsed           = errors.New("gate: nonce already used")
	ErrBeforeRegistryEpoch = errors.New("gate: issued_at not after the registry epoch")

	ErrAnchorNotFound       = errors.New("gate: anchor not found")
	ErrRetentionUnavailable = errors.New("gate: retention at the anchor height unreadable")

	ErrDACommitmentMismatch        = errors.New("gate: DA commitment mismatch")
	ErrArchiveRecomputeUnsupported = errors.New("gate: archive path needs a DA commitment recompute that is not available")
	ErrPayloadUnavailable          = errors.New("gate: payload unavailable")

	// ErrAnchorTooOld also matches ErrPayloadUnavailable.
	ErrAnchorTooOld = fmt.Errorf("gate: anchor too old, archive did not return the blob: %w", ErrPayloadUnavailable)

	// ErrBlobNotFound is returned by a BlobSource, never by Admit.
	ErrBlobNotFound = errors.New("gate: blob not found")

	ErrChainUnavailable     = errors.New("gate: chain data unavailable")
	ErrRegistryUnavailable  = errors.New("gate: registry unavailable")
	ErrAllowlistUnavailable = errors.New("gate: allowlist unavailable")
	ErrRegistryInUse        = errors.New("gate: registry already used by another gate")
	ErrClockRegression      = errors.New("gate: clock before the registry watermark")

	ErrExecutionRejected = errors.New("gate: rail rejected the order")
	ErrExecutionUnknown  = errors.New("gate: execution outcome unknown")
	ErrReceiptPending    = errors.New("gate: order placed, receipt pending")

	ErrNotUnknown        = errors.New("gate: entry is not in state unknown")
	ErrInvalidResolution = errors.New("gate: invalid manual resolution")

	ErrClosed        = errors.New("gate: closed")
	ErrInvalidConfig = errors.New("gate: invalid configuration")
)
