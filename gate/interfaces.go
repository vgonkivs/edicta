package gate

import (
	"context"
	"crypto/ed25519"
	"time"

	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/gate/registry"
)

type Clock interface{ Now() time.Time }

type Allowlist interface {
	// PubKey returns ErrAgentNotAllowed if agentID is not listed.
	PubKey(ctx context.Context, agentID string) ([32]byte, error)
}

type ChainParams interface {
	// FibreRetention is x/fibre shard_retention in seconds. Height 0 means
	// the latest value. For height > 0 it must return the value in force at
	// that height or an error; it must never fall back to the latest value.
	FibreRetention(ctx context.Context, height uint64) (uint64, error)
}

type HeaderSource interface {
	// BlockTime is the header time (Unix seconds) of a committed block. It
	// returns ErrAnchorNotFound if the block does not exist yet.
	BlockTime(ctx context.Context, height uint64) (uint64, error)
}

type Anchor struct {
	Height         uint64
	RetentionStart uint64 // da = 1: PaymentPromise creation time; 0 means unknown
}

type AnchorSource interface {
	// FindAnchor returns ErrAnchorNotFound if the block at ref.Height holds no
	// anchor matching ref.
	FindAnchor(ctx context.Context, ref commitment.PayloadRef) (Anchor, error)
}

type BlobSource interface {
	// Fetch returns the blob bytes and reads at most maxSize+1 bytes. It
	// returns ErrBlobNotFound when the source knows the blob is absent.
	Fetch(ctx context.Context, ref commitment.PayloadRef, maxSize uint64) ([]byte, error)
}

type DACommitter interface {
	// Check recomputes the DA commitment of blob and compares it with
	// ref.Commitment; it returns ErrDACommitmentMismatch on any difference.
	Check(ctx context.Context, ref commitment.PayloadRef, blob []byte) error
}

type Signer interface {
	PublicKey() ed25519.PublicKey
	Sign(ctx context.Context, msg []byte) ([]byte, error)
}

type Metrics interface {
	Admission(ev AdmissionEvent)
}

type AdmissionEvent struct {
	CommitmentHash commitment.Hash // zero if rejected before the signature check passed
	DA             commitment.DA
	Path           registry.Path  // 0 if no payload path was accepted
	State          registry.State // 0 if nothing was reserved
	Err            error          // nil on Executed
}

type Outcome uint8

const (
	OutcomeUnknown  Outcome = iota // may or may not have been placed
	OutcomeExecuted                // the rail acknowledged the order
	OutcomeRejected                // the rail guarantees it was not and will not be placed
	OutcomeNotFound                // Lookup only: no order with this client order id
)

type ExecRequest struct {
	CommitmentHash commitment.Hash
	ClientOrderID  string
	Order          commitment.IBKROrderV0
	NotAfter       time.Time // must not be sent after this instant
}

type ExecResult struct {
	Outcome Outcome
	RailRef string // required for OutcomeExecuted
}

// Executor places orders. A non-nil error means OutcomeUnknown whatever the
// result says. It must send ClientOrderID with every order and be safe for
// concurrent use.
type Executor interface {
	Rail() commitment.Rail
	Execute(ctx context.Context, req ExecRequest) (ExecResult, error)
	Lookup(ctx context.Context, clientOrderID string) (ExecResult, error)
}

type Deps struct {
	Clock      Clock
	Params     ChainParams
	Headers    HeaderSource
	Anchors    AnchorSource
	DA         BlobSource
	Archive    BlobSource
	Committers map[commitment.DA]DACommitter
	Allowlist  Allowlist
	Registry   registry.Registry
	Executor   Executor
	Signer     Signer
	Metrics    Metrics // nil means none
}
