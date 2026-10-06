package gate

import (
	"context"
	"crypto/ed25519"
	"log/slog"
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
	// BlockTime is the header time (Unix seconds) of a committed block. A block
	// that cannot be read, including one that does not exist yet, is
	// ErrChainUnavailable: an at-height read cannot prove absence.
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
	Check(ref commitment.PayloadRef, blob []byte) error
}

type Signer interface {
	PublicKey() ed25519.PublicKey
	Sign(ctx context.Context, msg []byte) ([]byte, error)
}

type Metrics interface {
	// Admission is called once per Authorize call, after it returns.
	Admission(ev AdmissionEvent)
	// StoredActionMismatch is called when a stored entry holds the presented
	// commitment but another action hash. That is a gate bug or a damaged
	// registry and needs an operator.
	StoredActionMismatch(h commitment.Hash)
}

type AdmissionEvent struct {
	CommitmentHash commitment.Hash // zero if rejected before the signature check passed
	DA             commitment.DA
	Path           registry.Path // 0 if no payload path was accepted
	Authorized     bool          // a new Authorization was issued and stored
	Err            error         // nil when Authorized
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
	Signer     Signer       // the gate key: Authorizations and receipts
	Metrics    Metrics      // nil means none
	Logger     *slog.Logger // nil means slog.Default()
}
