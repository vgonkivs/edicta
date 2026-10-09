package gate

import (
	"context"
	"crypto/ed25519"
	"log/slog"
	"time"

	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/gate/registry"
	"github.com/vgonkivs/edicta/policy"
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

// SourcedChainParams is a ChainParams that also reports what an at-height
// retention value rests on.
type SourcedChainParams interface {
	ChainParams
	FibreRetentionSourced(ctx context.Context, height uint64) (uint64, RetentionSource, error)
}

// RetentionSource says where an at-height retention value came from; the
// values equal the archive's.
type RetentionSource uint8

const (
	RetentionDirect   RetentionSource = 1
	RetentionObserved RetentionSource = 2
	RetentionBoth     RetentionSource = 3
)

// DecisionRecord is the envelope, the action bytes and the action salt
// exactly as presented, keyed by the commitment hash.
type DecisionRecord struct {
	CommitmentHash commitment.Hash
	Envelope       []byte
	Action         []byte
	ActionSalt     []byte
}

// Archiver stores a decision record durably before the gate reads or marks
// any nonce. Put is idempotent: the same record again returns nil. The gate
// calls it only after the agent signature, the action type allowlist and the
// action bytes check, so only signed, allowlisted decisions with their
// committed action bytes reach the archive; unsigned or unlisted input
// cannot fill it. A request refused after this stage leaves the record
// behind. Any error while the request's context is live becomes
// ErrArchiveUnavailable.
//
// A record whose commitment hash and action bytes equal the stored ones and
// whose envelope differs only in the agent signature MUST return nil and
// keep the stored record: the gate has verified that signature, and a
// re-signed retry must not become a permanent refusal.
type Archiver interface {
	Put(ctx context.Context, rec DecisionRecord) error
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
	Archiver   Archiver     // nil skips the archive stage
	Metrics    Metrics      // nil means none
	Logger     *slog.Logger // nil means slog.Default()
	// Extractors serves the policy; required when Config.Mandate is set.
	Extractors *policy.Extractors
}
