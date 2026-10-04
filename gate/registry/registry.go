// Package registry defines the nonce registry of the gate: one entry per
// (agent public key, nonce), which marks a nonce as used and keeps the
// Authorization issued for it.
package registry

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/vgonkivs/edicta/commitment"
)

// Key identifies a nonce of one agent key.
type Key struct {
	PubKey [32]byte
	Nonce  [16]byte
}

// Path is where the payload was accepted from; the values equal
// commitment.PayloadPath.
type Path uint8

const (
	PathDA      Path = 1
	PathArchive Path = 2
)

// Entry is the record of one authorized decision. It is written once by
// Consume; only Receipt may be set later, once, by AttachReceipt.
type Entry struct {
	Key            Key
	CommitmentHash commitment.Hash
	ActionHash     commitment.Hash
	Path           Path
	AuthorizedAt   uint64 // gate clock at authorization; feeds the watermark
	ValidUntil     uint64
	Authorization  []byte // canonical SignedAuthorization; never empty
	Receipt        []byte // canonical SignedReceipt; nil until attached
}

// Clone returns a deep copy that preserves nil slices.
func (e Entry) Clone() Entry {
	e.Authorization = slices.Clone(e.Authorization)
	e.Receipt = slices.Clone(e.Receipt)
	return e
}

type Meta struct {
	Epoch     uint64 // creation time of the store; persisted, never rewritten
	Watermark uint64 // largest AuthorizedAt ever written
	// PruneCutoff is the largest cutoff ever passed to Prune. It only grows.
	PruneCutoff uint64
}

var (
	ErrNotFound      = errors.New("registry: entry not found")
	ErrExists        = errors.New("registry: entry exists")
	ErrStateConflict = errors.New("registry: state conflict")
	ErrInvalidEntry  = errors.New("registry: invalid entry")
	// ErrBelowWatermark means an authorization is older than the newest one by more than the tolerance.
	ErrBelowWatermark = errors.New("registry: authorization below the watermark")
	// ErrCorruptMeta means a stored metadata value is missing, malformed or of an unknown schema.
	ErrCorruptMeta = errors.New("registry: corrupt metadata")
	// ErrInUse means another owner holds the registry.
	ErrInUse = errors.New("registry: in use by another gate")
	// ErrPrunedWindow means a decision expires inside a window that was already pruned.
	ErrPrunedWindow = errors.New("registry: decision expires inside the pruned window")
)

// ExistsError is returned by Consume; it matches ErrExists.
type ExistsError struct{ Existing Entry }

func (e *ExistsError) Error() string   { return "registry: entry exists" }
func (e *ExistsError) Is(t error) bool { return t == ErrExists }

// Registry is safe for concurrent use. Every method that changes state is
// atomic and, for durable implementations, durable before it returns.
type Registry interface {
	// Consume stores e if its key is absent; otherwise it returns an
	// *ExistsError. In the same transaction it refuses, writing nothing,
	// with ErrBelowWatermark if e.AuthorizedAt + tolerance is below the
	// stored watermark, so a pruned nonce can never be consumed again by a
	// clock that stepped back, and with ErrPrunedWindow if e.ValidUntil is
	// below the largest cutoff ever pruned, whatever the tolerance. It
	// raises the watermark to e.AuthorizedAt.
	Consume(ctx context.Context, e Entry, tolerance uint64) error
	Get(ctx context.Context, k Key) (Entry, error)
	// AttachReceipt sets Receipt if the entry exists, holds commitment hash h
	// and has no receipt. It returns ErrNotFound for an absent entry and
	// ErrStateConflict otherwise.
	AttachReceipt(ctx context.Context, k Key, h commitment.Hash, receipt []byte) error
	Meta(ctx context.Context) (Meta, error)
	// Prune deletes the entries with ValidUntil below cutoff and raises
	// PruneCutoff to cutoff if it is larger.
	Prune(ctx context.Context, cutoff uint64) (int, error)
}

// CheckConsume validates the entry given to Consume.
func CheckConsume(e Entry) error {
	if len(e.Authorization) == 0 {
		return fmt.Errorf("%w: Consume needs an Authorization", ErrInvalidEntry)
	}
	if e.Path != PathDA && e.Path != PathArchive {
		return fmt.Errorf("%w: path %d", ErrInvalidEntry, e.Path)
	}
	return nil
}

// Prunable reports whether Prune may delete e at cutoff.
func Prunable(e Entry, cutoff uint64) bool { return e.ValidUntil < cutoff }

// Claimer is implemented by registries that admit one owner at a time.
type Claimer interface {
	// Claim marks the registry as owned and returns a function that releases
	// it. It returns ErrInUse if it is already owned.
	Claim() (release func(), err error)
}

// BelowWatermark reports whether an authorization at authorizedAt is older
// than the watermark by more than tolerance.
func BelowWatermark(authorizedAt, tolerance, watermark uint64) bool {
	sum := authorizedAt + tolerance
	if sum < authorizedAt {
		sum = ^uint64(0)
	}
	return sum < watermark
}
