// Package registry defines the nonce registry of the gate: one entry per
// (agent public key, nonce), which marks a nonce as used.
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

type State uint8

const (
	StateReserved State = iota + 1
	StateExecuted
	StateRejected
	StateUnknown
)

func (s State) String() string {
	switch s {
	case StateReserved:
		return "reserved"
	case StateExecuted:
		return "executed"
	case StateRejected:
		return "rejected"
	case StateUnknown:
		return "unknown"
	}
	return fmt.Sprintf("state(%d)", uint8(s))
}

// Path is where the payload was accepted from; the values equal
// commitment.ReceiptPath.
type Path uint8

const (
	PathDA      Path = 1
	PathArchive Path = 2
)

type Source uint8

const (
	SourceRail    Source = iota + 1 // result of Execute
	SourceLookup                    // automatic reconciliation
	SourceManual                    // operator
	SourceRecover                   // restart: Reserved to Unknown
	SourceResign                    // a missing receipt was signed later
)

// Resolution is one append-only record of a state change.
type Resolution struct {
	Source    Source
	By        string // "gate" or the operator id
	At        uint64 // gate clock, Unix seconds
	Note      string // set only for SourceManual
	PrevState State
}

type Entry struct {
	Key            Key
	CommitmentHash commitment.Hash
	State          State
	Path           Path
	ReservedAt     uint64
	ValidUntil     uint64
	RailRef        string
	ExecutedAt     uint64
	Receipt        []byte // canonical SignedReceipt; nil until signed
	History        []Resolution
}

// Clone returns a deep copy that preserves nil slices.
func (e Entry) Clone() Entry {
	e.Receipt = slices.Clone(e.Receipt)
	e.History = slices.Clone(e.History)
	return e
}

type Meta struct {
	Epoch     uint64 // creation time of the store; persisted, never rewritten
	Watermark uint64 // largest ReservedAt ever written
	// PruneCutoff is the largest cutoff ever passed to Prune. It only grows.
	PruneCutoff uint64
}

var (
	ErrNotFound      = errors.New("registry: entry not found")
	ErrExists        = errors.New("registry: entry exists")
	ErrStateConflict = errors.New("registry: state conflict")
	ErrInvalidEntry  = errors.New("registry: invalid entry")
	// ErrBelowWatermark means a reservation is older than the newest one by more than the tolerance.
	ErrBelowWatermark = errors.New("registry: reservation below the watermark")
	// ErrInUse means another owner holds the registry.
	// ErrCorruptMeta means a stored metadata value is missing or malformed.
	ErrCorruptMeta = errors.New("registry: corrupt metadata")
	ErrInUse       = errors.New("registry: in use by another gate")
	// ErrPrunedWindow means a reservation expires inside a window that was already pruned.
	ErrPrunedWindow = errors.New("registry: reservation expires inside the pruned window")
)

// ExistsError is returned by Reserve; it matches ErrExists.
type ExistsError struct{ Existing Entry }

func (e *ExistsError) Error() string   { return "registry: entry exists" }
func (e *ExistsError) Is(t error) bool { return t == ErrExists }

// Registry is safe for concurrent use. Every method that changes state is
// atomic and, for durable implementations, durable before it returns.
type Registry interface {
	// Reserve stores e, which must be Reserved with an empty history, if the
	// key is absent. Otherwise it returns an *ExistsError. In the same
	// transaction it refuses with ErrBelowWatermark, writing nothing, if
	// e.ReservedAt + tolerance is below the stored watermark, so a pruned
	// nonce can never be reserved again by a clock that stepped back. It also
	// refuses with ErrPrunedWindow if e.ValidUntil is below the largest cutoff
	// ever pruned, whatever the tolerance.
	Reserve(ctx context.Context, e Entry, tolerance uint64) error
	// Resolve replaces the mutable fields of the entry (State, RailRef,
	// ExecutedAt, Receipt, History) with those of upd if the stored state is
	// from and the transition is allowed; otherwise it returns
	// ErrStateConflict. History must be the stored history plus one record.
	Resolve(ctx context.Context, k Key, from State, upd Entry) error
	Get(ctx context.Context, k Key) (Entry, error)
	// Pending returns the entries that need attention: Reserved, Unknown and
	// Executed without a receipt.
	Pending(ctx context.Context) ([]Entry, error)
	// Recover turns every Reserved entry into Unknown in one transaction and
	// records now as the time of the change.
	Recover(ctx context.Context, now uint64) (int, error)
	Meta(ctx context.Context) (Meta, error)
	// Prune deletes terminal entries (Executed with a receipt, Rejected)
	// whose ValidUntil is below cutoff.
	Prune(ctx context.Context, cutoff uint64) (int, error)
}

// CheckReserve validates the entry given to Reserve.
func CheckReserve(e Entry) error {
	if e.State != StateReserved || len(e.History) != 0 {
		return fmt.Errorf("%w: Reserve needs a Reserved entry without history", ErrInvalidEntry)
	}
	if e.Path != PathDA && e.Path != PathArchive {
		return fmt.Errorf("%w: path %d", ErrInvalidEntry, e.Path)
	}
	return nil
}

// Transition applies the state machine to a stored entry and returns the new
// stored entry. It is shared by all implementations so they cannot differ.
func Transition(stored Entry, from State, upd Entry) (Entry, error) {
	if stored.State != from {
		return Entry{}, fmt.Errorf("%w: stored state %s, expected %s", ErrStateConflict, stored.State, from)
	}
	switch {
	case from == StateReserved && (upd.State == StateExecuted || upd.State == StateRejected || upd.State == StateUnknown):
	case from == StateUnknown && (upd.State == StateExecuted || upd.State == StateRejected):
	case from == StateExecuted && upd.State == StateExecuted && stored.Receipt == nil && upd.Receipt != nil:
	default:
		return Entry{}, fmt.Errorf("%w: %s to %s", ErrStateConflict, from, upd.State)
	}
	n := len(stored.History)
	if len(upd.History) != n+1 || !slices.Equal(upd.History[:n], stored.History) {
		return Entry{}, fmt.Errorf("%w: history must grow by exactly one record", ErrInvalidEntry)
	}
	out := stored.Clone()
	out.History = slices.Clone(upd.History)
	if from == StateExecuted {
		out.Receipt = slices.Clone(upd.Receipt)
		return out, nil
	}
	out.State = upd.State
	if upd.State == StateExecuted {
		out.RailRef, out.ExecutedAt = upd.RailRef, upd.ExecutedAt
		out.Receipt = slices.Clone(upd.Receipt)
	}
	return out, nil
}

// Prunable reports whether Prune may delete e at cutoff.
func Prunable(e Entry, cutoff uint64) bool {
	terminal := e.State == StateRejected || e.State == StateExecuted && e.Receipt != nil
	return terminal && e.ValidUntil < cutoff
}

// NeedsAttention is the Pending predicate.
func NeedsAttention(e Entry) bool {
	return e.State == StateReserved || e.State == StateUnknown || e.State == StateExecuted && e.Receipt == nil
}

// RecoverEntry turns a Reserved entry into Unknown with the restart record.
func RecoverEntry(e Entry, at uint64) Entry {
	e = e.Clone()
	e.History = append(e.History, Resolution{Source: SourceRecover, By: "gate", At: at, PrevState: StateReserved})
	e.State = StateUnknown
	return e
}

// Claimer is implemented by registries that admit one owner at a time.
type Claimer interface {
	// Claim marks the registry as owned and returns a function that releases
	// it. It returns ErrInUse if it is already owned.
	Claim() (release func(), err error)
}

// BelowWatermark reports whether a reservation at reservedAt is older than
// the watermark by more than tolerance.
func BelowWatermark(reservedAt, tolerance, watermark uint64) bool {
	sum := reservedAt + tolerance
	if sum < reservedAt {
		sum = ^uint64(0)
	}
	return sum < watermark
}
