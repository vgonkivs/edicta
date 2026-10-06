// Package archive defines the archive record format, its strict codec and the
// Store interface. Stores are trusted for availability only: every reader
// re-checks what it uses.
package archive

import (
	"context"
	"errors"
	"io"

	"github.com/vgonkivs/edicta/commitment"
)

var (
	ErrNotFound = errors.New("archive: not found")
	ErrConflict = errors.New("archive: a different record is stored under this key")
	// ErrCorrupt wraps the decoding cause or describes a key mismatch.
	ErrCorrupt = errors.New("archive: corrupt record")
)

// MaxRecordSize bounds any record before parsing.
const MaxRecordSize = 1<<27 + 4096

type Kind uint64

const (
	KindPayload       Kind = 1
	KindEvidence      Kind = 2
	KindDecision      Kind = 3
	KindAuthorization Kind = 4
	KindRejection     Kind = 5
)

func (k Kind) String() string {
	switch k {
	case KindPayload:
		return "payload"
	case KindEvidence:
		return "evidence"
	case KindDecision:
		return "decision"
	case KindAuthorization:
		return "authorization"
	case KindRejection:
		return "rejection"
	}
	return "unknown"
}

// Record is one of the pointer record types below.
type Record interface {
	Kind() Kind
}

// PayloadRecord holds the exact blob bytes. Namespace and Signer are set for
// da = 2 only.
type PayloadRecord struct {
	DA           commitment.DA
	Commitment   []byte
	Namespace    []byte
	Signer       []byte
	Blob         []byte
	IntentHeight uint64
}

// EvidenceRecord holds the anchor evidence. The fields after BlobProof are
// defined for da = 1 only; BlobProof for da = 2 only. A nil byte field is
// absent.
type EvidenceRecord struct {
	DA              commitment.DA
	Commitment      []byte
	Namespace       []byte
	Height          uint64
	Header          []byte
	AnchorTx        []byte
	AnchorTxIndex   uint64
	AnchorTxProof   []byte
	BlobProof       []byte
	TxCode          uint64
	SystemBlob      []byte
	SystemBlobProof []byte
	PromiseHeight   uint64
	PromiseHeader   []byte
	HistoricalInfo  []byte
	PromiseValset   []byte
}

type DecisionRecord struct {
	Envelope []byte
	Action   []byte
}

// AuthorizationRecord has a nil K2 when it was repaired from the registry.
type AuthorizationRecord struct {
	SignedAuthorization []byte
	AuthorizedAt        uint64
	K2                  *K2Inputs
}

type RetentionSource uint64

const (
	RetentionDirect   RetentionSource = 1
	RetentionObserved RetentionSource = 2
	RetentionBoth     RetentionSource = 3
)

// K2Inputs are the inputs of the anchor-age rule as the gate used them. A
// zero uint field is absent.
type K2Inputs struct {
	DA                 commitment.DA
	CheckedAt          uint64
	BlockTime          uint64
	BlobRetentionS     uint64
	RetentionLatestS   uint64
	RetentionAtHeightS uint64
	RetentionSource    RetentionSource
	PromiseCreated     uint64
}

// RejectionRecord is the marker of one refused attempt. Error is a verdict
// sentinel name without package.
type RejectionRecord struct {
	CommitmentHash commitment.Hash
	Error          string
	GateID         string
	RejectedAt     uint64
}

func (*PayloadRecord) Kind() Kind       { return KindPayload }
func (*EvidenceRecord) Kind() Kind      { return KindEvidence }
func (*DecisionRecord) Kind() Kind      { return KindDecision }
func (*AuthorizationRecord) Kind() Kind { return KindAuthorization }
func (*RejectionRecord) Kind() Kind     { return KindRejection }

type Outcome int

const (
	// Written means the record was stored by this call.
	Written Outcome = iota + 1
	// Unchanged means the call stored nothing: the key already held an
	// identical record, or a marker was skipped because the decision is
	// authorized.
	Unchanged
)

type State int

const (
	StateAbsent State = iota
	StatePending
	StateRejected
	StateAuthorized
)

func (s State) String() string {
	switch s {
	case StateAbsent:
		return "absent"
	case StatePending:
		return "pending"
	case StateRejected:
		return "rejected"
	case StateAuthorized:
		return "authorized"
	}
	return "unknown"
}

// DecisionState is derived from the records present, never stored.
// Rejections are marker names ordered by rejected_at, then by name.
type DecisionState struct {
	State      State
	Rejections []string
}

// Store keeps records write-once under keys the records determine. Put
// returns ErrConflict for a different record under a stored key, ErrNotFound
// when the record it depends on is missing, and the DA committer's error for
// a payload that fails the recompute. Readers return ErrNotFound for an absent
// key and an ErrCorrupt error for a stored record that does not decode or
// does not carry its key. A key that cannot exist (a malformed commitment or
// an unknown da or verdict name) is an absent key: ErrNotFound.
type Store interface {
	Put(ctx context.Context, r Record) (Outcome, error)
	Payload(ctx context.Context, da commitment.DA, commit []byte) (*PayloadRecord, error)
	Evidence(ctx context.Context, da commitment.DA, commit []byte) (*EvidenceRecord, error)
	Decision(ctx context.Context, h commitment.Hash) (*DecisionRecord, error)
	Authorization(ctx context.Context, h commitment.Hash) (*AuthorizationRecord, error)
	Rejection(ctx context.Context, h commitment.Hash, name string) (*RejectionRecord, error)
	State(ctx context.Context, h commitment.Hash) (DecisionState, error)
}

// PayloadStreamer is implemented by stores that can hand out the encoded
// payload record without decoding it, so a reader can bound its memory. The
// bytes are untrusted: the reader validates what it uses.
type PayloadStreamer interface {
	PayloadReader(ctx context.Context, da commitment.DA, commit []byte) (io.ReadCloser, error)
}
