package policy

import (
	"bytes"
	"errors"
	"fmt"
	"slices"

	"github.com/vgonkivs/edicta/commitment"
)

const (
	// BucketSeconds is the fixed width of a history bucket.
	BucketSeconds = 3600
	// MaxClosed is the number of closed buckets a ledger retains.
	MaxClosed = 767
	// MaxPairs bounds the (asset, scale) pairs of one bucket.
	MaxPairs = 64
)

type Sum struct {
	Asset string `cbor:"1,keyasint"`
	Scale uint64 `cbor:"2,keyasint"`
	Sum   []byte `cbor:"3,keyasint"`
}

type Bucket struct {
	Format uint64 `cbor:"1,keyasint"`
	Index  uint64 `cbor:"2,keyasint"`
	Count  uint64 `cbor:"3,keyasint"`
	Sums   []Sum  `cbor:"4,keyasint"`
}

type ClosedRef struct {
	Index uint64 `cbor:"1,keyasint"`
	Hash  []byte `cbor:"2,keyasint"`
}

type ClosedSet struct {
	Format  uint64      `cbor:"1,keyasint"`
	Buckets []ClosedRef `cbor:"2,keyasint"`
}

type State struct {
	Format     uint64  `cbor:"1,keyasint"`
	Seq        uint64  `cbor:"2,keyasint"`
	LastT      uint64  `cbor:"3,keyasint,omitempty"`
	LastTH     uint64  `cbor:"4,keyasint,omitempty"`
	ClosedRoot []byte  `cbor:"5,keyasint"`
	Open       *Bucket `cbor:"6,keyasint,omitempty"`
}

func badState(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrStateInvalid, fmt.Sprintf(format, a...))
}

func (b *Bucket) Validate() error {
	if b == nil {
		return errNil
	}
	if b.Format != 1 {
		return fmt.Errorf("%w: bucket format %d: %w", ErrStateInvalid, b.Format, commitment.ErrUnsupportedVersion)
	}
	if b.Index > maxInt || b.Count > maxInt {
		return fmt.Errorf("%w: bucket: %w", ErrStateInvalid, commitment.ErrIntRange)
	}
	if b.Count < 1 {
		return fmt.Errorf("%w: bucket count: %w", ErrStateInvalid, commitment.ErrZeroValue)
	}
	return b.validateSums()
}

func (b *Bucket) validateSums() error {
	if n := len(b.Sums); n < 1 || n > MaxPairs {
		return badState("bucket with %d sums", n)
	}
	for i, s := range b.Sums {
		if !isPrintable(s.Asset, 1, 128) || s.Scale > 255 {
			return badState("sum %d asset or scale", i)
		}
		if err := checkAmount(s.Sum); err != nil {
			return badState("sum %d: %v", i, err)
		}
		if i > 0 && cmpPair(b.Sums[i-1].Asset, b.Sums[i-1].Scale, s.Asset, s.Scale) >= 0 {
			return badState("sums not strictly ascending")
		}
	}
	return nil
}

func cmpPair(a string, as uint64, b string, bs uint64) int {
	if c := bytes.Compare([]byte(a), []byte(b)); c != 0 {
		return c
	}
	switch {
	case as < bs:
		return -1
	case as > bs:
		return 1
	}
	return 0
}

func (s *ClosedSet) Validate() error {
	if s == nil {
		return errNil
	}
	if s.Format != 1 {
		return fmt.Errorf("%w: closed set format %d: %w", ErrStateInvalid, s.Format, commitment.ErrUnsupportedVersion)
	}
	if len(s.Buckets) > MaxClosed {
		return badState("%d closed refs", len(s.Buckets))
	}
	for i, r := range s.Buckets {
		if r.Index > maxInt {
			return fmt.Errorf("%w: ref index: %w", ErrStateInvalid, commitment.ErrIntRange)
		}
		if err := checkHash(r.Hash, "ref hash"); err != nil {
			return fmt.Errorf("%w: %w", ErrStateInvalid, err)
		}
		if i > 0 && s.Buckets[i-1].Index >= r.Index {
			return badState("refs not strictly ascending")
		}
	}
	return nil
}

func (s *State) Validate() error {
	if s == nil {
		return errNil
	}
	if s.Format != 1 {
		return fmt.Errorf("%w: state format %d: %w", ErrStateInvalid, s.Format, commitment.ErrUnsupportedVersion)
	}
	if s.Seq > maxInt || s.LastT > maxInt || s.LastTH > maxInt {
		return fmt.Errorf("%w: state: %w", ErrStateInvalid, commitment.ErrIntRange)
	}
	if err := checkHash(s.ClosedRoot, "closed_root"); err != nil {
		return fmt.Errorf("%w: %w", ErrStateInvalid, err)
	}
	if s.Seq == 0 {
		if s.LastT != 0 || s.LastTH != 0 || s.Open != nil {
			return fmt.Errorf("%w: seq 0 with fields: %w", ErrStateInvalid, commitment.ErrMissingField)
		}
		if !bytes.Equal(s.ClosedRoot, GenesisLedger().State.ClosedRoot) {
			return badState("genesis closed_root")
		}
		return nil
	}
	if s.LastT == 0 || s.LastTH == 0 || s.Open == nil {
		return fmt.Errorf("%w: seq >= 1 without last_t, last_th or open: %w", ErrStateInvalid, commitment.ErrMissingField)
	}
	if s.LastTH > s.LastT {
		return badState("last_th above last_t")
	}
	if err := s.Open.Validate(); err != nil {
		return err
	}
	if s.Open.Index != s.LastT/BucketSeconds {
		return badState("open bucket index is not k(last_t)")
	}
	return nil
}

func encodeValidated(v interface{ Validate() error }) ([]byte, error) {
	if err := v.Validate(); err != nil {
		return nil, err
	}
	return marshal(v)
}

func EncodeBucket(b *Bucket) ([]byte, error)       { return encodeValidated(b) }
func EncodeClosedSet(s *ClosedSet) ([]byte, error) { return encodeValidated(s) }
func EncodeState(s *State) ([]byte, error)         { return encodeValidated(s) }

func decodeVal[T any, P interface {
	*T
	Validate() error
}](b []byte, limit int) (*T, error) {
	v := new(T)
	if err := decodeStrict(b, limit, v, ErrStateInvalid); err != nil {
		return nil, err
	}
	if err := P(v).Validate(); err != nil {
		return nil, err
	}
	if err := requireCanonical(b, func() ([]byte, error) { return marshal(v) }, ErrStateInvalid); err != nil {
		return nil, err
	}
	return v, nil
}

func DecodeBucket(b []byte) (*Bucket, error)       { return decodeVal[Bucket](b, maxStateSize) }
func DecodeClosedSet(b []byte) (*ClosedSet, error) { return decodeVal[ClosedSet](b, maxClosedSize) }
func DecodeState(b []byte) (*State, error)         { return decodeVal[State](b, maxStateSize) }

func HashBucketBytes(canon []byte) commitment.Hash    { return hashTagged(TagBucket, canon) }
func HashClosedSetBytes(canon []byte) commitment.Hash { return hashTagged(TagClosed, canon) }
func HashStateBytes(canon []byte) commitment.Hash     { return hashTagged(TagState, canon) }

func HashBucket(b *Bucket) (commitment.Hash, error) {
	c, err := EncodeBucket(b)
	if err != nil {
		return commitment.Hash{}, err
	}
	return HashBucketBytes(c), nil
}

func HashClosedSet(s *ClosedSet) (commitment.Hash, error) {
	c, err := EncodeClosedSet(s)
	if err != nil {
		return commitment.Hash{}, err
	}
	return HashClosedSetBytes(c), nil
}

func HashState(s *State) (commitment.Hash, error) {
	c, err := EncodeState(s)
	if err != nil {
		return commitment.Hash{}, err
	}
	return HashStateBytes(c), nil
}

// EmptyClosedSet is the closed set of genesis.
func EmptyClosedSet() ClosedSet { return ClosedSet{Format: 1, Buckets: []ClosedRef{}} }

// GenesisLedger is the empty ledger every counter starts from.
func GenesisLedger() Ledger {
	set := EmptyClosedSet()
	root, _ := HashClosedSet(&set)
	return Ledger{State: State{Format: 1, ClosedRoot: root[:]}, Set: set, Closed: []Bucket{}}
}

// Ledger is what the engine evaluates: the State, the ClosedSet it names, and
// the contents of the closed buckets in hand. Closed may hold fewer buckets
// than Set lists; evaluation fails if a window needs one that is missing.
type Ledger struct {
	State  State     `cbor:"1,keyasint"`
	Set    ClosedSet `cbor:"2,keyasint"`
	Closed []Bucket  `cbor:"3,keyasint"`
}

// NewLedger checks every hash and the structural rules of a ledger.
func NewLedger(s State, closed []Bucket, set ClosedSet) (Ledger, error) {
	l := Ledger{State: s, Set: set, Closed: closed}
	if l.Closed == nil {
		l.Closed = []Bucket{}
	}
	return l, l.Validate()
}

// Validate checks the ledger rules: the set hashes to the state's root, the
// state is genesis or consistent, and each bucket in hand matches its ref.
func (l *Ledger) Validate() error {
	if err := l.State.Validate(); err != nil {
		return err
	}
	if err := l.Set.Validate(); err != nil {
		return err
	}
	root, err := HashClosedSet(&l.Set)
	if err != nil {
		return err
	}
	if !bytes.Equal(root[:], l.State.ClosedRoot) {
		return badState("closed set does not hash to closed_root")
	}
	s := &l.State
	if s.Seq == 0 {
		if len(l.Set.Buckets) != 0 || len(l.Closed) != 0 {
			return badState("genesis with closed buckets")
		}
		if !bytes.Equal(s.ClosedRoot, GenesisLedger().State.ClosedRoot) {
			return badState("genesis closed_root")
		}
		return nil
	}
	if s.LastTH > s.LastT {
		return badState("last_th above last_t")
	}
	if s.Open.Index != s.LastT/BucketSeconds {
		return badState("open bucket index is not k(last_t)")
	}
	for _, r := range l.Set.Buckets {
		if r.Index >= s.Open.Index || r.Index+MaxClosed < s.Open.Index {
			return badState("ref index %d outside the retained range", r.Index)
		}
	}
	for i := range l.Closed {
		b := &l.Closed[i]
		if err := b.Validate(); err != nil {
			return err
		}
		j, ok := slices.BinarySearchFunc(l.Set.Buckets, b.Index, func(r ClosedRef, idx uint64) int {
			switch {
			case r.Index < idx:
				return -1
			case r.Index > idx:
				return 1
			}
			return 0
		})
		if !ok {
			return badState("bucket %d is not in the closed set", b.Index)
		}
		h, err := HashBucket(b)
		if err != nil {
			return err
		}
		if !bytes.Equal(h[:], l.Set.Buckets[j].Hash) {
			return badState("bucket %d does not hash to its ref", b.Index)
		}
		if i > 0 && l.Closed[i-1].Index >= b.Index {
			return badState("closed buckets not ascending")
		}
	}
	return nil
}

// StateHash returns the hash of the ledger's state.
func (l *Ledger) StateHash() (commitment.Hash, error) { return HashState(&l.State) }

var errMissingBucket = errors.New("policy: closed bucket content missing")
