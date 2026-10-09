package policy

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/vgonkivs/edicta/commitment"
)

// Tags of private mode. The two envelope tags are never hashed or signed.
const (
	TagPrivatePart = "edicta/policy/v1/private-part"
	TagPrivateAEAD = "edicta/policy/v1/private"
	TagPrivateDEK  = "edicta/policy/v1/private-dek"
	TagStateBlind  = "edicta/policy/v1/state-blind"
	TagBlindKey    = "edicta/policy/v1/blind-key"
)

// Caps of a private envelope by plaintext kind. The action cap fits a
// maximal action with its salt and sixteen recipient entries.
const (
	MaxPrivateEnvelope       = 65536
	MaxPrivateActionEnvelope = 69632
	maxPrivatePartSize       = 16384
)

// PrivateKind is the plaintext kind of a private blob record.
type PrivateKind uint8

const (
	PrivateMandate   PrivateKind = 1
	PrivateBucket    PrivateKind = 2
	PrivateClosedSet PrivateKind = 3
	PrivatePartKind  PrivateKind = 4
	PrivateAction    PrivateKind = 5
)

// Valid reports whether k is a defined plaintext kind.
func (k PrivateKind) Valid() bool { return k >= PrivateMandate && k <= PrivateAction }

// EnvelopeCap is the largest envelope of the kind.
func (k PrivateKind) EnvelopeCap() int {
	if k == PrivateAction {
		return MaxPrivateActionEnvelope
	}
	return MaxPrivateEnvelope
}

var (
	// ErrPrivateUnopened means no configured auditor key opens a private
	// record: the record is private to the reader, not damaged.
	ErrPrivateUnopened = errors.New("policy: no configured auditor key opens the private record")
	// ErrPrivateCorrupt is a private envelope that does not decode, fails
	// the AEAD under a key it lists, or opens to bytes with another hash.
	ErrPrivateCorrupt = errors.New("policy: corrupt private record")
	// ErrStateSaltChanged refuses a successor mandate whose state_salt
	// differs from the one its counter blinds with.
	ErrStateSaltChanged = errors.New("policy: state_salt differs from the counter's")
)

// Sealer encrypts a plaintext of the kind to the auditors of a mandate.
type Sealer interface {
	Seal(kind PrivateKind, plaintext []byte, auditors []Auditor) ([]byte, error)
}

// Opener decrypts a private envelope with the reader's keys. It returns the
// plaintext and the kid of the entry that opened it, ErrPrivateUnopened when
// no key opens it, or an ErrPrivateCorrupt error. The caller compares the
// plaintext's hash with the record key before using it.
type Opener interface {
	Open(kind PrivateKind, envelope []byte) (plaintext, kid []byte, err error)
}

// PrivatePart holds the verdict keys a private-form verdict does not
// publish, under the same key numbers, and a per-verdict salt that keeps
// private_hash from being a dictionary oracle for reasons and amounts.
type PrivatePart struct {
	Format     uint64 `cbor:"1,keyasint"`
	Salt       []byte `cbor:"2,keyasint"`
	Reason     string `cbor:"8,keyasint,omitempty"`
	Extractor  string `cbor:"9,keyasint,omitempty"`
	Facts      *Facts `cbor:"10,keyasint,omitempty"`
	AnchorTime uint64 `cbor:"11,keyasint,omitempty"`
	EvalTime   uint64 `cbor:"12,keyasint,omitempty"`
	PrevState  *State `cbor:"13,keyasint,omitempty"`
	DecidedAt  uint64 `cbor:"17,keyasint,omitempty"`
	GateClock  uint64 `cbor:"18,keyasint,omitempty"`
}

// PrivatePartSaltSize is the length of the PrivatePart salt.
const PrivatePartSaltSize = 32

// Validate checks the value rules; presence against the outcome is
// CheckPresence of the merged verdict.
func (p *PrivatePart) Validate() error {
	if p == nil {
		return errNil
	}
	if p.Format != 1 {
		return fmt.Errorf("%w: private part format %d: %w", ErrVerdictInvalid, p.Format, commitment.ErrUnsupportedVersion)
	}
	if len(p.Salt) != PrivatePartSaltSize {
		return fmt.Errorf("%w: private part salt of %d bytes: %w", ErrVerdictInvalid, len(p.Salt), commitment.ErrFieldSize)
	}
	if p.DecidedAt == 0 {
		return fmt.Errorf("%w: private part decided_at: %w", ErrVerdictInvalid, commitment.ErrMissingField)
	}
	for name, u := range map[string]uint64{"anchor_time": p.AnchorTime, "eval_time": p.EvalTime, "decided_at": p.DecidedAt} {
		if u > maxInt {
			return fmt.Errorf("%w: %s: %w", ErrVerdictInvalid, name, commitment.ErrIntRange)
		}
	}
	if p.Extractor != "" && (len(p.Extractor) > 64 || !extractorID.MatchString(p.Extractor)) {
		return fmt.Errorf("%w: extractor id: %w", ErrVerdictInvalid, commitment.ErrInvalidString)
	}
	if p.Facts != nil {
		if err := p.Facts.Validate(); err != nil {
			return badVerdict("facts: %v", err)
		}
	}
	if p.PrevState != nil {
		if err := p.PrevState.Validate(); err != nil {
			return fmt.Errorf("%w: %w", ErrVerdictInvalid, err)
		}
	}
	if p.GateClock != 0 && p.GateClock != 1 {
		return fmt.Errorf("%w: gate_clock: %w", ErrVerdictInvalid, commitment.ErrInvalidEnum)
	}
	return nil
}

// EncodePrivatePart returns the canonical bytes of a validated part.
func EncodePrivatePart(p *PrivatePart) ([]byte, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return marshal(p)
}

// DecodePrivatePart strictly decodes a PrivatePart. Failures are
// ErrVerdictInvalid.
func DecodePrivatePart(b []byte) (*PrivatePart, error) {
	var p PrivatePart
	if err := decodeStrict(b, maxPrivatePartSize, &p, ErrVerdictInvalid); err != nil {
		return nil, err
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	if err := requireCanonical(b, func() ([]byte, error) { return marshal(&p) }, ErrVerdictInvalid); err != nil {
		return nil, err
	}
	return &p, nil
}

// PrivateHash is the private_hash of a canonical PrivatePart.
func PrivateHash(canon []byte) commitment.Hash { return hashTagged(TagPrivatePart, canon) }

// GenesisStateHash is the hash of the genesis state. It is the same in both
// modes, so the first allow of a counter is recognizable without a key.
func GenesisStateHash() commitment.Hash {
	g := GenesisLedger()
	h, _ := HashState(&g.State)
	return h
}

// StateHasher yields state_hash in public mode and the blinded state_hash_p
// in private mode, and maps bucket and closed-set hashes to their archive
// keys.
type StateHasher interface {
	StateHash(s *State) (commitment.Hash, error)
	// BlobKey maps the plaintext hash of a record to its kind 15 key.
	BlobKey(kind PrivateKind, plainHash commitment.Hash) commitment.Hash
	// Private reports whether the hasher blinds.
	Private() bool
}

type stateHasher struct{ salt []byte }

// NewStateHasher blinds with the mandate's state_salt iff it has auditors.
func NewStateHasher(m *Mandate) StateHasher {
	if m == nil || len(m.Auditors) == 0 {
		return stateHasher{}
	}
	return stateHasher{salt: bytes.Clone(m.StateSalt)}
}

// NewSaltHasher blinds with salt; a nil salt hashes publicly.
func NewSaltHasher(salt []byte) StateHasher { return stateHasher{salt: bytes.Clone(salt)} }

func (h stateHasher) Private() bool { return h.salt != nil }

func (h stateHasher) StateHash(s *State) (commitment.Hash, error) {
	c, err := EncodeState(s)
	if err != nil {
		return commitment.Hash{}, err
	}
	if h.salt == nil || s.Seq == 0 {
		return HashStateBytes(c), nil
	}
	return sha256.Sum256(tagged(TagStateBlind, h.salt, c)), nil
}

func (h stateHasher) BlobKey(kind PrivateKind, plainHash commitment.Hash) commitment.Hash {
	if h.salt == nil || (kind != PrivateBucket && kind != PrivateClosedSet) {
		return plainHash
	}
	return sha256.Sum256(tagged(TagBlindKey, h.salt, plainHash[:]))
}

// SplitVerdict turns a public-form verdict of a private-mode gate into its
// private form and its PrivatePart. NewStateHash must already be in the
// hasher's form; key 20 of an allow is the hasher's hash of prev_state.
func SplitVerdict(v *Verdict, salt []byte, h StateHasher) (*Verdict, *PrivatePart, error) {
	if v == nil || h == nil {
		return nil, nil, errNil
	}
	part := &PrivatePart{
		Format: 1, Salt: bytes.Clone(salt), Reason: v.Reason, Extractor: v.Extractor, Facts: v.Facts,
		AnchorTime: v.AnchorTime, EvalTime: v.EvalTime, PrevState: v.PrevState, DecidedAt: v.DecidedAt, GateClock: v.GateClock,
	}
	canon, err := EncodePrivatePart(part)
	if err != nil {
		return nil, nil, err
	}
	pub := &Verdict{
		Format: v.Format, GateID: v.GateID, MandateHash: v.MandateHash, CommitmentHash: v.CommitmentHash,
		ActionHash: v.ActionHash, AgentPubKey: v.AgentPubKey, Outcome: v.Outcome,
	}
	if v.Outcome == OutcomeAllow {
		if v.PrevState == nil {
			return nil, nil, fmt.Errorf("%w: allow without prev_state: %w", ErrVerdictInvalid, commitment.ErrMissingField)
		}
		ph, err := h.StateHash(v.PrevState)
		if err != nil {
			return nil, nil, err
		}
		pub.NewStateHash, pub.PrevCommitmentHash, pub.PrevVerdictHash = v.NewStateHash, v.PrevCommitmentHash, v.PrevVerdictHash
		pub.BlindPrevStateHash = ph[:]
	}
	ph := PrivateHash(canon)
	pub.PrivateHash = ph[:]
	if err := pub.Validate(); err != nil {
		return nil, nil, err
	}
	return pub, part, nil
}

// MergeUnchecked is the logical verdict: the public part without keys 19 and
// 20 plus the PrivatePart without its format and salt. It checks neither the
// hash nor the presence rule.
func MergeUnchecked(priv *Verdict, part *PrivatePart) *Verdict {
	m := *priv
	m.PrivateHash, m.BlindPrevStateHash = nil, nil
	m.Reason, m.Extractor, m.Facts = part.Reason, part.Extractor, part.Facts
	m.AnchorTime, m.EvalTime, m.PrevState = part.AnchorTime, part.EvalTime, part.PrevState
	m.DecidedAt, m.GateClock = part.DecidedAt, part.GateClock
	return &m
}

// MergeVerdict checks that part is the PrivatePart priv signed and that its
// presence fits priv's outcome, and returns the public-form verdict the
// public-mode checks read. Every failure is ErrVerdictInvalid.
func MergeVerdict(priv *Verdict, part *PrivatePart) (*Verdict, error) {
	if priv == nil || part == nil || priv.PrivateHash == nil {
		return nil, badVerdict("not a private-form verdict and its part")
	}
	canon, err := EncodePrivatePart(part)
	if err != nil {
		return nil, err
	}
	if h := PrivateHash(canon); !bytes.Equal(h[:], priv.PrivateHash) {
		return nil, badVerdict("private part does not hash to private_hash")
	}
	m := MergeUnchecked(priv, part)
	if err := m.Validate(); err != nil {
		return nil, err
	}
	return m, nil
}

// PlaintextHash is the hash a private blob's plaintext is filed under before
// blinding: mandate_hash, bucket_hash, closed_root, private_hash, or for an
// action (salt || bytes) the salted action hash under actionType. Bytes that
// do not decode are an error of the structure's sentinel.
func PlaintextHash(kind PrivateKind, plaintext []byte, actionType string) (commitment.Hash, error) {
	switch kind {
	case PrivateMandate:
		_, h, err := DecodeSignedMandate(plaintext)
		return h, err
	case PrivateBucket:
		if _, err := DecodeBucket(plaintext); err != nil {
			return commitment.Hash{}, err
		}
		return HashBucketBytes(plaintext), nil
	case PrivateClosedSet:
		if _, err := DecodeClosedSet(plaintext); err != nil {
			return commitment.Hash{}, err
		}
		return HashClosedSetBytes(plaintext), nil
	case PrivatePartKind:
		if _, err := DecodePrivatePart(plaintext); err != nil {
			return commitment.Hash{}, err
		}
		return PrivateHash(plaintext), nil
	case PrivateAction:
		if len(plaintext) <= commitment.ActionSaltSize {
			return commitment.Hash{}, fmt.Errorf("%w: action plaintext of %d bytes", commitment.ErrActionSize, len(plaintext))
		}
		return commitment.ActionHash(actionType, plaintext[:commitment.ActionSaltSize], plaintext[commitment.ActionSaltSize:])
	}
	return commitment.Hash{}, fmt.Errorf("%w: plaintext kind %d", commitment.ErrInvalidEnum, kind)
}
