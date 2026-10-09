package commitment

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"math/bits"
	"slices"
)

// MaxAuthorizationSize bounds a SignedAuthorization, checked before parsing.
const MaxAuthorizationSize = 256

// Mode of an Authorization v1.
const (
	ModeStrict = 1
	ModeFast   = 2
)

var errNilAuthorization = errors.New("commitment: nil authorization")

// Authorization is the gate's statement that one commitment passed every
// check for exactly one action, until Expires. Keys 1 to 6 are required in
// both versions; Mode is required in v1 and absent in v0, AnchorDeadline is
// present exactly when Mode is ModeFast.
type Authorization struct {
	Version        uint64      `cbor:"1,keyasint"`
	CommitmentHash []byte      `cbor:"2,keyasint"`
	ActionHash     []byte      `cbor:"3,keyasint"`
	GateID         string      `cbor:"4,keyasint"`
	Expires        uint64      `cbor:"5,keyasint"`
	Path           PayloadPath `cbor:"6,keyasint"`
	Mode           uint64      `cbor:"7,keyasint,omitempty"`
	AnchorDeadline uint64      `cbor:"8,keyasint,omitempty"`

	// A decoded key 7 or 8 holding 0 cannot be told from an absent key by
	// the fields above; static validation refuses both.
	modeZero, deadlineZero bool
}

type SignedAuthorization struct {
	Authorization Authorization `cbor:"1,keyasint"`
	Signature     []byte        `cbor:"2,keyasint"`
}

// AuthorizationCheck is what an executor knows on its own.
type AuthorizationCheck struct {
	GatePubKey ed25519.PublicKey
	GateID     string
	ActionType string
	Action     []byte
	Now        uint64
	SkewS      uint64
	// AcceptVersions lists the Authorization versions accepted; empty means
	// both 0 and 1.
	AcceptVersions []uint64
}

var (
	authorizationSchema = []field{
		{key: 1, name: "version", kind: kUint, required: true},
		{key: 2, name: "commitment_hash", kind: kBytes, min: 32, max: 32, required: true},
		{key: 3, name: "action_hash", kind: kBytes, min: 32, max: 32, required: true},
		{key: 4, name: "gate_id", kind: kText, min: 1, max: 64, charset: isID, required: true},
		{key: 5, name: "expires", kind: kUint, required: true},
		{key: 6, name: "path", kind: kUint, required: true},
	}
	// Key 7 precedes key 8 in canonical order, so the deadline's presence
	// rule is decided in the same pass, as for signer and da.
	authorizationSchemaV1 = append(slices.Clone(authorizationSchema),
		field{key: 7, name: "mode", kind: kUint, required: true},
		field{key: 8, name: "anchor_deadline", kind: kUint, onlyIf: notStrict, requiredIf: isFast},
	)
)

func modeIs(seen map[uint64]*node, mode uint64) bool {
	n := seen[7]
	return n != nil && n.major == majUint && n.u == mode
}

func notStrict(seen map[uint64]*node) bool { return !modeIs(seen, ModeStrict) }
func isFast(seen map[uint64]*node) bool    { return modeIs(seen, ModeFast) }

// AuthorizationTags returns the hash and signature tags of a version.
func AuthorizationTags(version uint64) (hashTag, sigTag string) {
	if version == VersionV1 {
		return TagAuthorizationV1, TagAuthorizationSigV1
	}
	return TagAuthorization, TagAuthorizationSig
}

// EncodeAuthorization returns the canonical CBOR of a. It does not validate values.
func EncodeAuthorization(a *Authorization) ([]byte, error) {
	if a == nil {
		return nil, errNilAuthorization
	}
	if encModeErr != nil {
		return nil, encModeErr
	}
	b, err := encMode.Marshal(a)
	if err != nil {
		return nil, fmt.Errorf("commitment: encode authorization: %w", err)
	}
	return b, nil
}

func EncodeSignedAuthorization(s *SignedAuthorization) ([]byte, error) {
	if s == nil {
		return nil, errNilAuthorization
	}
	if encModeErr != nil {
		return nil, encModeErr
	}
	b, err := encMode.Marshal(s)
	if err != nil {
		return nil, fmt.Errorf("commitment: encode signed authorization: %w", err)
	}
	return b, nil
}

// HashAuthorization hashes canonical v0 Authorization bytes under the v0 tag.
func HashAuthorization(canon []byte) Hash {
	return HashAuthorizationFor(VersionV0, canon)
}

// HashAuthorizationFor hashes canonical Authorization bytes under the tag of
// the given version.
func HashAuthorizationFor(version uint64, canon []byte) Hash {
	tag, _ := AuthorizationTags(version)
	return sha256.Sum256(tagged(tag, canon))
}

// AuthorizationSigningMessage is the exact 60 bytes the gate signs for a v0
// Authorization.
func AuthorizationSigningMessage(h Hash) []byte {
	return AuthorizationSigningMessageFor(VersionV0, h)
}

// AuthorizationSigningMessageFor is the exact 60 bytes the gate signs for an
// Authorization of the given version.
func AuthorizationSigningMessageFor(version uint64, h Hash) []byte {
	_, tag := AuthorizationTags(version)
	return tagged(tag, h[:])
}

// DecodeSignedAuthorization parses and strictly validates a SignedAuthorization
// of either version (wire format only) and returns the Authorization hash
// under the tag of its version. The Authorization's key 1 selects the schema.
// It checks neither values nor the signature.
func DecodeSignedAuthorization(b []byte) (*SignedAuthorization, Hash, error) {
	return decodeSignedAuthorization(b, true)
}

// decodeSignedAuthorization with v1 false is the frozen v0 reader.
func decodeSignedAuthorization(b []byte, v1 bool) (*SignedAuthorization, Hash, error) {
	if len(b) > MaxAuthorizationSize {
		return nil, Hash{}, fmt.Errorf("%w: authorization of %d bytes", ErrTooLarge, len(b))
	}
	root, err := scanTop(b, 1)
	if err != nil {
		return nil, Hash{}, err
	}
	if root.major != majMap {
		return nil, Hash{}, fmt.Errorf("%w: signed authorization is not a map", ErrWrongType)
	}

	var an, sn *node
	for _, e := range root.entries {
		switch e.key {
		case 1:
			if e.val.major != majMap {
				return nil, Hash{}, fmt.Errorf("%w: signed_authorization.authorization", ErrWrongType)
			}
			schema := authorizationSchema
			if v1 && schemaVersion(e.val) == VersionV1 {
				schema = authorizationSchemaV1
			}
			if err := checkMap(e.val, schema, "authorization"); err != nil {
				return nil, Hash{}, err
			}
			an = e.val
		case 2:
			if e.val.major != majBstr {
				return nil, Hash{}, fmt.Errorf("%w: signed_authorization.signature", ErrWrongType)
			}
			if len(e.val.b) != ed25519.SignatureSize {
				return nil, Hash{}, fmt.Errorf("%w: signature length %d", ErrFieldSize, len(e.val.b))
			}
			sn = e.val
		default:
			return nil, Hash{}, fmt.Errorf("%w: signed authorization key %d", ErrUnknownKey, e.key)
		}
	}
	if an == nil || sn == nil {
		return nil, Hash{}, fmt.Errorf("%w: signed authorization needs keys 1 and 2", ErrMissingField)
	}

	m := byKey(an)
	s := &SignedAuthorization{
		Authorization: Authorization{
			Version:        m[1].u,
			CommitmentHash: bytes.Clone(m[2].b),
			ActionHash:     bytes.Clone(m[3].b),
			GateID:         string(m[4].b),
			Expires:        m[5].u,
			Path:           PayloadPath(m[6].u),
		},
		Signature: bytes.Clone(sn.b),
	}
	a := &s.Authorization
	if n := m[7]; n != nil {
		a.Mode, a.modeZero = n.u, n.u == 0
	}
	if n := m[8]; n != nil {
		a.AnchorDeadline, a.deadlineZero = n.u, n.u == 0
	}
	canon := b[an.start:an.end]
	// A present zero cannot re-encode; the value is refused by static
	// validation, so only the comparison is skipped.
	if !a.modeZero && !a.deadlineZero {
		enc, err := EncodeAuthorization(a)
		if err != nil || !bytes.Equal(enc, canon) {
			return nil, Hash{}, fmt.Errorf("%w: authorization", ErrNonCanonical)
		}
		enc, err = EncodeSignedAuthorization(s)
		if err != nil || !bytes.Equal(enc, b) {
			return nil, Hash{}, fmt.Errorf("%w: signed authorization", ErrNonCanonical)
		}
	}
	return s, HashAuthorizationFor(a.Version, canon), nil
}

// ValidateAuthorization runs the static rules of an Authorization of either
// version in their normative order: the version (and acceptVersions, empty
// meaning 0 and 1), integer ranges, path, mode, expires, anchor_deadline.
func ValidateAuthorization(a *Authorization, acceptVersions []uint64) error {
	if a == nil {
		return errNilAuthorization
	}
	if len(acceptVersions) == 0 {
		acceptVersions = []uint64{VersionV0, VersionV1}
	}
	if a.Version != VersionV0 && a.Version != VersionV1 || !slices.Contains(acceptVersions, a.Version) {
		return fmt.Errorf("%w: %d", ErrUnsupportedVersion, a.Version)
	}
	v1 := a.Version == VersionV1
	if !v1 && (a.Mode != 0 || a.AnchorDeadline != 0 || a.modeZero || a.deadlineZero) {
		return fmt.Errorf("%w: v1 key in a v0 authorization", ErrUnknownKey)
	}
	for _, u := range []struct {
		name string
		v    uint64
	}{
		{"version", a.Version}, {"expires", a.Expires}, {"path", uint64(a.Path)},
		{"mode", a.Mode}, {"anchor_deadline", a.AnchorDeadline},
	} {
		if u.v > maxUint63 {
			return fmt.Errorf("%w: %s", ErrIntRange, u.name)
		}
	}
	if a.Path != PathDA && a.Path != PathArchive {
		return fmt.Errorf("%w: path %d", ErrInvalidEnum, a.Path)
	}
	if v1 && a.Mode != ModeStrict && a.Mode != ModeFast {
		return fmt.Errorf("%w: mode %d", ErrInvalidEnum, a.Mode)
	}
	if a.Expires == 0 {
		return fmt.Errorf("%w: expires", ErrZeroValue)
	}
	if a.deadlineZero {
		return fmt.Errorf("%w: anchor_deadline", ErrZeroValue)
	}
	// Built in memory rather than decoded: the presence rule of key 8.
	if v1 && (a.Mode == ModeFast) != (a.AnchorDeadline != 0) {
		if a.Mode == ModeFast {
			return fmt.Errorf("%w: anchor_deadline", ErrMissingField)
		}
		return fmt.Errorf("%w: anchor_deadline with mode %d", ErrUnknownKey, a.Mode)
	}
	return nil
}

// VerifyAuthorization is the executor-side check for both versions: decode,
// static rules, the signature under the pinned gate key and the tags of the
// Authorization's version, then the gate id, the exact action bytes under the
// expected type, and the expiry.
func VerifyAuthorization(b []byte, chk AuthorizationCheck) (*SignedAuthorization, Hash, error) {
	s, h, err := DecodeSignedAuthorization(b)
	if err != nil {
		return nil, Hash{}, err
	}
	a := &s.Authorization
	if err := ValidateAuthorization(a, chk.AcceptVersions); err != nil {
		return nil, Hash{}, err
	}

	if err := CheckPublicKey(chk.GatePubKey); err != nil {
		return nil, Hash{}, err
	}
	if !ed25519.Verify(chk.GatePubKey, AuthorizationSigningMessageFor(a.Version, h), s.Signature) {
		return nil, Hash{}, ErrSignatureInvalid
	}

	if a.GateID != chk.GateID {
		return nil, Hash{}, ErrScopeMismatch
	}
	ah, err := ActionHashFor(a.Version, chk.ActionType, chk.Action)
	if err != nil {
		if errors.Is(err, ErrActionSize) {
			return nil, Hash{}, err
		}
		return nil, Hash{}, fmt.Errorf("%w: %v", ErrActionMismatch, err)
	}
	if subtle.ConstantTimeCompare(ah[:], a.ActionHash) != 1 {
		return nil, Hash{}, ErrActionMismatch
	}
	horizon, carry := bits.Add64(chk.Now, chk.SkewS, 0)
	if carry != 0 {
		horizon = ^uint64(0)
	}
	if horizon >= a.Expires {
		return nil, Hash{}, fmt.Errorf("%w: expires %d, now %d", ErrExpired, a.Expires, chk.Now)
	}
	return s, h, nil
}
