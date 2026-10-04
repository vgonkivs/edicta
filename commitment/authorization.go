package commitment

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"math/bits"
)

// MaxAuthorizationSize bounds a SignedAuthorization, checked before parsing.
const MaxAuthorizationSize = 256

var errNilAuthorization = errors.New("commitment: nil authorization")

// Authorization is the gate's statement that one commitment passed every
// check for exactly one action, until Expires. All fields are required.
type Authorization struct {
	Version        uint64      `cbor:"1,keyasint"`
	CommitmentHash []byte      `cbor:"2,keyasint"`
	ActionHash     []byte      `cbor:"3,keyasint"`
	GateID         string      `cbor:"4,keyasint"`
	Expires        uint64      `cbor:"5,keyasint"`
	Path           PayloadPath `cbor:"6,keyasint"`
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
}

var authorizationSchema = []field{
	{key: 1, name: "version", kind: kUint, required: true},
	{key: 2, name: "commitment_hash", kind: kBytes, min: 32, max: 32, required: true},
	{key: 3, name: "action_hash", kind: kBytes, min: 32, max: 32, required: true},
	{key: 4, name: "gate_id", kind: kText, min: 1, max: 64, charset: isID, required: true},
	{key: 5, name: "expires", kind: kUint, required: true},
	{key: 6, name: "path", kind: kUint, required: true},
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

// HashAuthorization hashes canonical Authorization bytes under its domain tag.
func HashAuthorization(canon []byte) Hash {
	return sha256.Sum256(tagged(TagAuthorization, canon))
}

// AuthorizationSigningMessage is the exact 60 bytes the gate signs.
func AuthorizationSigningMessage(h Hash) []byte {
	return tagged(TagAuthorizationSig, h[:])
}

// DecodeSignedAuthorization parses and strictly validates a SignedAuthorization
// (wire format only) and returns the Authorization hash. It checks neither
// values nor the signature.
func DecodeSignedAuthorization(b []byte) (*SignedAuthorization, Hash, error) {
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
			if err := checkMap(e.val, authorizationSchema, "authorization"); err != nil {
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
	canon, err := EncodeAuthorization(&s.Authorization)
	if err != nil || !bytes.Equal(canon, b[an.start:an.end]) {
		return nil, Hash{}, fmt.Errorf("%w: authorization", ErrNonCanonical)
	}
	enc, err := EncodeSignedAuthorization(s)
	if err != nil || !bytes.Equal(enc, b) {
		return nil, Hash{}, fmt.Errorf("%w: signed authorization", ErrNonCanonical)
	}
	return s, HashAuthorization(canon), nil
}

// VerifyAuthorization is the executor-side check: decode, static rules, the
// signature under the pinned gate key, then the gate id, the exact action
// bytes under the expected type, and the expiry.
func VerifyAuthorization(b []byte, chk AuthorizationCheck) (*SignedAuthorization, Hash, error) {
	s, h, err := DecodeSignedAuthorization(b)
	if err != nil {
		return nil, Hash{}, err
	}
	a := &s.Authorization
	if a.Version != 0 {
		return nil, Hash{}, fmt.Errorf("%w: %d", ErrUnsupportedVersion, a.Version)
	}
	for _, u := range []struct {
		name string
		v    uint64
	}{{"version", a.Version}, {"expires", a.Expires}, {"path", uint64(a.Path)}} {
		if u.v > maxUint63 {
			return nil, Hash{}, fmt.Errorf("%w: %s", ErrIntRange, u.name)
		}
	}
	if a.Path != PathDA && a.Path != PathArchive {
		return nil, Hash{}, fmt.Errorf("%w: path %d", ErrInvalidEnum, a.Path)
	}
	if a.Expires == 0 {
		return nil, Hash{}, fmt.Errorf("%w: expires", ErrZeroValue)
	}

	if err := CheckPublicKey(chk.GatePubKey); err != nil {
		return nil, Hash{}, err
	}
	if !ed25519.Verify(chk.GatePubKey, AuthorizationSigningMessage(h), s.Signature) {
		return nil, Hash{}, ErrSignatureInvalid
	}

	if a.GateID != chk.GateID {
		return nil, Hash{}, ErrScopeMismatch
	}
	ah, err := ActionHash(chk.ActionType, chk.Action)
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
