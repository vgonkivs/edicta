package commitment

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
)

// MaxReceiptSize bounds a SignedReceipt, checked before parsing.
const MaxReceiptSize = 512

// ReceiptPath says where the gate accepted the payload from.
type ReceiptPath uint64

const (
	ReceiptPathDA      ReceiptPath = 1
	ReceiptPathArchive ReceiptPath = 2
)

var errNilReceipt = errors.New("commitment: nil receipt")

// Receipt maps one executed decision to the rail's reference. All fields are
// required.
type Receipt struct {
	Version        uint64      `cbor:"1,keyasint"`
	CommitmentHash []byte      `cbor:"2,keyasint"`
	GateID         string      `cbor:"3,keyasint"`
	GatePubKey     []byte      `cbor:"4,keyasint"`
	Rail           Rail        `cbor:"5,keyasint"`
	RailRef        string      `cbor:"6,keyasint"`
	Path           ReceiptPath `cbor:"7,keyasint"`
	ExecutedAt     uint64      `cbor:"8,keyasint"`
}

type SignedReceipt struct {
	Receipt   Receipt `cbor:"1,keyasint"`
	Signature []byte  `cbor:"2,keyasint"`
}

var receiptSchema = []field{
	{key: 1, name: "version", kind: kUint, required: true},
	{key: 2, name: "commitment_hash", kind: kBytes, min: 32, max: 32, required: true},
	{key: 3, name: "gate_id", kind: kText, min: 1, max: 64, charset: isID, required: true},
	{key: 4, name: "gate_pubkey", kind: kBytes, min: 32, max: 32, required: true},
	{key: 5, name: "rail", kind: kUint, required: true},
	{key: 6, name: "rail_ref", kind: kText, min: 1, max: 128, charset: isID, required: true},
	{key: 7, name: "path", kind: kUint, required: true},
	{key: 8, name: "executed_at", kind: kUint, required: true},
}

// EncodeReceipt returns the canonical CBOR of r. It does not validate values.
func EncodeReceipt(r *Receipt) ([]byte, error) {
	if r == nil {
		return nil, errNilReceipt
	}
	if encModeErr != nil {
		return nil, encModeErr
	}
	b, err := encMode.Marshal(r)
	if err != nil {
		return nil, fmt.Errorf("commitment: encode receipt: %w", err)
	}
	return b, nil
}

func EncodeSignedReceipt(s *SignedReceipt) ([]byte, error) {
	if s == nil {
		return nil, errNilReceipt
	}
	if encModeErr != nil {
		return nil, encModeErr
	}
	b, err := encMode.Marshal(s)
	if err != nil {
		return nil, fmt.Errorf("commitment: encode signed receipt: %w", err)
	}
	return b, nil
}

// HashReceipt hashes canonical receipt bytes under the receipt domain tag.
func HashReceipt(canon []byte) Hash {
	return sha256.Sum256(tagged(TagReceipt, canon))
}

// ReceiptSigningMessage is the exact 53 bytes the gate signs.
func ReceiptSigningMessage(h Hash) []byte {
	return tagged(TagReceiptSig, h[:])
}

// DecodeSignedReceipt parses and strictly validates a SignedReceipt (wire format only)
// and returns the receipt hash. It checks neither values nor the signature.
func DecodeSignedReceipt(b []byte) (*SignedReceipt, Hash, error) {
	if len(b) > MaxReceiptSize {
		return nil, Hash{}, fmt.Errorf("%w: receipt of %d bytes", ErrTooLarge, len(b))
	}
	root, err := scanTop(b, 1)
	if err != nil {
		return nil, Hash{}, err
	}
	if root.major != majMap {
		return nil, Hash{}, fmt.Errorf("%w: signed receipt is not a map", ErrWrongType)
	}

	var rn, sn *node
	for _, e := range root.entries {
		switch e.key {
		case 1:
			if e.val.major != majMap {
				return nil, Hash{}, fmt.Errorf("%w: signed_receipt.receipt", ErrWrongType)
			}
			if err := checkMap(e.val, receiptSchema, "receipt"); err != nil {
				return nil, Hash{}, err
			}
			rn = e.val
		case 2:
			if e.val.major != majBstr {
				return nil, Hash{}, fmt.Errorf("%w: signed_receipt.signature", ErrWrongType)
			}
			if len(e.val.b) != ed25519.SignatureSize {
				return nil, Hash{}, fmt.Errorf("%w: signature length %d", ErrFieldSize, len(e.val.b))
			}
			sn = e.val
		default:
			return nil, Hash{}, fmt.Errorf("%w: signed receipt key %d", ErrUnknownKey, e.key)
		}
	}
	if rn == nil || sn == nil {
		return nil, Hash{}, fmt.Errorf("%w: signed receipt needs keys 1 and 2", ErrMissingField)
	}

	m := byKey(rn)
	s := &SignedReceipt{
		Receipt: Receipt{
			Version:        m[1].u,
			CommitmentHash: bytes.Clone(m[2].b),
			GateID:         string(m[3].b),
			GatePubKey:     bytes.Clone(m[4].b),
			Rail:           Rail(m[5].u),
			RailRef:        string(m[6].b),
			Path:           ReceiptPath(m[7].u),
			ExecutedAt:     m[8].u,
		},
		Signature: bytes.Clone(sn.b),
	}
	canon, err := EncodeReceipt(&s.Receipt)
	if err != nil || !bytes.Equal(canon, b[rn.start:rn.end]) {
		return nil, Hash{}, fmt.Errorf("%w: receipt", ErrNonCanonical)
	}
	enc, err := EncodeSignedReceipt(s)
	if err != nil || !bytes.Equal(enc, b) {
		return nil, Hash{}, fmt.Errorf("%w: signed receipt", ErrNonCanonical)
	}
	return s, HashReceipt(canon), nil
}

// VerifyReceipt runs stages D, S and G. It proves only that the holder of
// gate_pubkey signed these bytes; the caller still has to bind the key to the
// gate id and the hash to a verified commitment.
func VerifyReceipt(b []byte) (*SignedReceipt, Hash, error) {
	s, h, err := DecodeSignedReceipt(b)
	if err != nil {
		return nil, Hash{}, err
	}
	r := &s.Receipt
	if r.Version != 0 {
		return nil, Hash{}, fmt.Errorf("%w: %d", ErrUnsupportedVersion, r.Version)
	}
	for _, u := range []struct {
		name string
		v    uint64
	}{{"version", r.Version}, {"rail", uint64(r.Rail)}, {"path", uint64(r.Path)}, {"executed_at", r.ExecutedAt}} {
		if u.v > maxUint63 {
			return nil, Hash{}, fmt.Errorf("%w: %s", ErrIntRange, u.name)
		}
	}
	if r.Rail == 0 {
		return nil, Hash{}, fmt.Errorf("%w: rail 0", ErrInvalidEnum)
	}
	if r.Path != ReceiptPathDA && r.Path != ReceiptPathArchive {
		return nil, Hash{}, fmt.Errorf("%w: path %d", ErrInvalidEnum, r.Path)
	}
	if r.Rail != RailIBKR {
		return nil, Hash{}, fmt.Errorf("%w: %d", ErrUnsupportedRail, r.Rail)
	}
	if r.ExecutedAt == 0 {
		return nil, Hash{}, fmt.Errorf("%w: executed_at", ErrZeroValue)
	}
	if err := CheckPublicKey(r.GatePubKey); err != nil {
		return nil, Hash{}, err
	}
	if !ed25519.Verify(r.GatePubKey, ReceiptSigningMessage(h), s.Signature) {
		return nil, Hash{}, ErrSignatureInvalid
	}
	return s, h, nil
}
