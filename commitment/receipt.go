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

// PayloadPath says where the gate accepted the payload from.
type PayloadPath uint64

const (
	PathDA      PayloadPath = 1
	PathArchive PayloadPath = 2
)

var errNilReceipt = errors.New("commitment: nil receipt")

// Receipt is the gate's attestation of the rail reference the integrator
// reported for one authorized decision. It is not proof of execution. All
// fields are required; keys 5 and 7 are retired.
type Receipt struct {
	Version        uint64 `cbor:"1,keyasint"`
	CommitmentHash []byte `cbor:"2,keyasint"`
	GateID         string `cbor:"3,keyasint"`
	GatePubKey     []byte `cbor:"4,keyasint"`
	RailRef        string `cbor:"6,keyasint"`
	RecordedAt     uint64 `cbor:"8,keyasint"`
	// ExecutorPubKey and ExecutorSignature are the executor's claim of
	// RailRef, signed over RecordRequestMessage.
	ExecutorPubKey    []byte `cbor:"9,keyasint"`
	ExecutorSignature []byte `cbor:"10,keyasint"`
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
	{key: 6, name: "rail_ref", kind: kText, min: 1, max: 128, charset: isID, required: true},
	{key: 8, name: "recorded_at", kind: kUint, required: true},
	{key: 9, name: "executor_pubkey", kind: kBytes, min: 32, max: 32, required: true},
	{key: 10, name: "executor_signature", kind: kBytes, min: 64, max: 64, required: true},
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

// ReceiptSigningMessage is the exact 54 bytes the gate signs.
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
			RailRef:        string(m[6].b),
			RecordedAt:     m[8].u,

			ExecutorPubKey:    bytes.Clone(m[9].b),
			ExecutorSignature: bytes.Clone(m[10].b),
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
	if r.Version != Version {
		return nil, Hash{}, fmt.Errorf("%w: %d", ErrUnsupportedVersion, r.Version)
	}
	for _, u := range []struct {
		name string
		v    uint64
	}{{"version", r.Version}, {"recorded_at", r.RecordedAt}} {
		if u.v > maxUint63 {
			return nil, Hash{}, fmt.Errorf("%w: %s", ErrIntRange, u.name)
		}
	}
	if r.RecordedAt == 0 {
		return nil, Hash{}, fmt.Errorf("%w: recorded_at", ErrZeroValue)
	}
	if bytes.Equal(r.ExecutorPubKey, r.GatePubKey) {
		return nil, Hash{}, fmt.Errorf("%w: executor key is the gate key", ErrKeyRole)
	}
	if err := CheckPublicKey(r.GatePubKey); err != nil {
		return nil, Hash{}, err
	}
	if !ed25519.Verify(r.GatePubKey, ReceiptSigningMessage(h), s.Signature) {
		return nil, Hash{}, ErrSignatureInvalid
	}
	var ch Hash
	copy(ch[:], r.CommitmentHash)
	if err := VerifyRecordRequest(ch, r.GateID, r.RailRef, r.ExecutorPubKey, r.ExecutorSignature); err != nil {
		return nil, Hash{}, err
	}
	return s, h, nil
}

// RecordRequestMessage is the message an executor signs, directly, to claim
// railRef for one decision: tag, commitment hash, length-prefixed gate id and reference.
func RecordRequestMessage(h Hash, gateID, railRef string) ([]byte, error) {
	if n := len(gateID); n < 1 || n > 64 {
		return nil, fmt.Errorf("%w: gate_id length %d", ErrFieldSize, n)
	}
	for i := 0; i < len(gateID); i++ {
		if !isID(gateID[i]) {
			return nil, fmt.Errorf("%w: gate_id byte 0x%02x outside charset", ErrInvalidString, gateID[i])
		}
	}
	if n := len(railRef); n < 1 || n > 128 {
		return nil, fmt.Errorf("%w: rail_ref length %d", ErrFieldSize, n)
	}
	for i := 0; i < len(railRef); i++ {
		if !isID(railRef[i]) {
			return nil, fmt.Errorf("%w: rail_ref byte 0x%02x outside charset", ErrInvalidString, railRef[i])
		}
	}
	return tagged(TagRecordRequest, h[:], []byte{byte(len(gateID))}, []byte(gateID), []byte{byte(len(railRef))}, []byte(railRef)), nil
}

// VerifyRecordRequest checks the reference, the executor key (no weak key)
// and the executor's signature. Whether the key is an allowed executor is the
// caller's business.
func VerifyRecordRequest(h Hash, gateID, railRef string, executorPub ed25519.PublicKey, sig []byte) error {
	msg, err := RecordRequestMessage(h, gateID, railRef)
	if err != nil {
		return err
	}
	if err := CheckPublicKey(executorPub); err != nil {
		return err
	}
	if !ed25519.Verify(executorPub, msg, sig) {
		return ErrSignatureInvalid
	}
	return nil
}
