// Package commitment implements DecisionCommitment v0: the canonical wire
// format, strict decoder, hashing, signing and the stateless checks of the
// gate.
//
// Functions are pure and bounded by the size limits, so they take no
// context.Context.
package commitment

const (
	TagCommitment = "edicta/v0/decision-commitment"
	TagSig        = "edicta/v0/sig"
	TagReceipt    = "edicta/v0/receipt"
	TagReceiptSig = "edicta/v0/receipt-sig"

	TagAction           = "edicta/v0/action"
	TagAuthorization    = "edicta/v0/authorization"
	TagAuthorizationSig = "edicta/v0/authorization-sig"

	MaxSignedSize     = 2176
	MaxCommitmentSize = 2048
	MaxPayloadSize    = 1 << 27

	// MaxActionSize bounds the action bytes the gate and executors hash.
	MaxActionSize = 1 << 16
	// MaxActionTypeSize bounds an action type in bytes.
	MaxActionTypeSize = 128
)

type Hash [32]byte

// DA is a uint64 because the decoder accepts any uint and rejects bad
// values during static validation.
type DA uint64

const (
	DAFibre        DA = 1
	DACelestiaBlob DA = 2
)

// Required fields carry no omitempty; only optional pointers do.
type Commitment struct {
	Version        uint64     `cbor:"1,keyasint"`
	AgentID        string     `cbor:"2,keyasint"`
	AgentPubKey    []byte     `cbor:"3,keyasint"`
	Nonce          []byte     `cbor:"4,keyasint"`
	IssuedAt       uint64     `cbor:"5,keyasint"`
	ValidUntil     uint64     `cbor:"6,keyasint"`
	Scope          Scope      `cbor:"7,keyasint"`
	Action         Action     `cbor:"8,keyasint"`
	PayloadRef     PayloadRef `cbor:"10,keyasint"`
	CiphertextHash []byte     `cbor:"11,keyasint"`
	PlaintextHash  []byte     `cbor:"12,keyasint"`
	PayloadSize    uint64     `cbor:"13,keyasint"`
}

type Scope struct {
	GateID string `cbor:"1,keyasint"`
}

// Action binds an opaque action by type and hash. The bytes are not part of
// the commitment.
type Action struct {
	Type string `cbor:"3,keyasint"`
	Hash []byte `cbor:"4,keyasint"`
}

type PayloadRef struct {
	DA         DA     `cbor:"1,keyasint"`
	Namespace  []byte `cbor:"2,keyasint"`
	Commitment []byte `cbor:"3,keyasint"`
	Height     uint64 `cbor:"4,keyasint"`
	Signer     []byte `cbor:"5,keyasint,omitempty"`
}

type SignedCommitment struct {
	Commitment Commitment `cbor:"1,keyasint"`
	Signature  []byte     `cbor:"2,keyasint"`
}

// GateScope is what the gate knows about itself.
type GateScope struct {
	GateID      string
	ActionTypes []string
}
