// Package commitment implements DecisionCommitment v1: the canonical
// wire format, strict decoder, hashing, signing and the stateless checks of
// the gate.
//
// Functions are pure and bounded by the size limits, so they take no
// context.Context.
package commitment

const (
	TagCommitment       = "edicta/v1/decision-commitment"
	TagSig              = "edicta/v1/sig"
	TagAction           = "edicta/v1/action"
	TagAuthorization    = "edicta/v1/authorization"
	TagAuthorizationSig = "edicta/v1/authorization-sig"
	TagReceipt          = "edicta/v1/receipt"
	TagReceiptSig       = "edicta/v1/receipt-sig"
	TagRecordRequest    = "edicta/v1/record-request"
	// TagBatchLeaf is reserved for a batch leaf hash and used by nothing yet.
	TagBatchLeaf = "edicta/v1/batch-leaf"

	// Version is the only wire version of the commitment, the Authorization
	// and the receipt.
	Version = 1

	// ActionSaltSize is the length of the agent's action salt.
	ActionSaltSize = 32

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

// AnchorPending is the payload_ref anchor value of a pending reference. An
// absent anchor (zero) means the reference names the anchor block itself.
const AnchorPending = 2

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
	// MandateRef is the mandate hash the agent acts under.
	MandateRef []byte `cbor:"14,keyasint,omitempty"`
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
	// Anchor is 0 (key absent) or AnchorPending.
	Anchor uint64 `cbor:"6,keyasint,omitempty"`

	// anchorZero records a decoded anchor key holding 0, which the struct
	// cannot otherwise tell from an absent key. It re-encodes as present, so
	// the decoder's canonical check holds, and static validation refuses it.
	anchorZero bool
}

type payloadRefWire struct {
	DA         DA      `cbor:"1,keyasint"`
	Namespace  []byte  `cbor:"2,keyasint"`
	Commitment []byte  `cbor:"3,keyasint"`
	Height     uint64  `cbor:"4,keyasint"`
	Signer     []byte  `cbor:"5,keyasint,omitempty"`
	Anchor     *uint64 `cbor:"6,keyasint,omitempty"`
}

// MarshalCBOR writes the anchor key when it holds a value or was decoded as
// a present zero.
func (r PayloadRef) MarshalCBOR() ([]byte, error) {
	if encModeErr != nil {
		return nil, encModeErr
	}
	w := payloadRefWire{DA: r.DA, Namespace: r.Namespace, Commitment: r.Commitment, Height: r.Height, Signer: r.Signer}
	if r.Anchor != 0 || r.anchorZero {
		a := r.Anchor
		w.Anchor = &a
	}
	return encMode.Marshal(w)
}

// Pending reports whether the reference is pending: its height is the
// reference height h0 and the anchor is still expected.
func (r PayloadRef) Pending() bool { return r.Anchor == AnchorPending }

type SignedCommitment struct {
	Commitment Commitment `cbor:"1,keyasint"`
	Signature  []byte     `cbor:"2,keyasint"`
}

// GateScope is what the gate knows about itself.
type GateScope struct {
	GateID      string
	ActionTypes []string
}
