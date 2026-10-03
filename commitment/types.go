// Package commitment implements DecisionCommitment v0: the canonical wire
// format, strict decoder, hashing, signing and the stateless checks of the
// gate.
//
// Functions are pure and bounded by the size limits, so they take no
// context.Context.
package commitment

const (
	TagCommitment = "prior/v0/decision-commitment"
	TagSig        = "prior/v0/sig"
	TagReceipt    = "prior/v0/receipt"

	MaxSignedSize     = 2176
	MaxCommitmentSize = 2048
	MaxPayloadSize    = 1 << 27

	QtyScale   = 10_000
	MoneyScale = 100_000_000

	KindIBKROrderV0 = "ibkr.order.v0"
)

type Hash [32]byte

// Enums are uint64 because the decoder accepts any uint and rejects bad
// values at stage S.
type (
	Side      uint64
	OrderType uint64
	TIF       uint64
	Rail      uint64
	DA        uint64
)

const (
	DAFibre        DA = 1
	DACelestiaBlob DA = 2

	RailIBKR Rail = 1

	SideBuy  Side = 1
	SideSell Side = 2

	OrderLimit  OrderType = 1
	OrderMarket OrderType = 2
)

// Required fields carry no omitempty; only optional pointers do.
type Commitment struct {
	Version        uint64      `cbor:"1,keyasint"`
	AgentID        string      `cbor:"2,keyasint"`
	AgentPubKey    []byte      `cbor:"3,keyasint"`
	Nonce          []byte      `cbor:"4,keyasint"`
	IssuedAt       uint64      `cbor:"5,keyasint"`
	ValidUntil     uint64      `cbor:"6,keyasint"`
	Scope          Scope       `cbor:"7,keyasint"`
	Action         Action      `cbor:"8,keyasint"`
	Constraints    Constraints `cbor:"9,keyasint"`
	PayloadRef     PayloadRef  `cbor:"10,keyasint"`
	CiphertextHash []byte      `cbor:"11,keyasint"`
	PlaintextHash  []byte      `cbor:"12,keyasint"`
	PayloadSize    uint64      `cbor:"13,keyasint"`
}

type Scope struct {
	GateID  string  `cbor:"1,keyasint"`
	Rail    Rail    `cbor:"2,keyasint"`
	Account string  `cbor:"3,keyasint"`
	ChainID *string `cbor:"4,keyasint,omitempty"`
}

type Action struct {
	Kind      string       `cbor:"1,keyasint"`
	IBKROrder *IBKROrderV0 `cbor:"2,keyasint"`
}

type IBKROrderV0 struct {
	Account    string    `cbor:"1,keyasint"`
	ConID      uint64    `cbor:"2,keyasint"`
	Symbol     *string   `cbor:"3,keyasint,omitempty"`
	Side       Side      `cbor:"4,keyasint"`
	Qty        uint64    `cbor:"5,keyasint"`
	OrderType  OrderType `cbor:"6,keyasint"`
	LimitPrice *uint64   `cbor:"7,keyasint,omitempty"`
	Currency   string    `cbor:"8,keyasint"`
	TIF        TIF       `cbor:"9,keyasint"`
}

type Constraints struct {
	MaxNotional uint64  `cbor:"1,keyasint"`
	PriceBound  *uint64 `cbor:"2,keyasint,omitempty"`
	Deadline    *uint64 `cbor:"3,keyasint,omitempty"`
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
	GateID  string
	Rail    Rail
	Account string
	ChainID *string
}
