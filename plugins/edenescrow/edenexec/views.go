// SPDX-License-Identifier: Apache-2.0

package edenexec

// Integer fields that go into an RLP encoding are kept as minimal big-endian
// bytes, zero as empty, exactly as the JSON-RPC quantity named them: the
// rebuild never converts them, so it cannot round them either.

// TxView is a transaction as eth_getTransactionByHash or a full block serves
// it.
type TxView struct {
	// Type is the EIP-2718 type. For a type RebuildSigned does not know, only
	// Type, Hash and the block fields are set.
	Type uint8
	Hash [32]byte

	ChainID          []byte
	Nonce            []byte
	GasPrice         []byte // types 0 and 1
	MaxPriorityFee   []byte // types 2, 3, 4
	MaxFee           []byte // types 2, 3, 4
	Gas              []byte
	To               *[20]byte // nil: contract creation
	Value            []byte
	Input            []byte
	AccessList       []AccessTuple
	MaxFeePerBlobGas []byte     // type 3
	BlobHashes       [][32]byte // type 3
	AuthList         []AuthTuple
	// V is the signature's first item as it is encoded: v for type 0, the
	// y parity for the typed transactions.
	V, R, S []byte

	// Block fields; Included is false for a pending transaction.
	Included    bool
	BlockHash   [32]byte
	BlockNumber uint64
	Index       uint64
}

// AccessTuple is one EIP-2930 access list entry.
type AccessTuple struct {
	Address     [20]byte
	StorageKeys [][32]byte
}

// AuthTuple is one EIP-7702 authorization.
type AuthTuple struct {
	ChainID []byte
	Address [20]byte
	Nonce   []byte
	YParity []byte
	R, S    []byte
}

// ReceiptView is a receipt as eth_getTransactionReceipt serves it.
type ReceiptView struct {
	Type              uint8
	Status            uint64 // 0 or 1
	CumulativeGasUsed []byte
	Bloom             [256]byte
	Logs              []LogView
	TxHash            [32]byte
	BlockHash         [32]byte
	BlockNumber       uint64
	Index             uint64
}

// LogView is one log of a receipt.
type LogView struct {
	Address   [20]byte
	Topics    [][32]byte
	Data      []byte
	BlockHash [32]byte
	TxHash    [32]byte
	Index     uint64 // transactionIndex
	Removed   bool
}

// HeaderView is a block header as eth_getBlockByHash serves it.
type HeaderView struct {
	Hash        [32]byte // as served; never trusted, VerifyBlock recomputes it
	ParentHash  [32]byte
	UncleHash   [32]byte
	Coinbase    [20]byte
	Root        [32]byte
	TxRoot      [32]byte
	ReceiptRoot [32]byte
	Bloom       [256]byte
	Difficulty  []byte
	Number      uint64
	GasLimit    uint64
	GasUsed     uint64
	Time        uint64
	Extra       []byte
	MixDigest   [32]byte
	Nonce       [8]byte
	// Fields added by later forks, in fork order; nil when not served.
	BaseFee          []byte
	HasBaseFee       bool
	WithdrawalsHash  *[32]byte
	BlobGasUsed      *uint64
	ExcessBlobGas    *uint64
	ParentBeaconRoot *[32]byte
	RequestsHash     *[32]byte
	// Unknown lists served keys that are neither header fields nor known
	// block fields. A header with one is never claimed proven.
	Unknown []string
}
