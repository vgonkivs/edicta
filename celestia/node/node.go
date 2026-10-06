package node

import (
	"context"
	"errors"
	"math/big"
	"time"

	"github.com/vgonkivs/edicta/celestia/heightcheck"
)

// Errors every implementation maps its transport errors onto.
var (
	// ErrNotFound means the node answered and has no such header, blob or tx.
	ErrNotFound = errors.New("node: not found")
	// ErrUnsupported means the node or chain is not one this build can use
	// (failed compatibility check, missing module, wrong API shape).
	ErrUnsupported = errors.New("node: unsupported")
	// ErrUnavailable means the node could not be asked or did not answer in time.
	ErrUnavailable = errors.New("node: unavailable")
	// ErrAlreadyInMempool means the node already holds this exact transaction
	// (mempool or cache); resending the same bytes is idempotent.
	ErrAlreadyInMempool = errors.New("node: tx already in mempool")
	// ErrSequenceMismatch means the node refused a transaction because the
	// signer's account sequence differs from the one signed.
	ErrSequenceMismatch = errors.New("node: account sequence mismatch")
	// ErrRejected means the node checked a broadcast transaction and refused
	// it for a reason other than the two above; resending will not help.
	ErrRejected = errors.New("node: tx rejected")
	// ErrMempoolFull means the node's mempool had no room; the same bytes
	// may be accepted later.
	ErrMempoolFull = errors.New("node: mempool full")
	// ErrTxIndexDisabled means the node does not index transactions, or does
	// not say that it does, so a transaction lookup cannot be trusted.
	ErrTxIndexDisabled = errors.New("node: transaction index disabled")
)

// Header is the part of a block header Edicta reads.
type Header struct {
	ChainID    string
	Height     uint64
	Time       time.Time
	AppVersion uint64
	DataRoot   []byte
}

// Blob is a blob as the node returns it.
type Blob struct {
	Namespace    []byte
	Data         []byte
	ShareVersion uint8
	// Signer is the share v1 signer address, 20 bytes; empty for share v0.
	Signer     []byte
	Commitment []byte
}

// CommitmentProof proves a blob commitment against a data root.
type CommitmentProof interface {
	Verify(dataRoot, commitment []byte) error
}

// Reader reads from a bridge node. Missing items are ErrNotFound.
type Reader interface {
	Head(ctx context.Context) (Header, error)
	HeaderAt(ctx context.Context, height uint64) (Header, error)
	Blob(ctx context.Context, height uint64, namespace, commitment []byte) (Blob, error)
	CommitmentProof(ctx context.Context, height uint64, namespace, commitment []byte) (CommitmentProof, error)
}

// Submitter submits blobs with the node's local key.
type Submitter interface {
	// Address is the 20-byte address of the signing key.
	Address(ctx context.Context) ([]byte, error)
	// SubmitBlob submits one share v1 blob signed by Address and returns the
	// inclusion height. It returns nothing else: the caller must verify.
	SubmitBlob(ctx context.Context, namespace, data []byte) (height uint64, err error)
}

// AccountInfo is an account's signing state.
type AccountInfo struct {
	Number   uint64
	Sequence uint64
}

// FibreParams are the x/fibre module params Edicta reads.
type FibreParams struct {
	// RetentionS is the Fibre blob retention in seconds.
	RetentionS uint64
}

// TxStatus is the on-chain state of a broadcast transaction.
type TxStatus struct {
	Found  bool
	Height uint64
	Code   uint32
	// NodeHeight is the height of the answering node, read before the lookup;
	// zero when it could not be read.
	NodeHeight uint64
}

// Consensus reads consensus-node state and broadcasts raw transactions.
type Consensus interface {
	// Network is the chain id the consensus gRPC node reports.
	Network(ctx context.Context) (string, error)
	// ProviderChainIDs are the chain ids reported by each configured
	// consensus RPC provider, in configuration order.
	ProviderChainIDs(ctx context.Context) ([]string, error)
	// FibreParams returns ErrNotFound when the chain has no x/fibre module.
	FibreParams(ctx context.Context) (FibreParams, error)
	// FibreParamsAt reads the params pinned to height and fails unless the
	// response echoes that height; the failure is ErrUnavailable and
	// heightcheck.ErrHeightIgnored.
	FibreParamsAt(ctx context.Context, height uint64) (FibreParams, error)
	// HeightCanary asks for state at heights that cannot hold it.
	HeightCanary(ctx context.Context) (heightcheck.Status, error)
	BondDenom(ctx context.Context) (string, error)
	Bech32Prefix(ctx context.Context) (string, error)
	Account(ctx context.Context, address string) (AccountInfo, error)
	// Broadcast sends txRaw unchanged and returns its hash.
	Broadcast(ctx context.Context, txRaw []byte) ([32]byte, error)
	Tx(ctx context.Context, hash [32]byte) (TxStatus, error)
	// TxAt is Tx for a transaction expected at height; a found transaction at
	// another height is refused like an ignored height. An unknown hash is
	// Found false.
	TxAt(ctx context.Context, hash [32]byte, height uint64) (TxStatus, error)
	// LatestHeight is the latest block height of the answering node.
	LatestHeight(ctx context.Context) (uint64, error)
	// TxIndex returns nil only when the node reports that it indexes
	// transactions; otherwise ErrTxIndexDisabled, also when it cannot be read.
	TxIndex(ctx context.Context) error
	// MinGasPrice is the node's minimum_gas_price in bond denom per gas unit.
	MinGasPrice(ctx context.Context) (*big.Rat, error)
}
