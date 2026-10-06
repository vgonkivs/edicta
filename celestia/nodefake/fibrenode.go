package nodefake

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"sync"
	"time"

	"github.com/celestiaorg/celestia-app/v10/pkg/da"
	"github.com/celestiaorg/celestia-node/share/shwap"
	libshare "github.com/celestiaorg/go-square/v4/share"
	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	cmttypes "github.com/cometbft/cometbft/types"

	"github.com/vgonkivs/edicta/celestia/node"
	"github.com/vgonkivs/edicta/celestia/test/fibrefix"
)

var _ node.FibreAnchorReader = (*FibreNode)(nil)

// LandedPFF is a PayForFibre tx that a FibreNode puts into a block.
type LandedPFF struct {
	// Header is the bare header of the block; its height is where the tx lands.
	Header cmtproto.Header
	// Block is the data behind the header: it must hold Tx in the PayForFibre
	// namespace and hash to Header.DataHash.
	Block fibrefix.Block
	Tx    []byte
	Code  uint32
	Index uint32
}

type fibreBlock struct {
	hdr   node.FibreHeader
	block fibrefix.Block
}

// FibreNode fakes the own node of a da = 1 Recorder: the consensus reads of an
// anchor lookup, the bridge reads, and the head, tx placement, validator set
// and x/fibre params the Recorder adds. Heights up to the head are served as
// empty blocks unless a block was put there; heights above the head do not
// exist. It has no clock of its own: block times come from timeAt.
type FibreNode struct {
	mu     sync.Mutex
	addr   string
	timeAt func(uint64) time.Time
	empty  fibrefix.Block

	head   uint64
	pruned uint64
	blocks map[uint64]fibreBlock
	signed map[uint64][]byte
	hist   map[uint64][]byte
	vals   map[uint64][]byte
	codes  map[codeKey]uint32
	places map[[32]byte]node.TxPlacement
	params node.FibreParams

	// Fail, when set, is returned by every consensus method.
	Fail error
	// FailBridge, when set, is returned by DAH and NamespaceData.
	FailBridge error
	// FailLatest, when set, is returned by LatestHeight only.
	FailLatest error
}

// NewFibreNode makes a node that reports addr as its consensus endpoint, dates
// block h at timeAt(h) and serves empty (a block without PayForFibre txs) at
// every height without a block of its own.
func NewFibreNode(addr string, timeAt func(uint64) time.Time, empty fibrefix.Block) *FibreNode {
	return &FibreNode{
		addr: addr, timeAt: timeAt, empty: empty,
		blocks: map[uint64]fibreBlock{}, signed: map[uint64][]byte{}, hist: map[uint64][]byte{},
		vals: map[uint64][]byte{}, codes: map[codeKey]uint32{}, places: map[[32]byte]node.TxPlacement{},
		params: node.FibreParams{RetentionS: 14400, PromiseHeightWindow: 1000},
	}
}

// TimeAt is the time of block h.
func (n *FibreNode) TimeAt(h uint64) time.Time { return n.timeAt(h) }

// Addr is the consensus endpoint the node says it is.
func (n *FibreNode) Addr() string { return n.addr }

// SetHead sets the latest height, up or down.
func (n *FibreNode) SetHead(h uint64) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.head = h
}

// Head is the latest height.
func (n *FibreNode) Head() uint64 {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.head
}

// Prune makes every block below h unavailable, as a node that dropped old state.
func (n *FibreNode) Prune(h uint64) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.pruned = h
}

// PutBlock stores the block at hdr.Height with a signed header whose commit is
// bound to hdr.
func (n *FibreNode) PutBlock(hdr cmtproto.Header, b fibrefix.Block) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.putLocked(hdr, b)
}

func (n *FibreNode) putLocked(hdr cmtproto.Header, b fibrefix.Block) {
	h := uint64(hdr.Height)
	n.blocks[h] = fibreBlock{
		hdr:   node.FibreHeader{Height: h, DataHash: bytes.Clone(hdr.DataHash), Time: hdr.Time, AppVersion: hdr.Version.App},
		block: b.Clone(),
	}
	n.signed[h] = boundSigned(hdr)
}

func boundSigned(hdr cmtproto.Header) []byte {
	ch, err := cmttypes.HeaderFromProto(&hdr)
	if err != nil {
		return nil
	}
	raw, err := (&cmtproto.SignedHeader{
		Header: &hdr,
		Commit: &cmtproto.Commit{Height: hdr.Height, BlockID: cmtproto.BlockID{Hash: ch.Hash()}},
	}).Marshal()
	if err != nil {
		return nil
	}
	return raw
}

// Land puts the block, the tx result and the tx placement in one step and
// moves the head up to the landing height.
func (n *FibreNode) Land(l LandedPFF) {
	n.mu.Lock()
	defer n.mu.Unlock()
	h := uint64(l.Header.Height)
	n.putLocked(l.Header, l.Block)
	hash := sha256.Sum256(l.Tx)
	n.codes[codeKey{h, hash}] = l.Code
	n.places[hash] = node.TxPlacement{Height: h, Index: l.Index, Code: l.Code, Status: "COMMITTED"}
	if h > n.head {
		n.head = h
	}
}

// SetSignedHeader replaces the SignedHeader served at height.
func (n *FibreNode) SetSignedHeader(height uint64, raw []byte) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.signed[height] = bytes.Clone(raw)
}

// SetHistoricalInfo stores the raw HistoricalInfo at height.
func (n *FibreNode) SetHistoricalInfo(height uint64, raw []byte) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.hist[height] = bytes.Clone(raw)
}

// SetValidatorSet stores the protobuf validator set at height.
func (n *FibreNode) SetValidatorSet(height uint64, raw []byte) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.vals[height] = bytes.Clone(raw)
}

// SetTxPlace scripts where the node says a tx is.
func (n *FibreNode) SetTxPlace(hash [32]byte, p node.TxPlacement) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.places[hash] = p
}

// SetFibreParams sets the x/fibre params.
func (n *FibreNode) SetFibreParams(p node.FibreParams) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.params = p
}

func (n *FibreNode) block(h uint64) (fibreBlock, bool) {
	if h == 0 || h > n.head || h < n.pruned {
		return fibreBlock{}, false
	}
	if b, ok := n.blocks[h]; ok {
		return b, true
	}
	return fibreBlock{
		hdr:   node.FibreHeader{Height: h, DataHash: bytes.Clone(n.empty.DataHash), Time: n.timeAt(h), AppVersion: node.FibreAppVersion},
		block: n.empty,
	}, true
}

func (n *FibreNode) LatestHeight(context.Context) (uint64, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.Fail != nil {
		return 0, n.Fail
	}
	if n.FailLatest != nil {
		return 0, n.FailLatest
	}
	return n.head, nil
}

func (n *FibreNode) Header(_ context.Context, height uint64) (node.FibreHeader, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.Fail != nil {
		return node.FibreHeader{}, n.Fail
	}
	b, ok := n.block(height)
	if !ok {
		return node.FibreHeader{}, fmt.Errorf("%w: header %d", node.ErrNotFound, height)
	}
	h := b.hdr
	h.DataHash = bytes.Clone(h.DataHash)
	return h, nil
}

func (n *FibreNode) DAH(_ context.Context, height uint64) (*da.DataAvailabilityHeader, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.FailBridge != nil {
		return nil, n.FailBridge
	}
	b, ok := n.block(height)
	if !ok {
		return nil, fmt.Errorf("%w: dah %d", node.ErrNotFound, height)
	}
	return &da.DataAvailabilityHeader{RowRoots: cloneByteSlices(b.block.Rows), ColumnRoots: cloneByteSlices(b.block.Cols)}, nil
}

func (n *FibreNode) NamespaceData(_ context.Context, height uint64, ns libshare.Namespace) (shwap.NamespaceData, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if !ns.Equals(libshare.PayForFibreNamespace) {
		return nil, fmt.Errorf("%w: namespace %x", node.ErrNotFound, ns.Bytes())
	}
	if n.FailBridge != nil {
		return nil, n.FailBridge
	}
	b, ok := n.block(height)
	if !ok {
		return nil, fmt.Errorf("%w: namespace data %d", node.ErrNotFound, height)
	}
	return b.block.ND, nil
}

func (n *FibreNode) TxCode(_ context.Context, height uint64, hash [32]byte) (uint32, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.Fail != nil {
		return 0, n.Fail
	}
	return n.codes[codeKey{height, hash}], nil
}

func (n *FibreNode) HistoricalInfo(_ context.Context, height uint64) ([]byte, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.Fail != nil {
		return nil, n.Fail
	}
	b, ok := n.hist[height]
	if !ok {
		return nil, fmt.Errorf("%w: historical info %d", node.ErrNotFound, height)
	}
	return bytes.Clone(b), nil
}

func (n *FibreNode) SignedHeader(_ context.Context, height uint64) ([]byte, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.Fail != nil {
		return nil, n.Fail
	}
	b, ok := n.signed[height]
	if !ok || height < n.pruned {
		return nil, fmt.Errorf("%w: signed header %d", node.ErrNotFound, height)
	}
	return bytes.Clone(b), nil
}

func (n *FibreNode) TxPlace(_ context.Context, hash [32]byte) (node.TxPlacement, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.Fail != nil {
		return node.TxPlacement{}, n.Fail
	}
	p, ok := n.places[hash]
	if !ok {
		return node.TxPlacement{}, fmt.Errorf("%w: tx %x", node.ErrNotFound, hash)
	}
	return p, nil
}

func (n *FibreNode) ValidatorSet(_ context.Context, height uint64) ([]byte, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.Fail != nil {
		return nil, n.Fail
	}
	b, ok := n.vals[height]
	if !ok {
		return nil, fmt.Errorf("%w: validator set %d", node.ErrNotFound, height)
	}
	return bytes.Clone(b), nil
}

func (n *FibreNode) FibreParams(context.Context) (node.FibreParams, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.Fail != nil {
		return node.FibreParams{}, n.Fail
	}
	return n.params, nil
}
