package node

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"strings"
	"sync"
	"time"

	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	coregrpc "github.com/cometbft/cometbft/rpc/grpc"
	core "github.com/cometbft/cometbft/types"
	txtypes "github.com/cosmos/cosmos-sdk/types/tx"
	stakingtypes "github.com/cosmos/cosmos-sdk/x/staking/types"

	"github.com/celestiaorg/celestia-app/v10/pkg/da"
	"github.com/celestiaorg/celestia-node/share/shwap"
	libshare "github.com/celestiaorg/go-square/v4/share"

	"github.com/vgonkivs/edicta/celestia/heightcheck"
)

// ErrInvalidConfig means a config struct failed its stateless checks.
var ErrInvalidConfig = errors.New("node: invalid config")

// FibreHeader is the part of the consensus header at a height that the anchor
// lookup uses.
type FibreHeader struct {
	Height     uint64
	DataHash   []byte
	Time       time.Time
	AppVersion uint64
}

// FibreChainReader reads the consensus-endpoint evidence of a Fibre anchor.
// Block reads name their own height and the implementation refuses one for
// another height. A missing item is ErrNotFound.
type FibreChainReader interface {
	// Header is the header at height.
	Header(ctx context.Context, height uint64) (FibreHeader, error)
	// TxCode is the execution result code of the tx the node says is at height.
	TxCode(ctx context.Context, height uint64, txHash [32]byte) (uint32, error)
	// HistoricalInfo is the raw staking HistoricalInfo recorded at height.
	HistoricalInfo(ctx context.Context, height uint64) ([]byte, error)
	// SignedHeader is the raw CometBFT header at height.
	SignedHeader(ctx context.Context, height uint64) ([]byte, error)
}

// FibreBridgeReader reads the untrusted bridge answers of a Fibre anchor. The
// caller verifies both against the header at height.
type FibreBridgeReader interface {
	// DAH is the data availability header of the bridge's header at height.
	DAH(ctx context.Context, height uint64) (*da.DataAvailabilityHeader, error)
	// NamespaceData is share.GetNamespaceData(height, namespace).
	NamespaceData(ctx context.Context, height uint64, namespace libshare.Namespace) (shwap.NamespaceData, error)
}

// FibreAnchorReader is the chain and the bridge side of the anchor lookup.
type FibreAnchorReader interface {
	FibreChainReader
	FibreBridgeReader
}

type fibreReader struct {
	FibreChainReader
	FibreBridgeReader
}

// NewFibreAnchorReader joins a consensus reader and a bridge reader. A missing
// bridge is a configuration error: the anchor proof needs one.
func NewFibreAnchorReader(chain FibreChainReader, bridge FibreBridgeReader) (FibreAnchorReader, error) {
	if chain == nil {
		return nil, fmt.Errorf("%w: no consensus reader", ErrInvalidConfig)
	}
	if bridge == nil {
		return nil, fmt.Errorf("%w: no bridge reader", ErrInvalidConfig)
	}
	return fibreReader{chain, bridge}, nil
}

// FibreDownloader downloads a Fibre blob by its 33-byte blob id. A missing
// blob is ErrNotFound.
type FibreDownloader interface {
	// Download returns the blob, or an error wrapping ErrTooLarge when it
	// holds more than maxSize bytes. Implementations bound what they read
	// from the source by maxSize.
	Download(ctx context.Context, id [33]byte, promiseHeight uint64, maxSize uint64) ([]byte, error)
}

// ErrTooLarge means a blob is larger than the size the caller allowed.
var ErrTooLarge = errors.New("node: blob above the size limit")

var _ FibreChainReader = (*ConsensusClient)(nil)

func int64Height(height uint64) (int64, error) {
	if height == 0 || height > math.MaxInt64 {
		return 0, fmt.Errorf("%w: height %d out of range", ErrUnavailable, height)
	}
	return int64(height), nil
}

// headerCacheEntries is how many verified headers are kept.
const headerCacheEntries = 128

type headerCache struct {
	mu    sync.Mutex
	m     map[uint64]cmtproto.Header
	order []uint64
}

func (c *headerCache) get(height uint64) (cmtproto.Header, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	h, ok := c.m[height]
	return h, ok
}

func (c *headerCache) put(height uint64, h cmtproto.Header) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m == nil {
		c.m = map[uint64]cmtproto.Header{}
	}
	if _, ok := c.m[height]; !ok {
		for len(c.order) >= headerCacheEntries {
			delete(c.m, c.order[0])
			c.order = c.order[1:]
		}
		c.order = append(c.order, height)
	}
	c.m[height] = h
}

// blockHeader returns the header at height, read once and then kept: a header
// of a Celestia block is final. Only the first message of the block stream is
// read, so the cost does not grow with the size of the block.
func (c *ConsensusClient) blockHeader(ctx context.Context, height uint64) (cmtproto.Header, error) {
	h, err := int64Height(height)
	if err != nil {
		return cmtproto.Header{}, err
	}
	if hdr, ok := c.hdrs.get(height); ok {
		return hdr, nil
	}
	hdr, err := c.streamHeader(ctx, height, h)
	if err != nil {
		return cmtproto.Header{}, err
	}
	c.hdrs.put(height, hdr)
	return hdr, nil
}

// streamHeader reads the first message of the block stream: the first block
// part, which starts with the header, and the commit. The header must name
// height and hash to the block id of that commit, and the part must prove into
// the part set hash of the same block id. The commit signatures are not
// checked: the node is trusted for the header.
func (c *ConsensusClient) streamHeader(ctx context.Context, height uint64, h int64) (cmtproto.Header, error) {
	sctx, cancel := context.WithCancel(ctx)
	defer cancel()
	st, err := c.blocks.BlockByHeight(sctx, &coregrpc.BlockByHeightRequest{Height: h, Prove: true})
	if err != nil {
		return cmtproto.Header{}, classifyGRPC(ctx, err)
	}
	m, err := st.Recv()
	if err != nil {
		return cmtproto.Header{}, classifyGRPC(ctx, err)
	}
	part, err := core.PartFromProto(m.GetBlockPart())
	if err != nil {
		return cmtproto.Header{}, fmt.Errorf("%w: block part at height %d: %w", ErrUnavailable, height, err)
	}
	if part.Index != 0 {
		return cmtproto.Header{}, fmt.Errorf("%w: first block part at height %d has index %d", ErrUnavailable, height, part.Index)
	}
	hdr, err := headerFromPart(part.Bytes)
	if err != nil {
		return cmtproto.Header{}, fmt.Errorf("%w: block at height %d: %w", ErrUnavailable, height, err)
	}
	if hdr.Height < 0 {
		c.flag.Mark()
		return cmtproto.Header{}, heightIgnored(fmt.Errorf("%w: header at height %d", heightcheck.ErrHeightIgnored, hdr.Height))
	}
	if err := heightcheck.HeaderHeight(uint64(hdr.Height), height); err != nil {
		c.flag.Mark()
		return cmtproto.Header{}, heightIgnored(err)
	}
	if err := verifyHeaderBlockID(hdr, part, m.GetCommit()); err != nil {
		return cmtproto.Header{}, fmt.Errorf("%w: block at height %d: %w", ErrUnavailable, height, err)
	}
	return hdr, nil
}

func verifyHeaderBlockID(hdr cmtproto.Header, part *core.Part, commit *cmtproto.Commit) error {
	if commit == nil {
		return errors.New("no commit")
	}
	if commit.Height != hdr.Height {
		return fmt.Errorf("commit at height %d, header at %d", commit.Height, hdr.Height)
	}
	bid, err := core.BlockIDFromProto(&commit.BlockID)
	if err != nil {
		return fmt.Errorf("block id: %w", err)
	}
	ch, err := core.HeaderFromProto(&hdr)
	if err != nil {
		return fmt.Errorf("header: %w", err)
	}
	if got := ch.Hash(); len(got) == 0 || !bytes.Equal(got, bid.Hash) {
		return errors.New("header does not hash to the block id")
	}
	if err := part.Proof.Verify(bid.PartSetHeader.Hash, part.Bytes); err != nil {
		return fmt.Errorf("block part proof: %w", err)
	}
	return nil
}

// headerFromPart decodes the header at the start of a serialized block, where
// it is field 1.
func headerFromPart(b []byte) (cmtproto.Header, error) {
	var hdr cmtproto.Header
	if len(b) == 0 || b[0] != 0x0a {
		return hdr, errors.New("first part does not start with a header")
	}
	n, k := binary.Uvarint(b[1:])
	if k <= 0 || n > uint64(len(b)-1-k) {
		return hdr, errors.New("header is not inside the first part")
	}
	if err := hdr.Unmarshal(b[1+k : 1+k+int(n)]); err != nil {
		return hdr, fmt.Errorf("header: %w", err)
	}
	return hdr, nil
}

// Header reads the header at height.
func (c *ConsensusClient) Header(ctx context.Context, height uint64) (FibreHeader, error) {
	hdr, err := c.blockHeader(ctx, height)
	if err != nil {
		return FibreHeader{}, err
	}
	if len(hdr.DataHash) == 0 {
		return FibreHeader{}, fmt.Errorf("%w: header at height %d has no data hash", ErrUnavailable, height)
	}
	return FibreHeader{
		Height: height, DataHash: append([]byte(nil), hdr.DataHash...), Time: hdr.Time, AppVersion: hdr.Version.App,
	}, nil
}

// SignedHeader reads the raw header at height.
func (c *ConsensusClient) SignedHeader(ctx context.Context, height uint64) ([]byte, error) {
	hdr, err := c.blockHeader(ctx, height)
	if err != nil {
		return nil, err
	}
	raw, err := hdr.Marshal()
	if err != nil {
		return nil, fmt.Errorf("%w: header: %w", ErrUnavailable, err)
	}
	return raw, nil
}

// TxCode reads the result code of a tx the node says is at height. GetTx is a
// read by hash, not at a height: an answer for another height or hash fails
// this read and does not mark the endpoint as ignoring heights.
func (c *ConsensusClient) TxCode(ctx context.Context, height uint64, hash [32]byte) (uint32, error) {
	want := strings.ToUpper(hex.EncodeToString(hash[:]))
	r, err := c.tx.GetTx(ctx, &txtypes.GetTxRequest{Hash: want})
	if err != nil {
		return 0, classifyGRPC(ctx, err)
	}
	tr := r.GetTxResponse()
	if tr == nil {
		return 0, fmt.Errorf("%w: tx result", ErrNotFound)
	}
	if tr.Height < 0 || uint64(tr.Height) != height {
		return 0, fmt.Errorf("%w: tx result at height %d, want %d", ErrUnavailable, tr.Height, height)
	}
	if !strings.EqualFold(tr.TxHash, want) {
		return 0, fmt.Errorf("%w: tx result for hash %q, want %s", ErrUnavailable, tr.TxHash, want)
	}
	return tr.Code, nil
}

// HistoricalInfo reads the staking HistoricalInfo at height.
func (c *ConsensusClient) HistoricalInfo(ctx context.Context, height uint64) ([]byte, error) {
	h, err := int64Height(height)
	if err != nil {
		return nil, err
	}
	r, err := c.staking.HistoricalInfo(ctx, &stakingtypes.QueryHistoricalInfoRequest{Height: h})
	if err != nil {
		return nil, classifyGRPC(ctx, err)
	}
	if r.Hist == nil {
		return nil, fmt.Errorf("%w: no historical info at height %d", ErrNotFound, height)
	}
	if r.Hist.Header.Height < 0 {
		c.flag.Mark()
		return nil, heightIgnored(fmt.Errorf("%w: historical info at height %d", heightcheck.ErrHeightIgnored, r.Hist.Header.Height))
	}
	if err := heightcheck.HeaderHeight(uint64(r.Hist.Header.Height), height); err != nil {
		c.flag.Mark()
		return nil, heightIgnored(err)
	}
	b, err := r.Hist.Marshal()
	if err != nil {
		return nil, fmt.Errorf("%w: historical info: %w", ErrUnavailable, err)
	}
	return b, nil
}
