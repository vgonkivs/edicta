package node

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	"github.com/cosmos/cosmos-sdk/client/grpc/cmtservice"
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
	Height   uint64
	DataHash []byte
	Time     time.Time
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
	Download(ctx context.Context, id [33]byte, promiseHeight uint64) ([]byte, error)
}

var _ FibreChainReader = (*ConsensusClient)(nil)

func int64Height(height uint64) (int64, error) {
	if height == 0 || height > math.MaxInt64 {
		return 0, fmt.Errorf("%w: height %d out of range", ErrUnavailable, height)
	}
	return int64(height), nil
}

// blockHeader reads the block at height through the block query and returns
// its header once the header names that height.
func (c *ConsensusClient) blockHeader(ctx context.Context, height uint64) (cmtproto.Header, error) {
	h, err := int64Height(height)
	if err != nil {
		return cmtproto.Header{}, err
	}
	r, err := c.cmt.GetBlockByHeight(ctx, &cmtservice.GetBlockByHeightRequest{Height: h})
	if err != nil {
		return cmtproto.Header{}, classifyGRPC(ctx, err)
	}
	b := r.GetBlock()
	if b == nil {
		return cmtproto.Header{}, fmt.Errorf("%w: no block at height %d", ErrUnavailable, height)
	}
	if b.Header.Height < 0 {
		c.flag.Mark()
		return cmtproto.Header{}, heightIgnored(fmt.Errorf("%w: header at height %d", heightcheck.ErrHeightIgnored, b.Header.Height))
	}
	if err := heightcheck.HeaderHeight(uint64(b.Header.Height), height); err != nil {
		c.flag.Mark()
		return cmtproto.Header{}, heightIgnored(err)
	}
	return b.Header, nil
}

// Header reads the header at height. The block query carries the whole block;
// only the header is used.
func (c *ConsensusClient) Header(ctx context.Context, height uint64) (FibreHeader, error) {
	hdr, err := c.blockHeader(ctx, height)
	if err != nil {
		return FibreHeader{}, err
	}
	if len(hdr.DataHash) == 0 {
		return FibreHeader{}, fmt.Errorf("%w: header at height %d has no data hash", ErrUnavailable, height)
	}
	return FibreHeader{Height: height, DataHash: append([]byte(nil), hdr.DataHash...), Time: hdr.Time}, nil
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
