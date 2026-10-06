package nodefake

import (
	"bytes"
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/celestiaorg/celestia-app/v10/pkg/da"
	"github.com/celestiaorg/celestia-node/share/shwap"
	libshare "github.com/celestiaorg/go-square/v4/share"

	"github.com/vgonkivs/edicta/celestia/node"
)

var (
	_ node.FibreAnchorReader = (*FibreChain)(nil)
	_ node.FibreDownloader   = (*Downloader)(nil)
)

type codeKey struct {
	h    uint64
	hash [32]byte
}

// FibreChain fakes the consensus and bridge reads of a Fibre anchor lookup.
type FibreChain struct {
	mu       sync.Mutex
	headers  map[uint64]node.FibreHeader
	dahs     map[uint64]*da.DataAvailabilityHeader
	nsData   map[uint64]shwap.NamespaceData
	codes    map[codeKey]uint32
	hist     map[uint64][]byte
	signed   map[uint64][]byte
	answerAs uint64
	reads    int
	nsReads  int
	dahReads int
	// Fail, when set, is returned by every consensus method.
	Fail error
	// FailBridge, when set, is returned by DAH and NamespaceData.
	FailBridge error
}

// NewFibreChain makes an empty chain.
func NewFibreChain() *FibreChain {
	return &FibreChain{
		headers: map[uint64]node.FibreHeader{}, dahs: map[uint64]*da.DataAvailabilityHeader{},
		nsData: map[uint64]shwap.NamespaceData{}, codes: map[codeKey]uint32{},
		hist: map[uint64][]byte{}, signed: map[uint64][]byte{},
	}
}

// AddHeader stores the header at height.
func (c *FibreChain) AddHeader(height uint64, dataHash []byte, t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.headers[height] = node.FibreHeader{Height: height, DataHash: bytes.Clone(dataHash), Time: t, AppVersion: node.FibreAppVersion}
}

// SetAppVersion changes the app version of the stored header at height.
func (c *FibreChain) SetAppVersion(height uint64, v uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	h := c.headers[height]
	h.AppVersion = v
	c.headers[height] = h
}

// SetDAH stores the data availability header the bridge serves at height.
func (c *FibreChain) SetDAH(height uint64, rows, cols [][]byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.dahs[height] = &da.DataAvailabilityHeader{RowRoots: cloneByteSlices(rows), ColumnRoots: cloneByteSlices(cols)}
}

// SetNamespaceData stores the namespace data the bridge serves at height.
func (c *FibreChain) SetNamespaceData(height uint64, nd shwap.NamespaceData) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.nsData[height] = nd
}

// SetTxCode scripts the result code of a tx; others have code 0.
func (c *FibreChain) SetTxCode(height uint64, hash [32]byte, code uint32) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.codes[codeKey{height, hash}] = code
}

// SetHistoricalInfo stores the raw HistoricalInfo at height.
func (c *FibreChain) SetHistoricalInfo(height uint64, raw []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.hist[height] = bytes.Clone(raw)
}

// SetSignedHeader stores the protobuf SignedHeader at height.
func (c *FibreChain) SetSignedHeader(height uint64, raw []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.signed[height] = bytes.Clone(raw)
}

// IgnoreHeights makes Header answer every request with the header stored at
// height, like an endpoint that drops the requested height.
func (c *FibreChain) IgnoreHeights(height uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.answerAs = height
}

// HeaderReads counts Header calls.
func (c *FibreChain) HeaderReads() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.reads
}

// BridgeReads counts DAH and NamespaceData calls.
func (c *FibreChain) BridgeReads() (dah, namespaceData int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.dahReads, c.nsReads
}

func cloneByteSlices(txs [][]byte) [][]byte {
	out := make([][]byte, len(txs))
	for i, t := range txs {
		out[i] = bytes.Clone(t)
	}
	return out
}

func (c *FibreChain) Header(_ context.Context, height uint64) (node.FibreHeader, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reads++
	if c.Fail != nil {
		return node.FibreHeader{}, c.Fail
	}
	if c.answerAs != 0 {
		height = c.answerAs
	}
	h, ok := c.headers[height]
	if !ok {
		return node.FibreHeader{}, fmt.Errorf("%w: header %d", node.ErrNotFound, height)
	}
	return node.FibreHeader{Height: h.Height, DataHash: bytes.Clone(h.DataHash), Time: h.Time, AppVersion: h.AppVersion}, nil
}

func (c *FibreChain) DAH(_ context.Context, height uint64) (*da.DataAvailabilityHeader, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.dahReads++
	if c.FailBridge != nil {
		return nil, c.FailBridge
	}
	d, ok := c.dahs[height]
	if !ok {
		return nil, fmt.Errorf("%w: dah %d", node.ErrNotFound, height)
	}
	return &da.DataAvailabilityHeader{RowRoots: cloneByteSlices(d.RowRoots), ColumnRoots: cloneByteSlices(d.ColumnRoots)}, nil
}

func (c *FibreChain) NamespaceData(_ context.Context, height uint64, ns libshare.Namespace) (shwap.NamespaceData, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.nsReads++
	if !ns.Equals(libshare.PayForFibreNamespace) {
		return nil, fmt.Errorf("%w: namespace %x", node.ErrNotFound, ns.Bytes())
	}
	if c.FailBridge != nil {
		return nil, c.FailBridge
	}
	nd, ok := c.nsData[height]
	if !ok {
		return nil, fmt.Errorf("%w: namespace data %d", node.ErrNotFound, height)
	}
	return nd, nil
}

func (c *FibreChain) TxCode(_ context.Context, height uint64, hash [32]byte) (uint32, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.Fail != nil {
		return 0, c.Fail
	}
	return c.codes[codeKey{height, hash}], nil
}

func (c *FibreChain) HistoricalInfo(_ context.Context, height uint64) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.Fail != nil {
		return nil, c.Fail
	}
	b, ok := c.hist[height]
	if !ok {
		return nil, fmt.Errorf("%w: historical info %d", node.ErrNotFound, height)
	}
	return bytes.Clone(b), nil
}

func (c *FibreChain) SignedHeader(_ context.Context, height uint64) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.Fail != nil {
		return nil, c.Fail
	}
	b, ok := c.signed[height]
	if !ok {
		return nil, fmt.Errorf("%w: header %d", node.ErrNotFound, height)
	}
	return bytes.Clone(b), nil
}

// Downloader fakes a Fibre blob download by blob id.
type Downloader struct {
	mu    sync.Mutex
	blobs map[[33]byte][]byte
	calls int
	// Fail, when set, is returned by Download.
	Fail error
}

// NewDownloader makes an empty downloader.
func NewDownloader() *Downloader { return &Downloader{blobs: map[[33]byte][]byte{}} }

// Put stores a blob under id; the data is copied.
func (d *Downloader) Put(id [33]byte, data []byte) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.blobs[id] = bytes.Clone(data)
}

// Calls counts Download calls, failed ones included.
func (d *Downloader) Calls() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.calls
}

func (d *Downloader) Download(ctx context.Context, id [33]byte, _, maxSize uint64) ([]byte, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.calls++
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if d.Fail != nil {
		return nil, d.Fail
	}
	b, ok := d.blobs[id]
	if !ok {
		return nil, node.ErrNotFound
	}
	if uint64(len(b)) > maxSize {
		return nil, fmt.Errorf("%w: blob of %d bytes, limit %d", node.ErrTooLarge, len(b), maxSize)
	}
	return bytes.Clone(b), nil
}
