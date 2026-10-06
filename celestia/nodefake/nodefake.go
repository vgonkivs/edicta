package nodefake

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
	"sync"

	"github.com/vgonkivs/edicta/celestia/heightcheck"
	"github.com/vgonkivs/edicta/celestia/node"
)

var (
	_ node.Reader    = (*Chain)(nil)
	_ node.Submitter = (*Chain)(nil)
	_ node.Consensus = (*Consensus)(nil)
)

// ErrInjected is the default failure of the Fail fields.
var ErrInjected = errors.New("nodefake: injected failure")

type blobKey struct {
	h  uint64
	ns string
	c  string
}

// Chain fakes a bridge node and a local submitting key.
type Chain struct {
	mu      sync.Mutex
	headers map[uint64]node.Header
	head    uint64
	blobs   map[blobKey]node.Blob
	proofs  map[blobKey]node.CommitmentProof
	addr    []byte
	// Fail, when set, is returned by every method.
	Fail error
	// SubmitHeight, when set, replaces the height SubmitBlob reports (a lying
	// submitter).
	SubmitHeight uint64
	// Submitted counts SubmitBlob calls.
	Submitted int
}

// NewChain makes an empty chain whose submitting key has address addr.
func NewChain(addr []byte) *Chain {
	return &Chain{
		headers: map[uint64]node.Header{}, blobs: map[blobKey]node.Blob{},
		proofs: map[blobKey]node.CommitmentProof{}, addr: bytes.Clone(addr),
	}
}

// AddHeader stores h and moves the head up if h is higher.
func (c *Chain) AddHeader(h node.Header) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.headers[h.Height] = h
	if h.Height > c.head {
		c.head = h.Height
	}
}

// AddBlob stores b at height h and, if p is not nil, its commitment proof.
func (c *Chain) AddBlob(h uint64, b node.Blob, p node.CommitmentProof) {
	c.mu.Lock()
	defer c.mu.Unlock()
	k := blobKey{h, string(b.Namespace), string(b.Commitment)}
	c.blobs[k] = b
	if p != nil {
		c.proofs[k] = p
	}
}

func (c *Chain) Head(context.Context) (node.Header, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.Fail != nil {
		return node.Header{}, c.Fail
	}
	h, ok := c.headers[c.head]
	if !ok {
		return node.Header{}, node.ErrNotFound
	}
	return h, nil
}

func (c *Chain) HeaderAt(_ context.Context, height uint64) (node.Header, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.Fail != nil {
		return node.Header{}, c.Fail
	}
	h, ok := c.headers[height]
	if !ok {
		return node.Header{}, node.ErrNotFound
	}
	return h, nil
}

func (c *Chain) Blob(_ context.Context, height uint64, ns, commitment []byte) (node.Blob, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.Fail != nil {
		return node.Blob{}, c.Fail
	}
	b, ok := c.blobs[blobKey{height, string(ns), string(commitment)}]
	if !ok {
		return node.Blob{}, node.ErrNotFound
	}
	return b, nil
}

func (c *Chain) CommitmentProof(_ context.Context, height uint64, ns, commitment []byte) (node.CommitmentProof, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.Fail != nil {
		return nil, c.Fail
	}
	p, ok := c.proofs[blobKey{height, string(ns), string(commitment)}]
	if !ok {
		return nil, node.ErrNotFound
	}
	return p, nil
}

func (c *Chain) Address(context.Context) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.Fail != nil {
		return nil, c.Fail
	}
	return bytes.Clone(c.addr), nil
}

// SubmitBlob records a share v1 blob at the next height after the head, with
// a header carrying the previous header's fields, and returns that height (or
// SubmitHeight if set). The commitment is sha256(namespace || data), a stand-in.
func (c *Chain) SubmitBlob(_ context.Context, ns, data []byte) (uint64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.Fail != nil {
		return 0, c.Fail
	}
	c.Submitted++
	prev := c.headers[c.head]
	h := prev
	h.Height = c.head + 1
	c.headers[h.Height] = h
	c.head = h.Height
	sum := sha256.Sum256(append(bytes.Clone(ns), data...))
	b := node.Blob{Namespace: bytes.Clone(ns), Data: bytes.Clone(data), ShareVersion: 1,
		Signer: bytes.Clone(c.addr), Commitment: sum[:]}
	c.blobs[blobKey{h.Height, string(ns), string(sum[:])}] = b
	if c.SubmitHeight != 0 {
		return c.SubmitHeight, nil
	}
	return h.Height, nil
}

// Consensus fakes a consensus node.
type Consensus struct {
	mu        sync.Mutex
	ChainID   string
	Providers []string
	Fibre     *node.FibreParams // nil = module absent
	Denom     string
	HRP       string
	// MinPrice is the minimum gas price MinGasPrice returns, in Denom per gas.
	MinPrice *big.Rat
	Accounts map[string]node.AccountInfo
	txs      map[[32]byte]node.TxStatus
	Sent     [][]byte
	height   uint64
	// CanaryStatus is what HeightCanary reports; zero means honoured.
	CanaryStatus heightcheck.Status
	// Fail, when set, is returned by every method.
	Fail error
}

// NewConsensus makes a consensus fake on chainID with one agreeing provider.
func NewConsensus(chainID string) *Consensus {
	return &Consensus{
		ChainID: chainID, Providers: []string{chainID}, Denom: "utia", HRP: "celestia", MinPrice: big.NewRat(1, 250),
		Accounts: map[string]node.AccountInfo{}, txs: map[[32]byte]node.TxStatus{},
	}
}

func (c *Consensus) Network(context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ChainID, c.Fail
}

func (c *Consensus) ProviderChainIDs(context.Context) ([]string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.Providers...), c.Fail
}

func (c *Consensus) FibreParams(context.Context) (node.FibreParams, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.Fail != nil {
		return node.FibreParams{}, c.Fail
	}
	if c.Fibre == nil {
		return node.FibreParams{}, node.ErrNotFound
	}
	return *c.Fibre, nil
}

// FibreParamsAt returns the one configured value for every height.
func (c *Consensus) FibreParamsAt(ctx context.Context, _ uint64) (node.FibreParams, error) {
	return c.FibreParams(ctx)
}

// HeightCanary reports CanaryStatus, honoured by default. The fake has no
// response headers to echo, so the outcome is scripted instead of derived.
func (c *Consensus) HeightCanary(context.Context) (heightcheck.Status, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.Fail != nil {
		return heightcheck.Inconclusive, c.Fail
	}
	if c.CanaryStatus == 0 {
		return heightcheck.Honoured, nil
	}
	if c.CanaryStatus == heightcheck.Inconclusive {
		return c.CanaryStatus, node.ErrUnavailable
	}
	return c.CanaryStatus, nil
}

func (c *Consensus) BondDenom(context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.Denom, c.Fail
}

func (c *Consensus) MinGasPrice(context.Context) (*big.Rat, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.Fail != nil {
		return nil, c.Fail
	}
	return new(big.Rat).Set(c.MinPrice), nil
}

func (c *Consensus) Bech32Prefix(context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.HRP, c.Fail
}

func (c *Consensus) Account(_ context.Context, addr string) (node.AccountInfo, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.Fail != nil {
		return node.AccountInfo{}, c.Fail
	}
	a, ok := c.Accounts[addr]
	if !ok {
		return node.AccountInfo{}, fmt.Errorf("%w: account", node.ErrNotFound)
	}
	return a, nil
}

// Broadcast stores txRaw unchanged and returns sha256(txRaw).
func (c *Consensus) Broadcast(_ context.Context, txRaw []byte) ([32]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.Fail != nil {
		return [32]byte{}, c.Fail
	}
	c.Sent = append(c.Sent, bytes.Clone(txRaw))
	return sha256.Sum256(txRaw), nil
}

// SetTx sets the status Tx reports for hash.
func (c *Consensus) SetTx(hash [32]byte, s node.TxStatus) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.txs[hash] = s
}

func (c *Consensus) Tx(_ context.Context, hash [32]byte) (node.TxStatus, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.Fail != nil {
		return node.TxStatus{}, c.Fail
	}
	return c.txs[hash], nil
}

// TxAt is Tx for a transaction expected at height; a found one at another
// height is refused.
func (c *Consensus) TxAt(ctx context.Context, hash [32]byte, height uint64) (node.TxStatus, error) {
	st, err := c.Tx(ctx, hash)
	if err != nil {
		return node.TxStatus{}, err
	}
	if st.Found {
		if err := heightcheck.HeaderHeight(st.Height, height); err != nil {
			return node.TxStatus{}, fmt.Errorf("%w: %w", node.ErrUnavailable, err)
		}
	}
	return st, nil
}

// SetHeight sets the latest height LatestHeight reports.
func (c *Consensus) SetHeight(h uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.height = h
}

// LatestHeight reports the height set by SetHeight; zero is unavailable, as on
// a node that returns no block.
func (c *Consensus) LatestHeight(context.Context) (uint64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.Fail != nil {
		return 0, c.Fail
	}
	if c.height == 0 {
		return 0, fmt.Errorf("%w: no latest height set", node.ErrUnavailable)
	}
	return c.height, nil
}

// TxIndex reports the index as on unless Fail is set.
func (c *Consensus) TxIndex(context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.Fail
}
