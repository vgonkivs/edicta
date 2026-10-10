package demo

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/celestiaorg/celestia-app/v10/pkg/da"
	"github.com/celestiaorg/celestia-node/share/shwap"
	libshare "github.com/celestiaorg/go-square/v4/share"
	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	cmtversion "github.com/cometbft/cometbft/proto/tendermint/version"
	core "github.com/cometbft/cometbft/types"

	"github.com/vgonkivs/edicta/celestia/absence"
	"github.com/vgonkivs/edicta/celestia/heightcheck"
	"github.com/vgonkivs/edicta/celestia/node"
)

var (
	_ node.Reader          = (*offlineChain)(nil)
	_ node.Consensus       = (*offlineChain)(nil)
	_ absence.ProofSource  = (*offlineChain)(nil)
	_ absence.HeaderSource = (*offlineChain)(nil)
)

const offlineBlockTime = 6 * time.Second

// offlineChain is the network edge of the offline scene: one in-process
// chain that plays the bridge node and the consensus node. Its blocks are
// empty and hash-linked, so header trust walks them like a real chain; the
// rest of the scene (gate, Recorder, verifier, absence proofs) is the real
// code. It accepts every broadcast and lands none: the anchor is killed.
type offlineChain struct {
	mu      sync.Mutex
	chainID string
	base    uint64
	start   time.Time
	hdrs    map[uint64]core.Header
	head    uint64
	dah     da.DataAvailabilityHeader
	sent    int
	// now is the scene's clock: two seconds after the head's time.
	now time.Time
}

// newOfflineChain builds blocks base..base+n-1, the first dated start.
func newOfflineChain(chainID string, base, n uint64, start time.Time) *offlineChain {
	c := &offlineChain{chainID: chainID, base: base, start: start, hdrs: map[uint64]core.Header{}, dah: da.MinDataAvailabilityHeader()}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.grow(n)
	return c
}

func filler(tag string, h uint64) []byte {
	s := sha256.Sum256([]byte(fmt.Sprintf("edicta-demo/%s/%d", tag, h)))
	return s[:]
}

// grow appends n empty blocks and moves the clock to just after the new head.
func (c *offlineChain) grow(n uint64) {
	for range n {
		h := c.base
		prev := filler("genesis", c.base)
		if len(c.hdrs) > 0 {
			h = c.head + 1
			hd := c.hdrs[c.head]
			prev = hd.Hash()
		}
		c.hdrs[h] = core.Header{
			Version:            cmtversion.Consensus{Block: 11, App: absence.PinnedAppVersion},
			ChainID:            c.chainID,
			Height:             int64(h),
			Time:               c.start.Add(time.Duration(h-c.base) * offlineBlockTime),
			LastBlockID:        core.BlockID{Hash: prev, PartSetHeader: core.PartSetHeader{Total: 1, Hash: filler("parts", h)}},
			LastCommitHash:     filler("last-commit", h),
			DataHash:           c.dah.Hash(),
			ValidatorsHash:     filler("validators", 0),
			NextValidatorsHash: filler("validators", 0),
			ConsensusHash:      filler("consensus", 0),
			AppHash:            filler("app", h),
			LastResultsHash:    filler("results", h),
			EvidenceHash:       filler("evidence", 0),
			ProposerAddress:    filler("proposer", 0)[:20],
		}
		c.head = h
	}
	c.now = c.hdrs[c.head].Time.Add(2 * time.Second)
}

// Mine adds n blocks.
func (c *offlineChain) Mine(n uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.grow(n)
}

// Now is the scene's clock.
func (c *offlineChain) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *offlineChain) Height() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.head
}

// Swallowed is how many broadcasts the chain accepted and dropped.
func (c *offlineChain) Swallowed() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.sent
}

func (c *offlineChain) header(h uint64) (core.Header, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	hd, ok := c.hdrs[h]
	if !ok {
		return core.Header{}, fmt.Errorf("%w: header %d", node.ErrNotFound, h)
	}
	return hd, nil
}

func (c *offlineChain) nodeHeader(h uint64) (node.Header, error) {
	hd, err := c.header(h)
	if err != nil {
		return node.Header{}, err
	}
	return node.Header{ChainID: hd.ChainID, Height: uint64(hd.Height), Time: hd.Time, AppVersion: hd.Version.App,
		DataRoot: bytes.Clone(hd.DataHash)}, nil
}

// HeaderProto is the canonical protobuf header at h.
func (c *offlineChain) HeaderProto(h uint64) ([]byte, []byte, error) {
	hd, err := c.header(h)
	if err != nil {
		return nil, nil, err
	}
	p := hd.ToProto()
	raw, err := p.Marshal()
	if err != nil {
		return nil, nil, err
	}
	return raw, hd.Hash(), nil
}

func (c *offlineChain) Head(ctx context.Context) (node.Header, error) {
	return c.HeaderAt(ctx, c.Height())
}

func (c *offlineChain) HeaderAt(_ context.Context, height uint64) (node.Header, error) {
	return c.nodeHeader(height)
}

func (c *offlineChain) Blob(_ context.Context, height uint64, _, _ []byte) (node.Blob, error) {
	return node.Blob{}, fmt.Errorf("%w: blob at %d", node.ErrNotFound, height)
}

func (c *offlineChain) CommitmentProof(_ context.Context, height uint64, _, _ []byte) (node.CommitmentProof, error) {
	return nil, fmt.Errorf("%w: proof at %d", node.ErrNotFound, height)
}

// SignedHeader binds the commit to the header. Its one signature is a
// placeholder that nothing checks: the verifier trusts headers through the
// hash chain down from its trusted header, never through signatures.
func (c *offlineChain) SignedHeader(_ context.Context, height uint64) ([]byte, error) {
	hd, err := c.header(height)
	if err != nil {
		return nil, err
	}
	p := hd.ToProto()
	return (&cmtproto.SignedHeader{
		Header: p,
		Commit: &cmtproto.Commit{
			Height:  p.Height,
			BlockID: cmtproto.BlockID{Hash: hd.Hash(), PartSetHeader: cmtproto.PartSetHeader{Total: 1, Hash: filler("parts", height)}},
			Signatures: []cmtproto.CommitSig{{BlockIdFlag: cmtproto.BlockIDFlagCommit, ValidatorAddress: filler("proposer", 0)[:20],
				Timestamp: hd.Time, Signature: filler("signature", height)}},
		},
	}).Marshal()
}

// Header serves the bare protobuf header, for the verifier's header walk.
func (c *offlineChain) Header(_ context.Context, height uint64) ([]byte, error) {
	raw, _, err := c.HeaderProto(height)
	return raw, err
}

func (c *offlineChain) DAH(_ context.Context, height uint64) (*da.DataAvailabilityHeader, error) {
	if _, err := c.header(height); err != nil {
		return nil, err
	}
	return &da.DataAvailabilityHeader{RowRoots: cloneRows(c.dah.RowRoots), ColumnRoots: cloneRows(c.dah.ColumnRoots)}, nil
}

// NamespaceData is empty: no block holds a blob in any namespace.
func (c *offlineChain) NamespaceData(_ context.Context, height uint64, _ libshare.Namespace) (shwap.NamespaceData, error) {
	if _, err := c.header(height); err != nil {
		return nil, err
	}
	return shwap.NamespaceData{}, nil
}

func cloneRows(r [][]byte) [][]byte {
	out := make([][]byte, len(r))
	for i := range r {
		out[i] = bytes.Clone(r[i])
	}
	return out
}

func (c *offlineChain) Network(context.Context) (string, error) { return c.chainID, nil }

func (c *offlineChain) ProviderChainIDs(context.Context) ([]string, error) {
	return []string{c.chainID}, nil
}

func (c *offlineChain) FibreParams(context.Context) (node.FibreParams, error) {
	return node.FibreParams{}, node.ErrNotFound
}

func (c *offlineChain) FibreParamsAt(context.Context, uint64) (node.FibreParams, error) {
	return node.FibreParams{}, node.ErrNotFound
}

func (c *offlineChain) HeightCanary(context.Context) (heightcheck.Status, error) {
	return heightcheck.Honoured, nil
}

func (c *offlineChain) BondDenom(context.Context) (string, error)    { return "utia", nil }
func (c *offlineChain) Bech32Prefix(context.Context) (string, error) { return "celestia", nil }

func (c *offlineChain) MinGasPrice(context.Context) (*big.Rat, error) { return big.NewRat(1, 250), nil }

// Account answers every address with the same fresh account: the killed
// anchor tx never lands, so no sequence ever moves.
func (c *offlineChain) Account(context.Context, string) (node.AccountInfo, error) {
	return node.AccountInfo{Number: 7}, nil
}

func (c *offlineChain) AccountAt(ctx context.Context, addr string, height uint64) (node.AccountInfo, error) {
	if height == 0 || height > c.Height() {
		return node.AccountInfo{}, fmt.Errorf("%w: height %d not reached", node.ErrUnavailable, height)
	}
	return c.Account(ctx, addr)
}

func (c *offlineChain) TxBySequence(context.Context, string, uint64) ([]node.SeqTx, error) {
	return nil, nil
}

// Broadcast accepts the tx and drops it.
func (c *offlineChain) Broadcast(_ context.Context, txRaw []byte) ([32]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sent++
	return sha256.Sum256(txRaw), nil
}

func (c *offlineChain) Tx(context.Context, [32]byte) (node.TxStatus, error) {
	return node.TxStatus{NodeHeight: c.Height()}, nil
}

func (c *offlineChain) TxAt(ctx context.Context, hash [32]byte, _ uint64) (node.TxStatus, error) {
	return c.Tx(ctx, hash)
}

func (c *offlineChain) LatestHeight(context.Context) (uint64, error) { return c.Height(), nil }

func (c *offlineChain) TxIndex(context.Context) error { return nil }
