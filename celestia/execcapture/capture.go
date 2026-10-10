package execcapture

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	abci "github.com/cometbft/cometbft/abci/types"
	"github.com/cometbft/cometbft/crypto/merkle"
	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	core "github.com/cometbft/cometbft/types"

	"github.com/celestiaorg/celestia-app/v10/pkg/appconsts"

	"github.com/vgonkivs/edicta/celestia/railverify"
	"github.com/vgonkivs/edicta/commitment"
)

// MinPruneWindowBlocks is the smallest node prune window accepted: below it
// the warning and alert thresholds leave no time to act.
const MinPruneWindowBlocks = 100

var (
	// ErrNotYet is a capture that cannot be done yet: the transaction or the
	// block after it is not on the chain.
	ErrNotYet = errors.New("execcapture: not on the chain yet")
	// ErrUnproven is a capture whose parts do not prove each other: results
	// that do not hash to the next header's last_results_hash, or a
	// transaction missing from its block.
	ErrUnproven = errors.New("execcapture: the capture does not verify")
	// ErrWrongChain is a capture node whose chain is not the gate's.
	ErrWrongChain = errors.New("execcapture: the capture node is on another chain")
)

// Chain reads what a capture needs from a CometBFT RPC node.
type Chain interface {
	Latest(ctx context.Context) (uint64, error)
	Tx(ctx context.Context, hash [32]byte, prove bool) (railverify.RawTx, error)
	BlockTxs(ctx context.Context, height uint64) ([][]byte, error)
	BlockResults(ctx context.Context, height uint64) ([]railverify.TxResult, error)
	// Header returns the protobuf Header at height.
	Header(ctx context.Context, height uint64) ([]byte, error)
}

// Config configures a Capturer.
type Config struct {
	// ChainID is the chain the rail transactions run on.
	ChainID string
	// PruneWindowBlocks is how many blocks the node keeps block results
	// and headers. A Record that arrives after a quarter of it is warned
	// about; a capture still missing after half of it is overdue, and after
	// all of it lost.
	PruneWindowBlocks uint64
}

// ValidateBasic checks the fields that need no dependency.
func (c Config) ValidateBasic() error {
	if !validChainID(c.ChainID) {
		return fmt.Errorf("%w: chain id", ErrInvalid)
	}
	if c.PruneWindowBlocks < MinPruneWindowBlocks {
		return fmt.Errorf("%w: prune window %d blocks, at least %d", ErrInvalid, c.PruneWindowBlocks, MinPruneWindowBlocks)
	}
	return nil
}

// LateBlocks is the age at which a Record is late.
func (c Config) LateBlocks() uint64 { return c.PruneWindowBlocks / 4 }

// OverdueBlocks is the age at which a missing capture raises the alert.
func (c Config) OverdueBlocks() uint64 { return c.PruneWindowBlocks / 2 }

// LostBlocks is the age at which a missing capture is given up: the node
// has pruned what it needs, so no retry can succeed.
func (c Config) LostBlocks() uint64 { return c.PruneWindowBlocks }

// Capturer captures the execution result proofs of recorded rail
// transactions and retries until each is done.
type Capturer struct {
	cfg   Config
	chain Chain
	store Store
	log   *slog.Logger

	// mu serializes passes, so that one reference is never captured twice
	// at once.
	mu      sync.Mutex
	overdue atomic.Uint64
	alerted map[string]bool
	// conflicted holds the references whose conflict was logged.
	conflicted map[string]bool
	kick       chan struct{}
}

// New returns a Capturer.
func New(cfg Config, chain Chain, store Store, log *slog.Logger) (*Capturer, error) {
	if err := cfg.ValidateBasic(); err != nil {
		return nil, err
	}
	if chain == nil || store == nil {
		return nil, fmt.Errorf("%w: no chain or store", ErrInvalid)
	}
	if log == nil {
		log = slog.Default()
	}
	return &Capturer{cfg: cfg, chain: chain, store: store, log: log, alerted: map[string]bool{}, conflicted: map[string]bool{}, kick: make(chan struct{}, 1)}, nil
}

// Config is the configuration the Capturer runs with.
func (c *Capturer) Config() Config { return c.cfg }

// Overdue is the number of captures still missing past the alert threshold
// at the last pass. A capture given up as lost is not counted.
func (c *Capturer) Overdue() uint64 { return c.overdue.Load() }

// CheckChain reads the header at the node's head and requires its chain id
// to be the configured one, so that captures of two networks never mix.
func (c *Capturer) CheckChain(ctx context.Context) error {
	head, err := c.chain.Latest(ctx)
	if err != nil {
		return fmt.Errorf("execcapture: capture node head: %w", err)
	}
	raw, err := c.chain.Header(ctx, head)
	if err != nil {
		return fmt.Errorf("execcapture: capture node header %d: %w", head, err)
	}
	var ph cmtproto.Header
	if err := ph.Unmarshal(raw); err != nil {
		return fmt.Errorf("execcapture: capture node header %d: %w", head, err)
	}
	if ph.ChainID != c.cfg.ChainID {
		return fmt.Errorf("%w: %q, the gate's is %q", ErrWrongChain, ph.ChainID, c.cfg.ChainID)
	}
	return nil
}

// Kick is signalled after a new reference is tracked.
func (c *Capturer) Kick() <-chan struct{} { return c.kick }

// Track records that railRef needs a capture and wakes Run. It reads only
// the local store, so Record is not slowed by the chain. It is idempotent: a
// captured or already pending reference is left as it is. It reports whether
// the reference was added.
func (c *Capturer) Track(ctx context.Context, railRef string, h commitment.Hash, fromSweep bool) (bool, error) {
	if !ValidRailRef(railRef) {
		return false, fmt.Errorf("%w: rail_ref", ErrInvalid)
	}
	done, err := c.store.Captured(ctx, railRef)
	if err != nil || done {
		return false, err
	}
	lost, err := c.store.Lost(ctx, railRef)
	if err != nil || lost {
		return false, err
	}
	// A pending file that does not decode must not stop new references from
	// being tracked; the store moves it aside, so this is logged once.
	pend, err := c.store.ListPending(ctx)
	if err != nil && pend == nil {
		return false, err
	}
	if err != nil {
		c.log.Error("execcapture: pending captures not all read", "err", err)
	}
	for _, p := range pend {
		if p.RailRef == railRef {
			return false, nil
		}
	}
	p := Pending{RailRef: railRef, CommitmentHash: hex.EncodeToString(h[:]), FromSweep: fromSweep}
	if err := c.store.PutPending(ctx, p); err != nil {
		return false, err
	}
	select {
	case c.kick <- struct{}{}:
	default:
	}
	return true, nil
}

// Pass tries every pending capture once and recounts the overdue ones.
func (c *Capturer) Pass(ctx context.Context) {
	c.mu.Lock()
	defer c.mu.Unlock()
	pend, err := c.store.ListPending(ctx)
	if err != nil {
		c.log.Error("execcapture: pending captures not all read", "err", err)
	}
	head, herr := c.chain.Latest(ctx)
	var overdue uint64
	for _, p := range pend {
		if ctx.Err() != nil {
			return
		}
		if p.SeenHead == 0 && herr == nil {
			p.SeenHead = head
			if err := c.store.PutPending(ctx, p); err != nil {
				c.log.Warn("execcapture: pending capture not updated", "rail_ref", p.RailRef, "err", err)
			}
		}
		err := c.attempt(ctx, &p)
		if err == nil {
			delete(c.alerted, p.RailRef)
			delete(c.conflicted, p.RailRef)
			continue
		}
		if errors.Is(err, ErrConflict) && !c.conflicted[p.RailRef] {
			c.conflicted[p.RailRef] = true
			c.log.Error("execcapture: the node's answer conflicts with the capture already stored for the block; the stored one stays and the reference stays pending",
				"rail_ref", p.RailRef, "commitment_hash", p.CommitmentHash, "exec_height", p.ExecHeight, "err", err)
		}
		if herr != nil {
			continue
		}
		if c.isAged(p, head, c.cfg.LostBlocks()) {
			c.markLost(ctx, p, head, err)
			continue
		}
		if c.isAged(p, head, c.cfg.OverdueBlocks()) {
			overdue++
			if !c.alerted[p.RailRef] {
				c.alerted[p.RailRef] = true
				c.log.Error("execcapture: an execution result capture is still missing past half the node prune window; the node may prune its proof",
					"rail_ref", p.RailRef, "commitment_hash", p.CommitmentHash, "exec_height", p.ExecHeight,
					"head", head, "prune_window_blocks", c.cfg.PruneWindowBlocks, "err", err)
			}
		} else if !errors.Is(err, ErrNotYet) {
			c.log.Warn("execcapture: capture failed, retried later", "rail_ref", p.RailRef, "err", err)
		}
	}
	if herr == nil {
		c.overdue.Store(overdue)
	}
}

func (c *Capturer) isAged(p Pending, head, blocks uint64) bool {
	from := p.SeenHead
	if p.ExecHeight != 0 {
		from = p.ExecHeight
	}
	return from != 0 && head > from && head-from >= blocks
}

// markLost gives up a capture whose age reached the node prune window. It is
// logged once, here, and no longer counts as overdue, so health recovers;
// the entry stays in the store's lost list for the operator.
func (c *Capturer) markLost(ctx context.Context, p Pending, head uint64, cause error) {
	p.LostAtHead = head
	if err := c.store.MarkLost(ctx, p); err != nil {
		c.log.Warn("execcapture: a lost capture was not marked lost, retried later", "rail_ref", p.RailRef, "err", err)
		return
	}
	delete(c.alerted, p.RailRef)
	delete(c.conflicted, p.RailRef)
	c.log.Error("execcapture: an execution result capture is lost: the node prune window has passed, so its proof is gone from that node; it is no longer retried",
		"rail_ref", p.RailRef, "commitment_hash", p.CommitmentHash, "exec_height", p.ExecHeight, "seen_head", p.SeenHead,
		"head", head, "prune_window_blocks", c.cfg.PruneWindowBlocks, "err", cause)
}

// attempt captures one pending reference. It keeps what it learned (the
// execution height) in the store, and removes the entry once captured.
func (c *Capturer) attempt(ctx context.Context, p *Pending) error {
	done, err := c.store.Captured(ctx, p.RailRef)
	if err != nil {
		return err
	}
	if done {
		return c.store.DeletePending(ctx, p.RailRef)
	}
	var hash [32]byte
	if _, err := hex.Decode(hash[:], []byte(p.RailRef)); err != nil {
		return fmt.Errorf("%w: rail_ref", ErrInvalid)
	}
	if p.ExecHeight == 0 {
		tx, err := c.chain.Tx(ctx, hash, false)
		if err != nil {
			if errors.Is(err, railverify.ErrTxNotFound) {
				return fmt.Errorf("%w: %w", ErrNotYet, err)
			}
			return err
		}
		if tx.Height == 0 {
			return fmt.Errorf("%w: no height", ErrNotYet)
		}
		p.ExecHeight = tx.Height
		if err := c.store.PutPending(ctx, *p); err != nil {
			return err
		}
		c.warnLate(ctx, *p)
	}
	b, err := c.Capture(ctx, p.RailRef, p.ExecHeight)
	if err != nil {
		return err
	}
	if err := c.store.PutBlock(ctx, b); err != nil {
		return err
	}
	return c.store.DeletePending(ctx, p.RailRef)
}

// warnLate warns when the reference reached the gate with a quarter of the
// node prune window already gone.
func (c *Capturer) warnLate(ctx context.Context, p Pending) {
	head, err := c.chain.Latest(ctx)
	if err != nil || head <= p.ExecHeight || head-p.ExecHeight < c.cfg.LateBlocks() {
		return
	}
	msg := "execcapture: Record arrived late against the node prune window; executors should call Record right after inclusion"
	if p.FromSweep {
		msg = "execcapture: the sweep found a receipt without a capture late against the node prune window"
	}
	c.log.Warn(msg, "rail_ref", p.RailRef, "exec_height", p.ExecHeight, "head", head,
		"age_blocks", head-p.ExecHeight, "prune_window_blocks", c.cfg.PruneWindowBlocks)
}

// Capture reads and checks the proof of the result of the transaction
// railRef at height: the namespace proofs against data_hash of the header at
// height give the transaction's index, the header at height + 1 follows that
// header, and the results of the block hash to its last_results_hash.
func (c *Capturer) Capture(ctx context.Context, railRef string, height uint64) (Block, error) {
	var hash [32]byte
	if !ValidRailRef(railRef) {
		return Block{}, fmt.Errorf("%w: rail_ref", ErrInvalid)
	}
	if _, err := hex.Decode(hash[:], []byte(railRef)); err != nil {
		return Block{}, fmt.Errorf("%w: rail_ref", ErrInvalid)
	}
	head, err := c.chain.Latest(ctx)
	if err != nil {
		return Block{}, err
	}
	if head <= height {
		return Block{}, fmt.Errorf("%w: head %d, the next header %d", ErrNotYet, head, height+1)
	}
	rawNext, err := c.chain.Header(ctx, height+1)
	if err != nil {
		return Block{}, fmt.Errorf("execcapture: header %d: %w", height+1, err)
	}
	var ph cmtproto.Header
	if err := ph.Unmarshal(rawNext); err != nil {
		return Block{}, fmt.Errorf("%w: header %d: %w", ErrUnproven, height+1, err)
	}
	if ph.Height < 0 || uint64(ph.Height) != height+1 || ph.ChainID != c.cfg.ChainID {
		return Block{}, fmt.Errorf("%w: header %d is for height %d on chain %q", ErrUnproven, height+1, ph.Height, ph.ChainID)
	}
	rawHdr, hdr, err := c.execHeader(ctx, height, &ph)
	if err != nil {
		return Block{}, err
	}
	txs, err := c.chain.BlockTxs(ctx, height)
	if err != nil {
		return Block{}, fmt.Errorf("execcapture: block %d: %w", height, err)
	}
	proofs, err := positionProofs(txs, hdr.DataHash)
	if err != nil {
		return Block{}, fmt.Errorf("block %d: %w", height, err)
	}
	index, unit, err := position(proofs, hdr.DataHash, hash, len(txs))
	if err != nil {
		return Block{}, fmt.Errorf("block %d: %w", height, err)
	}
	if !bytes.Equal(txs[index], unit) {
		return Block{}, fmt.Errorf("%w: transaction %d of block %d is not the proven unit", ErrUnproven, index, height)
	}
	results, err := c.chain.BlockResults(ctx, height)
	if err != nil {
		return Block{}, fmt.Errorf("execcapture: results %d: %w", height, err)
	}
	if len(results) != len(txs) {
		return Block{}, fmt.Errorf("%w: %d results for %d transactions at %d", ErrUnproven, len(results), len(txs), height)
	}
	rs := make([]*abci.ExecTxResult, len(results))
	for i, r := range results {
		rs[i] = &abci.ExecTxResult{Code: r.Code, Data: r.Data, GasWanted: r.GasWanted, GasUsed: r.GasUsed}
	}
	abciRs := core.NewResults(rs)
	if !bytes.Equal(abciRs.Hash(), ph.LastResultsHash) {
		return Block{}, fmt.Errorf("%w: results of %d do not hash to last_results_hash of %d", ErrUnproven, height, height+1)
	}
	leaf, err := abciRs[index].Marshal()
	if err != nil {
		return Block{}, fmt.Errorf("%w: result %d: %w", ErrUnproven, index, err)
	}
	pr := abciRs.ProveResult(index)
	if err := pr.Verify(ph.LastResultsHash, leaf); err != nil {
		return Block{}, fmt.Errorf("%w: result path: %w", ErrUnproven, err)
	}
	r := results[index]
	return Block{
		ChainID: c.cfg.ChainID, Height: height, Header: rawHdr, NextHeader: bytes.Clone(rawNext), Namespaces: proofs,
		Txs: []Tx{{
			RailRef: railRef, Index: uint32(index),
			Result: Result{Code: r.Code, Data: bytes.Clone(r.Data), GasWanted: r.GasWanted, GasUsed: r.GasUsed},
			Proof:  Proof{Total: pr.Total, Index: pr.Index, LeafHash: bytes.Clone(pr.LeafHash), Aunts: pr.Aunts},
		}},
	}, nil
}

// execHeader reads the header at height and ties it to the next header.
func (c *Capturer) execHeader(ctx context.Context, height uint64, next *cmtproto.Header) ([]byte, core.Header, error) {
	raw, err := c.chain.Header(ctx, height)
	if err != nil {
		return nil, core.Header{}, fmt.Errorf("execcapture: header %d: %w", height, err)
	}
	hdr, err := tieHeader(raw, c.cfg.ChainID, height, next)
	if err != nil {
		return nil, core.Header{}, err
	}
	return bytes.Clone(raw), hdr, nil
}

// tieHeader decodes the header at height and requires the next header's
// last_block_id to name its hash. The position of a transaction is derived
// under the square rules of the pinned app version only.
func tieHeader(raw []byte, chainID string, height uint64, next *cmtproto.Header) (core.Header, error) {
	var ph cmtproto.Header
	if err := ph.Unmarshal(raw); err != nil {
		return core.Header{}, fmt.Errorf("%w: header %d: %w", ErrUnproven, height, err)
	}
	hdr, err := core.HeaderFromProto(&ph)
	if err != nil {
		return core.Header{}, fmt.Errorf("%w: header %d: %w", ErrUnproven, height, err)
	}
	if hdr.Height < 0 || uint64(hdr.Height) != height || hdr.ChainID != chainID {
		return core.Header{}, fmt.Errorf("%w: header %d is for height %d on chain %q", ErrUnproven, height, hdr.Height, hdr.ChainID)
	}
	if h := hdr.Hash(); len(h) == 0 || !bytes.Equal(h, next.LastBlockId.Hash) {
		return core.Header{}, fmt.Errorf("%w: header %d is not the one header %d follows", ErrUnproven, height, height+1)
	}
	if hdr.Version.App != appconsts.Version {
		return core.Header{}, fmt.Errorf("%w: block %d is of app version %d; the position proof is built for %d only", ErrUnproven, height, hdr.Version.App, appconsts.Version)
	}
	return hdr, nil
}

// VerifyTx checks a stored capture against its block's headers: the
// namespace proofs give the transaction's index under data_hash, the next
// header follows the header, and the result's leaf, through the path, gives
// last_results_hash.
func VerifyTx(b Block, t Tx) error {
	var ph cmtproto.Header
	if err := ph.Unmarshal(b.NextHeader); err != nil {
		return fmt.Errorf("%w: next header: %w", ErrUnproven, err)
	}
	if ph.Height < 0 || uint64(ph.Height) != b.Height+1 || ph.ChainID != b.ChainID {
		return fmt.Errorf("%w: next header for height %d on chain %q", ErrUnproven, ph.Height, ph.ChainID)
	}
	var hash [32]byte
	if !ValidRailRef(t.RailRef) {
		return fmt.Errorf("%w: rail_ref", ErrInvalid)
	}
	if _, err := hex.Decode(hash[:], []byte(t.RailRef)); err != nil {
		return fmt.Errorf("%w: rail_ref", ErrInvalid)
	}
	hdr, err := tieHeader(b.Header, b.ChainID, b.Height, &ph)
	if err != nil {
		return err
	}
	if t.Proof.Total < 1 || t.Proof.Total > int64(maxInt) {
		return fmt.Errorf("%w: path total %d", ErrUnproven, t.Proof.Total)
	}
	index, _, err := position(b.Namespaces, hdr.DataHash, hash, int(t.Proof.Total))
	if err != nil {
		return err
	}
	if index != int(t.Index) {
		return fmt.Errorf("%w: the namespace proofs give index %d, the capture %d", ErrUnproven, index, t.Index)
	}
	leaf, err := core.NewResults([]*abci.ExecTxResult{{Code: t.Result.Code, Data: t.Result.Data, GasWanted: t.Result.GasWanted, GasUsed: t.Result.GasUsed}})[0].Marshal()
	if err != nil {
		return fmt.Errorf("%w: %w", ErrUnproven, err)
	}
	if t.Proof.Index != int64(t.Index) {
		return fmt.Errorf("%w: path index %d, tx index %d", ErrUnproven, t.Proof.Index, t.Index)
	}
	pr := merkleProof(t.Proof)
	if err := pr.Verify(ph.LastResultsHash, leaf); err != nil {
		return fmt.Errorf("%w: %w", ErrUnproven, err)
	}
	return nil
}

const maxInt = int(^uint(0) >> 1)

func merkleProof(p Proof) *merkle.Proof {
	return &merkle.Proof{Total: p.Total, Index: p.Index, LeafHash: p.LeafHash, Aunts: p.Aunts}
}

// Run makes a pass at start, on every tick and after every Track, until ctx
// ends. A nil tick means a ticker of every.
func (c *Capturer) Run(ctx context.Context, tick <-chan time.Time, every time.Duration) {
	if tick == nil {
		t := time.NewTicker(every)
		defer t.Stop()
		tick = t.C
	}
	c.Pass(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick:
		case <-c.kick:
		}
		c.Pass(ctx)
	}
}
