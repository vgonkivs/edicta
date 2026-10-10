package execcapture

import (
	"bytes"
	"context"
	"crypto/sha256"
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
	// about; a capture still missing after half of it is overdue.
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
	kick    chan struct{}
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
	return &Capturer{cfg: cfg, chain: chain, store: store, log: log, alerted: map[string]bool{}, kick: make(chan struct{}, 1)}, nil
}

// Config is the configuration the Capturer runs with.
func (c *Capturer) Config() Config { return c.cfg }

// Overdue is the number of captures still missing past the alert threshold
// at the last pass.
func (c *Capturer) Overdue() uint64 { return c.overdue.Load() }

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
	pend, err := c.store.ListPending(ctx)
	if err != nil && pend == nil {
		return false, err
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
			continue
		}
		if herr != nil {
			continue
		}
		if c.isOverdue(p, head) {
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

func (c *Capturer) isOverdue(p Pending, head uint64) bool {
	from := p.SeenHead
	if p.ExecHeight != 0 {
		from = p.ExecHeight
	}
	return from != 0 && head > from && head-from >= c.cfg.OverdueBlocks()
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
// railRef at height: the results of the block hash to last_results_hash of
// the header at height + 1, and the transaction sits at the captured index
// of the block.
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
	txs, err := c.chain.BlockTxs(ctx, height)
	if err != nil {
		return Block{}, fmt.Errorf("execcapture: block %d: %w", height, err)
	}
	index := -1
	for i, tx := range txs {
		if sha256.Sum256(tx) == hash {
			index = i
			break
		}
	}
	if index < 0 {
		return Block{}, fmt.Errorf("%w: transaction %s not in block %d", ErrUnproven, railRef, height)
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
		ChainID: c.cfg.ChainID, Height: height, NextHeader: bytes.Clone(rawNext),
		Txs: []Tx{{
			RailRef: railRef, Index: uint32(index),
			Result: Result{Code: r.Code, Data: bytes.Clone(r.Data), GasWanted: r.GasWanted, GasUsed: r.GasUsed},
			Proof:  Proof{Total: pr.Total, Index: pr.Index, LeafHash: bytes.Clone(pr.LeafHash), Aunts: pr.Aunts},
		}},
	}, nil
}

// VerifyTx checks a stored capture against its block's next header: the
// result's leaf, through the path, gives last_results_hash.
func VerifyTx(b Block, t Tx) error {
	var ph cmtproto.Header
	if err := ph.Unmarshal(b.NextHeader); err != nil {
		return fmt.Errorf("%w: next header: %w", ErrUnproven, err)
	}
	if ph.Height < 0 || uint64(ph.Height) != b.Height+1 || ph.ChainID != b.ChainID {
		return fmt.Errorf("%w: next header for height %d on chain %q", ErrUnproven, ph.Height, ph.ChainID)
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
