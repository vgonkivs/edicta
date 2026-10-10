package edictad

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/celestia/cometrpc"
	"github.com/vgonkivs/edicta/celestia/execcapture"
	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/examples/tia-transfer/bankaction"
	"github.com/vgonkivs/edicta/gate/registry"
)

// CaptureConfig configures the execution result capture: for a rail whose
// result is proven through last_results_hash, the gate keeps the proof of
// the recorded transaction's result outside the archive before the node
// prunes it. Verifiers do not read the store.
type CaptureConfig struct {
	Enabled bool `toml:"enabled"`
	// Dir is the capture store; it must not be the archive directory.
	Dir string `toml:"dir"`
	// CometRPC is the CometBFT RPC URL of a node of the rail's chain that
	// serves /tx, /block, /block_results and /header.
	CometRPC string `toml:"comet_rpc"`
	// NodePruneWindowBlocks is how many blocks that node keeps block results
	// and headers. A Record later than a quarter of it is warned about; a
	// capture still missing after half of it degrades health.
	NodePruneWindowBlocks uint64 `toml:"node_prune_window_blocks"`
	RetryEveryS           uint64 `toml:"retry_every_s"`
}

const (
	defaultCaptureRetryS = 30
	maxCaptureRetryS     = 3600
	// maxPruneWindowBlocks is about a year of 6-second blocks.
	maxPruneWindowBlocks = 6_000_000
)

// capturedTypes are the action types whose rail result is proven through
// last_results_hash: Celestia rails.
var capturedTypes = []string{bankaction.ActionType}

func capturesType(t string) bool { return slices.Contains(capturedTypes, t) }

func (c CaptureConfig) withDefaults() CaptureConfig {
	if c.Enabled && c.RetryEveryS == 0 {
		c.RetryEveryS = defaultCaptureRetryS
	}
	return c
}

func (c Config) validateCapture() error {
	p := c.Capture
	if !p.Enabled {
		if p != (CaptureConfig{}) {
			return cfgErr("capture.dir, comet_rpc, node_prune_window_blocks and retry_every_s need capture.enabled")
		}
		return nil
	}
	switch {
	case strings.TrimSpace(p.Dir) == "":
		return cfgErr("capture.dir is required")
	case sameOrInside(p.Dir, c.Archive.Dir):
		return cfgErr("capture.dir must be outside archive.dir: captures are not archive records")
	case !strings.HasPrefix(p.CometRPC, "http://") && !strings.HasPrefix(p.CometRPC, "https://"):
		return cfgErr("capture.comet_rpc must be an http or https URL")
	case p.NodePruneWindowBlocks < execcapture.MinPruneWindowBlocks || p.NodePruneWindowBlocks > maxPruneWindowBlocks:
		return cfgErr("capture.node_prune_window_blocks must be %d..%d", execcapture.MinPruneWindowBlocks, maxPruneWindowBlocks)
	case p.RetryEveryS < 1 || p.RetryEveryS > maxCaptureRetryS:
		return cfgErr("capture.retry_every_s must be 1..%d", maxCaptureRetryS)
	}
	if !slices.ContainsFunc(c.Gate.ActionTypes, capturesType) {
		return cfgErr("capture.enabled needs an action type whose result is proven on chain in gate.action_types (%s)", strings.Join(capturedTypes, ", "))
	}
	return nil
}

func sameOrInside(dir, root string) bool {
	if root == "" {
		return false
	}
	rel, err := filepath.Rel(filepath.Clean(root), filepath.Clean(dir))
	return err == nil && (rel == "." || !strings.HasPrefix(rel, ".."))
}

// captureSweep finds receipts of captured types that no capture and no
// pending entry covers, from the registry, and tracks them. It is the
// fallback for a Record whose capture was never tracked (a crash, a store
// outage).
type captureSweep struct {
	lister registry.Lister
	// decision reads the archived decision record, for its action type.
	decision func(ctx context.Context, h commitment.Hash) (*archive.DecisionRecord, error)
	cap      *execcapture.Capturer
	log      *slog.Logger
	timeout  time.Duration
	// settled holds the decisions this process found captured, tracked or
	// not of a captured type, so a pass does not read them again.
	settled map[commitment.Hash]struct{}
}

const maxCaptureSettled = 1 << 16

func (s *captureSweep) pass(ctx context.Context) {
	var after *registry.Key
	for ctx.Err() == nil {
		page, err := s.lister.List(ctx, after, sweepPage)
		if err != nil {
			s.log.Error("edictad: capture sweep could not list the registry", "err", err)
			return
		}
		if len(page) == 0 {
			return
		}
		for _, e := range page {
			if ctx.Err() != nil {
				return
			}
			s.entry(ctx, e)
		}
		after = &page[len(page)-1].Key
	}
}

func (s *captureSweep) settle(h commitment.Hash) {
	if s.settled == nil || len(s.settled) >= maxCaptureSettled {
		s.settled = map[commitment.Hash]struct{}{}
	}
	s.settled[h] = struct{}{}
}

func (s *captureSweep) entry(ctx context.Context, e registry.Entry) {
	if len(e.Receipt) == 0 {
		return
	}
	if _, ok := s.settled[e.CommitmentHash]; ok {
		return
	}
	sr, _, err := commitment.DecodeSignedReceipt(e.Receipt)
	if err != nil {
		s.log.Error("edictad: capture sweep: the registry's receipt does not decode", "commitment_hash", hex.EncodeToString(e.CommitmentHash[:]), "err", err)
		s.settle(e.CommitmentHash)
		return
	}
	rctx, cancel := context.WithTimeout(ctx, s.timeout)
	d, err := s.decision(rctx, e.CommitmentHash)
	cancel()
	if err != nil {
		if errors.Is(err, archive.ErrNotFound) || errors.Is(err, archive.ErrCorrupt) {
			s.log.Warn("edictad: capture sweep: no readable decision record, the action type is unknown", "commitment_hash", hex.EncodeToString(e.CommitmentHash[:]), "err", err)
			s.settle(e.CommitmentHash)
		}
		return
	}
	sc, err := commitment.DecodeSigned(d.Envelope)
	if err != nil || !capturesType(sc.Commitment.Action.Type) {
		s.settle(e.CommitmentHash)
		return
	}
	added, err := s.cap.Track(ctx, sr.Receipt.RailRef, e.CommitmentHash, true)
	switch {
	case errors.Is(err, execcapture.ErrInvalid):
		s.log.Error("edictad: capture sweep: the receipt's rail_ref is not a transaction hash", "commitment_hash", hex.EncodeToString(e.CommitmentHash[:]))
		s.settle(e.CommitmentHash)
	case err != nil:
		s.log.Warn("edictad: capture sweep: not tracked, retried next pass", "err", err)
	default:
		if added {
			s.log.Warn("edictad: capture sweep found a receipt without a capture", "rail_ref", sr.Receipt.RailRef,
				"commitment_hash", hex.EncodeToString(e.CommitmentHash[:]))
		}
		s.settle(e.CommitmentHash)
	}
}

// loop runs a sweep pass at start and on every tick until ctx ends.
func (s *captureSweep) loop(ctx context.Context, tick <-chan time.Time, every time.Duration) {
	if tick == nil {
		t := time.NewTicker(every)
		defer t.Stop()
		tick = t.C
	}
	for {
		s.pass(ctx)
		select {
		case <-ctx.Done():
			return
		case <-tick:
		}
	}
}

// startCapture builds the capturer and starts its retry loop and its sweep;
// nil without capture.enabled.
func startCapture(ctx context.Context, cfg Config, d Deps, chainID string, reg registry.Lister, aio *archiveIO,
	timeout time.Duration, log *slog.Logger, bg *sync.WaitGroup) (*execcapture.Capturer, error) {
	p := cfg.Capture
	if !p.Enabled {
		return nil, nil
	}
	chain := d.CaptureChain
	if chain == nil {
		src, err := cometrpc.New(p.CometRPC, nil)
		if err != nil {
			return nil, cfgErr("capture.comet_rpc: %v", err)
		}
		chain = src
	}
	st, err := execcapture.OpenDir(p.Dir)
	if err != nil {
		return nil, fmt.Errorf("edictad: capture store: %w", err)
	}
	c, err := execcapture.New(execcapture.Config{ChainID: chainID, PruneWindowBlocks: p.NodePruneWindowBlocks}, chain, st, log)
	if err != nil {
		return nil, fmt.Errorf("edictad: capture: %w", err)
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	err = c.CheckChain(cctx)
	cancel()
	if err != nil {
		return nil, fmt.Errorf("edictad: capture.comet_rpc: %w", err)
	}
	sw := &captureSweep{lister: reg, decision: aio.decision, cap: c, log: log, timeout: timeout}
	bg.Add(2)
	go func() {
		defer bg.Done()
		c.Run(ctx, d.CaptureTick, time.Duration(p.RetryEveryS)*time.Second)
	}()
	go func() {
		defer bg.Done()
		sw.loop(ctx, d.CaptureSweepTick, time.Duration(cfg.Archive.SweepIntervalS)*time.Second)
	}()
	log.Info("edictad: execution result capture on", "dir", p.Dir, "node_prune_window_blocks", p.NodePruneWindowBlocks,
		"late_after_blocks", c.Config().LateBlocks(), "alert_after_blocks", c.Config().OverdueBlocks())
	return c, nil
}

// trackRecord starts the capture of a receipt the gate just issued or
// returned again. A failure never changes the answer: the sweep tracks what
// this missed.
func (a *archivingGate) trackRecord(ctx context.Context, envelope []byte, receipt []byte) {
	if a.cap == nil || len(receipt) == 0 {
		return
	}
	sc, err := commitment.DecodeSigned(envelope)
	if err != nil || !capturesType(sc.Commitment.Action.Type) {
		return
	}
	sr, _, err := commitment.DecodeSignedReceipt(receipt)
	if err != nil {
		return
	}
	ch, err := commitment.HashOf(&sc.Commitment)
	if err != nil {
		return
	}
	if _, err := a.cap.Track(ctx, sr.Receipt.RailRef, ch, false); err != nil {
		a.w.log.Error("edictad: execution result capture not tracked; the sweep tracks it later",
			"rail_ref", sr.Receipt.RailRef, "commitment_hash", hex.EncodeToString(ch[:]), "err", err)
	}
}
