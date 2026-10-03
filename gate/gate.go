package gate

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math"
	"math/bits"
	"sync/atomic"
	"time"

	"github.com/vgonkivs/prior/commitment"
	"github.com/vgonkivs/prior/gate/registry"
)

// Gate is safe for concurrent use. It starts no goroutines.
type Gate struct {
	cfg       Config
	d         Deps
	gateKeys  map[[32]byte]struct{}
	signerPub []byte
	epoch     uint64
	watermark atomic.Uint64
	sem       *weightedSem
	release   func()
	closed    atomic.Bool

	// Test hooks; production code leaves them nil. A hook that returns an
	// error makes Admit return at once, as a crash would.
	afterReserve  func() error
	afterExecute  func() error
	beforeResolve func() error
	mutateOrder   func(*commitment.IBKROrderV0)
}

type Result struct {
	CommitmentHash commitment.Hash // zero if rejected before the signature check passed
	State          registry.State  // 0 if no registry entry was written or found
	Path           registry.Path   // 0 until a payload path was accepted
	Receipt        []byte          // canonical SignedReceipt; set only when State is Executed and the receipt is signed
}

type ReconcileReport struct{ Executed, Rejected, StillUnknown int }

// hasKey is implemented by allowlists that can say whether a key is listed.
type hasKey interface{ HasKey(key [32]byte) bool }

// New validates the configuration, loads the registry metadata and moves
// every Reserved entry to Unknown.
func New(ctx context.Context, cfg Config, d Deps) (*Gate, error) {
	bad := func(format string, a ...any) error {
		return fmt.Errorf("%w: %s", ErrInvalidConfig, fmt.Sprintf(format, a...))
	}
	switch {
	case cfg.SkewS > maxSkewS:
		return nil, bad("skew_s %d above %d", cfg.SkewS, maxSkewS)
	case cfg.BlobRetentionS < 1 || cfg.BlobRetentionS > math.MaxInt64:
		return nil, bad("blob_retention_s %d", cfg.BlobRetentionS)
	case cfg.DATimeout <= 0 || cfg.ArchiveTimeout <= 0 || cfg.ExecTimeout <= 0 || cfg.ChainTimeout <= 0:
		return nil, bad("timeouts must be positive")
	case cfg.MaxFetchBytes == 0:
		return nil, bad("max_fetch_bytes is zero")
	case cfg.PruneGrace <= cfg.ClockTolerance:
		return nil, bad("prune_grace %d must be above clock_tolerance %d", cfg.PruneGrace, cfg.ClockTolerance)
	case d.Clock == nil || d.Params == nil || d.Headers == nil || d.Anchors == nil || d.DA == nil ||
		d.Archive == nil || d.Allowlist == nil || d.Registry == nil || d.Executor == nil || d.Signer == nil:
		return nil, bad("missing dependency")
	}
	if d.Committers[commitment.DACelestiaBlob] == nil {
		return nil, bad("a committer for da = 2 is required")
	}
	if d.Executor.Rail() != cfg.Scope.Rail {
		return nil, bad("executor rail %d differs from scope rail %d", d.Executor.Rail(), cfg.Scope.Rail)
	}

	g := &Gate{cfg: cfg, d: d, gateKeys: make(map[[32]byte]struct{}), sem: newWeightedSem(cfg.MaxFetchBytes)}
	g.signerPub = bytes.Clone(d.Signer.PublicKey())
	if err := commitment.CheckPublicKey(g.signerPub); err != nil {
		return nil, fmt.Errorf("gate: signer key: %w", err)
	}
	var sk [32]byte
	copy(sk[:], g.signerPub)
	g.gateKeys[sk] = struct{}{}
	for i, k := range cfg.OtherGateKeys {
		if err := commitment.CheckPublicKey(k[:]); err != nil {
			return nil, fmt.Errorf("gate: other gate key %d: %w", i, err)
		}
		g.gateKeys[k] = struct{}{}
	}
	if hk, ok := d.Allowlist.(hasKey); ok {
		for k := range g.gateKeys {
			if hk.HasKey(k) {
				return nil, fmt.Errorf("%w: a gate key is in the allowlist", ErrAgentKeyIsGateKey)
			}
		}
	}

	now := g.now()
	if now == 0 {
		return nil, fmt.Errorf("%w: clock reads 0", ErrClockRegression)
	}
	if cl, ok := d.Registry.(registry.Claimer); ok {
		release, err := cl.Claim()
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrRegistryInUse, err)
		}
		g.release = release
	}
	started := false
	defer func() {
		if !started && g.release != nil {
			g.release()
		}
	}()
	m, err := d.Registry.Meta(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: meta: %w", ErrRegistryUnavailable, err)
	}
	if m.Epoch == 0 || m.Epoch > satAdd(now, cfg.ClockTolerance) {
		return nil, bad("registry epoch %d is zero or ahead of the clock %d", m.Epoch, now)
	}
	g.epoch = m.Epoch
	g.watermark.Store(m.Watermark)
	if _, err := d.Registry.Recover(ctx, now); err != nil {
		return nil, fmt.Errorf("%w: recover: %w", ErrRegistryUnavailable, err)
	}
	started = true
	return g, nil
}

// Close releases the registry so another Gate may be built on it. In-flight
// calls are not interrupted.
func (g *Gate) Close() error {
	if g.closed.CompareAndSwap(false, true) && g.release != nil {
		g.release()
	}
	return nil
}

func satAdd(a, b uint64) uint64 {
	s, carry := bits.Add64(a, b, 0)
	if carry != 0 {
		return math.MaxUint64
	}
	return s
}

func (g *Gate) now() uint64 {
	t := g.d.Clock.Now().Unix()
	if t < 0 {
		return 0
	}
	return uint64(t)
}

func (g *Gate) bumpWatermark(v uint64) {
	for {
		old := g.watermark.Load()
		if v <= old || g.watermark.CompareAndSwap(old, v) {
			return
		}
	}
}

// Admit verifies the envelope and, if every stage passes, executes the
// committed order at most once and returns a signed receipt. Result.State is
// authoritative; the error explains it.
func (g *Gate) Admit(ctx context.Context, envelope []byte) (res Result, err error) {
	var ev AdmissionEvent
	defer func() {
		if g.d.Metrics != nil {
			ev.CommitmentHash, ev.Path, ev.State, ev.Err = res.CommitmentHash, res.Path, res.State, err
			g.d.Metrics.Admission(ev)
		}
	}()
	return g.admit(ctx, envelope, &ev)
}

func (g *Gate) admit(ctx context.Context, envelope []byte, ev *AdmissionEvent) (Result, error) {
	if g.closed.Load() {
		return Result{}, ErrClosed
	}
	if err := ctx.Err(); err != nil {
		return Result{}, fmt.Errorf("gate: %w", err)
	}

	// Clock.
	now := g.now()
	if now == 0 || satAdd(now, g.cfg.ClockTolerance) < g.watermark.Load() {
		return Result{}, fmt.Errorf("%w: now %d, watermark %d", ErrClockRegression, now, g.watermark.Load())
	}

	// Chain params.
	latest, err := g.fibreRetention(ctx, 0)
	if err != nil {
		return Result{}, g.chainErr(ctx, "fibre retention", err)
	}
	p := commitment.Params{FibreRetentionS: latest, BlobRetentionS: g.cfg.BlobRetentionS, SkewS: g.cfg.SkewS}

	// Stateless verification: decoding, validation, signature, time, scope.
	s, h, err := commitment.VerifyForGate(envelope, now, g.cfg.Scope, p)
	if err != nil {
		return Result{}, err
	}
	c := &s.Commitment
	ev.DA = c.PayloadRef.DA
	res := Result{CommitmentHash: h}

	// Registry epoch.
	if c.IssuedAt <= satAdd(g.epoch, g.cfg.SkewS) {
		return res, fmt.Errorf("%w: issued_at %d, epoch %d", ErrBeforeRegistryEpoch, c.IssuedAt, g.epoch)
	}

	// Key roles, then the allowlist.
	var agentKey [32]byte
	copy(agentKey[:], c.AgentPubKey)
	if _, ok := g.gateKeys[agentKey]; ok {
		return res, ErrAgentKeyIsGateKey
	}
	listed, err := g.allowlistKey(ctx, c.AgentID)
	if err != nil {
		if errors.Is(err, ErrAgentNotAllowed) {
			return res, err
		}
		if cerr := ctx.Err(); cerr != nil {
			return res, fmt.Errorf("gate: %w", cerr)
		}
		return res, fmt.Errorf("%w: %w", ErrAllowlistUnavailable, err)
	}
	if listed != agentKey {
		return res, ErrAgentKeyMismatch
	}

	// The order is built from the committed params and checked.
	order := *c.Action.IBKROrder
	if order.LimitPrice != nil {
		v := *order.LimitPrice
		order.LimitPrice = &v
	}
	if order.Symbol != nil {
		v := *order.Symbol
		order.Symbol = &v
	}
	if g.mutateOrder != nil {
		g.mutateOrder(&order)
	}
	if err := commitment.CheckAction(c, order); err != nil {
		return res, err
	}
	coid, err := commitment.ClientOrderID(g.cfg.Scope.Rail, h)
	if err != nil {
		return res, err
	}

	// Advisory nonce check.
	key := registry.Key{PubKey: agentKey}
	copy(key.Nonce[:], c.Nonce)
	switch old, err := g.d.Registry.Get(ctx, key); {
	case err == nil:
		return replay(h, old)
	case !errors.Is(err, registry.ErrNotFound):
		return res, fmt.Errorf("%w: %w", ErrRegistryUnavailable, err)
	}

	// Other admissions may have raised the watermark while the registry was read.
	if satAdd(now, g.cfg.ClockTolerance) < g.watermark.Load() {
		return res, fmt.Errorf("%w: now %d, watermark %d", ErrClockRegression, now, g.watermark.Load())
	}

	// Anchor, anchor time, retention window.
	anchor, err := g.findAnchor(ctx, c.PayloadRef)
	if err != nil {
		return res, g.anchorErr(ctx, "anchor", err)
	}
	if anchor.Height != c.PayloadRef.Height {
		return res, fmt.Errorf("%w: anchor at height %d, reference at %d", ErrAnchorNotFound, anchor.Height, c.PayloadRef.Height)
	}
	blockTime, err := g.blockTime(ctx, c.PayloadRef.Height)
	if err != nil {
		return res, g.anchorErr(ctx, "header", err)
	}
	if err := commitment.CheckAnchorTime(c, blockTime, p); err != nil {
		return res, err
	}
	within, err := g.retentionHolds(ctx, c, anchor, blockTime, latest)
	if err != nil {
		return res, err
	}

	// Payload.
	path, err := g.acquirePayload(ctx, c, within)
	if err != nil {
		return res, err
	}
	res.Path = path

	// Time again, because fetching takes time.
	now2 := g.now()
	if now2 == 0 || satAdd(now2, g.cfg.ClockTolerance) < g.watermark.Load() {
		return res, fmt.Errorf("%w: now %d, watermark %d", ErrClockRegression, now2, g.watermark.Load())
	}
	if err := commitment.CheckTime(c, now2, p); err != nil {
		return res, err
	}

	// The nonce is consumed here, before anything is sent.
	if err := ctx.Err(); err != nil {
		return res, fmt.Errorf("gate: %w", err)
	}
	entry := registry.Entry{
		Key: key, CommitmentHash: h, State: registry.StateReserved, Path: path,
		ReservedAt: now2, ValidUntil: c.ValidUntil,
	}
	if err := g.d.Registry.Reserve(ctx, entry, g.cfg.ClockTolerance); err != nil {
		var ee *registry.ExistsError
		if errors.As(err, &ee) {
			return replay(h, ee.Existing)
		}
		if errors.Is(err, registry.ErrBelowWatermark) || errors.Is(err, registry.ErrPrunedWindow) {
			return res, fmt.Errorf("%w: %w", ErrClockRegression, err)
		}
		return res, fmt.Errorf("%w: reserve: %w", ErrRegistryUnavailable, err)
	}
	g.bumpWatermark(now2)
	res.State = registry.StateReserved
	if g.afterReserve != nil {
		if err := g.afterReserve(); err != nil {
			return res, fmt.Errorf("gate: after reserve: %w", err)
		}
	}

	// Execute, detached from the caller's cancellation.
	dctx := context.WithoutCancel(ctx)
	expiry := c.ValidUntil
	if c.Constraints.Deadline != nil {
		expiry = *c.Constraints.Deadline
	}
	notAfter := time.Unix(int64(expiry-min(expiry, g.cfg.SkewS)), 0)
	er, eerr := g.execute(dctx, ExecRequest{CommitmentHash: h, ClientOrderID: coid, Order: order, NotAfter: notAfter})
	if g.afterExecute != nil {
		if err := g.afterExecute(); err != nil {
			return res, fmt.Errorf("gate: after execute: %w", err)
		}
	}

	outcome, ref := registry.StateUnknown, ""
	if eerr == nil {
		switch er.Outcome {
		case OutcomeExecuted:
			if validID(er.RailRef, 128) {
				outcome, ref = registry.StateExecuted, er.RailRef
			}
		case OutcomeRejected:
			outcome = registry.StateRejected
		}
	}
	if g.beforeResolve != nil {
		if err := g.beforeResolve(); err != nil {
			return res, fmt.Errorf("gate: before resolve: %w", err)
		}
	}

	// Receipt and resolution.
	at := g.now()
	if at == 0 {
		at = now2
	}
	upd := entry
	upd.State = outcome
	upd.History = []registry.Resolution{{Source: registry.SourceRail, By: "gate", At: at, PrevState: registry.StateReserved}}
	var signErr error
	if outcome == registry.StateExecuted {
		upd.RailRef, upd.ExecutedAt = ref, at
		upd.Receipt, signErr = g.signReceipt(dctx, h, path, ref, at)
	}
	if err := g.d.Registry.Resolve(dctx, key, registry.StateReserved, upd); err != nil {
		cause := fmt.Errorf("resolve: %w", err)
		switch outcome {
		case registry.StateExecuted:
			return res, fmt.Errorf("%w: %w", ErrReceiptPending, cause)
		case registry.StateRejected:
			return res, fmt.Errorf("%w: %w", ErrExecutionRejected, cause)
		}
		return res, fmt.Errorf("%w: %v: %w", ErrExecutionUnknown, eerr, cause)
	}
	res.State = outcome
	switch outcome {
	case registry.StateExecuted:
		if signErr != nil {
			return res, fmt.Errorf("%w: sign: %w", ErrReceiptPending, signErr)
		}
		res.Receipt = bytes.Clone(upd.Receipt)
		return res, nil
	case registry.StateRejected:
		return res, ErrExecutionRejected
	}
	if eerr != nil {
		return res, fmt.Errorf("%w: %w", ErrExecutionUnknown, eerr)
	}
	return res, fmt.Errorf("%w: outcome %d", ErrExecutionUnknown, er.Outcome)
}

// replay answers a submission whose nonce is taken. It reports the stored
// entry only if it belongs to the same commitment.
func replay(h commitment.Hash, old registry.Entry) (Result, error) {
	if old.CommitmentHash != h {
		return Result{CommitmentHash: h}, fmt.Errorf("%w: held by commitment %x", ErrNonceUsed, old.CommitmentHash[:])
	}
	r := Result{CommitmentHash: h, State: old.State, Path: old.Path}
	if old.State == registry.StateExecuted {
		r.Receipt = bytes.Clone(old.Receipt)
	}
	return r, ErrNonceUsed
}

func (g *Gate) chainErr(ctx context.Context, what string, err error) error {
	if cerr := ctx.Err(); cerr != nil {
		return fmt.Errorf("gate: %w", cerr)
	}
	return fmt.Errorf("%w: %s: %w", ErrChainUnavailable, what, err)
}

func (g *Gate) anchorErr(ctx context.Context, what string, err error) error {
	if errors.Is(err, ErrAnchorNotFound) {
		return fmt.Errorf("%w: %s", ErrAnchorNotFound, what)
	}
	return g.chainErr(ctx, what, err)
}

// retentionHolds reports whether the signed validity window ends before the payload can be pruned. For da = 1 it reads the retention at the anchor
// height and never substitutes the latest value when that read fails.
func (g *Gate) retentionHolds(ctx context.Context, c *commitment.Commitment, a Anchor, blockTime, latest uint64) (bool, error) {
	switch c.PayloadRef.DA {
	case commitment.DAFibre:
		atH, err := g.fibreRetention(ctx, c.PayloadRef.Height)
		if err != nil {
			if cerr := ctx.Err(); cerr != nil {
				return false, fmt.Errorf("gate: %w", cerr)
			}
			return false, fmt.Errorf("%w: height %d: %w", ErrRetentionUnavailable, c.PayloadRef.Height, err)
		}
		if a.RetentionStart == 0 {
			return false, nil
		}
		return commitment.WithinRetention(c, min(blockTime, a.RetentionStart), min(latest, atH)), nil
	case commitment.DACelestiaBlob:
		return commitment.WithinRetention(c, blockTime, g.cfg.BlobRetentionS), nil
	}
	return false, nil
}

func (g *Gate) execute(ctx context.Context, req ExecRequest) (res ExecResult, err error) {
	ctx, cancel := context.WithTimeout(ctx, g.cfg.ExecTimeout)
	defer cancel()
	defer func() {
		if r := recover(); r != nil {
			res, err = ExecResult{}, fmt.Errorf("executor panicked: %v", r)
		}
	}()
	return g.d.Executor.Execute(ctx, req)
}

func (g *Gate) chainCtx(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, g.cfg.ChainTimeout)
}

func (g *Gate) fibreRetention(ctx context.Context, height uint64) (uint64, error) {
	ctx, cancel := g.chainCtx(ctx)
	defer cancel()
	return g.d.Params.FibreRetention(ctx, height)
}

func (g *Gate) allowlistKey(ctx context.Context, id string) ([32]byte, error) {
	ctx, cancel := g.chainCtx(ctx)
	defer cancel()
	return g.d.Allowlist.PubKey(ctx, id)
}

func (g *Gate) findAnchor(ctx context.Context, ref commitment.PayloadRef) (Anchor, error) {
	ctx, cancel := g.chainCtx(ctx)
	defer cancel()
	return g.d.Anchors.FindAnchor(ctx, ref)
}

func (g *Gate) blockTime(ctx context.Context, height uint64) (uint64, error) {
	ctx, cancel := g.chainCtx(ctx)
	defer cancel()
	return g.d.Headers.BlockTime(ctx, height)
}

// sign runs the signer under a timeout and turns a panic into an error, so a
// broken signer leaves an Executed entry without a receipt.
func (g *Gate) sign(ctx context.Context, msg []byte) (sig []byte, err error) {
	ctx, cancel := context.WithTimeout(ctx, g.cfg.ExecTimeout)
	defer cancel()
	defer func() {
		if r := recover(); r != nil {
			sig, err = nil, fmt.Errorf("signer panicked: %v", r)
		}
	}()
	return g.d.Signer.Sign(ctx, msg)
}

func (g *Gate) signReceipt(ctx context.Context, h commitment.Hash, path registry.Path, ref string, executedAt uint64) ([]byte, error) {
	r := commitment.Receipt{
		CommitmentHash: h[:],
		GateID:         g.cfg.Scope.GateID,
		GatePubKey:     g.signerPub,
		Rail:           g.cfg.Scope.Rail,
		RailRef:        ref,
		Path:           commitment.ReceiptPath(path),
		ExecutedAt:     executedAt,
	}
	canon, err := commitment.EncodeReceipt(&r)
	if err != nil {
		return nil, err
	}
	sig, err := g.sign(ctx, commitment.ReceiptSigningMessage(commitment.HashReceipt(canon)))
	if err != nil {
		return nil, err
	}
	b, err := commitment.EncodeSignedReceipt(&commitment.SignedReceipt{Receipt: r, Signature: sig})
	if err != nil {
		return nil, err
	}
	if _, _, err := commitment.VerifyReceipt(b); err != nil {
		return nil, fmt.Errorf("receipt does not verify: %w", err)
	}
	return b, nil
}

// Prune deletes terminal entries that can no longer pass the time check. It
// uses the persisted watermark, so a clock that jumps forward cannot prune
// early.
func (g *Gate) Prune(ctx context.Context) (int, error) {
	if g.closed.Load() {
		return 0, ErrClosed
	}
	m, err := g.d.Registry.Meta(ctx)
	if err != nil {
		return 0, fmt.Errorf("%w: meta: %w", ErrRegistryUnavailable, err)
	}
	if m.Watermark <= g.cfg.PruneGrace {
		return 0, nil
	}
	n, err := g.d.Registry.Prune(ctx, m.Watermark-g.cfg.PruneGrace)
	if err != nil {
		return 0, fmt.Errorf("%w: prune: %w", ErrRegistryUnavailable, err)
	}
	return n, nil
}
