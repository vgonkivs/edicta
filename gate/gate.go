package gate

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"math/bits"
	"reflect"
	"slices"
	"sync/atomic"

	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/gate/registry"
)

// Gate is safe for concurrent use. It starts no goroutines.
type Gate struct {
	cfg       Config
	d         Deps
	log       *slog.Logger
	gateKeys  map[[32]byte]struct{}
	executors map[[32]byte]struct{}
	signerPub []byte
	epoch     uint64
	watermark atomic.Uint64
	sem       *weightedSem
	release   func()
	closed    atomic.Bool
}

type Result struct {
	CommitmentHash commitment.Hash // zero if rejected before the signature check passed
	ActionHash     commitment.Hash // zero if rejected before the action bytes were checked
	Path           registry.Path   // 0 until a payload path was accepted
	// DecisionArchived is set once the archive stage succeeded.
	DecisionArchived bool
	// AuthorizedAt is the clock reading of the Authorization; zero on a refusal.
	AuthorizedAt uint64
	// Authorization is the canonical SignedAuthorization. It is set on
	// success, and with ErrNonceUsed when the same commitment is presented
	// again with the committed action bytes.
	Authorization []byte
	// K2 holds the inputs of the retention decision, for archiving. It is
	// zero until the decision was made.
	K2 K2Inputs
}

// K2Inputs are the values the path selection used. The retention fields are
// set for da = 1 only.
type K2Inputs struct {
	DA                 commitment.DA
	BlobRetentionS     uint64          // da = 2 only
	RetentionSource    RetentionSource // zero if the params do not report one
	CheckedAt          uint64          // the clock reading the checks ran at
	BlockTime          uint64
	RetentionStart     uint64
	RetentionLatestS   uint64
	RetentionAtHeightS uint64
}

// checkScope validates the gate id and the action type allowlist.
func checkScope(sc commitment.GateScope) error {
	if n := len(sc.GateID); n < 1 || n > 64 {
		return fmt.Errorf("gate id length %d", n)
	}
	for i := 0; i < len(sc.GateID); i++ {
		c := sc.GateID[i]
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' ||
			c == '.' || c == '_' || c == ':' || c == '/' || c == '-') {
			return errors.New("gate id has a character outside the id charset")
		}
	}
	if len(sc.ActionTypes) == 0 {
		return errors.New("no action types")
	}
	seen := make(map[string]struct{}, len(sc.ActionTypes))
	for _, t := range sc.ActionTypes {
		if !commitment.ValidMediaType(t, 128) {
			return fmt.Errorf("action type %q is not a media type", t)
		}
		if _, dup := seen[t]; dup {
			return fmt.Errorf("duplicate action type %q", t)
		}
		seen[t] = struct{}{}
	}
	return nil
}

// hasKey is implemented by allowlists that can say whether a key is listed.
type hasKey interface{ HasKey(key [32]byte) bool }

// New validates the configuration and loads the registry metadata.
func New(ctx context.Context, cfg Config, d Deps) (*Gate, error) {
	cfg = cfg.withDefaults()
	if err := cfg.ValidateBasic(); err != nil {
		return nil, err
	}
	bad := func(format string, a ...any) error {
		return fmt.Errorf("%w: %s", ErrInvalidConfig, fmt.Sprintf(format, a...))
	}
	if d.Clock == nil || d.Params == nil || d.Headers == nil || d.Anchors == nil || d.DA == nil ||
		d.Archive == nil || d.Allowlist == nil || d.Registry == nil || d.Signer == nil {
		return nil, bad("missing dependency")
	}
	committers := make(map[commitment.DA]DACommitter, len(d.Committers))
	for da, c := range d.Committers {
		if !isNilCommitter(c) {
			committers[da] = c
		}
	}
	d.Committers = committers
	if d.Committers[commitment.DACelestiaBlob] == nil {
		return nil, bad("a committer for da = 2 is required")
	}
	if fc := d.Committers[commitment.DAFibre]; fc != nil {
		if mc, ok := fc.(interface{ MaxDataSize() uint64 }); ok && cfg.FibreMaxDataBytes > mc.MaxDataSize() {
			return nil, bad("fibre_max_data_bytes %d above the committer cap %d", cfg.FibreMaxDataBytes, mc.MaxDataSize())
		}
		if cfg.MaxFetchBytes/fibreFetchFactor < cfg.FibreMaxDataBytes {
			return nil, bad("max_fetch_bytes %d below %d times fibre_max_data_bytes %d",
				cfg.MaxFetchBytes, fibreFetchFactor, cfg.FibreMaxDataBytes)
		}
	}
	cfg.Scope.ActionTypes = slices.Clone(cfg.Scope.ActionTypes)
	cfg.AllowedDA = slices.Clone(cfg.AllowedDA)

	g := &Gate{cfg: cfg, d: d, log: d.Logger, gateKeys: make(map[[32]byte]struct{}), sem: newWeightedSem(cfg.MaxFetchBytes)}
	if g.log == nil {
		g.log = slog.Default()
	}
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
	g.executors = make(map[[32]byte]struct{}, len(cfg.ExecutorKeys))
	for i, k := range cfg.ExecutorKeys {
		if err := commitment.CheckPublicKey(k[:]); err != nil {
			return nil, fmt.Errorf("gate: executor key %d: %w", i, err)
		}
		if _, ok := g.gateKeys[k]; ok {
			return nil, fmt.Errorf("%w: executor key %d is a gate key", commitment.ErrKeyRole, i)
		}
		if hk, ok := d.Allowlist.(hasKey); ok && hk.HasKey(k) {
			return nil, fmt.Errorf("%w: executor key %d is an agent key", commitment.ErrKeyRole, i)
		}
		g.executors[k] = struct{}{}
	}
	cfg.ExecutorKeys = slices.Clone(cfg.ExecutorKeys)
	g.cfg = cfg

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

// Authorize verifies the envelope and, if every check passes, signs an
// Authorization for exactly the presented action bytes, consumes the nonce
// and stores the Authorization in one registry transaction, and only then
// returns it. A nonce that is already used gives ErrNonceUsed; the stored
// Authorization comes back with it only if the same commitment is presented
// with the committed action bytes.
func (g *Gate) Authorize(ctx context.Context, envelope, action []byte) (res Result, err error) {
	var ev AdmissionEvent
	defer func() {
		if g.d.Metrics != nil {
			ev.CommitmentHash, ev.Path, ev.Authorized, ev.Err = res.CommitmentHash, res.Path, err == nil, err
			g.d.Metrics.Admission(ev)
		}
	}()
	return g.authorize(ctx, envelope, action, &ev)
}

func (g *Gate) authorize(ctx context.Context, envelope, action []byte, ev *AdmissionEvent) (Result, error) {
	envelope = bytes.Clone(envelope)
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

	// The latest Fibre retention is read only for a da = 1 commitment that
	// this gate allows. Otherwise the placeholder merely satisfies
	// Params.Validate; a da = 1 commitment the gate does not allow is refused
	// right after verification, so the value never admits anything.
	latest := uint64(math.MaxInt64)
	if pre, derr := commitment.DecodeSigned(envelope); derr == nil &&
		pre.Commitment.PayloadRef.DA == commitment.DAFibre && daAllowed(g.cfg.AllowedDA, commitment.DAFibre) {
		var err error
		latest, err = g.fibreRetention(ctx, 0)
		if err != nil {
			return Result{}, g.chainErr(ctx, "fibre retention", err)
		}
	}
	p := commitment.Params{FibreRetentionS: latest, BlobRetentionS: g.cfg.BlobRetentionS, SkewS: g.cfg.SkewS}

	// Stateless verification: decoding, validation, signature, time, scope,
	// action type.
	s, h, err := commitment.VerifyForGate(envelope, now, g.cfg.Scope, p)
	if err != nil {
		return Result{}, err
	}
	c := &s.Commitment
	ev.DA = c.PayloadRef.DA
	res := Result{CommitmentHash: h}
	if !daAllowed(g.cfg.AllowedDA, c.PayloadRef.DA) {
		return res, fmt.Errorf("%w: da %d", ErrDANotAllowed, c.PayloadRef.DA)
	}
	if c.PayloadRef.DA == commitment.DAFibre && g.d.Committers[commitment.DAFibre] != nil &&
		c.PayloadSize > g.cfg.FibreMaxDataBytes {
		return res, fmt.Errorf("%w: payload_size %d, limit %d", ErrPayloadAboveCap, c.PayloadSize, g.cfg.FibreMaxDataBytes)
	}

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

	// The presented bytes must be exactly the committed ones. This runs before
	// any registry read, so bytes that do not match learn nothing about a
	// used nonce.
	if err := commitment.CheckAction(c, action); err != nil {
		return res, err
	}
	copy(res.ActionHash[:], c.Action.Hash)

	// Archive the decision before any nonce read, so a request that is
	// refused later or retried still leaves the signed decision behind.
	if g.d.Archiver != nil {
		if err := g.archiveDecision(ctx, h, envelope, action); err != nil {
			return res, err
		}
		res.DecisionArchived = true
	}

	// Advisory nonce check.
	key := registry.Key{PubKey: agentKey}
	copy(key.Nonce[:], c.Nonce)
	switch old, err := g.d.Registry.Get(ctx, key); {
	case err == nil:
		return g.replayArchived(res, old)
	case !errors.Is(err, registry.ErrNotFound):
		return res, fmt.Errorf("%w: %w", ErrRegistryUnavailable, err)
	}

	// Other calls may have raised the watermark while the registry was read.
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
	within, atH, src, err := g.retentionHolds(ctx, c, anchor, blockTime, latest)
	if err != nil {
		return res, err
	}
	res.K2 = K2Inputs{DA: c.PayloadRef.DA, CheckedAt: now, BlockTime: blockTime}
	switch c.PayloadRef.DA {
	case commitment.DAFibre:
		res.K2.RetentionStart, res.K2.RetentionLatestS, res.K2.RetentionAtHeightS = anchor.RetentionStart, latest, atH
		res.K2.RetentionSource = src
	case commitment.DACelestiaBlob:
		res.K2.BlobRetentionS = g.cfg.BlobRetentionS
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

	// Sign. Nothing is written yet, so a failing signer burns no nonce.
	if err := ctx.Err(); err != nil {
		return res, fmt.Errorf("gate: %w", err)
	}
	expires := min(c.ValidUntil, satAdd(now2, g.cfg.MaxAuthorizationTTL))
	signed, err := g.signAuthorization(ctx, h, res.ActionHash, c, action, path, expires, now2)
	if err != nil {
		return res, err
	}

	// Consume the nonce and store the Authorization in one transaction. The
	// Authorization leaves the gate only after this commit.
	if err := ctx.Err(); err != nil {
		return res, fmt.Errorf("gate: %w", err)
	}
	entry := registry.Entry{
		Key: key, CommitmentHash: h, ActionHash: res.ActionHash, Path: path,
		AuthorizedAt: now2, ValidUntil: c.ValidUntil, Authorization: signed,
	}
	if err := g.d.Registry.Consume(ctx, entry, g.cfg.ClockTolerance); err != nil {
		var ee *registry.ExistsError
		if errors.As(err, &ee) {
			return g.replayArchived(res, ee.Existing)
		}
		if errors.Is(err, registry.ErrBelowWatermark) || errors.Is(err, registry.ErrPrunedWindow) {
			return res, fmt.Errorf("%w: %w", ErrClockRegression, err)
		}
		return res, fmt.Errorf("%w: consume: %w", ErrRegistryUnavailable, err)
	}
	g.bumpWatermark(now2)
	res.Authorization = bytes.Clone(signed)
	res.AuthorizedAt = now2
	return res, nil
}

// archiveDecision writes the decision record under its own deadline. A done
// parent context is the caller's, not an archive fault.
func (g *Gate) archiveDecision(ctx context.Context, h commitment.Hash, envelope, action []byte) error {
	wctx, cancel := context.WithTimeout(ctx, g.cfg.ArchiveWriteTimeout)
	defer cancel()
	err := g.d.Archiver.Put(wctx, DecisionRecord{CommitmentHash: h, Envelope: bytes.Clone(envelope), Action: bytes.Clone(action)})
	if err == nil {
		return nil
	}
	if cerr := ctx.Err(); cerr != nil {
		return fmt.Errorf("gate: %w", cerr)
	}
	return fmt.Errorf("%w: %w", ErrArchiveUnavailable, err)
}

// replayArchived is replay that keeps what the earlier stages already set.
func (g *Gate) replayArchived(pre Result, old registry.Entry) (Result, error) {
	res, err := g.replay(pre.CommitmentHash, pre.ActionHash, old)
	res.DecisionArchived = pre.DecisionArchived
	return res, err
}

// replay answers a presentation whose nonce is already used. The signed
// Authorization stored with the entry is the source of truth: it is handed
// out only if it names this commitment and the presented action hash.
// Otherwise it reports the used nonce and nothing of the entry, or a mismatch
// if the stored token disagrees with the commitment.
func (g *Gate) replay(h, actionHash commitment.Hash, old registry.Entry) (Result, error) {
	res := Result{CommitmentHash: h}
	if old.CommitmentHash != h {
		return res, ErrNonceUsed
	}
	res.ActionHash = actionHash
	sa, ah, err := commitment.DecodeSignedAuthorization(old.Authorization)
	if err != nil ||
		!ed25519.Verify(g.signerPub, commitment.AuthorizationSigningMessage(ah), sa.Signature) ||
		subtle.ConstantTimeCompare(sa.Authorization.CommitmentHash, h[:]) != 1 ||
		subtle.ConstantTimeCompare(sa.Authorization.ActionHash, actionHash[:]) != 1 {
		g.log.Error("stored authorization disagrees with the commitment",
			"commitment_hash", hex.EncodeToString(h[:]),
			"action_hash", hex.EncodeToString(actionHash[:]))
		if g.d.Metrics != nil {
			g.d.Metrics.StoredActionMismatch(h)
		}
		return res, fmt.Errorf("%w: stored authorization disagrees", commitment.ErrActionMismatch)
	}
	res.Path = old.Path
	res.AuthorizedAt = old.AuthorizedAt
	res.Authorization = bytes.Clone(old.Authorization)
	return res, ErrNonceUsed
}

// signAuthorization builds, signs and self-verifies the Authorization.
func (g *Gate) signAuthorization(ctx context.Context, h, actionHash commitment.Hash, c *commitment.Commitment, action []byte, path registry.Path, expires, now uint64) ([]byte, error) {
	a := commitment.Authorization{
		CommitmentHash: h[:],
		ActionHash:     actionHash[:],
		GateID:         g.cfg.Scope.GateID,
		Expires:        expires,
		Path:           commitment.PayloadPath(path),
	}
	canon, err := commitment.EncodeAuthorization(&a)
	if err != nil {
		return nil, fmt.Errorf("gate: encode authorization: %w", err)
	}
	sig, err := g.sign(ctx, commitment.AuthorizationSigningMessage(commitment.HashAuthorization(canon)))
	if err != nil {
		return nil, fmt.Errorf("gate: sign authorization: %w", err)
	}
	b, err := commitment.EncodeSignedAuthorization(&commitment.SignedAuthorization{Authorization: a, Signature: sig})
	if err != nil {
		return nil, fmt.Errorf("gate: encode signed authorization: %w", err)
	}
	_, _, err = commitment.VerifyAuthorization(b, commitment.AuthorizationCheck{
		GatePubKey: g.signerPub, GateID: g.cfg.Scope.GateID, ActionType: c.Action.Type,
		Action: action, Now: now, SkewS: g.cfg.SkewS,
	})
	if err != nil {
		return nil, fmt.Errorf("gate: authorization does not verify: %w", err)
	}
	return b, nil
}

// Record attests the rail reference that the integrator reports for an
// authorized commitment and returns the canonical SignedReceipt. The receipt
// is the gate's record of the claim, not proof of execution. At most one
// receipt is stored per decision; a second call returns it with
// ErrReceiptExists.
func (g *Gate) Record(ctx context.Context, envelope []byte, railRef string, executorPub ed25519.PublicKey, executorSig []byte) ([]byte, error) {
	if g.closed.Load() {
		return nil, ErrClosed
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("gate: %w", err)
	}
	s, err := commitment.DecodeSigned(envelope)
	if err != nil {
		return nil, err
	}
	h, err := commitment.HashOf(&s.Commitment)
	if err != nil {
		return nil, err
	}
	if err := commitment.VerifyRecordRequest(h, g.cfg.Scope.GateID, railRef, executorPub, executorSig); err != nil {
		return nil, err
	}
	var ek [32]byte
	copy(ek[:], executorPub)
	if _, ok := g.executors[ek]; !ok {
		return nil, ErrExecutorNotAllowed
	}
	if _, isGate := g.gateKeys[ek]; isGate || bytes.Equal(executorPub, s.Commitment.AgentPubKey) {
		return nil, fmt.Errorf("%w: executor key", commitment.ErrKeyRole)
	}
	var key registry.Key
	copy(key.PubKey[:], s.Commitment.AgentPubKey)
	copy(key.Nonce[:], s.Commitment.Nonce)

	ent, err := g.d.Registry.Get(ctx, key)
	switch {
	case errors.Is(err, registry.ErrNotFound):
		return nil, ErrNotAuthorized
	case err != nil:
		return nil, fmt.Errorf("%w: %w", ErrRegistryUnavailable, err)
	case ent.CommitmentHash != h:
		return nil, ErrNotAuthorized
	case len(ent.Receipt) != 0:
		return bytes.Clone(ent.Receipt), ErrReceiptExists
	}

	at := g.now()
	if at == 0 {
		return nil, fmt.Errorf("%w: now %d", ErrClockRegression, at)
	}
	receipt, err := g.signReceipt(ctx, h, railRef, executorPub, executorSig, at)
	if err != nil {
		return nil, err
	}
	switch err := g.d.Registry.AttachReceipt(ctx, key, h, receipt); {
	case err == nil:
		return receipt, nil
	case errors.Is(err, registry.ErrNotFound):
		return nil, ErrNotAuthorized
	case errors.Is(err, registry.ErrStateConflict):
		// Another call attached its receipt first; only the stored one counts.
		cur, gerr := g.d.Registry.Get(ctx, key)
		if gerr == nil && cur.CommitmentHash == h && len(cur.Receipt) != 0 {
			return bytes.Clone(cur.Receipt), ErrReceiptExists
		}
		return nil, fmt.Errorf("%w: attach receipt: %w", ErrRegistryUnavailable, err)
	default:
		return nil, fmt.Errorf("%w: attach receipt: %w", ErrRegistryUnavailable, err)
	}
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
func (g *Gate) retentionHolds(ctx context.Context, c *commitment.Commitment, a Anchor, blockTime, latest uint64) (within bool, atH uint64, src RetentionSource, err error) {
	switch c.PayloadRef.DA {
	case commitment.DAFibre:
		atH, src, err = g.fibreRetentionSourced(ctx, c.PayloadRef.Height)
		if err != nil {
			if cerr := ctx.Err(); cerr != nil {
				return false, 0, 0, fmt.Errorf("gate: %w", cerr)
			}
			return false, 0, 0, fmt.Errorf("%w: height %d: %w", ErrRetentionUnavailable, c.PayloadRef.Height, err)
		}
		if a.RetentionStart == 0 {
			return false, atH, src, nil
		}
		return commitment.WithinRetention(c, min(blockTime, a.RetentionStart), min(latest, atH)), atH, src, nil
	case commitment.DACelestiaBlob:
		return commitment.WithinRetention(c, blockTime, g.cfg.BlobRetentionS), 0, 0, nil
	}
	return false, 0, 0, nil
}

func (g *Gate) chainCtx(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, g.cfg.ChainTimeout)
}

func (g *Gate) fibreRetention(ctx context.Context, height uint64) (uint64, error) {
	ctx, cancel := g.chainCtx(ctx)
	defer cancel()
	return g.d.Params.FibreRetention(ctx, height)
}

// fibreRetentionSourced reports the source when the params can; otherwise it
// is zero.
func (g *Gate) fibreRetentionSourced(ctx context.Context, height uint64) (uint64, RetentionSource, error) {
	sp, ok := g.d.Params.(SourcedChainParams)
	if !ok {
		v, err := g.fibreRetention(ctx, height)
		return v, 0, err
	}
	ctx, cancel := g.chainCtx(ctx)
	defer cancel()
	return sp.FibreRetentionSourced(ctx, height)
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
// broken signer cannot hang or crash the gate.
func (g *Gate) sign(ctx context.Context, msg []byte) (sig []byte, err error) {
	ctx, cancel := context.WithTimeout(ctx, g.cfg.SignTimeout)
	defer cancel()
	defer func() {
		if r := recover(); r != nil {
			sig, err = nil, fmt.Errorf("signer panicked: %v", r)
		}
	}()
	return g.d.Signer.Sign(ctx, msg)
}

func (g *Gate) signReceipt(ctx context.Context, h commitment.Hash, ref string, executorPub, executorSig []byte, recordedAt uint64) ([]byte, error) {
	r := commitment.Receipt{
		CommitmentHash: h[:],
		GateID:         g.cfg.Scope.GateID,
		GatePubKey:     g.signerPub,
		RailRef:        ref,
		RecordedAt:     recordedAt,

		ExecutorPubKey:    bytes.Clone(executorPub),
		ExecutorSignature: bytes.Clone(executorSig),
	}
	canon, err := commitment.EncodeReceipt(&r)
	if err != nil {
		return nil, err
	}
	// Reject an invalid reference before spending a signature.
	probe, err := commitment.EncodeSignedReceipt(&commitment.SignedReceipt{Receipt: r, Signature: make([]byte, 64)})
	if err != nil {
		return nil, err
	}
	if _, _, err := commitment.DecodeSignedReceipt(probe); err != nil {
		return nil, err
	}
	sig, err := g.sign(ctx, commitment.ReceiptSigningMessage(commitment.HashReceipt(canon)))
	if err != nil {
		return nil, fmt.Errorf("gate: sign receipt: %w", err)
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

// Prune deletes the entries whose decision can no longer pass the time check. It
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

// PublicKey is the gate key that verifies Authorizations and receipts.
func (g *Gate) PublicKey() ed25519.PublicKey { return bytes.Clone(g.signerPub) }

// normalizeDA returns a private copy of the allowed set; empty means {1, 2}.
func isNilCommitter(c DACommitter) bool {
	if c == nil {
		return true
	}
	v := reflect.ValueOf(c)
	switch v.Kind() {
	case reflect.Pointer, reflect.Map, reflect.Slice, reflect.Func, reflect.Chan, reflect.Interface:
		return v.IsNil()
	}
	return false
}

func normalizeDA(in []commitment.DA) ([]commitment.DA, error) {
	if len(in) == 0 {
		return []commitment.DA{commitment.DAFibre, commitment.DACelestiaBlob}, nil
	}
	out := slices.Clone(in)
	for i, da := range out {
		if da != commitment.DAFibre && da != commitment.DACelestiaBlob {
			return nil, fmt.Errorf("allowed_da: unknown da %d", da)
		}
		if slices.Contains(out[:i], da) {
			return nil, fmt.Errorf("allowed_da: duplicate da %d", da)
		}
	}
	return out, nil
}

func daAllowed(set []commitment.DA, da commitment.DA) bool {
	if len(set) == 0 {
		return da == commitment.DAFibre || da == commitment.DACelestiaBlob
	}
	return slices.Contains(set, da)
}

// Preflight checks the configuration against the chain. When da = 1 is
// allowed the Fibre parameters must be readable; no chain call is made
// otherwise.
func Preflight(ctx context.Context, cfg Config, d Deps) error {
	allowed, err := normalizeDA(cfg.AllowedDA)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidConfig, err)
	}
	if !daAllowed(allowed, commitment.DAFibre) {
		return nil
	}
	if d.Params == nil {
		return fmt.Errorf("%w: missing chain params dependency", ErrInvalidConfig)
	}
	cctx, cancel := ctx, context.CancelFunc(func() {})
	if cfg.ChainTimeout > 0 {
		cctx, cancel = context.WithTimeout(ctx, cfg.ChainTimeout)
	}
	defer cancel()
	if _, err := d.Params.FibreRetention(cctx, 0); err != nil {
		return fmt.Errorf("%w: fibre (da=1) is allowed but the chain has no x/fibre or it is unreachable: %w", ErrInvalidConfig, err)
	}
	return nil
}
