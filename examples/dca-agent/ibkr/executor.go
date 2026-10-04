package ibkr

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"math/bits"
	"time"

	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/examples/dca-agent/ibkrorder"
)

// ErrInvalidConfig means NewExecutor refused its configuration.
var ErrInvalidConfig = errors.New("ibkr: invalid configuration")

// ErrOutcomeUnknown means the order may or may not exist at the broker. The
// record stays in flight; a later Execute resolves it by lookup and never by
// sending again.
var ErrOutcomeUnknown = errors.New("ibkr: order outcome unknown")

const (
	maxSkewS           = 300
	defaultExecTimeout = 30 * time.Second
)

// Clock is the executor's time source.
type Clock interface{ Now() time.Time }

// ExecutorConfig pins the gate and the operator's limits.
type ExecutorConfig struct {
	GatePubKey ed25519.PublicKey
	GateID     string
	// SkewS is the clock tolerance, 0..300.
	SkewS uint64
	// SettleS is how long after expires plus skew the executor waits before
	// it treats "not found at the broker" as final. Must be above zero.
	SettleS uint64
	// ExecTimeout bounds one broker call; zero means 30 seconds.
	ExecTimeout time.Duration
	Check       CheckConfig
	// SignKey is the executor's own key for record requests. Optional: without
	// it RecordRequest fails. It must be on the gate's executor allowlist.
	SignKey ed25519.PrivateKey
}

// Executor places an authorized order once.
type Executor struct {
	cfg    ExecutorConfig
	broker Broker
	store  Store
	clock  Clock
}

// NewExecutor validates cfg and the dependencies.
func NewExecutor(cfg ExecutorConfig, b Broker, s Store, c Clock) (*Executor, error) {
	bad := func(format string, a ...any) error {
		return fmt.Errorf("%w: %s", ErrInvalidConfig, fmt.Sprintf(format, a...))
	}
	if err := commitment.CheckPublicKey(cfg.GatePubKey); err != nil {
		return nil, fmt.Errorf("%w: gate key: %w", ErrInvalidConfig, err)
	}
	switch {
	case cfg.GateID == "":
		return nil, bad("empty gate id")
	case cfg.Check.Account == "":
		return nil, bad("empty account")
	case cfg.SkewS > maxSkewS:
		return nil, bad("skew %d above %d", cfg.SkewS, maxSkewS)
	case cfg.SettleS == 0:
		return nil, bad("settle time is zero")
	case cfg.SignKey != nil && len(cfg.SignKey) != ed25519.PrivateKeySize:
		return nil, bad("sign key length")
	case cfg.ExecTimeout < 0:
		return nil, bad("negative exec timeout")
	case b == nil || s == nil || c == nil:
		return nil, bad("nil broker, store or clock")
	}
	cfg.SignKey = bytes.Clone(cfg.SignKey)
	if cfg.ExecTimeout == 0 {
		cfg.ExecTimeout = defaultExecTimeout
	}
	return &Executor{cfg: cfg, broker: b, store: s, clock: c}, nil
}

func (e *Executor) now() uint64 {
	t := e.clock.Now().Unix()
	if t < 0 {
		return 0
	}
	return uint64(t)
}

// Execute verifies the authorization for exactly these action bytes, parses
// them as they are, applies the executor's checks, and places the order once.
// It returns the broker's order id. ErrSeen comes with the stored id of an
// order already placed.
func (e *Executor) Execute(ctx context.Context, authorization, action []byte) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	action = bytes.Clone(action)
	sa, _, err := commitment.VerifyAuthorization(authorization, commitment.AuthorizationCheck{
		GatePubKey: e.cfg.GatePubKey, GateID: e.cfg.GateID, ActionType: ibkrorder.ActionType,
		Action: action, Now: e.now(), SkewS: e.cfg.SkewS,
	})
	if err != nil {
		return "", err
	}
	o, err := CheckOrder(e.cfg.Check, action)
	if err != nil {
		return "", err
	}
	var h commitment.Hash
	if copy(h[:], sa.Authorization.CommitmentHash) != len(h) {
		return "", fmt.Errorf("%w: commitment hash length", commitment.ErrActionMismatch)
	}
	expires := sa.Authorization.Expires
	cid := ClientOrderID(h)

	switch err := e.store.Begin(ctx, h, expires); {
	case err == nil:
	case errors.Is(err, ErrSeen):
		id, finished, err := e.reconcile(ctx, h)
		if err == nil && finished {
			return id, ErrSeen
		}
		return id, err
	default:
		return "", fmt.Errorf("ibkr: begin: %w", err)
	}

	if err := ctx.Err(); err != nil {
		return "", fmt.Errorf("%w: %w", ErrOutcomeUnknown, err)
	}
	if horizon, carry := bits.Add64(e.now(), e.cfg.SkewS, 0); carry != 0 || horizon >= expires {
		// Nothing was sent, so the record can be closed at once.
		if aerr := e.store.Abandon(ctx, h); aerr != nil {
			return "", fmt.Errorf("%w before placement; closing the record: %w", commitment.ErrExpired, aerr)
		}
		return "", fmt.Errorf("%w before placement", commitment.ErrExpired)
	}

	pctx, cancel := context.WithTimeout(ctx, e.cfg.ExecTimeout)
	defer cancel()
	id, err := e.broker.Place(pctx, RequestFromOrder(o, cid))
	if err != nil {
		return "", fmt.Errorf("%w: place: %w", ErrOutcomeUnknown, err)
	}
	if id == "" {
		return "", fmt.Errorf("%w: broker returned no order id", ErrOutcomeUnknown)
	}
	if err := e.store.Finish(ctx, h, id); err != nil {
		return "", fmt.Errorf("%w: order %s placed, record not finished: %w", ErrOutcomeUnknown, id, err)
	}
	return id, nil
}

// Reconcile resolves a commitment's record by lookup only; it never places and
// needs no live Authorization. A finished record returns its order id. A found
// order finishes the record. "Not found" closes the record (ErrNotPlaced) only
// after expires + skew + SettleS; before that, and on any lookup error, the
// outcome stays unknown and the record stays in flight.
func (e *Executor) Reconcile(ctx context.Context, h commitment.Hash) (string, error) {
	id, _, err := e.reconcile(ctx, h)
	return id, err
}

// reconcile also reports whether the record was already finished before the
// call.
func (e *Executor) reconcile(ctx context.Context, h commitment.Hash) (string, bool, error) {
	rec, err := e.store.Get(ctx, h)
	if err != nil {
		return "", false, fmt.Errorf("ibkr: get: %w", err)
	}
	switch {
	case rec.NotPlaced:
		return "", false, ErrNotPlaced
	case !rec.InFlight():
		return rec.OrderID, true, nil
	}
	lctx, cancel := context.WithTimeout(ctx, e.cfg.ExecTimeout)
	defer cancel()
	id, found, err := e.broker.LookupByClientOrderID(lctx, ClientOrderID(h))
	if err != nil {
		return "", false, fmt.Errorf("%w: lookup: %w", ErrOutcomeUnknown, err)
	}
	if found && id != "" {
		if err := e.store.Finish(ctx, h, id); err != nil {
			return "", false, fmt.Errorf("%w: order %s found, record not finished: %w", ErrOutcomeUnknown, id, err)
		}
		return id, false, nil
	}
	final, c1 := bits.Add64(rec.Expires, e.cfg.SkewS, 0)
	final, c2 := bits.Add64(final, e.cfg.SettleS, 0)
	if c1 == 0 && c2 == 0 && e.now() >= final {
		if err := e.store.Abandon(ctx, h); err != nil {
			return "", false, fmt.Errorf("%w: closing the record: %w", ErrOutcomeUnknown, err)
		}
		return "", false, ErrNotPlaced
	}
	return "", false, fmt.Errorf("%w: not found at the broker", ErrOutcomeUnknown)
}

// RecordRequest signs the executor's claim that railRef belongs to the
// decision h, for the gate's Record. It returns the executor's public key and
// the signature.
func (e *Executor) RecordRequest(h commitment.Hash, railRef string) (ed25519.PublicKey, []byte, error) {
	if e.cfg.SignKey == nil {
		return nil, nil, errors.New("ibkr: no sign key configured")
	}
	msg, err := commitment.RecordRequestMessage(h, e.cfg.GateID, railRef)
	if err != nil {
		return nil, nil, err
	}
	pub, ok := e.cfg.SignKey.Public().(ed25519.PublicKey)
	if !ok {
		return nil, nil, errors.New("ibkr: bad sign key")
	}
	return pub, ed25519.Sign(e.cfg.SignKey, msg), nil
}
