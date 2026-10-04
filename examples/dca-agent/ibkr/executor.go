package ibkr

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"math/bits"
	"time"

	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/examples/dca-agent/ibkrorder"
)

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
	// ExecTimeout bounds one broker call; zero means 30 seconds.
	ExecTimeout time.Duration
	Check       CheckConfig
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
	if err := commitment.CheckPublicKey(cfg.GatePubKey); err != nil {
		return nil, fmt.Errorf("ibkr: gate key: %w", err)
	}
	if cfg.GateID == "" {
		return nil, errors.New("ibkr: empty gate id")
	}
	if cfg.Check.Account == "" {
		return nil, errors.New("ibkr: empty account")
	}
	if cfg.SkewS > maxSkewS {
		return nil, fmt.Errorf("ibkr: skew %d above %d", cfg.SkewS, maxSkewS)
	}
	if cfg.ExecTimeout < 0 {
		return nil, errors.New("ibkr: negative exec timeout")
	}
	if cfg.ExecTimeout == 0 {
		cfg.ExecTimeout = defaultExecTimeout
	}
	if b == nil || s == nil || c == nil {
		return nil, errors.New("ibkr: nil broker, store or clock")
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
		return e.resolve(ctx, h, cid)
	default:
		return "", fmt.Errorf("ibkr: begin: %w", err)
	}

	if err := ctx.Err(); err != nil {
		return "", fmt.Errorf("%w: %w", ErrOutcomeUnknown, err)
	}
	if horizon, carry := bits.Add64(e.now(), e.cfg.SkewS, 0); carry != 0 || horizon >= expires {
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

// resolve handles a commitment that already has a record. A finished record
// reports its order with ErrSeen. An in-flight record is resolved by lookup
// only; the order is never sent again.
func (e *Executor) resolve(ctx context.Context, h commitment.Hash, cid string) (string, error) {
	rec, err := e.store.Get(ctx, h)
	if err != nil {
		return "", fmt.Errorf("ibkr: get: %w", err)
	}
	if !rec.InFlight() {
		return rec.OrderID, ErrSeen
	}
	lctx, cancel := context.WithTimeout(ctx, e.cfg.ExecTimeout)
	defer cancel()
	id, found, err := e.broker.LookupByClientOrderID(lctx, cid)
	if err != nil {
		return "", fmt.Errorf("%w: lookup: %w", ErrOutcomeUnknown, err)
	}
	if !found || id == "" {
		return "", fmt.Errorf("%w: not found at the broker", ErrOutcomeUnknown)
	}
	if err := e.store.Finish(ctx, h, id); err != nil {
		return "", fmt.Errorf("%w: order %s found, record not finished: %w", ErrOutcomeUnknown, id, err)
	}
	return id, nil
}
