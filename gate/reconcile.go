package gate

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/vgonkivs/prior/commitment"
	"github.com/vgonkivs/prior/gate/registry"
)

type ManualOutcome uint8

const (
	ManualExecuted ManualOutcome = iota + 1 // the operator confirmed the order exists at the rail
	ManualRejected                          // the operator confirmed no order exists and none can appear
)

type ManualResolution struct {
	Outcome  ManualOutcome
	RailRef  string // required for ManualExecuted, empty for ManualRejected
	Operator string // ID charset, 1..64
	Note     string // printable ASCII, 1..512
}

func (r ManualResolution) valid() bool {
	if !validID(r.Operator, 64) || len(r.Note) < 1 || len(r.Note) > 512 {
		return false
	}
	for i := 0; i < len(r.Note); i++ {
		if r.Note[i] < 0x20 || r.Note[i] > 0x7e {
			return false
		}
	}
	switch r.Outcome {
	case ManualExecuted:
		return validID(r.RailRef, 128)
	case ManualRejected:
		return r.RailRef == ""
	}
	return false
}

// Reconcile resolves entries whose outcome is unknown by looking the order
// up at the rail, and signs receipts that are still missing. It never
// executes anything. An entry that another resolver changed first is skipped.
func (g *Gate) Reconcile(ctx context.Context) (ReconcileReport, error) {
	var rep ReconcileReport
	if g.closed.Load() {
		return rep, ErrClosed
	}
	pending, err := g.d.Registry.Pending(ctx)
	if err != nil {
		return rep, fmt.Errorf("%w: pending: %w", ErrRegistryUnavailable, err)
	}
	sort.Slice(pending, func(i, j int) bool { return pending[i].ReservedAt < pending[j].ReservedAt })
	var errs []error
	for _, e := range pending {
		if err := ctx.Err(); err != nil {
			return rep, fmt.Errorf("gate: %w", err)
		}
		var err error
		switch e.State {
		case registry.StateUnknown:
			err = g.reconcileOne(ctx, e, &rep)
		case registry.StateExecuted:
			err = g.resign(ctx, e)
		}
		if err != nil && !errors.Is(err, registry.ErrStateConflict) {
			errs = append(errs, err)
		}
	}
	return rep, errors.Join(errs...)
}

func (g *Gate) reconcileOne(ctx context.Context, e registry.Entry, rep *ReconcileReport) error {
	now := g.now()
	if now == 0 {
		rep.StillUnknown++
		return fmt.Errorf("%w: now %d", ErrClockRegression, now)
	}
	coid, err := commitment.ClientOrderID(g.cfg.Scope.Rail, e.CommitmentHash)
	if err != nil {
		rep.StillUnknown++
		return err
	}
	res, err := g.lookup(ctx, coid)
	if err != nil {
		rep.StillUnknown++
		return fmt.Errorf("gate: lookup %s: %w", coid, err)
	}
	upd := e
	upd.History = append(append([]registry.Resolution(nil), e.History...),
		registry.Resolution{Source: registry.SourceLookup, By: "gate", At: now, PrevState: registry.StateUnknown})
	switch {
	case res.Outcome == OutcomeExecuted && validID(res.RailRef, 128):
		upd.State, upd.RailRef, upd.ExecutedAt = registry.StateExecuted, res.RailRef, now
		// A signing failure leaves Executed without a receipt; resign retries.
		upd.Receipt, _ = g.signReceipt(ctx, e.CommitmentHash, e.Path, res.RailRef, now)
		if err := g.d.Registry.Resolve(ctx, e.Key, registry.StateUnknown, upd); err != nil {
			return err
		}
		rep.Executed++
	case res.Outcome == OutcomeNotFound && now > satAdd(e.ValidUntil, g.cfg.SettleS):
		upd.State = registry.StateRejected
		if err := g.d.Registry.Resolve(ctx, e.Key, registry.StateUnknown, upd); err != nil {
			return err
		}
		rep.Rejected++
	default:
		rep.StillUnknown++
	}
	return nil
}

func (g *Gate) lookup(ctx context.Context, coid string) (res ExecResult, err error) {
	ctx, cancel := context.WithTimeout(ctx, g.cfg.ExecTimeout)
	defer cancel()
	defer func() {
		if r := recover(); r != nil {
			res, err = ExecResult{}, fmt.Errorf("executor panicked: %v", r)
		}
	}()
	return g.d.Executor.Lookup(ctx, coid)
}

// resign signs the receipt of an Executed entry that has none.
func (g *Gate) resign(ctx context.Context, e registry.Entry) error {
	now := g.now()
	receipt, err := g.signReceipt(ctx, e.CommitmentHash, e.Path, e.RailRef, e.ExecutedAt)
	if err != nil {
		return fmt.Errorf("gate: sign receipt: %w", err)
	}
	upd := e
	upd.Receipt = receipt
	upd.History = append(append([]registry.Resolution(nil), e.History...),
		registry.Resolution{Source: registry.SourceResign, By: "gate", At: now, PrevState: registry.StateExecuted})
	return g.d.Registry.Resolve(ctx, e.Key, registry.StateExecuted, upd)
}

// ResolveManually records the operator's decision for an entry in state
// Unknown. It never executes anything and never makes a nonce usable again.
// It returns the stored entry.
func (g *Gate) ResolveManually(ctx context.Context, k registry.Key, r ManualResolution) (registry.Entry, error) {
	if g.closed.Load() {
		return registry.Entry{}, ErrClosed
	}
	if !r.valid() {
		return registry.Entry{}, ErrInvalidResolution
	}
	e, err := g.d.Registry.Get(ctx, k)
	if err != nil {
		if errors.Is(err, registry.ErrNotFound) {
			return registry.Entry{}, err
		}
		return registry.Entry{}, fmt.Errorf("%w: %w", ErrRegistryUnavailable, err)
	}
	if e.State != registry.StateUnknown {
		return registry.Entry{}, fmt.Errorf("%w: state %s", ErrNotUnknown, e.State)
	}
	now := g.now()
	if now == 0 {
		return registry.Entry{}, fmt.Errorf("%w: now %d", ErrClockRegression, now)
	}
	upd := e
	upd.History = append(append([]registry.Resolution(nil), e.History...), registry.Resolution{
		Source: registry.SourceManual, By: r.Operator, At: now, Note: r.Note, PrevState: registry.StateUnknown,
	})
	var signErr error
	if r.Outcome == ManualExecuted {
		upd.State, upd.RailRef, upd.ExecutedAt = registry.StateExecuted, r.RailRef, now
		upd.Receipt, signErr = g.signReceipt(ctx, e.CommitmentHash, e.Path, r.RailRef, now)
	} else {
		upd.State = registry.StateRejected
	}
	if err := g.d.Registry.Resolve(ctx, k, registry.StateUnknown, upd); err != nil {
		return registry.Entry{}, fmt.Errorf("gate: resolve: %w", err)
	}
	stored, gerr := g.d.Registry.Get(ctx, k)
	if gerr != nil {
		stored = upd
	}
	if signErr != nil {
		return stored, fmt.Errorf("%w: sign: %v", ErrReceiptPending, signErr)
	}
	return stored, nil
}
