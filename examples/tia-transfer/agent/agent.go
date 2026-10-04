// Package agent is the demo price-band agent. It watches one price, keeps a
// baseline, and when the price leaves a band around it builds the decision
// for one transfer. Committing, authorizing and executing are the Actor's job.
package agent

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/vgonkivs/edicta/examples/tia-transfer/bankaction"
	"github.com/vgonkivs/edicta/examples/tia-transfer/bankmsg"
	"github.com/vgonkivs/edicta/examples/tia-transfer/pricefeed"
	"github.com/vgonkivs/edicta/examples/tia-transfer/pricetrigger"
)

// DefaultThresholdBP is the band half-width used when Config.ThresholdBP is
// zero: 1 percent.
const DefaultThresholdBP = 100

const maxObservations = 8

// ErrInvalidConfig means New refused its arguments.
var ErrInvalidConfig = errors.New("agent: invalid configuration")

// Config is the agent's fixed strategy.
type Config struct {
	StrategyID string
	ChainID    string
	HRP        string
	Sender     string
	// Up and Down are the transfers for a move up and down.
	Up, Down pricetrigger.Branch
	// ThresholdBP is the move in basis points that triggers; zero means
	// DefaultThresholdBP.
	ThresholdBP uint64
	// Reason is optional free text carried in the published context.
	Reason string
}

// Decision is what the agent hands to the Actor: the context and action
// bytes to commit, and the context they were built from.
type Decision struct {
	Context []byte
	Action  []byte
	Payload *pricetrigger.Payload
}

// Actor commits, authorizes and executes a decision.
type Actor interface {
	Act(ctx context.Context, d Decision) error
}

// Clock is the agent's time source.
type Clock interface{ Now() time.Time }

// Agent holds the baseline and the recent observations.
type Agent struct {
	cfg   Config
	feed  pricefeed.Feed
	actor Actor
	clock Clock

	mu       sync.Mutex
	obs      []pricetrigger.Observation
	baseline pricetrigger.Baseline
}

// New validates cfg, including that both branches encode as transfers.
func New(cfg Config, f pricefeed.Feed, a Actor, c Clock) (*Agent, error) {
	bad := func(format string, args ...any) error {
		return fmt.Errorf("%w: %s", ErrInvalidConfig, fmt.Sprintf(format, args...))
	}
	if f == nil || a == nil || c == nil {
		return nil, bad("nil feed, actor or clock")
	}
	if cfg.ThresholdBP == 0 {
		cfg.ThresholdBP = DefaultThresholdBP
	}
	if cfg.ThresholdBP > 10000 {
		return nil, bad("threshold %d above 10000", cfg.ThresholdBP)
	}
	for _, br := range []pricetrigger.Branch{cfg.Up, cfg.Down} {
		if br.ToAddress == cfg.Sender {
			return nil, bad("branch %q sends to the sender", br.Name)
		}
		if _, _, err := buildAction(cfg, br); err != nil {
			return nil, bad("branch %q: %v", br.Name, err)
		}
	}
	probe := &pricetrigger.Payload{
		StrategyID:   cfg.StrategyID,
		Asset:        pricetrigger.Asset{Feed: "probe", AssetID: "probe", Quote: "USD"},
		Observations: []pricetrigger.Observation{{Source: "probe", Price: 1, ObservedAt: 1, FetchedAt: 1}},
		Baseline:     pricetrigger.Baseline{Price: 1, SetAt: 1},
		ThresholdBP:  cfg.ThresholdBP, Direction: 1, MoveBP: cfg.ThresholdBP,
		Branch: cfg.Up, Reason: cfg.Reason,
	}
	if _, err := pricetrigger.Encode(probe); err != nil {
		return nil, bad("%v", err)
	}
	return &Agent{cfg: cfg, feed: f, actor: a, clock: c}, nil
}

func buildAction(cfg Config, br pricetrigger.Branch) ([]byte, bankmsg.MsgSend, error) {
	m := bankmsg.MsgSend{From: cfg.Sender, To: br.ToAddress, Denom: br.Denom, Amount: br.Amount}
	msg, err := bankmsg.Encode(m, cfg.HRP)
	if err != nil {
		return nil, m, err
	}
	raw, err := bankaction.Encode(bankaction.Action{ChainID: cfg.ChainID, Msg: msg})
	return raw, m, err
}

// Trigger reports whether price left the band around baseline: the move in
// basis points, rounded down, reaches thresholdBP. direction is 1 for up and
// 2 for down. A zero baseline never triggers.
func Trigger(baseline, price, thresholdBP uint64) (direction, moveBP uint64, fired bool) {
	move, ok := pricetrigger.MoveBP(price, baseline)
	if !ok || move < thresholdBP || price == baseline {
		return 0, 0, false
	}
	direction = 1
	if price < baseline {
		direction = 2
	}
	return direction, move, true
}

func (a *Agent) now() uint64 {
	t := a.clock.Now().Unix()
	if t < 0 {
		return 0
	}
	return uint64(t)
}

// Step reads the feed once. The first reading becomes the baseline. After
// that, a move past the threshold hands one decision to the Actor and, when
// the Actor succeeds, moves the baseline to the trigger price; acted reports
// that. Any error leaves the baseline and history as they were, except that a
// failed Actor keeps the new reading in the history.
func (a *Agent) Step(ctx context.Context) (acted bool, err error) {
	o, err := a.feed.Observe(ctx)
	if err != nil {
		return false, err
	}
	if o.Price == 0 {
		return false, fmt.Errorf("%w: zero price", pricefeed.ErrPrice)
	}
	a.mu.Lock()
	defer a.mu.Unlock()

	a.obs = append([]pricetrigger.Observation{{
		Source: o.Source, Price: o.Price, ObservedAt: o.ObservedAt, FetchedAt: o.FetchedAt,
	}}, a.obs...)
	if len(a.obs) > maxObservations {
		a.obs = a.obs[:maxObservations]
	}
	if a.baseline.Price == 0 {
		a.baseline = pricetrigger.Baseline{Price: o.Price, SetAt: a.now()}
		return false, nil
	}
	dir, move, fired := Trigger(a.baseline.Price, o.Price, a.cfg.ThresholdBP)
	if !fired {
		return false, nil
	}

	br := a.cfg.Up
	if dir == 2 {
		br = a.cfg.Down
	}
	action, _, err := buildAction(a.cfg, br)
	if err != nil {
		return false, fmt.Errorf("agent: action: %w", err)
	}
	p := &pricetrigger.Payload{
		StrategyID:   a.cfg.StrategyID,
		Asset:        pricetrigger.Asset{Feed: o.Source, AssetID: o.AssetID, Quote: o.Quote},
		Observations: append([]pricetrigger.Observation(nil), a.obs...),
		Baseline:     a.baseline,
		ThresholdBP:  a.cfg.ThresholdBP,
		Direction:    dir,
		MoveBP:       move,
		Branch:       br,
		Reason:       a.cfg.Reason,
	}
	body, err := pricetrigger.Encode(p)
	if err != nil {
		return false, fmt.Errorf("agent: context: %w", err)
	}
	if err := a.actor.Act(ctx, Decision{Context: body, Action: action, Payload: p}); err != nil {
		return false, err
	}
	a.baseline = pricetrigger.Baseline{Price: o.Price, SetAt: a.now()}
	return true, nil
}
