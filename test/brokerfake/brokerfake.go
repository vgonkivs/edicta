// Package brokerfake is an in-memory IBKR broker for executor tests. It
// records every request and refuses a second order with the same client order
// id, as the real venue does.
package brokerfake

import (
	"context"
	"errors"
	"strconv"
	"sync"

	"github.com/vgonkivs/edicta/examples/dca-agent/ibkr"
)

// ErrDuplicate is returned for a client order id the broker already holds.
var ErrDuplicate = errors.New("brokerfake: duplicate client order id")

type Broker struct {
	mu       sync.Mutex
	calls    int
	lookups  int
	reqs     []ibkr.PlaceRequest
	orders   map[string]string
	failPlan []error // consumed per accepted order: place, then report this error
	lookErr  error
	refuse   []error // consumed per Place: refuse without storing anything
}

func New() *Broker { return &Broker{orders: map[string]string{}} }

// FailAfterPlace makes the next Place store the order and then return err, the
// ambiguous outcome of a lost response.
func (b *Broker) FailAfterPlace(err error) {
	b.mu.Lock()
	b.failPlan = append(b.failPlan, err)
	b.mu.Unlock()
}

// FailBeforePlace makes the next Place return err without storing an order,
// as a refused connection or a definitive reject does.
func (b *Broker) FailBeforePlace(err error) {
	b.mu.Lock()
	b.refuse = append(b.refuse, err)
	b.mu.Unlock()
}

// FailLookup makes every lookup return err.
func (b *Broker) FailLookup(err error) { b.mu.Lock(); b.lookErr = err; b.mu.Unlock() }

func (b *Broker) Place(_ context.Context, req ibkr.PlaceRequest) (string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.calls++
	if len(b.refuse) > 0 {
		err := b.refuse[0]
		b.refuse = b.refuse[1:]
		return "", err
	}
	if _, ok := b.orders[req.ClientOrderID]; ok {
		return "", ErrDuplicate
	}
	id := strconv.Itoa(1000 + len(b.orders))
	b.orders[req.ClientOrderID] = id
	b.reqs = append(b.reqs, req)
	if len(b.failPlan) > 0 {
		err := b.failPlan[0]
		b.failPlan = b.failPlan[1:]
		return "", err
	}
	return id, nil
}

func (b *Broker) LookupByClientOrderID(_ context.Context, clientOrderID string) (string, bool, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.lookups++
	if b.lookErr != nil {
		return "", false, b.lookErr
	}
	id, ok := b.orders[clientOrderID]
	return id, ok, nil
}

// PlaceCalls counts every Place call, accepted or not.
func (b *Broker) PlaceCalls() int { b.mu.Lock(); defer b.mu.Unlock(); return b.calls }

// Lookups counts every lookup.
func (b *Broker) Lookups() int { b.mu.Lock(); defer b.mu.Unlock(); return b.lookups }

// Placed returns the requests of accepted orders in arrival order.
func (b *Broker) Placed() []ibkr.PlaceRequest {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]ibkr.PlaceRequest(nil), b.reqs...)
}
