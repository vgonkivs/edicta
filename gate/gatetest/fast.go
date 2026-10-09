package gatetest

import (
	"bytes"
	"context"
	"fmt"
	"strconv"
	"sync"

	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/gate"
)

// Intents is an in-memory intent source.
type Intents struct {
	mu    sync.Mutex
	recs  map[string]*gate.AnchorIntent
	err   error
	reads int
}

func NewIntents() *Intents { return &Intents{recs: make(map[string]*gate.AnchorIntent)} }

func intentKey(da commitment.DA, commit []byte, h uint64) string {
	return strconv.FormatUint(uint64(da), 10) + "/" + string(commit) + "/" + strconv.FormatUint(h, 10)
}

// Put stores rec under its own key.
func (s *Intents) Put(rec gate.AnchorIntent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r := rec
	r.Commitment, r.Namespace = bytes.Clone(rec.Commitment), bytes.Clone(rec.Namespace)
	r.Tx, r.Signer = bytes.Clone(rec.Tx), bytes.Clone(rec.Signer)
	s.recs[intentKey(rec.DA, rec.Commitment, rec.RefHeight)] = &r
}

// Fail makes every read fail with err; nil clears it.
func (s *Intents) Fail(err error) { s.mu.Lock(); s.err = err; s.mu.Unlock() }

func (s *Intents) Reads() int { s.mu.Lock(); defer s.mu.Unlock(); return s.reads }

func (s *Intents) Intent(_ context.Context, da commitment.DA, commit []byte, refHeight uint64) (*gate.AnchorIntent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reads++
	if s.err != nil {
		return nil, s.err
	}
	r, ok := s.recs[intentKey(da, commit, refHeight)]
	if !ok {
		return nil, fmt.Errorf("gatetest: no intent: %w", gate.ErrBlobNotFound)
	}
	c := *r
	c.Commitment, c.Namespace, c.Tx, c.Signer = bytes.Clone(r.Commitment), bytes.Clone(r.Namespace), bytes.Clone(r.Tx), bytes.Clone(r.Signer)
	return &c, nil
}

// IntentVerifier returns scripted facts per intent tx, or an error.
type IntentVerifier struct {
	mu    sync.Mutex
	facts map[string]gate.IntentFacts
	err   error
	calls int
}

func NewIntentVerifier() *IntentVerifier {
	return &IntentVerifier{facts: make(map[string]gate.IntentFacts)}
}

// Set scripts the facts returned for an intent whose tx is tx.
func (v *IntentVerifier) Set(tx []byte, f gate.IntentFacts) {
	v.mu.Lock()
	v.facts[string(tx)] = f
	v.mu.Unlock()
}

// Fail makes every call fail with err; nil clears it.
func (v *IntentVerifier) Fail(err error) { v.mu.Lock(); v.err = err; v.mu.Unlock() }

func (v *IntentVerifier) Calls() int { v.mu.Lock(); defer v.mu.Unlock(); return v.calls }

func (v *IntentVerifier) VerifyIntent(_ context.Context, _ commitment.PayloadRef, rec *gate.AnchorIntent, _ uint64) (gate.IntentFacts, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.calls++
	if v.err != nil {
		return gate.IntentFacts{}, v.err
	}
	f, ok := v.facts[string(rec.Tx)]
	if !ok {
		return gate.IntentFacts{}, fmt.Errorf("gatetest: unscripted intent: %w", gate.ErrAnchorIntentInvalid)
	}
	return f, nil
}

// Broadcaster scripts the lookup answer and the broadcast outcome, and
// records every broadcast.
type Broadcaster struct {
	mu         sync.Mutex
	status     map[string]gate.TxStatus
	lookupErr  error
	sendErr    error
	lookups    int
	broadcasts []Broadcast
}

// Broadcast is one recorded broadcast.
type Broadcast struct {
	DA   commitment.DA
	Tx   []byte
	Blob []byte
}

func NewBroadcaster() *Broadcaster { return &Broadcaster{status: make(map[string]gate.TxStatus)} }

// SetStatus scripts the lookup answer for tx; unset means not found.
func (b *Broadcaster) SetStatus(tx []byte, st gate.TxStatus) {
	b.mu.Lock()
	b.status[string(tx)] = st
	b.mu.Unlock()
}

// FailLookup and FailBroadcast inject errors; nil clears them.
func (b *Broadcaster) FailLookup(err error)    { b.mu.Lock(); b.lookupErr = err; b.mu.Unlock() }
func (b *Broadcaster) FailBroadcast(err error) { b.mu.Lock(); b.sendErr = err; b.mu.Unlock() }

func (b *Broadcaster) Lookups() int { b.mu.Lock(); defer b.mu.Unlock(); return b.lookups }

func (b *Broadcaster) Broadcasts() []Broadcast {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]Broadcast(nil), b.broadcasts...)
}

func (b *Broadcaster) Lookup(_ context.Context, rec *gate.AnchorIntent) (gate.TxStatus, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.lookups++
	if b.lookupErr != nil {
		return gate.TxStatus{}, b.lookupErr
	}
	return b.status[string(rec.Tx)], nil
}

func (b *Broadcaster) Broadcast(_ context.Context, da commitment.DA, rec *gate.AnchorIntent, blob []byte) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.sendErr != nil {
		return b.sendErr
	}
	b.broadcasts = append(b.broadcasts, Broadcast{DA: da, Tx: bytes.Clone(rec.Tx), Blob: bytes.Clone(blob)})
	return nil
}
