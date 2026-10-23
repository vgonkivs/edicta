// SPDX-License-Identifier: Apache-2.0

// Package signer is edicta-signer: the executor that holds the payer key and
// signs a rail transaction only for a decision that carries both the
// agent's signed envelope and the gate's Authorization for exactly those
// action bytes. Neither the agent nor the gate ever holds the payer key. The
// service is rail-agnostic; a Handler per action type holds the profile's
// checks (package signer/eden for the eden-escrow form T deposit).
package signer

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"sync"
	"time"

	"github.com/vgonkivs/edicta/engine/commitment"
)

// Clock is the signer's clock.
type Clock interface{ Now() time.Time }

type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now() }

// Verified is a request that carries a valid agent envelope and a valid
// gate Authorization for its exact bytes.
type Verified struct {
	CommitmentHash commitment.Hash
	Commitment     commitment.Commitment
	Authorization  commitment.Authorization
	Action, Salt   []byte
	// Requirements are the request's payment requirements, if presented.
	Requirements []byte
	// SkewS is the signer's skew_s.
	SkewS uint64
	// Repeat is set when the store already holds signed bytes for this
	// decision; checks of mutable chain state that only make sense before
	// the first signature (the payer's pending nonce) are skipped.
	Repeat bool
}

// Plan is what a handler decided may be signed for a verified request.
type Plan struct {
	// Key is the chain id; with the envelope's agent key it selects the
	// wallet.
	Key   uint64
	Payer [20]byte
	// Digest is exactly what the payer key signs.
	Digest [32]byte
	// Value and Fee are what the operator caps count.
	Value, Fee *big.Int
	// Until is the chain time after which the transaction, not found, was
	// not executed, Unix seconds.
	Until int64
	// Slot is the rail resource that only one unresolved decision may hold
	// (the payer's nonce); empty is none.
	Slot string
}

// Settlement is what the rail did with a signed decision.
type Settlement struct {
	State   State // StateExecuted, StateReverted, StateNotExecuted or StateWrong
	Outcome string
	Detail  string
	// Seen: some source served the transaction while waiting. Set also
	// when the state is unknown, so the next wait carries it.
	Seen bool
	// PaymentProofAllowed: the outcome rests on evidence strong enough to
	// release a payment proof.
	PaymentProofAllowed bool
}

// Handler is the profile part for one action type.
type Handler interface {
	ActionType() string
	// Start checks the handler's pins against the chain and the wallets
	// before the service accepts a request.
	Start(ctx context.Context, payers map[WalletKey][20]byte) error
	// Check runs the profile's checks on the exact action bytes and returns
	// what may be signed.
	Check(ctx context.Context, v Verified, now time.Time) (Plan, error)
	// Finish splices the signature into the action's transaction. It is
	// pure; the signature must recover to payer.
	Finish(action []byte, sig [65]byte, payer [20]byte) (signed []byte, railRef string, err error)
	// Send hands the signed bytes of the action to the rail.
	Send(ctx context.Context, key uint64, action, signed []byte) error
	// Settle waits for the rail until the entry's deadline, resending the
	// stored bytes while resend is set, and reports what it saw. It
	// continues the wait the entry's Seen describes. An error means the
	// state is unknown: look again later, never sign again; the returned
	// Settlement's Seen still counts.
	Settle(ctx context.Context, e Entry, resend bool) (Settlement, error)
	// ErrorRules are the rail's request refusals for the API's error
	// answers. They match after the signer's own refusals and before the
	// transport and encoding errors, and are not retryable.
	ErrorRules() []ErrorRule
	// MaxRequestBytes bounds the rail's part of a request, the payment
	// requirements, from 0 to signerapi.MaxRequirementsSize. The API reads
	// a request body no longer than the core material plus the largest
	// bound of the served handlers.
	MaxRequestBytes() int64
}

// ErrorRule maps a rail's request refusal to an HTTP status and an error
// code of the API.
type ErrorRule struct {
	Err    error
	Status int
	Code   string
}

// Slotter is a Handler whose plans hold slots: it names the slot of a
// decision stored by an earlier build without one, so that the in-flight
// check also covers those.
type Slotter interface {
	SlotOf(e Entry) (string, error)
}

// PaymentProver is the optional part of a Handler that releases a payment
// proof for a decision the rail executed: a signature by the payer key over
// a message the profile derives from the committed action and the payment
// requirements, never over bytes a request names.
type PaymentProver interface {
	// PaymentProofEnabled says whether the configuration offers payment
	// proofs at all.
	PaymentProofEnabled() bool
	// CheckPaymentProofField refuses a field the handler does not offer,
	// with ErrPinMismatch.
	CheckPaymentProofField(field string) error
	// ActionDigest is what the payer key signs for the action bytes.
	ActionDigest(action []byte) ([32]byte, error)
	// PaymentProofDigest checks the committed action and the requirements
	// and returns the proof's message and the digest the payer key signs.
	PaymentProofDigest(action, requirements []byte) (message, digest [32]byte, err error)
	// FinishPaymentProof formats the payer's signature over the message's
	// digest; it must recover to payer.
	FinishPaymentProof(message [32]byte, sig [65]byte, payer [20]byte) ([]byte, error)
}

// Recorder sends a record request to the gate. A receipt the
// gate already holds counts as success. A retryable failure wraps
// ErrUnavailable.
type Recorder interface {
	Record(ctx context.Context, envelope []byte, railRef string, executorPub, executorSig []byte) ([]byte, error)
}

// WalletKey names one payer key: the agent key it pays for and the chain
// (a plan's Key). A payer is dedicated to one agent on one chain, so that
// the escrow's buyer, the deposit and the payment proof name one agent, and
// one agent's stuck nonce never blocks another's.
type WalletKey struct {
	Agent [ed25519.PublicKeySize]byte
	Key   uint64
}

// NewWalletKey is the WalletKey of an agent public key and a chain.
func NewWalletKey(agent []byte, key uint64) (WalletKey, error) {
	if len(agent) != ed25519.PublicKeySize {
		return WalletKey{}, fmt.Errorf("signer: agent key of %d bytes", len(agent))
	}
	return WalletKey{Agent: [ed25519.PublicKeySize]byte(agent), Key: key}, nil
}

// Deps are the service's collaborators.
type Deps struct {
	Store Store
	// Wallets holds one payer key per served agent per served chain.
	Wallets  map[WalletKey]WalletBackend
	Handlers []Handler
	// Executor and Recorder enable the record request; both or neither.
	Executor ExecutorKey
	Recorder Recorder
	Clock    Clock
	Log      *slog.Logger
}

// Service is the signer.
type Service struct {
	cfg      Config
	st       Store
	wallets  map[WalletKey]WalletBackend
	handlers map[string]Handler
	ordered  []Handler // as in Deps: the order of the handlers' error rules
	provers  map[string]PaymentProver
	exec     ExecutorKey
	rec      Recorder
	clk      Clock
	log      *slog.Logger

	payers  map[WalletKey][20]byte
	started bool

	kick     chan struct{}
	mu       sync.Mutex
	inflight map[commitment.Hash]bool
}

// New checks the configuration and the dependencies.
func New(cfg Config, d Deps) (*Service, error) {
	if err := cfg.ValidateBasic(); err != nil {
		return nil, err
	}
	switch {
	case d.Store == nil:
		return nil, errors.New("signer: no store")
	case len(d.Wallets) == 0:
		return nil, errors.New("signer: no wallet")
	case len(d.Handlers) == 0:
		return nil, errors.New("signer: no handler")
	case (d.Executor == nil) != (d.Recorder == nil):
		return nil, errors.New("signer: the record request needs both the executor key and the gate client")
	}
	for k, w := range d.Wallets {
		if w == nil {
			return nil, fmt.Errorf("signer: wallet of agent %x chain %d is nil", k.Agent, k.Key)
		}
		if !agentIn(cfg.AgentKeys, k.Agent[:]) {
			return nil, fmt.Errorf("signer: wallet for agent %x, which is not served", k.Agent)
		}
	}
	hs := make(map[string]Handler, len(d.Handlers))
	ordered := make([]Handler, 0, len(d.Handlers))
	ps := map[string]PaymentProver{}
	for _, h := range d.Handlers {
		if h == nil {
			return nil, errors.New("signer: nil handler")
		}
		if _, dup := hs[h.ActionType()]; dup {
			return nil, fmt.Errorf("signer: two handlers for %s", h.ActionType())
		}
		hs[h.ActionType()] = h
		ordered = append(ordered, h)
		if p, ok := h.(PaymentProver); ok && p.PaymentProofEnabled() {
			ps[h.ActionType()] = p
		}
	}
	if d.Executor != nil {
		if err := checkExecutorKey(cfg, d.Executor.PublicKey()); err != nil {
			return nil, err
		}
	}
	if d.Clock == nil {
		d.Clock = systemClock{}
	}
	if d.Log == nil {
		d.Log = slog.Default()
	}
	return &Service{
		cfg: cfg, st: d.Store, wallets: d.Wallets, handlers: hs, ordered: ordered, provers: ps, exec: d.Executor, rec: d.Recorder,
		clk: d.Clock, log: d.Log, kick: make(chan struct{}, 1), inflight: map[commitment.Hash]bool{},
	}, nil
}

// checkExecutorKey keeps the executor role apart from the gate and agent
// roles: a key in two roles would let one party sign for both.
func checkExecutorKey(cfg Config, pub ed25519.PublicKey) error {
	if err := commitment.CheckPublicKey(pub); err != nil {
		return fmt.Errorf("signer: executor key: %w", err)
	}
	if bytes.Equal(pub, cfg.GatePubKey) {
		return errors.New("signer: the executor key is the gate key")
	}
	for i, k := range cfg.AgentKeys {
		if bytes.Equal(pub, k) {
			return fmt.Errorf("signer: the executor key is agent key %d", i)
		}
	}
	return nil
}

// Start reads every wallet's address and runs each handler's startup checks.
// The service refuses requests until it succeeds.
func (s *Service) Start(ctx context.Context) error {
	payers := make(map[WalletKey][20]byte, len(s.wallets))
	seen := map[[20]byte]WalletKey{}
	for k, w := range s.wallets {
		a, err := w.Address(ctx)
		if err != nil {
			return fmt.Errorf("signer: wallet of agent %x chain %d: %w", k.Agent, k.Key, err)
		}
		// One key per agent per chain keeps a mistake or a compromise on one
		// chain or of one agent from reaching another; two files may hold
		// one key.
		if other, dup := seen[a]; dup {
			return fmt.Errorf("signer: one payer key %x serves agent %x chain %d and agent %x chain %d",
				a, other.Agent, other.Key, k.Agent, k.Key)
		}
		seen[a] = k
		payers[k] = a
	}
	for _, h := range s.handlers {
		if err := h.Start(ctx, payers); err != nil {
			return err
		}
	}
	if err := s.indexOldSlots(ctx); err != nil {
		return err
	}
	s.mu.Lock()
	s.payers, s.started = payers, true
	s.mu.Unlock()
	return nil
}

// indexOldSlots gives every unresolved decision stored without a slot its
// slot. A store written before slots were kept would otherwise let a new
// decision take a nonce still in flight.
func (s *Service) indexOldSlots(ctx context.Context) error {
	entries, err := s.st.Unfinished(ctx, StateReserved, StateSigned, StateWrong)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.Slot != "" {
			continue
		}
		sl, ok := s.handlers[e.ActionType].(Slotter)
		if !ok {
			continue
		}
		slot, err := sl.SlotOf(e)
		if err != nil {
			return fmt.Errorf("signer: stored decision %x has no slot and none can be derived: %w", e.CommitmentHash, err)
		}
		if err := s.st.IndexSlot(ctx, e.CommitmentHash, slot); err != nil {
			return err
		}
	}
	return nil
}

// Sign checks both signatures and the profile's rules, reserves and counts
// the digest in one durable write, signs it, stores the signed bytes and
// makes the first send. A repeat of a signed decision returns the stored
// bytes.
func (s *Service) Sign(ctx context.Context, req Request) (Output, error) {
	return s.SignAs(ctx, req, nil)
}

// SignAs is Sign for a caller whose API credential is pinned to the agent
// key caller; nil is a shared credential. A pinned caller may submit only
// its own agent's decisions.
func (s *Service) SignAs(ctx context.Context, req Request, caller []byte) (Output, error) {
	s.mu.Lock()
	started := s.started
	s.mu.Unlock()
	if !started {
		return Output{}, fmt.Errorf("%w: not started", ErrUnavailable)
	}
	now := s.clk.Now()
	v, h, err := s.verify(req, now)
	if err != nil {
		return Output{}, err
	}
	if caller != nil && subtle.ConstantTimeCompare(caller, v.Commitment.AgentPubKey) != 1 {
		return Output{}, fmt.Errorf("%w: the API credential is not the decision's agent's", ErrNotAuthorized)
	}
	prior, found, err := s.st.Get(ctx, v.CommitmentHash)
	if err != nil {
		return Output{}, err
	}
	v.Repeat = found && len(prior.Signed) > 0
	plan, err := h.Check(ctx, v, now)
	if err != nil {
		return Output{}, err
	}
	if v.Authorization.Mode == commitment.ModeFast && s.cfg.RefuseFast {
		return Output{}, ErrFastModeRefused
	}
	wk, err := NewWalletKey(v.Commitment.AgentPubKey, plan.Key)
	if err != nil {
		return Output{}, fmt.Errorf("%w: %w", ErrNotAuthorized, err)
	}
	wallet := s.wallets[wk]
	if wallet == nil || s.payer(wk) != plan.Payer {
		return Output{}, fmt.Errorf("%w: no payer key of this agent for chain %d", ErrPinMismatch, plan.Key)
	}
	if plan.Value == nil || plan.Fee == nil || plan.Value.Sign() < 0 || plan.Fee.Sign() < 0 {
		return Output{}, errors.New("signer: handler returned no amounts")
	}

	e := Entry{
		CommitmentHash: v.CommitmentHash, Digest: plan.Digest, ActionType: h.ActionType(),
		Key: plan.Key, Payer: plan.Payer, Value: plan.Value.Bytes(), Fee: plan.Fee.Bytes(),
		ReservedAt: now.Unix(), Until: plan.Until,
		Envelope: bytes.Clone(req.Envelope), Action: bytes.Clone(req.Action), Salt: bytes.Clone(req.Salt),
		Authorization: bytes.Clone(req.Authorization), AuthExpires: v.Authorization.Expires, Mode: v.Authorization.Mode,
		Requirements: bytes.Clone(req.Requirements), Slot: plan.Slot,
		State: StateReserved,
	}
	stored, existing, err := s.st.Reserve(ctx, e, now.Add(-HourWindow).Unix()+1, func(t Totals) error {
		// Two different transactions on one nonce: the second fails at the
		// chain, after its fee was counted and its decision consumed.
		if t.SlotHolder != nil && t.SlotHolder.HoldsSlot(now, s.cfg.SkewS) {
			return fmt.Errorf("%w: %s is held by the unresolved decision %x", ErrPinMismatch, plan.Slot, t.SlotHolder.CommitmentHash)
		}
		return s.admit(plan, t)
	})
	if err != nil {
		return Output{}, err
	}
	if existing {
		if stored.Digest != plan.Digest {
			return Output{}, ErrDigestConflict
		}
		if stored.Payer != plan.Payer {
			return Output{}, fmt.Errorf("%w: the decision was reserved for payer %x", ErrPinMismatch, stored.Payer)
		}
		if len(stored.Signed) > 0 {
			s.wake()
			return Output{CommitmentHash: v.CommitmentHash, Signed: stored.Signed, RailRef: stored.RailRef, Repeat: true}, nil
		}
	}
	s.log.Info("signer: signing", "commitment_hash", hex.EncodeToString(v.CommitmentHash[:]), "action_type", h.ActionType(),
		"chain", plan.Key, "mode", v.Authorization.Mode, "anchor_deadline", v.Authorization.AnchorDeadline, "repeat", existing)

	sig, err := wallet.SignDigest(ctx, plan.Digest)
	if err != nil {
		return Output{}, fmt.Errorf("%w: wallet: %w", ErrUnavailable, err)
	}
	signed, railRef, err := h.Finish(req.Action, sig, plan.Payer)
	if err != nil {
		return Output{}, fmt.Errorf("signer: splice: %w", err)
	}
	// The signed bytes are durable before they leave, so a crash after the
	// send resolves by looking up this rail_ref, never by signing again.
	sendOK := sendAllowed(now, s.cfg.SkewS, v.Authorization.Expires)
	stored, err = s.st.Update(ctx, v.CommitmentHash, func(e *Entry) error {
		if len(e.Signed) == 0 {
			e.Signed, e.RailRef, e.State = signed, railRef, StateSigned
		}
		e.SendStarted = e.SendStarted || sendOK
		return nil
	})
	if err != nil {
		return Output{}, err
	}
	if sendOK {
		if err := h.Send(ctx, plan.Key, req.Action, stored.Signed); err != nil {
			s.log.Warn("signer: first send failed; it is resent until the deadline",
				"commitment_hash", hex.EncodeToString(v.CommitmentHash[:]), "rail_ref", stored.RailRef, "err", err)
		}
	}
	s.wake()
	return Output{CommitmentHash: v.CommitmentHash, Signed: stored.Signed, RailRef: stored.RailRef, Repeat: existing}, nil
}

// sendAllowed: no send starts once now + skew_s >= expires.
func sendAllowed(now time.Time, skew, expires uint64) bool {
	n := now.Unix()
	return n >= 0 && uint64(n)+skew < expires
}

func (s *Service) payer(key WalletKey) [20]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.payers[key]
}

// admit applies the operator caps inside the reservation's write, so a
// stored signature is always counted.
func (s *Service) admit(p Plan, t Totals) error {
	c := s.cfg.Caps
	if p.Value.Cmp(c.MaxValuePerAction) > 0 {
		return fmt.Errorf("%w: value %s above the per-action cap", ErrRiskLimit, p.Value)
	}
	if v := new(big.Int).Add(t.Value, p.Value); v.Cmp(c.MaxValuePerHour) > 0 {
		return fmt.Errorf("%w: value in the last hour would be %s", ErrRiskLimit, v)
	}
	if f := new(big.Int).Add(t.Fee, p.Fee); f.Cmp(c.MaxFeePerHour) > 0 {
		return fmt.Errorf("%w: fee bound in the last hour would be %s", ErrRiskLimit, f)
	}
	return nil
}

// verify requires both signatures: the envelope decodes, validates and
// verifies under a pinned agent key, names a handled type and hashes to the
// presented bytes and salt; then the Authorization verifies under the pinned
// gate key for exactly those bytes, for this commitment. A gate signature
// alone never suffices.
func (s *Service) verify(req Request, now time.Time) (Verified, Handler, error) {
	deny := func(err error) (Verified, Handler, error) {
		return Verified{}, nil, fmt.Errorf("%w: %w", ErrNotAuthorized, err)
	}
	p := commitment.DefaultParams()
	p.SkewS = s.cfg.SkewS
	env, err := commitment.DecodeSigned(req.Envelope)
	if err != nil {
		return deny(err)
	}
	c := &env.Commitment
	if err := commitment.ValidateStatic(c, p); err != nil {
		return deny(err)
	}
	h, err := commitment.Verify(env)
	if err != nil {
		return deny(err)
	}
	if !s.agentPinned(c.AgentPubKey) {
		return deny(errors.New("agent key is not pinned"))
	}
	// The agent scoped the decision to one gate; an Authorization for it
	// from that gate's key but for another scope is not what the agent asked.
	if c.Scope.GateID != s.cfg.GateID {
		return deny(fmt.Errorf("%w: the commitment names gate %q", commitment.ErrScopeMismatch, c.Scope.GateID))
	}
	hd := s.handlers[c.Action.Type]
	if hd == nil {
		return deny(fmt.Errorf("%w: %q", commitment.ErrActionTypeNotAllowed, c.Action.Type))
	}
	if err := commitment.CheckAction(c, req.Action, req.Salt); err != nil {
		return deny(err)
	}
	unix := now.Unix()
	if unix < 0 {
		return Verified{}, nil, errors.New("signer: clock before 1970")
	}
	sa, _, err := commitment.VerifyAuthorization(req.Authorization, commitment.AuthorizationCheck{
		GatePubKey: s.cfg.GatePubKey, GateID: s.cfg.GateID, ActionType: c.Action.Type,
		Action: req.Action, ActionSalt: req.Salt, Now: uint64(unix), SkewS: s.cfg.SkewS,
	})
	if err != nil {
		// Expiry is reported as such, not as a missing authorization.
		if errors.Is(err, commitment.ErrExpired) {
			return Verified{}, nil, fmt.Errorf("%w: %w", ErrExpired, err)
		}
		return deny(err)
	}
	if !bytes.Equal(sa.Authorization.CommitmentHash, h[:]) {
		return deny(errors.New("the Authorization names another commitment"))
	}
	// A compromised gate must not revive an envelope past the agent's own
	// validity: the decision's window bounds the Authorization too.
	if err := commitment.CheckTime(c, uint64(unix), p); err != nil {
		if errors.Is(err, commitment.ErrExpired) {
			return Verified{}, nil, fmt.Errorf("%w: %w", ErrExpired, err)
		}
		return deny(err)
	}
	if sa.Authorization.Expires > c.ValidUntil {
		return deny(fmt.Errorf("the Authorization expires at %d, after the commitment's valid_until %d",
			sa.Authorization.Expires, c.ValidUntil))
	}
	return Verified{
		CommitmentHash: h, Commitment: *c, Authorization: sa.Authorization,
		Action: bytes.Clone(req.Action), Salt: bytes.Clone(req.Salt), Requirements: bytes.Clone(req.Requirements),
		SkewS: s.cfg.SkewS,
	}, hd, nil
}

func (s *Service) agentPinned(pub []byte) bool { return agentIn(s.cfg.AgentKeys, pub) }

func agentIn(keys [][]byte, pub []byte) bool {
	for _, k := range keys {
		if bytes.Equal(k, pub) {
			return true
		}
	}
	return false
}

func (s *Service) wake() {
	select {
	case s.kick <- struct{}{}:
	default:
	}
}
