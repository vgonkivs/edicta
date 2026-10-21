// SPDX-License-Identifier: Apache-2.0

// Package eden is the signer's handler for the eden-escrow form T deposit:
// the profile's checks on the exact action bytes (strict decode, pins,
// escrow code, payer code, nonce, payment requirements, time), the splice
// of the payer's signature into those bytes, the broadcast to Eden, the wait
// for the settlement, and the Payment-Signature for an executed deposit.
package eden

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"slices"
	"time"

	"github.com/vgonkivs/edicta/edenescrow"
	"github.com/vgonkivs/edicta/edenexec"
	"github.com/vgonkivs/edicta/signer"
)

// emptyCodeHash is keccak256 of no code: an account without code.
var emptyCodeHash = [32]byte{
	0xc5, 0xd2, 0x46, 0x01, 0x86, 0xf7, 0x23, 0x3c, 0x92, 0x7e, 0x7d, 0xb2, 0xdc, 0xc7, 0x03, 0xc0,
	0xe5, 0x00, 0xb6, 0x53, 0xca, 0x82, 0x27, 0x3b, 0x7b, 0xfa, 0xd8, 0x04, 0x5d, 0x85, 0xa4, 0x70,
}

// Chain is the signer's own Eden JSON-RPC endpoint for one chain.
type Chain interface {
	ChainID(ctx context.Context) (uint64, error)
	// CodeHash is keccak256 of the code at addr in the latest block.
	CodeHash(ctx context.Context, addr [20]byte) ([32]byte, error)
	PendingNonce(ctx context.Context, addr [20]byte) (uint64, error)
	// LatestNonce is how many transactions of addr the chain executed.
	LatestNonce(ctx context.Context, addr [20]byte) (uint64, error)
	SendRawTransaction(ctx context.Context, signed []byte) ([32]byte, error)
}

// Settler waits for a transaction's settlement (edenexec.Checker). seen
// continues an earlier wait for the same rail_ref.
type Settler interface {
	AwaitSeen(ctx context.Context, t edenexec.Target, until time.Time, seen bool) (edenexec.Report, error)
}

// paymentProofSetup is a Settler that can say whether its executed state
// may carry a payment proof.
type paymentProofSetup interface {
	CheckPaymentProofSetup() error
}

// Relay hands signed bytes to the payment server. Its answer is never
// evidence of anything: a nil error only means the bytes need not also be
// sent directly yet. Inclusion is decided by the Settler alone.
type Relay interface {
	Send(ctx context.Context, signed []byte, railRef string, paymentID [32]byte) error
}

// Broadcast modes.
const (
	// BroadcastRelay sends through the payment server's relay once, when
	// signed, and directly when the relay fails and on every resend after
	// RelayGrace.
	BroadcastRelay = "houston-relay"
	// BroadcastDirect sends with eth_sendRawTransaction on the chain's RPC.
	BroadcastDirect = "direct"
)

// Payment-Signature fields.
const (
	// FieldPaymentID: the Payment-Signature covers the quote's paymentId,
	// the 32 bytes the pinned facilitator signed.
	FieldPaymentID = "paymentId"
	// FieldOff: no Payment-Signature.
	FieldOff = "off"
)

// ChainPins are the operator's pins for one served chain. The
// escrow address and its code hash come from the compiled table, never from
// here.
type ChainPins struct {
	ChainID uint64
	// Payer is the address of the chain's payer key, checked at start.
	Payer        [20]byte
	Facilitators [][20]byte
	// MaxRefundDelay bounds refundAfter - expiresAt, in seconds.
	MaxRefundDelay uint64
	MaxFeePerGas   *big.Int
	MaxGas         uint64
	// MaxFeePerAction bounds max_fee_per_gas * gas_limit.
	MaxFeePerAction *big.Int
	// Broadcast is BroadcastRelay (the default) or BroadcastDirect.
	Broadcast string
}

// NotExecutedSources is how many operators must answer that the
// transaction is not there before a decision is final as not executed.
const NotExecutedSources = 2

// notFoundOperators counts the operators of a final report that answered
// not found.
func notFoundOperators(rep edenexec.Report) int {
	ops := map[string]bool{}
	for _, s := range rep.Sources {
		if s.State == edenexec.StateNotFound {
			ops[s.Operator] = true
		}
	}
	return len(ops)
}

// Defaults and bounds.
const (
	DefaultResendEvery = 5 * time.Second
	MaxResendEvery     = 10 * time.Minute
	DefaultRelayGrace  = 30 * time.Second
)

// Config is the handler's configuration.
type Config struct {
	Chains []ChainPins
	// AwaitGrace is added to the deposit's expiresAt: past it, a transaction
	// no source served was not executed.
	AwaitGrace time.Duration
	// ResendEvery is how often the stored bytes are resent while waiting.
	ResendEvery time.Duration
	// RelayGrace is how long after signing a relayed deposit is left to the
	// relay; after it every resend goes directly. At most AwaitGrace.
	RelayGrace time.Duration
	// PaymentSignatureField is FieldPaymentID (the default) or FieldOff.
	PaymentSignatureField string
	// CheckServerSignature requires the facilitator's signature over
	// paymentId in the requirements; nil is true.
	CheckServerSignature *bool
}

// ApplyDefaults fills the zero fields that have defaults.
func (c *Config) ApplyDefaults() {
	if c.AwaitGrace == 0 {
		c.AwaitGrace = edenexec.DefaultAwaitGrace
	}
	if c.ResendEvery == 0 {
		c.ResendEvery = DefaultResendEvery
	}
	if c.RelayGrace == 0 {
		c.RelayGrace = min(DefaultRelayGrace, c.AwaitGrace)
	}
	if c.PaymentSignatureField == "" {
		c.PaymentSignatureField = FieldPaymentID
	}
	if c.CheckServerSignature == nil {
		on := true
		c.CheckServerSignature = &on
	}
	for i := range c.Chains {
		if c.Chains[i].Broadcast == "" {
			c.Chains[i].Broadcast = BroadcastRelay
		}
	}
}

func (c Config) checkServerSignature() bool {
	return c.CheckServerSignature == nil || *c.CheckServerSignature
}

// PaymentSignatureEnabled: field paymentId and the server-signature check.
func (c Config) PaymentSignatureEnabled() bool {
	return c.PaymentSignatureField == FieldPaymentID && c.checkServerSignature()
}

// ValidateBasic checks the fields alone, against this build's table.
func (c Config) ValidateBasic() error {
	if len(c.Chains) == 0 {
		return errors.New("signer/eden: no served chain")
	}
	for i, p := range c.Chains {
		if _, ok := edenescrow.Lookup(p.ChainID); !ok {
			return fmt.Errorf("signer/eden: chain %d is not in this build's escrow table", p.ChainID)
		}
		for j := range i {
			if c.Chains[j].ChainID == p.ChainID {
				return fmt.Errorf("signer/eden: chain %d pinned twice", p.ChainID)
			}
		}
		switch {
		case p.Payer == [20]byte{}:
			return fmt.Errorf("signer/eden: chain %d: no payer address", p.ChainID)
		case len(p.Facilitators) == 0:
			return fmt.Errorf("signer/eden: chain %d: no allowed facilitator", p.ChainID)
		case slices.Contains(p.Facilitators, [20]byte{}):
			return fmt.Errorf("signer/eden: chain %d: the zero address as facilitator", p.ChainID)
		case p.MaxRefundDelay == 0:
			return fmt.Errorf("signer/eden: chain %d: MaxRefundDelay must be above zero", p.ChainID)
		case p.MaxGas == 0:
			return fmt.Errorf("signer/eden: chain %d: MaxGas must be above zero", p.ChainID)
		case p.MaxFeePerGas == nil || p.MaxFeePerGas.Sign() <= 0:
			return fmt.Errorf("signer/eden: chain %d: MaxFeePerGas must be above zero", p.ChainID)
		case p.MaxFeePerAction == nil || p.MaxFeePerAction.Sign() <= 0:
			return fmt.Errorf("signer/eden: chain %d: MaxFeePerAction must be above zero", p.ChainID)
		case p.Broadcast != BroadcastRelay && p.Broadcast != BroadcastDirect:
			return fmt.Errorf("signer/eden: chain %d: broadcast %q is not %s or %s", p.ChainID, p.Broadcast, BroadcastRelay, BroadcastDirect)
		}
	}
	switch {
	case c.AwaitGrace <= 0 || c.AwaitGrace > edenexec.MaxAwaitGrace:
		return fmt.Errorf("signer/eden: AwaitGrace %v is not in (0, %v]", c.AwaitGrace, edenexec.MaxAwaitGrace)
	case c.ResendEvery <= 0 || c.ResendEvery > MaxResendEvery:
		return fmt.Errorf("signer/eden: ResendEvery %v is not in (0, %v]", c.ResendEvery, MaxResendEvery)
	case c.RelayGrace <= 0 || c.RelayGrace > c.AwaitGrace:
		return fmt.Errorf("signer/eden: RelayGrace %v is not in (0, AwaitGrace %v]", c.RelayGrace, c.AwaitGrace)
	}
	switch c.PaymentSignatureField {
	case FieldPaymentID, FieldOff:
	case "nonce":
		// No server signature covers extra.nonce, so the agent would choose
		// the bytes the payer key signs.
		return errors.New("signer/eden: Payment-Signature field nonce is not offered: no server signature covers it")
	default:
		return fmt.Errorf("signer/eden: Payment-Signature field %q is not %s or %s", c.PaymentSignatureField, FieldPaymentID, FieldOff)
	}
	return nil
}

// Deps are the handler's collaborators, per served chain.
type Deps struct {
	Chains   map[uint64]Chain
	Settlers map[uint64]Settler
	// Relays are needed for the chains that broadcast through a relay.
	Relays map[uint64]Relay
	// Now is the local clock that decides when to stop waiting; nil is the
	// system clock.
	Now func() time.Time
	Log *slog.Logger
}

// Handler is the form T handler.
type Handler struct {
	cfg      Config
	pins     map[uint64]ChainPins
	chains   map[uint64]Chain
	settlers map[uint64]Settler
	relays   map[uint64]Relay
	now      func() time.Time
	log      *slog.Logger
}

var (
	_ signer.Handler       = (*Handler)(nil)
	_ signer.PaymentProver = (*Handler)(nil)
)

// New wires one Chain and one Settler per served chain, and a Relay per
// relayed chain. With the Payment-Signature enabled, every Settler must
// confirm that its executed state can carry one (L1, explicit operator
// labels, enough operators); otherwise the handler refuses to start.
func New(cfg Config, d Deps) (*Handler, error) {
	if err := cfg.ValidateBasic(); err != nil {
		return nil, err
	}
	pins := make(map[uint64]ChainPins, len(cfg.Chains))
	for _, p := range cfg.Chains {
		if d.Chains[p.ChainID] == nil {
			return nil, fmt.Errorf("signer/eden: no RPC for chain %d", p.ChainID)
		}
		st := d.Settlers[p.ChainID]
		if st == nil {
			return nil, fmt.Errorf("signer/eden: no settlement sources for chain %d", p.ChainID)
		}
		if p.Broadcast == BroadcastRelay && d.Relays[p.ChainID] == nil {
			return nil, fmt.Errorf("signer/eden: chain %d broadcasts through a relay but has none", p.ChainID)
		}
		if cfg.PaymentSignatureEnabled() {
			ps, ok := st.(paymentProofSetup)
			if !ok {
				return nil, fmt.Errorf("signer/eden: chain %d: the settlement sources cannot show that a Payment-Signature is safe", p.ChainID)
			}
			if err := ps.CheckPaymentProofSetup(); err != nil {
				return nil, fmt.Errorf("signer/eden: chain %d: Payment-Signature enabled: %w", p.ChainID, err)
			}
		}
		pins[p.ChainID] = p
	}
	if d.Now == nil {
		d.Now = time.Now
	}
	if d.Log == nil {
		d.Log = slog.Default()
	}
	return &Handler{cfg: cfg, pins: pins, chains: d.Chains, settlers: d.Settlers, relays: d.Relays, now: d.Now, log: d.Log}, nil
}

func (h *Handler) ActionType() string { return edenescrow.ActionType }

// Start checks, for every served chain: the RPC serves that chain, the
// chain's wallet is the pinned payer, the escrow code is the table's, and
// the payer has no code.
func (h *Handler) Start(ctx context.Context, payers map[uint64][20]byte) error {
	for id, p := range h.pins {
		got, ok := payers[id]
		if !ok {
			return fmt.Errorf("signer/eden: chain %d: no payer key", id)
		}
		if got != p.Payer {
			return fmt.Errorf("signer/eden: chain %d: the payer key's address is %x, the pin %x", id, got, p.Payer)
		}
		c := h.chains[id]
		served, err := c.ChainID(ctx)
		if err != nil {
			return fmt.Errorf("signer/eden: chain %d: %w: %w", id, signer.ErrUnavailable, err)
		}
		if served != id {
			return fmt.Errorf("signer/eden: the RPC for chain %d serves chain %d", id, served)
		}
		row, _ := edenescrow.Lookup(id)
		if err := h.escrowCode(ctx, c, row); err != nil {
			return err
		}
		if err := h.payerCode(ctx, c, p.Payer); err != nil {
			return err
		}
	}
	return nil
}

// escrowCode requires the table's runtime code at the escrow, read through
// the signer's own RPC, failing closed: a value transfer to an address
// without the code succeeds as a plain transfer and strands the money, and a
// rolled-back block can remove a copy's deployment.
func (h *Handler) escrowCode(ctx context.Context, c Chain, row edenescrow.Row) error {
	got, err := c.CodeHash(ctx, row.Escrow)
	if err != nil {
		return fmt.Errorf("%w: %w: chain %d: %w", signer.ErrEscrowCode, signer.ErrUnavailable, row.ChainID, err)
	}
	if got != row.CodeHash {
		return fmt.Errorf("%w: chain %d escrow %x has code hash %x", signer.ErrEscrowCode, row.ChainID, row.Escrow, got)
	}
	return nil
}

// payerCode requires a payer without code: a delegated payer may not accept
// the escrow's refund within its gas stipend, which then goes to the
// facilitator.
func (h *Handler) payerCode(ctx context.Context, c Chain, payer [20]byte) error {
	got, err := c.CodeHash(ctx, payer)
	if err != nil {
		return fmt.Errorf("%w: %w: payer code: %w", signer.ErrPinMismatch, signer.ErrUnavailable, err)
	}
	if got != emptyCodeHash {
		return fmt.Errorf("%w: the payer %x has code", signer.ErrPinMismatch, payer)
	}
	return nil
}

// nonceSlot is the resource only one unresolved decision may hold: one
// payer nonce on one chain.
func nonceSlot(chainID uint64, payer [20]byte, nonce uint64) string {
	return fmt.Sprintf("eden-escrow/%d/%x/nonce/%d", chainID, payer, nonce)
}

// Check decodes the exact action bytes strictly and holds them to the pins,
// the escrow and payer code, the payer's pending nonce, the payment
// requirements and the time rules.
func (h *Handler) Check(ctx context.Context, v signer.Verified, now time.Time) (signer.Plan, error) {
	a, err := edenescrow.DecodeTxAction(v.Action)
	if err != nil {
		return signer.Plan{}, err
	}
	p, ok := h.pins[a.ChainID]
	if !ok {
		return signer.Plan{}, fmt.Errorf("%w: chain %d is not served", signer.ErrPinMismatch, a.ChainID)
	}
	d := a.Deposit
	feePerGas := new(big.Int).SetBytes(a.MaxFeePerGas)
	feeBound := new(big.Int).Mul(feePerGas, new(big.Int).SetUint64(a.GasLimit))
	switch {
	case !slices.Contains(p.Facilitators, d.Facilitator):
		return signer.Plan{}, fmt.Errorf("%w: facilitator %x is not allowed", signer.ErrPinMismatch, d.Facilitator)
	case d.RefundAfter-d.ExpiresAt > p.MaxRefundDelay:
		return signer.Plan{}, fmt.Errorf("%w: refund delay %d s above %d s", signer.ErrPinMismatch, d.RefundAfter-d.ExpiresAt, p.MaxRefundDelay)
	case feePerGas.Cmp(p.MaxFeePerGas) > 0:
		return signer.Plan{}, fmt.Errorf("%w: max fee per gas %s above %s", signer.ErrPinMismatch, feePerGas, p.MaxFeePerGas)
	case a.GasLimit > p.MaxGas:
		return signer.Plan{}, fmt.Errorf("%w: gas limit %d above %d", signer.ErrPinMismatch, a.GasLimit, p.MaxGas)
	case feeBound.Cmp(p.MaxFeePerAction) > 0:
		return signer.Plan{}, fmt.Errorf("%w: fee bound %s above %s", signer.ErrPinMismatch, feeBound, p.MaxFeePerAction)
	}
	c := h.chains[a.ChainID]
	if err := h.escrowCode(ctx, c, a.Row); err != nil {
		return signer.Plan{}, err
	}
	if err := h.payerCode(ctx, c, p.Payer); err != nil {
		return signer.Plan{}, err
	}
	if !v.Repeat {
		n, err := c.PendingNonce(ctx, p.Payer)
		if err != nil {
			return signer.Plan{}, fmt.Errorf("%w: %w: pending nonce: %w", signer.ErrPinMismatch, signer.ErrUnavailable, err)
		}
		if a.Nonce != n {
			return signer.Plan{}, fmt.Errorf("%w: nonce %d, the payer's pending nonce is %d", signer.ErrPinMismatch, a.Nonce, n)
		}
	}

	// With the Payment-Signature enabled the quote is required before the
	// deposit, so the signer never pays a deposit whose proof it would then
	// refuse.
	if v.Requirements != nil || h.cfg.PaymentSignatureEnabled() {
		if v.Requirements == nil {
			return signer.Plan{}, fmt.Errorf("%w: no payment requirements; the Payment-Signature needs them", signer.ErrRequirements)
		}
		if _, err := edenescrow.CheckRequirements(a, v.Requirements, h.cfg.checkServerSignature()); err != nil {
			return signer.Plan{}, fmt.Errorf("%w: %w", signer.ErrRequirements, err)
		}
	}

	expires := v.Authorization.Expires
	unix := now.Unix()
	if unix < 0 {
		return signer.Plan{}, errors.New("signer/eden: clock before 1970")
	}
	horizon := uint64(unix) + v.SkewS
	switch {
	case d.ExpiresAt > expires:
		return signer.Plan{}, fmt.Errorf("%w: the deposit's expiresAt %d is after the Authorization's expires %d", signer.ErrExpired, d.ExpiresAt, expires)
	case horizon >= expires:
		return signer.Plan{}, fmt.Errorf("%w: the Authorization expires at %d", signer.ErrExpired, expires)
	case d.ExpiresAt <= horizon:
		return signer.Plan{}, fmt.Errorf("%w: the deposit's expiresAt %d has passed; it would revert", signer.ErrExpired, d.ExpiresAt)
	}

	until := time.Unix(int64(d.ExpiresAt), 0).Add(h.cfg.AwaitGrace)
	return signer.Plan{
		Key: a.ChainID, Payer: p.Payer, Digest: a.SigHash(),
		Value: new(big.Int).SetBytes(a.Value), Fee: feeBound, Until: until.Unix(),
		Slot: nonceSlot(a.ChainID, p.Payer, a.Nonce),
	}, nil
}

// Finish splices the signature into the action's own bytes; nothing is
// re-encoded from fields.
func (h *Handler) Finish(action []byte, sig [65]byte, payer [20]byte) ([]byte, string, error) {
	a, err := edenescrow.DecodeTxAction(action)
	if err != nil {
		return nil, "", err
	}
	signed, err := a.Splice(signer.UnpackSig(sig), payer)
	if err != nil {
		return nil, "", err
	}
	return signed, edenescrow.RailRef(signed), nil
}

// Send broadcasts the stored bytes: through the relay when the chain uses
// one, directly when the relay fails or is not used. The relay body's
// paymentId comes from the decoded action, never from a request.
func (h *Handler) Send(ctx context.Context, key uint64, action, signed []byte) error {
	a, err := edenescrow.DecodeTxAction(action)
	if err != nil {
		return err
	}
	if a.ChainID != key {
		return fmt.Errorf("signer/eden: the action is for chain %d, not %d", a.ChainID, key)
	}
	return h.broadcast(ctx, key, signed, a.Deposit.PaymentID)
}

func (h *Handler) broadcast(ctx context.Context, key uint64, signed []byte, paymentID [32]byte) error {
	c, p := h.chains[key], h.pins[key]
	if c == nil {
		return fmt.Errorf("signer/eden: no RPC for chain %d", key)
	}
	if p.Broadcast == BroadcastRelay {
		railRef := edenescrow.RailRef(signed)
		err := h.relays[key].Send(ctx, signed, railRef, paymentID)
		if err == nil {
			return nil
		}
		h.log.Warn("signer/eden: relay failed; sending the same bytes directly", "rail_ref", railRef, "err", err)
	}
	_, err := c.SendRawTransaction(ctx, signed)
	return err
}

// Settle resends the stored bytes while resend is set and the deadline has
// not passed, and waits until the sources show the transaction at the
// configured level, which a record request needs. It continues the wait
// the entry's Seen describes. It reports executed or reverted with that
// outcome, not executed when past the deadline enough operators answered
// and none ever served the transaction, and wrong when the rail_ref names
// other bytes. Anything else is unknown, an error; the returned Seen still
// counts.
func (h *Handler) Settle(ctx context.Context, e signer.Entry, resend bool) (signer.Settlement, error) {
	t, err := edenexec.NewTarget(e.Action, e.RailRef, e.AuthExpires, 0)
	if err != nil {
		return signer.Settlement{State: signer.StateWrong, Detail: err.Error()}, nil
	}
	key := t.Action.ChainID
	st := h.settlers[key]
	if h.chains[key] == nil || st == nil {
		return signer.Settlement{Seen: e.Seen}, fmt.Errorf("signer/eden: chain %d is no longer served", key)
	}
	until := time.Unix(e.Until, 0)
	relayUntil := time.Unix(e.ReservedAt, 0).Add(h.cfg.RelayGrace)
	seen := e.Seen
	for {
		now := h.now()
		horizon := until
		if resend && now.Before(until) {
			// The relay had the bytes once, when they were signed, with a
			// direct send on any fault. After RelayGrace every resend goes
			// directly, whatever a source showed: a relay that answers
			// success and withholds the bytes, or a sighting in a soft block
			// that was rolled back, then costs at most RelayGrace.
			if h.pins[key].Broadcast != BroadcastRelay || !now.Before(relayUntil) {
				if _, err := h.chains[key].SendRawTransaction(ctx, e.Signed); err != nil {
					h.log.Debug("signer/eden: resend", "rail_ref", e.RailRef, "err", err)
				}
			}
			if next := now.Add(h.cfg.ResendEvery); next.Before(until) {
				horizon = next
			}
		}
		rep, err := st.AwaitSeen(ctx, t, horizon, seen)
		// A transaction once served and gone now is a rolled-back block or
		// a pruning node, not one that never landed.
		seen = seen || rep.Seen || errors.Is(err, edenexec.ErrUnconfirmed)
		switch {
		case err == nil:
			state := signer.StateExecuted
			if rep.Outcome == edenexec.OutcomeReverted {
				state = signer.StateReverted
			}
			return signer.Settlement{State: state, Outcome: string(rep.Outcome), Seen: true,
				Detail:              fmt.Sprintf("block %d index %d level %s", rep.Block, rep.Index, rep.Level),
				PaymentProofAllowed: rep.PaymentSignatureAllowed()}, nil
		case ctx.Err() != nil:
			return signer.Settlement{Seen: seen}, ctx.Err()
		case errors.Is(err, edenexec.ErrViolation), errors.Is(err, edenexec.ErrMalformedRailRef), errors.Is(err, edenexec.ErrActionRefused):
			return signer.Settlement{State: signer.StateWrong, Detail: err.Error(), Seen: seen}, nil
		}
		if horizon.Equal(until) || !h.now().Before(until) {
			if errors.Is(err, edenexec.ErrNotFound) && !seen {
				// Final only on the word of independent operators: one
				// lagging or partitioned node must not strand a deposit that
				// landed.
				if n := notFoundOperators(rep); n < NotExecutedSources {
					return signer.Settlement{}, fmt.Errorf("%w: only %d of the %d operators needed say not found",
						edenexec.ErrBelowLevel, n, NotExecutedSources)
				}
				return signer.Settlement{State: signer.StateNotExecuted, Detail: err.Error()}, nil
			}
			return signer.Settlement{Seen: seen}, err
		}
	}
}

// CheckNonceRelease is the operator's check before releasing the nonce of
// a decision: it must be final as not executed past its deadline, and the
// payer's latest nonce must not be above the deposit's, which would show
// that a transaction with that nonce executed (a pruned or lagging source
// can make an executed deposit read as not executed).
func (h *Handler) CheckNonceRelease(ctx context.Context, e signer.Entry) error {
	if e.State != signer.StateNotExecuted {
		return fmt.Errorf("signer/eden: decision in state %s, not %s", e.State, signer.StateNotExecuted)
	}
	if h.now().Unix() < e.Until {
		return errors.New("signer/eden: the deadline has not passed")
	}
	a, err := edenescrow.DecodeTxAction(e.Action)
	if err != nil {
		return err
	}
	c := h.chains[a.ChainID]
	if c == nil {
		return fmt.Errorf("signer/eden: chain %d is not served", a.ChainID)
	}
	n, err := c.LatestNonce(ctx, e.Payer)
	if err != nil {
		return fmt.Errorf("%w: latest nonce: %w", signer.ErrUnavailable, err)
	}
	if n > a.Nonce {
		return fmt.Errorf("signer/eden: the payer's latest nonce is %d: a transaction with nonce %d executed", n, a.Nonce)
	}
	return nil
}
