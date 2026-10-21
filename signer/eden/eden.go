// SPDX-License-Identifier: Apache-2.0

// Package eden is the signer's handler for the eden-escrow form T deposit:
// the profile's checks on the exact action bytes (strict decode, pins,
// escrow code, payer code, nonce, time), the splice of the payer's
// signature into those bytes, the send to Eden and the wait for the
// settlement.
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
	SendRawTransaction(ctx context.Context, signed []byte) ([32]byte, error)
}

// Settler waits for a transaction's settlement (edenexec.Checker).
type Settler interface {
	Await(ctx context.Context, t edenexec.Target, until time.Time) (edenexec.Report, error)
}

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
}

// NotExecutedSources is how many sources, distinct by host, must answer
// that the transaction is not there before a decision is final as not
// executed.
const NotExecutedSources = 2

// notFoundSources counts the sources of a final report that answered not
// found.
func notFoundSources(rep edenexec.Report) int {
	names := map[string]bool{}
	for _, s := range rep.Sources {
		if s.Result == edenexec.SourceSetAside && s.Reason == edenexec.ReasonNotFound {
			names[s.Name] = true
		}
	}
	return len(names)
}

// Defaults and bounds.
const (
	DefaultResendEvery = 5 * time.Second
	MaxResendEvery     = 10 * time.Minute
)

// Config is the handler's configuration.
type Config struct {
	Chains []ChainPins
	// AwaitGrace is added to the deposit's expiresAt: past it, a transaction
	// no source served was not executed.
	AwaitGrace time.Duration
	// ResendEvery is how often the stored bytes are resent while waiting.
	ResendEvery time.Duration
}

// ApplyDefaults fills the zero fields that have defaults.
func (c *Config) ApplyDefaults() {
	if c.AwaitGrace == 0 {
		c.AwaitGrace = edenexec.DefaultAwaitGrace
	}
	if c.ResendEvery == 0 {
		c.ResendEvery = DefaultResendEvery
	}
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
		}
	}
	switch {
	case c.AwaitGrace <= 0 || c.AwaitGrace > edenexec.MaxAwaitGrace:
		return fmt.Errorf("signer/eden: AwaitGrace %v is not in (0, %v]", c.AwaitGrace, edenexec.MaxAwaitGrace)
	case c.ResendEvery <= 0 || c.ResendEvery > MaxResendEvery:
		return fmt.Errorf("signer/eden: ResendEvery %v is not in (0, %v]", c.ResendEvery, MaxResendEvery)
	}
	return nil
}

// Handler is the form T handler.
type Handler struct {
	cfg      Config
	pins     map[uint64]ChainPins
	chains   map[uint64]Chain
	settlers map[uint64]Settler
	now      func() time.Time
	log      *slog.Logger
}

var _ signer.Handler = (*Handler)(nil)

// New wires one Chain and one Settler per served chain. now is the local
// clock that decides when to stop waiting; nil is the system clock.
func New(cfg Config, chains map[uint64]Chain, settlers map[uint64]Settler, now func() time.Time, log *slog.Logger) (*Handler, error) {
	if err := cfg.ValidateBasic(); err != nil {
		return nil, err
	}
	pins := make(map[uint64]ChainPins, len(cfg.Chains))
	for _, p := range cfg.Chains {
		if chains[p.ChainID] == nil {
			return nil, fmt.Errorf("signer/eden: no RPC for chain %d", p.ChainID)
		}
		if settlers[p.ChainID] == nil {
			return nil, fmt.Errorf("signer/eden: no settlement sources for chain %d", p.ChainID)
		}
		pins[p.ChainID] = p
	}
	if now == nil {
		now = time.Now
	}
	if log == nil {
		log = slog.Default()
	}
	return &Handler{cfg: cfg, pins: pins, chains: chains, settlers: settlers, now: now, log: log}, nil
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

// Check decodes the exact action bytes strictly and holds them to the pins,
// the escrow and payer code, the payer's pending nonce and the time rules.
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

// Send is eth_sendRawTransaction on the chain's own RPC.
func (h *Handler) Send(ctx context.Context, key uint64, signed []byte) error {
	c := h.chains[key]
	if c == nil {
		return fmt.Errorf("signer/eden: no RPC for chain %d", key)
	}
	_, err := c.SendRawTransaction(ctx, signed)
	return err
}

// Settle resends the stored bytes, while resend is set and the deadline has
// not passed, and waits for one source to show the transaction at the
// confirmation depth, which a record request needs. It reports executed or reverted when a source shows the
// transaction at the confirmation depth, not executed when past the deadline
// a source answered and none ever served it, and wrong when the rail_ref
// names other bytes. Anything else is unknown, an error.
func (h *Handler) Settle(ctx context.Context, e signer.Entry, resend bool) (signer.Settlement, error) {
	t, err := edenexec.NewTarget(e.Action, e.RailRef, e.AuthExpires, 0)
	if err != nil {
		return signer.Settlement{State: signer.StateWrong, Detail: err.Error()}, nil
	}
	c, st := h.chains[t.Action.ChainID], h.settlers[t.Action.ChainID]
	if c == nil || st == nil {
		return signer.Settlement{}, fmt.Errorf("signer/eden: chain %d is no longer served", t.Action.ChainID)
	}
	until := time.Unix(e.Until, 0)
	seen := false
	for {
		now := h.now()
		horizon := until
		if resend && now.Before(until) {
			if _, err := c.SendRawTransaction(ctx, e.Signed); err != nil {
				h.log.Debug("signer/eden: resend", "rail_ref", e.RailRef, "err", err)
			}
			if next := now.Add(h.cfg.ResendEvery); next.Before(until) {
				horizon = next
			}
		}
		rep, err := st.Await(ctx, t, horizon)
		switch {
		case err == nil:
			state := signer.StateExecuted
			if rep.Outcome == edenexec.OutcomeReverted {
				state = signer.StateReverted
			}
			return signer.Settlement{State: state, Outcome: string(rep.Outcome),
				Detail: fmt.Sprintf("block %d index %d", rep.Block, rep.Index)}, nil
		case ctx.Err() != nil:
			return signer.Settlement{}, ctx.Err()
		case errors.Is(err, edenexec.ErrViolation), errors.Is(err, edenexec.ErrMalformedRailRef), errors.Is(err, edenexec.ErrActionRefused):
			return signer.Settlement{State: signer.StateWrong, Detail: err.Error()}, nil
		case errors.Is(err, edenexec.ErrUnconfirmed):
			seen = true
		}
		if horizon.Equal(until) || !h.now().Before(until) {
			// A transaction once served and gone now is a rolled-back block,
			// not one that never landed.
			if errors.Is(err, edenexec.ErrNotFound) && !seen {
				// Final only on the word of independent operators: one
				// lagging or partitioned node must not strand a deposit that
				// landed. Otherwise the state stays unknown and is looked
				// up again.
				if n := notFoundSources(rep); n < NotExecutedSources {
					return signer.Settlement{}, fmt.Errorf("%w: only %d of the %d sources needed say not found",
						edenexec.ErrBelowLevel, n, NotExecutedSources)
				}
				return signer.Settlement{State: signer.StateNotExecuted, Detail: err.Error()}, nil
			}
			return signer.Settlement{}, err
		}
	}
}
