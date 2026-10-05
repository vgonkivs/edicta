// Package transfer is the executor of the bank-send profile. It signs the
// authorized transfer itself, with the commitment hash as memo, and sends the
// same signed bytes until the transaction is included, its timeout height
// passes or the Authorization runs out.
package transfer

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/examples/tia-transfer/bankaction"
)

// ActionType is the action_type this executor accepts.
const ActionType = bankaction.ActionType

var (
	// ErrInvalidConfig means NewExecutor refused its arguments.
	ErrInvalidConfig = errors.New("transfer: invalid configuration")
	// ErrHandedOff means the transaction was not included in time and the
	// operator takes over. No second transaction is built for the decision.
	ErrHandedOff = errors.New("transfer: not included before timeout_height; handed to the operator")
	// ErrFailedOnChain means the transaction was included and failed; the
	// code is in Result.
	ErrFailedOnChain = errors.New("transfer: transaction failed on chain")

	// ErrRejected is the Rail's final answer to a broadcast: the node checked
	// the transaction and refused it, so sending the same bytes again cannot
	// help. The Rail's error carries the node's code and log.
	ErrRejected = errors.New("transfer: transaction rejected by the node")

	ErrChainMismatch  = bankaction.ErrChainMismatch
	ErrSenderMismatch = bankaction.ErrSenderMismatch
	ErrDenomMismatch  = bankaction.ErrDenomMismatch
	ErrDestination    = bankaction.ErrDestination
	ErrRiskLimit      = bankaction.ErrRiskLimit
	ErrExpired        = bankaction.ErrExpired
)

const (
	maxSkewS                = 300
	defaultMaxTimeoutBlocks = 200
	defaultRebroadcastEvery = 10 * time.Second
	handOffReason           = "not included by timeout_height"
	defaultHandOffGrace     = 10 * time.Minute
	rejectRecheckDelay      = 2 * time.Second
)

// TxState is what the chain knows about a transaction.
type TxState int

const (
	TxUnknown TxState = iota
	TxPending
	TxCommitted
)

// TxStatus is a transaction's state; Height and Code are set once committed.
type TxStatus struct {
	State  TxState
	Height uint64
	Code   uint32
}

// Domain is the executor's own view of the chain and its key.
type Domain struct{ ChainID, Denom, HRP, Sender string }

// Clock is the executor's time source.
type Clock interface {
	Now() time.Time
	After(d time.Duration) <-chan time.Time
}

// Rail is the chain. Signing and broadcasting live behind it so the main
// module carries no chain dependencies.
type Rail interface {
	Domain(ctx context.Context) (Domain, error)
	// Head returns the current height, its time in Unix seconds, and the
	// block interval estimated from recent headers.
	Head(ctx context.Context) (height, headTime uint64, blockInterval time.Duration, err error)
	// Sign returns the TxRaw for body; body_bytes must be body unchanged. The
	// signer must not attach a fee above maxFee base units.
	Sign(ctx context.Context, body []byte, chainID string, maxFee uint64) (txRaw []byte, err error)
	Broadcast(ctx context.Context, txRaw []byte) error
	Status(ctx context.Context, hash [32]byte) (TxStatus, error)
}

// Config pins the gate and holds the operator's limits.
type Config struct {
	GatePubKey ed25519.PublicKey
	GateID     string
	// SkewS is the clock tolerance, 0..300.
	SkewS uint64
	// MaxAmount in base units; 0 disables the check.
	MaxAmount uint64
	// MaxFee is the fee cap handed to the Rail's signer, which enforces it.
	MaxFee       uint64
	Destinations []string
	// MaxTimeoutBlocks caps timeout_height - head; zero means 200.
	MaxTimeoutBlocks uint64
	// RebroadcastEvery is the resend interval; zero means 10 seconds.
	RebroadcastEvery time.Duration
	// HandOffGrace is how long after the Authorization expires the executor
	// keeps watching a transaction whose timeout height the head has not
	// passed (a stalled chain); zero means 10 minutes.
	HandOffGrace time.Duration
	// SignKey signs record requests. Optional; it must not be the chain key.
	SignKey ed25519.PrivateKey
}

// Result is the outcome of an included transaction.
type Result struct {
	TxHash [32]byte
	Height uint64
	Code   uint32
}

// Executor performs an authorized transfer once.
type Executor struct {
	cfg    Config
	dom    Domain
	rail   Rail
	store  Store
	clock  Clock
	limits bankaction.Limits
}

// NewExecutor validates its arguments.
func NewExecutor(cfg Config, d Domain, r Rail, s Store, c Clock) (*Executor, error) {
	bad := func(format string, a ...any) error {
		return fmt.Errorf("%w: %s", ErrInvalidConfig, fmt.Sprintf(format, a...))
	}
	if err := commitment.CheckPublicKey(cfg.GatePubKey); err != nil {
		return nil, fmt.Errorf("%w: gate key: %w", ErrInvalidConfig, err)
	}
	switch {
	case cfg.GateID == "":
		return nil, bad("empty gate id")
	case cfg.SkewS > maxSkewS:
		return nil, bad("skew %d above %d", cfg.SkewS, maxSkewS)
	case cfg.MaxTimeoutBlocks > bankaction.MaxTimeoutBlocks:
		return nil, bad("max timeout blocks above %d", bankaction.MaxTimeoutBlocks)
	case cfg.HandOffGrace < 0:
		return nil, bad("negative hand-off grace")
	case cfg.RebroadcastEvery < 0:
		return nil, bad("negative rebroadcast interval")
	case cfg.SignKey != nil && len(cfg.SignKey) != ed25519.PrivateKeySize:
		return nil, bad("sign key length")
	case d.ChainID == "" || d.Denom == "" || d.HRP == "" || d.Sender == "":
		return nil, bad("incomplete domain")
	case r == nil || s == nil || c == nil:
		return nil, bad("nil rail, store or clock")
	}
	cfg.GatePubKey = bytes.Clone(cfg.GatePubKey)
	cfg.SignKey = bytes.Clone(cfg.SignKey)
	cfg.Destinations = append([]string(nil), cfg.Destinations...)
	if cfg.MaxTimeoutBlocks == 0 {
		cfg.MaxTimeoutBlocks = defaultMaxTimeoutBlocks
	}
	if cfg.HandOffGrace == 0 {
		cfg.HandOffGrace = defaultHandOffGrace
	}
	if cfg.RebroadcastEvery == 0 {
		cfg.RebroadcastEvery = defaultRebroadcastEvery
	}
	return &Executor{
		cfg: cfg, dom: d, rail: r, store: s, clock: c,
		limits: bankaction.Limits{Destinations: cfg.Destinations, MaxAmount: cfg.MaxAmount},
	}, nil
}

func (e *Executor) now() uint64 {
	t := e.clock.Now().Unix()
	if t < 0 {
		return 0
	}
	return uint64(t)
}

// valid reports now + skew < expires without overflow.
func (e *Executor) valid(expires uint64) bool {
	now := e.now()
	return expires > now && expires-now > e.cfg.SkewS
}

// Execute verifies the authorization for exactly these action bytes, applies
// the executor's checks, signs one transaction and sends it until it is
// included. A decision that already has a record returns ErrSeen together with
// the stored outcome; the same bytes are sent again if the record is still
// being worked on.
func (e *Executor) Execute(ctx context.Context, authorization, action []byte) (Result, error) {
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	action = bytes.Clone(action)
	sa, _, err := commitment.VerifyAuthorization(authorization, commitment.AuthorizationCheck{
		GatePubKey: e.cfg.GatePubKey, GateID: e.cfg.GateID, ActionType: ActionType,
		Action: action, Now: e.now(), SkewS: e.cfg.SkewS,
	})
	if err != nil {
		return Result{}, err
	}
	a, _, err := bankaction.CheckExecution(action, bankaction.Domain(e.dom), e.limits)
	if err != nil {
		return Result{}, err
	}
	var h commitment.Hash
	if copy(h[:], sa.Authorization.CommitmentHash) != len(h) {
		return Result{}, fmt.Errorf("%w: commitment hash length", commitment.ErrActionMismatch)
	}
	expires := sa.Authorization.Expires

	switch err := e.store.Begin(ctx, h, expires); {
	case err == nil:
	case errors.Is(err, ErrSeen):
		return e.seen(ctx, h)
	default:
		return Result{}, fmt.Errorf("transfer: begin: %w", err)
	}

	p, err := e.prepare(ctx, h, a, expires)
	if err != nil {
		return Result{}, err
	}
	return e.drive(ctx, h, p)
}

// abandon closes a begun record, keeping the cause.
func (e *Executor) abandon(ctx context.Context, h commitment.Hash, cause error) error {
	if err := e.store.Abandon(ctx, h); err != nil {
		return errors.Join(cause, fmt.Errorf("transfer: closing the record: %w", err))
	}
	return cause
}

// prepare builds, signs and durably stores the transaction. Before Prepare
// returns nothing has been sent, so every failure up to it closes the record.
func (e *Executor) prepare(ctx context.Context, h commitment.Hash, a bankaction.Action, expires uint64) (Prepared, error) {
	if !e.valid(expires) {
		return Prepared{}, e.abandon(ctx, h, ErrExpired)
	}
	height, headTime, interval, err := e.rail.Head(ctx)
	if err != nil {
		return Prepared{}, e.abandon(ctx, h, fmt.Errorf("transfer: head: %w", err))
	}
	if interval <= 0 {
		return Prepared{}, e.abandon(ctx, h, errors.New("transfer: no block interval"))
	}
	tauMs := uint64((interval + time.Millisecond - 1) / time.Millisecond)
	th, err := bankaction.TimeoutHeight(bankaction.TimeoutInput{
		HeadHeight: height, HeadTime: headTime, TauMs: tauMs, Expires: expires,
		SkewS: e.cfg.SkewS, MaxBlocks: e.cfg.MaxTimeoutBlocks, Now: e.now(),
	})
	if err != nil {
		return Prepared{}, e.abandon(ctx, h, err)
	}
	body, err := bankaction.Body(a.Msg, h, th)
	if err != nil {
		return Prepared{}, e.abandon(ctx, h, err)
	}
	raw, err := e.rail.Sign(ctx, body, a.ChainID, e.cfg.MaxFee)
	if err != nil {
		return Prepared{}, e.abandon(ctx, h, fmt.Errorf("transfer: sign: %w", err))
	}
	if err := checkTxBody(raw, body); err != nil {
		return Prepared{}, e.abandon(ctx, h, err)
	}
	p := Prepared{TxRaw: raw, Hash: sha256.Sum256(raw), TimeoutHeight: th, Expires: expires}
	if err := e.store.Prepare(ctx, h, p); err != nil {
		// The write may have landed, so the record is left for Resume.
		return Prepared{}, fmt.Errorf("transfer: prepare: %w", err)
	}
	return p, nil
}

// checkTxBody requires the first field of txRaw, body_bytes, to equal body.
func checkTxBody(txRaw, body []byte) error {
	if len(txRaw) == 0 || txRaw[0] != 0x0a {
		return fmt.Errorf("%w: signed transaction has no body", bankaction.ErrBodyMismatch)
	}
	n, k := binary.Uvarint(txRaw[1:])
	if k <= 0 || n > uint64(len(txRaw)-1-k) {
		return fmt.Errorf("%w: signed transaction body length", bankaction.ErrBodyMismatch)
	}
	if !bytes.Equal(txRaw[1+k:1+k+int(n)], body) {
		return fmt.Errorf("%w: signed body differs from the built body", bankaction.ErrBodyMismatch)
	}
	return nil
}

// seen answers an Execute for a decision that has a record. A begun record is
// not touched: its owner may be signing right now.
func (e *Executor) seen(ctx context.Context, h commitment.Hash) (Result, error) {
	rec, err := e.store.Get(ctx, h)
	if err != nil {
		return Result{}, fmt.Errorf("%w: get: %w", ErrSeen, err)
	}
	if rec.State == StateBegun {
		return Result{}, fmt.Errorf("%w: another call is preparing it", ErrSeen)
	}
	res, err := e.resolve(ctx, h, rec)
	if err == nil {
		return res, ErrSeen
	}
	return res, fmt.Errorf("%w: %w", ErrSeen, err)
}

// Resume continues a decision after a crash, by lookup and by the stored
// bytes only. It never signs. A record that never got a transaction is
// closed.
func (e *Executor) Resume(ctx context.Context, h commitment.Hash) (Result, error) {
	rec, err := e.store.Get(ctx, h)
	if err != nil {
		return Result{}, fmt.Errorf("transfer: resume: %w", err)
	}
	if rec.State == StateBegun {
		return Result{}, e.abandon(ctx, h, fmt.Errorf("%w: no transaction was prepared", ErrAbandoned))
	}
	return e.resolve(ctx, h, rec)
}

func (e *Executor) resolve(ctx context.Context, h commitment.Hash, rec Record) (Result, error) {
	switch rec.State {
	case StatePrepared:
		return e.drive(ctx, h, rec.Prepared)
	case StateFinished:
		return outcome(rec.Prepared.Hash, rec.Height, rec.Code)
	case StateHandedOff:
		return e.reconcile(ctx, h, rec)
	case StateAbandoned:
		return Result{}, ErrAbandoned
	default:
		return Result{}, fmt.Errorf("transfer: record in state %d", rec.State)
	}
}

// reconcile looks a handed-off transaction up once: it may have been included
// after the hand-off was written. Nothing is signed or sent.
func (e *Executor) reconcile(ctx context.Context, h commitment.Hash, rec Record) (Result, error) {
	res := Result{TxHash: rec.Prepared.Hash}
	st, err := e.rail.Status(ctx, rec.Prepared.Hash)
	if err != nil {
		return res, fmt.Errorf("%w: status: %w", ErrHandedOff, err)
	}
	if st.State != TxCommitted {
		return res, ErrHandedOff
	}
	return e.finish(ctx, h, rec.Prepared.Hash, st)
}

func outcome(hash [32]byte, height uint64, code uint32) (Result, error) {
	res := Result{TxHash: hash, Height: height, Code: code}
	if code != 0 {
		return res, fmt.Errorf("%w: code %d", ErrFailedOnChain, code)
	}
	return res, nil
}

// drive sends the stored transaction until it is included, then ends the
// record. It sends only while the Authorization is valid by the wall clock and
// the chain has not passed the timeout height, and looks the status up before
// every send so an included transaction is never sent again. After the
// Authorization runs out it only watches: the transaction may still be
// included until the timeout height, so the hand-off waits for a status check
// made with a head past it.
func (e *Executor) drive(ctx context.Context, h commitment.Hash, p Prepared) (Result, error) {
	res := Result{TxHash: p.Hash}
	var lastSendErr error
	for {
		if err := ctx.Err(); err != nil {
			return res, err
		}
		live := e.valid(p.Expires)
		height, _, _, headErr := e.rail.Head(ctx)
		pastTimeout := headErr == nil && height > p.TimeoutHeight

		// The status is read after the head, so a transaction included
		// before that head is seen here.
		st, statusErr := e.rail.Status(ctx, p.Hash)
		if statusErr == nil && st.State == TxCommitted {
			return e.finish(ctx, h, p.Hash, st)
		}
		graceOver := e.now() >= p.Expires && e.now()-p.Expires >= uint64(e.cfg.HandOffGrace/time.Second)
		if pastTimeout || graceOver {
			if statusErr != nil {
				return res, fmt.Errorf("transfer: final status: %w", statusErr)
			}
			bound := fmt.Sprintf("head %d is past timeout_height %d", height, p.TimeoutHeight)
			if !pastTimeout {
				bound = fmt.Sprintf("hand-off grace of %s after expiry has passed while timeout_height %d is not reached; the transaction may still be included until then",
					e.cfg.HandOffGrace, p.TimeoutHeight)
			}
			reason := fmt.Sprintf("%s: %s (tx %x)", handOffReason, bound, p.Hash)
			if err := e.store.HandOff(ctx, h, reason); err != nil {
				return res, fmt.Errorf("transfer: hand off: %w", err)
			}
			if lastSendErr != nil {
				return res, fmt.Errorf("%w: %s (tx %x): last broadcast error: %w", ErrHandedOff, bound, p.Hash, lastSendErr)
			}
			return res, fmt.Errorf("%w: %s (tx %x)", ErrHandedOff, bound, p.Hash)
		}
		if !live && headErr != nil {
			return res, fmt.Errorf("transfer: head after the authorization expired: %w", headErr)
		}
		if live && headErr == nil {
			// A transient failure is retried with the same bytes on the next
			// turn; a final rejection ends the attempt.
			lastSendErr = e.rail.Broadcast(ctx, p.TxRaw)
			if errors.Is(lastSendErr, ErrRejected) {
				return e.rejected(ctx, h, p, lastSendErr)
			}
		}
		select {
		case <-ctx.Done():
			return res, ctx.Err()
		case <-e.clock.After(e.cfg.RebroadcastEvery):
		}
	}
}

func (e *Executor) finish(ctx context.Context, h commitment.Hash, hash [32]byte, st TxStatus) (Result, error) {
	if err := e.store.Finish(ctx, h, st.Height, st.Code); err != nil {
		return Result{TxHash: hash}, fmt.Errorf("transfer: finish: %w", err)
	}
	return outcome(hash, st.Height, st.Code)
}

// rejected ends a transfer the node refused. The refusal can come from a
// resend of a transaction that was included in the meantime (the ante checks
// may fail before the sequence check does), so the chain is asked once more
// after a short wait before anything is handed off.
func (e *Executor) rejected(ctx context.Context, h commitment.Hash, p Prepared, cause error) (Result, error) {
	res := Result{TxHash: p.Hash}
	select {
	case <-ctx.Done():
		return res, errors.Join(cause, ctx.Err())
	case <-e.clock.After(rejectRecheckDelay):
	}
	st, err := e.rail.Status(ctx, p.Hash)
	if err != nil {
		return res, errors.Join(cause, fmt.Errorf("transfer: status after the rejection: %w", err))
	}
	if st.State == TxCommitted {
		return e.finish(ctx, h, p.Hash, st)
	}
	if err := e.store.HandOff(ctx, h, "rejected by the node: "+cause.Error()); err != nil {
		return res, errors.Join(cause, fmt.Errorf("transfer: hand off: %w", err))
	}
	return res, fmt.Errorf("%w: %w", ErrHandedOff, cause)
}

// RecordRequest signs the executor's claim that railRef belongs to the
// decision h, for the gate's Record. It returns the executor's public key and
// the signature.
func (e *Executor) RecordRequest(h commitment.Hash, railRef string) (ed25519.PublicKey, []byte, error) {
	if e.cfg.SignKey == nil {
		return nil, nil, errors.New("transfer: no sign key configured")
	}
	msg, err := commitment.RecordRequestMessage(h, e.cfg.GateID, railRef)
	if err != nil {
		return nil, nil, err
	}
	pub, ok := e.cfg.SignKey.Public().(ed25519.PublicKey)
	if !ok {
		return nil, nil, errors.New("transfer: bad sign key")
	}
	return pub, ed25519.Sign(e.cfg.SignKey, msg), nil
}
