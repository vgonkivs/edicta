// SPDX-License-Identifier: Apache-2.0

package commitcmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/vgonkivs/edicta/plugins/edenescrow"
	"github.com/vgonkivs/edicta/plugins/edenescrow/edenrelay"
)

// Pickup delay bounds: the wait between two paid retries that must both be
// refused before the relay handoff, and between the handoff and the last
// retry. It covers a server that reads a lagging RPC or waits for
// confirmations.
const (
	DefaultPickupDelay = 10 * time.Second
	MaxPickupDelay     = 120 * time.Second
)

// MaxRetryAnswer bounds the body of a paid retry's answer; a longer one is
// never a recognised refusal.
const MaxRetryAnswer = 16384

// buyerRefusal is the payment server's refusal of a Payment-Signature whose
// signer is not the escrow's buyer. The signer's proof always comes from the
// buyer, so the remaining reading is a server that does not see the deposit.
var buyerRefusal = []byte("neither the escrow buyer")

// Recognised refusals of a paid retry.
const (
	// RefusalAsksAgain is a 402 whose PAYMENT-REQUIRED names the decision's
	// own paymentId.
	RefusalAsksAgain = "RR1"
	// RefusalBuyer is a 403 with the server's buyer-check text.
	RefusalBuyer = "RR2"
)

// RecognisedRefusal classifies the payment server's answer to a paid retry
// that carried the decision's Payment-Signature. It returns RefusalAsksAgain
// or RefusalBuyer, or "" for anything else (a success, any other status, a
// 402 naming another paymentId, an answer over MaxRetryAnswer bytes):
// only an exact match may lead to the relay handoff.
func RecognisedRefusal(status int, paymentRequired string, body []byte, paymentID [32]byte) string {
	if len(body) > MaxRetryAnswer {
		return ""
	}
	switch status {
	case http.StatusPaymentRequired:
		if paymentRequired == "" {
			return ""
		}
		r, err := edenescrow.DecodePaymentRequired(paymentRequired)
		if err != nil || edenescrow.CheckAsksForPayment(r, paymentID) != nil {
			return ""
		}
		return RefusalAsksAgain
	case http.StatusForbidden:
		if bytes.Contains(body, buyerRefusal) {
			return RefusalBuyer
		}
	}
	return ""
}

// HandoffConfig configures the relay handoff after a refused paid retry.
type HandoffConfig struct {
	// PaymentServer is the base URL the client called /deposit/build on
	// (https). The handoff posts to its /deposit/send and nowhere else.
	PaymentServer string
	// PickupDelay separates the two recognised refusals, and the handoff
	// from the last retry.
	PickupDelay time.Duration
	// ServerTimeout bounds the relay call.
	ServerTimeout time.Duration
}

// ApplyDefaults fills the zero fields.
func (c *HandoffConfig) ApplyDefaults() {
	if c.PickupDelay == 0 {
		c.PickupDelay = DefaultPickupDelay
	}
	if c.ServerTimeout == 0 {
		c.ServerTimeout = edenrelay.DefaultServerTimeout
	}
}

func (c HandoffConfig) relay() edenrelay.HoustonConfig {
	return edenrelay.HoustonConfig{BaseURL: c.PaymentServer, Timeout: c.ServerTimeout}
}

// ValidateBasic checks the fields alone.
func (c HandoffConfig) ValidateBasic() error {
	if c.PickupDelay <= 0 || c.PickupDelay > MaxPickupDelay {
		return fmt.Errorf("commitcmd: pickup delay %v is not in (0, %v]", c.PickupDelay, MaxPickupDelay)
	}
	if err := c.relay().ValidateBasic(); err != nil {
		return fmt.Errorf("commitcmd: payment server: %w", err)
	}
	return nil
}

// Handoff hands the stored signed deposit of an executed decision to the
// payment server's relay once, after its paid retry was refused twice in a
// recognised way. It signs nothing and moves no new money: the bytes are
// the ones the signer already signed and the chain already executed.
type Handoff struct {
	cfg   HandoffConfig
	relay *edenrelay.HoustonRelay
	log   *slog.Logger
}

// NewHandoff builds the relay for the configured payment server; hc nil is
// a client that follows no redirect, log nil the default logger.
func NewHandoff(cfg HandoffConfig, hc *http.Client, log *slog.Logger) (*Handoff, error) {
	if err := cfg.ValidateBasic(); err != nil {
		return nil, err
	}
	if log == nil {
		log = slog.Default()
	}
	r, err := edenrelay.NewHoustonRelay(cfg.relay(), hc, log)
	if err != nil {
		return nil, err
	}
	return &Handoff{cfg: cfg, relay: r, log: log}, nil
}

// PaidRetry is the payment server's answer to a paid retry, as the client
// received it.
type PaidRetry struct {
	CommitmentHash string `json:"commitment_hash"`
	// PaymentSignature is the one the retry carried.
	PaymentSignature string `json:"payment_signature"`
	Status           int    `json:"status"`
	// PaymentRequired is the answer's PAYMENT-REQUIRED header value, if any.
	PaymentRequired string `json:"payment_required,omitempty"`
	// Body is the whole answer body.
	Body []byte `json:"body,omitempty"`
}

// What the client does after a reported paid retry.
const (
	// NextNone: not a recognised refusal; nothing is done here.
	NextNone = "none"
	// NextRetry: retry the paid call with the same Payment-Signature after
	// RetryAfterMS.
	NextRetry = "retry"
	// NextOperator: refused again after the handoff; the operator decides.
	NextOperator = "operator"
)

// PaidRetryResult says what the client does next. The relay's answer is
// never evidence of anything; RelayFault only reports it.
type PaidRetryResult struct {
	CommitmentHash string `json:"commitment_hash"`
	// Refusal is RefusalAsksAgain, RefusalBuyer or empty.
	Refusal string `json:"refusal,omitempty"`
	Next    string `json:"next"`
	// RetryAfterMS is the wait before the next paid retry.
	RetryAfterMS int64 `json:"retry_after_ms,omitempty"`
	// HandedOff is set on the answer that made the handoff.
	HandedOff bool `json:"handed_off,omitempty"`
	// RelayFault is the relay's error, if the handoff call failed; it is
	// not retried.
	RelayFault string `json:"relay_fault,omitempty"`
	// HandoffOutcome is what became of the one handoff, once it was made:
	// one of the HandoffOutcome constants.
	HandoffOutcome string `json:"handoff_outcome,omitempty"`
	// PaymentSignature is the stored one, for the retry; never another.
	PaymentSignature string `json:"payment_signature,omitempty"`
}

// What became of the one relay handoff. None of them is evidence that the
// deposit landed, and none allows a second handoff.
const (
	// HandoffOutcomeSent: the relay answered with a success that names no
	// other transaction.
	HandoffOutcomeSent = "sent"
	// HandoffOutcomeRelayFault: the request was written to the relay, and
	// its answer was an error, never came, or named another transaction.
	HandoffOutcomeRelayFault = "relay_fault"
	// HandoffOutcomeNotSent: the request never completely left this
	// process, so the payment server cannot have read the bytes from it.
	// The operator decides whether to hand them over by other means.
	HandoffOutcomeNotSent = "not_sent"
	// HandoffOutcomeUnknown: the mark is stored but no outcome yet. Either
	// the call is still running or the process stopped during it, so the
	// bytes may or may not have left.
	HandoffOutcomeUnknown = "unknown"
)

func handoffRefused(format string, a ...any) *Failure {
	return &Failure{Exit: ExitRefused, Code: "handoff_refused", Message: fmt.Sprintf(format, a...)}
}

// PaidRetry takes the answer to one paid retry and decides the next step.
// Two recognised refusals at least PickupDelay apart lead to one handoff of
// the stored signed bytes to the configured payment server, recorded in the
// state store before it is sent; one more recognised refusal at least
// PickupDelay after it goes to the operator.
func (s *Service) PaidRetry(ctx context.Context, rep PaidRetry) (PaidRetryResult, error) {
	h := s.Handoff
	if h == nil {
		return PaidRetryResult{}, usagef("no payment server is configured for the relay handoff")
	}
	if s.State == nil {
		return PaidRetryResult{}, usagef("the relay handoff needs a state directory: its once mark must survive a restart")
	}
	out, send, err := s.decideRetry(rep, h.cfg.PickupDelay)
	if err != nil || send == nil {
		return out, err
	}
	out.HandedOff = true
	// The mark is spent already, so the caller going away must not cancel
	// the one call it allows; the relay bounds the call with its own
	// timeout.
	err = h.relay.Send(context.WithoutCancel(ctx), send.signed, send.railRef, send.paymentID)
	switch {
	case err == nil:
		out.HandoffOutcome = HandoffOutcomeSent
	case errors.Is(err, edenrelay.ErrNotSent):
		out.HandoffOutcome, out.RelayFault = HandoffOutcomeNotSent, err.Error()
		h.log.Warn("commitcmd: the relay handoff never left this process; it is not repeated, the operator decides",
			"commitment_hash", rep.CommitmentHash, "rail_ref", send.railRef, "err", err)
	default:
		out.HandoffOutcome, out.RelayFault = HandoffOutcomeRelayFault, err.Error()
		h.log.Warn("commitcmd: relay handoff failed; it is not repeated", "commitment_hash", rep.CommitmentHash,
			"rail_ref", send.railRef, "err", err)
	}
	if err := s.recordHandoffOutcome(rep.CommitmentHash, out.HandoffOutcome); err != nil {
		h.log.Warn("commitcmd: the relay handoff's outcome could not be stored; it reads as unknown",
			"commitment_hash", rep.CommitmentHash, "outcome", out.HandoffOutcome, "err", err)
	}
	return out, nil
}

// recordHandoffOutcome stores what became of the handoff next to its mark.
func (s *Service) recordHandoffOutcome(hexHash, outcome string) error {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	st, ok, err := s.State.Load(hexHash)
	if err != nil {
		return err
	}
	if !ok || st.HandoffAtMS == 0 {
		return errors.New("commitcmd: the stored state lost the handoff mark")
	}
	st.HandoffOutcome = outcome
	return s.State.Save(hexHash, st)
}

type handoffSend struct {
	signed    []byte
	railRef   string
	paymentID [32]byte
}

// decideRetry reads the report against the stored run and, when it is the
// second recognised refusal, stores the once mark and returns what to send.
func (s *Service) decideRetry(rep PaidRetry, pickup time.Duration) (PaidRetryResult, *handoffSend, error) {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()

	st, f := s.loadState(rep.CommitmentHash)
	if f != nil {
		return PaidRetryResult{}, nil, f
	}
	if st.PaymentSignature == "" {
		return PaidRetryResult{}, nil, handoffRefused("no Payment-Signature was released here for commitment %s", rep.CommitmentHash)
	}
	if rep.PaymentSignature != st.PaymentSignature {
		return PaidRetryResult{}, nil, handoffRefused("the paid retry did not carry this decision's Payment-Signature")
	}
	tx, err := edenescrow.DecodeTxAction(st.Action)
	if err != nil {
		return PaidRetryResult{}, nil, handoffRefused("the stored action is not an Eden escrow deposit: %v", err)
	}
	out := PaidRetryResult{CommitmentHash: rep.CommitmentHash, Next: NextNone, PaymentSignature: st.PaymentSignature}
	out.Refusal = RecognisedRefusal(rep.Status, rep.PaymentRequired, rep.Body, tx.Deposit.PaymentID)
	if out.Refusal == "" {
		return out, nil, nil
	}

	now := s.now().UnixMilli()
	delay := pickup.Milliseconds()
	retryAt := func(from int64) PaidRetryResult {
		out.Next, out.RetryAfterMS = NextRetry, max(from+delay-now, 0)
		return out
	}
	save := func() *Failure {
		if err := s.State.Save(rep.CommitmentHash, st); err != nil {
			return &Failure{Exit: ExitUnavailable, Code: "state_unavailable", Retryable: true, Message: err.Error()}
		}
		return nil
	}
	if st.HandoffAtMS != 0 {
		out.HandoffOutcome = st.HandoffOutcome
		if out.HandoffOutcome == "" {
			out.HandoffOutcome = HandoffOutcomeUnknown
		}
	}
	switch {
	case st.HandoffAtMS != 0 && now-st.HandoffAtMS < delay:
		return retryAt(st.HandoffAtMS), nil, nil
	case st.HandoffAtMS != 0:
		out.Next = NextOperator
		return out, nil, nil
	case st.RefusedAtMS == 0:
		st.RefusedAtMS = now
		if f := save(); f != nil {
			return PaidRetryResult{}, nil, f
		}
		return retryAt(now), nil, nil
	case now-st.RefusedAtMS < delay:
		return retryAt(st.RefusedAtMS), nil, nil
	}

	signed, railRef, f := handoffBytes(tx, st)
	if f != nil {
		return PaidRetryResult{}, nil, f
	}
	// The mark is durable before the bytes leave: a crash after it never
	// leads to a second handoff.
	st.HandoffAtMS = now
	if f := save(); f != nil {
		return PaidRetryResult{}, nil, f
	}
	return retryAt(now), &handoffSend{signed: signed, railRef: railRef, paymentID: tx.Deposit.PaymentID}, nil
}

// handoffBytes are the stored signed bytes, checked to be the committed
// transaction with the signature of the payer that also made the stored
// Payment-Signature, and to hash to the stored rail_ref.
func handoffBytes(tx edenescrow.TxAction, st State) ([]byte, string, *Failure) {
	if len(st.Signed) == 0 {
		return nil, "", handoffRefused("no signed deposit is stored for this decision")
	}
	if got := edenescrow.RailRef(st.Signed); got != st.RailRef {
		return nil, "", handoffRefused("the stored signed bytes hash to %s, not the rail_ref %s", got, st.RailRef)
	}
	_, payer, err := edenescrow.ParseSigned(tx, st.Signed)
	if err != nil {
		return nil, "", handoffRefused("the stored signed bytes are not the committed transaction: %v", err)
	}
	sig, ok := parseProofSignature([]byte(st.PaymentSignature))
	if !ok {
		return nil, "", handoffRefused("the stored Payment-Signature is malformed")
	}
	who, err := edenescrow.RecoverPersonal(tx.Deposit.PaymentID, sig)
	if err != nil || who != payer {
		return nil, "", handoffRefused("the stored Payment-Signature is not the deposit payer's")
	}
	return st.Signed, st.RailRef, nil
}

// DecodePaidRetry reads one report strictly, as DecodeRequest does.
func DecodePaidRetry(r io.Reader) (PaidRetry, error) {
	data, err := io.ReadAll(io.LimitReader(r, MaxRequestBytes+1))
	if err != nil {
		return PaidRetry{}, usagef("read request: %v", err)
	}
	if len(data) > MaxRequestBytes {
		return PaidRetry{}, usagef("request larger than %d bytes", MaxRequestBytes)
	}
	if err := CheckJSON(data); err != nil {
		return PaidRetry{}, usagef("request: %v", err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var rep PaidRetry
	if err := dec.Decode(&rep); err != nil {
		return PaidRetry{}, usagef("request: %v", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return PaidRetry{}, usagef("request: data after the object")
	}
	return rep, nil
}
