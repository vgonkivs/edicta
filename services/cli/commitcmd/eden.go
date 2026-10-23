// SPDX-License-Identifier: Apache-2.0

package commitcmd

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/vgonkivs/edicta/api/signerapi"
	"github.com/vgonkivs/edicta/engine/commitment"
	"github.com/vgonkivs/edicta/plugins/edenescrow"
)

// PaymentField is the Payment-Signature field `edicta commit` asks for. It is
// the only one the signer offers.
const PaymentField = "paymentId"

const (
	defaultSettleWait = 5 * time.Minute
	maxSettleWait     = time.Hour
	defaultPoll       = 2 * time.Second
	// ContextKey is the member of the payload context that carries the
	// quote and the resource; a caller's own context may not use it.
	ContextKey = "eden_escrow"
)

// EdenInput is the Eden input mode: the payment server's /deposit/build
// answer and the PAYMENT-REQUIRED header of its 402. The action bytes are
// converted by edenescrow; the server's transaction is untrusted input and
// the decoded transaction is what is committed.
type EdenInput struct {
	// Build is the /deposit/build JSON, verbatim.
	Build json.RawMessage `json:"build,omitempty"`
	// PaymentRequired is the header value as received (base64); its decoded
	// bytes are the quote R.
	PaymentRequired string `json:"payment_required,omitempty"`
	// Resource is the https:// URL the client calls. Empty takes the quote's
	// resource URL when that already starts with https://.
	Resource string `json:"resource,omitempty"`
}

// State is what a run keeps so that it can continue after a crash. It holds
// no key.
type State struct {
	Envelope      []byte `json:"envelope"`
	Action        []byte `json:"action"`
	Salt          []byte `json:"salt"`
	Authorization []byte `json:"authorization,omitempty"`
	Requirements  []byte `json:"requirements,omitempty"`
	Signed        []byte `json:"signed_tx,omitempty"`
	RailRef       string `json:"rail_ref,omitempty"`
	Mode          string `json:"mode"`
	// PaymentSignature is the signer's Payment-Signature, once released and
	// checked here.
	PaymentSignature string `json:"payment_signature,omitempty"`
	// RefusedAtMS is when the first recognised refusal of a paid retry was
	// reported, Unix milliseconds.
	RefusedAtMS int64 `json:"refused_at_ms,omitempty"`
	// HandoffAtMS marks the one relay handoff; it is stored before the bytes
	// are sent.
	HandoffAtMS int64 `json:"handoff_at_ms,omitempty"`
	// HandoffOutcome is what became of that handoff, stored after the call:
	// a HandoffOutcome constant. Empty with HandoffAtMS set means the
	// process stopped before it was stored.
	HandoffOutcome string `json:"handoff_outcome,omitempty"`
}

// StateStore persists a State by commitment hash (64 lower-case hex). Save
// replaces atomically. It may do I/O.
type StateStore interface {
	Save(hash string, st State) error
	Load(hash string) (State, bool, error)
}

type edenContext struct {
	Header          string                 `json:"payment_required_header"`
	PaymentRequired []byte                 `json:"payment_required"`
	RequirementsH   string                 `json:"requirements_hash"`
	Resource        string                 `json:"resource"`
	Deposit         edenescrow.DepositView `json:"deposit"`
}

func edenUsage(format string, a ...any) *Failure {
	return &Failure{Exit: ExitUsage, Code: "eden_input", Message: fmt.Sprintf(format, a...)}
}

func (r Request) wantsSettle() bool { return r.Sign || r.Broadcast || r.Record || r.PaymentSignature }

// settleWait parses the bound on the settlement wait.
func (s *Service) settleWait(req Request) (time.Duration, *Failure) {
	d := s.DefaultWait
	if d <= 0 {
		d = defaultSettleWait
	}
	if req.Wait != "" {
		p, err := time.ParseDuration(req.Wait)
		if err != nil || p <= 0 || p > maxSettleWait {
			return 0, usagef("wait %q is not a duration in (0, %s]", req.Wait, maxSettleWait)
		}
		d = p
	}
	return d, nil
}

// checkEdenFlags refuses an inconsistent request before anything is
// published.
func (s *Service) checkEdenFlags(req Request) *Failure {
	resuming := req.Resume != nil || req.ResumeHash != ""
	if req.Eden == nil && !req.wantsSettle() && !resuming {
		return nil
	}
	if req.Eden == nil && !resuming {
		return usagef("sign, broadcast, record and payment_signature need the eden input")
	}
	if (req.Record || req.PaymentSignature) && !req.Sign && !resuming {
		return usagef("record and payment_signature on a new commitment need sign and broadcast (nothing could be paid otherwise)")
	}
	if req.wantsSettle() {
		if s.Signer == nil {
			return usagef("no signer is configured: pass the signer URL and token file")
		}
		if req.Sign != req.Broadcast {
			return usagef("the signer sends the transaction as soon as it signs it: sign and broadcast go together")
		}
	}
	if _, f := s.settleWait(req); f != nil {
		return f
	}
	if req.ResumeHash != "" && s.State == nil {
		return usagef("resume by commitment hash needs a state directory")
	}
	return nil
}

// prepared is the outcome of the Eden conversion.
type prepared struct {
	action []byte
	rr     []byte
	tx     edenescrow.TxAction
	ctx    json.RawMessage
}

// prepareEden converts the build answer and the quote into the committed
// action bytes and the payload context. It runs before anything is
// published.
func (s *Service) prepareEden(req Request) (*prepared, *Failure) {
	e := req.Eden
	switch {
	case len(bytes.TrimSpace(e.Build)) == 0:
		return nil, edenUsage("eden.build is required")
	case e.PaymentRequired == "":
		return nil, edenUsage("eden.payment_required is required")
	case req.ActionType != "" || len(req.Action) != 0:
		return nil, edenUsage("action_type and action come from the eden input")
	}
	rr, err := edenescrow.DecodePaymentRequired(e.PaymentRequired)
	if err != nil {
		return nil, edenUsage("payment_required: %v", err)
	}
	resource := e.Resource
	if resource == "" {
		resource = quoteResource(rr)
	}
	if !strings.HasPrefix(resource, "https://") {
		return nil, edenUsage("the resource %q does not start with https://: pass eden.resource with the https URL the client calls", resource)
	}
	h := edenescrow.RequirementsHash(rr)
	action, tx, err := edenescrow.ActionFromDepositBuild(e.Build, resource, h)
	if err != nil {
		return nil, edenUsage("build: %v", err)
	}
	if _, err := edenescrow.CheckRequirements(tx, rr, true); err != nil {
		return nil, edenUsage("payment_required: %v", err)
	}
	now := s.now()
	if uint64(now.Unix())+authSkewS >= tx.Deposit.ExpiresAt {
		return nil, &Failure{Exit: ExitRefused, Code: "quote_expired", Message: "the quote's expiresAt has passed: fetch a new 402"}
	}
	if req.ValidFor != "" {
		if d, err := time.ParseDuration(req.ValidFor); err == nil && d > 0 && uint64(now.Add(d).Unix()) < tx.Deposit.ExpiresAt {
			return nil, edenUsage("valid_for ends before the quote's expiresAt: the signer would refuse the deposit")
		}
	}
	ctx, err := composeContext(req.Context, edenContext{
		Header: e.PaymentRequired, PaymentRequired: rr, RequirementsH: hex.EncodeToString(h[:]),
		Resource: resource, Deposit: tx.DepositView(),
	})
	if err != nil {
		return nil, edenUsage("%v", err)
	}
	return &prepared{action: action, rr: rr, tx: tx, ctx: ctx}, nil
}

// composeContext adds the quote member to the caller's context object, so an
// auditor holding the payload can recompute the requirements hash.
func composeContext(user json.RawMessage, ec edenContext) (json.RawMessage, error) {
	members := map[string]json.RawMessage{}
	if t := bytes.TrimSpace(user); len(t) != 0 && !bytes.Equal(t, []byte("null")) {
		if err := CheckJSON(user); err != nil {
			return nil, fmt.Errorf("context: %v", err)
		}
		if err := json.Unmarshal(user, &members); err != nil {
			return nil, errors.New("context must be a JSON object when the eden input is used")
		}
		for k := range members {
			if strings.EqualFold(k, ContextKey) {
				return nil, fmt.Errorf("context may not use the member %q", ContextKey)
			}
		}
	}
	raw, err := marshalPlain(ec)
	if err != nil {
		return nil, err
	}
	members[ContextKey] = raw
	return marshalPlain(members)
}

// marshalPlain is json.Marshal without HTML escaping, so the payload keeps
// the caller's bytes for < > and &.
func marshalPlain(v any) (json.RawMessage, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// quoteResource returns resource.url of R, or "" when R has none.
func quoteResource(rr []byte) string {
	var d struct {
		Resource struct {
			URL string `json:"url"`
		} `json:"resource"`
	}
	if CheckJSON(rr) != nil || json.Unmarshal(rr, &d) != nil {
		return ""
	}
	return d.Resource.URL
}

// run is the state of one commit across the steps.
type run struct {
	hash commitment.Hash
	hexH string
	mode string
	st   State
	rr   []byte
}

func (r *run) carry(f *Failure) *Failure {
	f.CommitmentHash = r.hexH
	f.Envelope, f.Action, f.Salt = r.st.Envelope, r.st.Action, r.st.Salt
	if len(r.st.Authorization) != 0 {
		f.Authorization = r.st.Authorization
	}
	f.RailRef = r.st.RailRef
	return f
}

func envelopeHash(envelope []byte) (commitment.Hash, *Failure) {
	sc, err := commitment.DecodeSigned(envelope)
	if err != nil {
		return commitment.Hash{}, usagef("envelope: %v", err)
	}
	h, err := commitment.HashOf(&sc.Commitment)
	if err != nil {
		return commitment.Hash{}, usagef("envelope: %v", err)
	}
	return h, nil
}

func (s *Service) save(r *run) *Failure {
	if s.State == nil {
		return nil
	}
	r.st.Requirements = r.rr
	r.st.Mode = r.mode
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	// The paid-retry marks are written by their own reports, never by a
	// run: a run that started before them keeps them.
	if old, ok, err := s.State.Load(r.hexH); err == nil && ok && bytes.Equal(old.Envelope, r.st.Envelope) {
		r.st.RefusedAtMS = max(r.st.RefusedAtMS, old.RefusedAtMS)
		r.st.HandoffAtMS = max(r.st.HandoffAtMS, old.HandoffAtMS)
		if r.st.HandoffOutcome == "" {
			r.st.HandoffOutcome = old.HandoffOutcome
		}
		if r.st.PaymentSignature == "" {
			r.st.PaymentSignature = old.PaymentSignature
		}
	}
	if err := s.State.Save(r.hexH, r.st); err != nil {
		return r.carry(&Failure{Exit: ExitUnavailable, Code: "state_unavailable", Retryable: true,
			Message: fmt.Sprintf("the state could not be stored (continue with the resume fields): %v", err)})
	}
	return nil
}

// loadState reads the run a previous call kept and checks that it is the one
// asked for.
func (s *Service) loadState(hexHash string) (State, *Failure) {
	b, err := hex.DecodeString(hexHash)
	if err != nil || len(b) != 32 || hex.EncodeToString(b) != hexHash {
		return State{}, usagef("resume_hash must be 64 lower-case hex characters")
	}
	st, ok, err := s.State.Load(hexHash)
	if err != nil {
		return State{}, &Failure{Exit: ExitUnavailable, Code: "state_unavailable", Retryable: true, Message: err.Error()}
	}
	if !ok {
		return State{}, usagef("no stored state for commitment %s", hexHash)
	}
	h, ferr := envelopeHash(st.Envelope)
	if ferr != nil {
		return State{}, ferr
	}
	if hex.EncodeToString(h[:]) != hexHash {
		return State{}, usagef("the stored state does not belong to commitment %s", hexHash)
	}
	if len(st.Action) == 0 || len(st.Salt) == 0 {
		return State{}, usagef("the stored state is incomplete")
	}
	return st, nil
}

// signTimeout bounds the sign call. It runs detached from the caller's
// cancellation: the signer may finish and send the deposit after the caller
// gave up, and the answer must still be stored.
const signTimeout = 2 * time.Minute

// routeAbsent is the code a signer without the status route answers with.
const routeAbsent = "edictaapi.ErrRouteNotFound"

// unknownDecision is the code of a hash the signer holds nothing for (or does
// not show to this credential).
const unknownDecision = signerapi.CodeUnknownDecision

func signerCode(err error) string {
	var se *SignerError
	if errors.As(err, &se) {
		return se.Code
	}
	return ""
}

// final marks an error that ends a poll.
type final struct{ f *Failure }

func (e final) Error() string { return e.f.Error() }

// settle takes an authorized Eden commitment through the flags the request
// set: sign (the signer also sends), then follow the deposit until it
// executed. The signer's answers are checked here against the committed
// action; none is taken on trust.
func (s *Service) settle(ctx context.Context, req Request, r *run, resp *Response) error {
	tx, err := edenescrow.DecodeTxAction(r.st.Action)
	if err != nil {
		return r.carry(usagef("the action is not an Eden escrow deposit: %v", err))
	}
	if len(r.rr) == 0 {
		return r.carry(usagef("the quote R is needed: pass eden.payment_required"))
	}
	if _, err := edenescrow.CheckRequirements(tx, r.rr, true); err != nil {
		return r.carry(usagef("payment_required: %v", err))
	}
	view := tx.DepositView()
	resp.Deposit = &view
	var payer [20]byte
	havePayer := false
	fill := func() *Failure {
		if len(r.st.Signed) == 0 {
			return nil
		}
		_, p, err := edenescrow.ParseSigned(tx, r.st.Signed)
		if err != nil {
			return r.carry(usagef("the stored signed transaction is not the committed one: %v", err))
		}
		payer, havePayer = p, true
		resp.SignedTx, resp.RailRef, resp.Payer = r.st.Signed, edenescrow.RailRef(r.st.Signed), "0x"+hex.EncodeToString(p[:])
		return nil
	}
	if f := fill(); f != nil {
		return f
	}
	if !req.wantsSettle() {
		return nil
	}
	wait, _ := s.settleWait(req)

	// The signer may already hold this decision (an earlier call was cut
	// off after it signed): follow its bytes, never sign again.
	statusAbsent, confirmedUnknown := false, false
	if len(r.st.Signed) == 0 {
		st, serr := s.Signer.Status(ctx, r.hash)
		switch {
		case serr == nil && len(st.Signed) != 0:
			if f := s.adopt(r, tx, st.Signed, st.RailRef); f != nil {
				return f
			}
			if f := s.save(r); f != nil {
				return f
			}
			if f := fill(); f != nil {
				return f
			}
		case serr == nil:
		case signerCode(serr) == routeAbsent:
			statusAbsent = true
		case signerCode(serr) == unknownDecision:
			confirmedUnknown = true
		}
	}

	if req.Sign && len(r.st.Signed) == 0 {
		hold := "the signer may already hold this decision: continue with the commitment hash (resume_hash with record or payment_signature) or ask the operator; do not commit again"
		if uint64(s.now().Unix())+authSkewS >= resp.Expires {
			msg := "the Authorization has expired and the signer holds nothing for this decision: commit again"
			if !confirmedUnknown {
				msg = "the Authorization has expired; " + hold
			}
			return r.carry(&Failure{Exit: ExitRefused, Code: "authorization_expired", Message: msg})
		}
		if tx.Deposit.ExpiresAt > resp.Expires {
			return r.carry(&Failure{Exit: ExitRefused, Code: "quote_outlives_authorization",
				Message: "the quote's expiresAt is after the Authorization's expiry: commit again with a longer valid_for"})
		}
		sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), signTimeout)
		out, err := s.Signer.Sign(sctx, signerapi.Request{
			Envelope: r.st.Envelope, Action: r.st.Action, Salt: r.st.Salt, Authorization: r.st.Authorization, Requirements: r.rr,
		})
		cancel()
		if err != nil {
			f := classify(err)
			if f.Exit == ExitRefused && f.Code == "signer.unparsable" {
				f.Exit, f.Retryable = ExitUnavailable, true
			}
			if f.Exit == ExitUnavailable {
				f.Message += " (" + hold + ")"
			}
			return r.carry(f)
		}
		if out.CommitmentHash != r.hash || out.RailRef != edenescrow.RailRef(out.Signed) {
			return r.carry(&Failure{Exit: ExitRefused, Code: "signer_response_invalid", Message: "the signer answered for another decision or rail_ref"})
		}
		if f := s.adopt(r, tx, out.Signed, out.RailRef); f != nil {
			return f
		}
		if f := s.save(r); f != nil {
			f.SignedTx = r.st.Signed
			return f
		}
		if f := fill(); f != nil {
			return f
		}
	}
	if !req.Record && !req.PaymentSignature {
		return nil
	}
	if len(r.st.Signed) == 0 && !statusAbsent {
		msg := "the signer holds no signed deposit for this commitment: pass sign and broadcast"
		if !confirmedUnknown {
			msg = "the signer's status is unknown; " + "continue later with the commitment hash"
		}
		return r.carry(usagef("%s", msg))
	}

	if !statusAbsent {
		st, absent, err := s.awaitSettled(ctx, r, wait)
		if err != nil {
			return err
		}
		if !absent {
			resp.Settled, resp.Recorded = true, st.State == signerapi.StateRecorded
			if resp.Recorded {
				resp.Receipt = st.Receipt
			}
		}
		statusAbsent = absent
	}
	if !req.PaymentSignature && !statusAbsent {
		return nil
	}
	proof, err := s.awaitProof(ctx, r, wait)
	if err != nil {
		return err
	}
	msg, err := edenescrow.PaymentProofMessage(tx, r.rr)
	if err != nil {
		return r.carry(&Failure{Exit: ExitRefused, Code: "payment_proof_unavailable", Message: err.Error()})
	}
	sig, ok := parseProofSignature(proof.Signature)
	if proof.Message != msg || !ok {
		return r.carry(&Failure{Exit: ExitRefused, Code: "signer_response_invalid", Message: "the payment proof does not cover the decision's paymentId"})
	}
	who, err := edenescrow.RecoverPersonal(msg, sig)
	if err != nil || havePayer && who != payer {
		return r.carry(&Failure{Exit: ExitRefused, Code: "signer_response_invalid", Message: "the payment proof was not made by the payer of the signed transaction"})
	}
	if !havePayer {
		resp.Payer = "0x" + hex.EncodeToString(who[:])
		resp.Warning = "the signed transaction is not known here: the payer is taken from the payment proof and was not cross-checked"
	}
	resp.Settled = true
	if r.st.PaymentSignature != string(proof.Signature) {
		r.st.PaymentSignature = string(proof.Signature)
		if f := s.save(r); f != nil {
			return f
		}
	}
	if req.PaymentSignature {
		resp.PaymentSignature = string(proof.Signature)
	}
	return nil
}

// adopt checks signed bytes against the committed action and keeps them. A
// stored value is never replaced by different bytes.
func (s *Service) adopt(r *run, tx edenescrow.TxAction, signed []byte, railRef string) *Failure {
	if _, _, err := edenescrow.ParseSigned(tx, signed); err != nil {
		return r.carry(&Failure{Exit: ExitRefused, Code: "signer_response_invalid", Message: fmt.Sprintf("the signed transaction is not the committed one: %v", err)})
	}
	if railRef != "" && railRef != edenescrow.RailRef(signed) {
		return r.carry(&Failure{Exit: ExitRefused, Code: "signer_response_invalid", Message: "the signer's rail_ref is not the hash of its signed transaction"})
	}
	if len(r.st.Signed) != 0 && !bytes.Equal(r.st.Signed, signed) {
		return r.carry(&Failure{Exit: ExitRefused, Code: "signer_response_invalid", Message: "the signer's signed transaction differs from the stored one"})
	}
	r.st.Signed, r.st.RailRef = bytes.Clone(signed), edenescrow.RailRef(signed)
	return nil
}

// poll repeats step every poll interval until it returns nil, a final error
// or the wait is over. The wait is counted in intervals and also bounded by
// the wall clock, since one step may take as long as the client timeout.
func (s *Service) poll(ctx context.Context, r *run, wait time.Duration, step func(ctx context.Context) error) error {
	interval := s.PollInterval
	if interval <= 0 {
		interval = defaultPoll
	}
	wctx, cancel := context.WithTimeout(ctx, wait)
	defer cancel()
	pending := func(err error) error {
		f := classify(err)
		f.Exit, f.Retryable, f.Code = ExitUnavailable, true, "settlement_pending"
		f.Message = fmt.Sprintf("the deposit was not reported executed within %s (continue with the commitment hash): %v", wait, err)
		return r.carry(f)
	}
	for elapsed := time.Duration(0); ; elapsed += interval {
		err := step(wctx)
		if err == nil {
			return nil
		}
		var fin final
		if errors.As(err, &fin) {
			return r.carry(fin.f)
		}
		if ctx.Err() != nil {
			return r.carry(classify(ctx.Err()))
		}
		var se *SignerError
		if errors.As(err, &se) && !se.Retryable && se.Code != "signer.unparsable" {
			return r.carry(classify(err))
		}
		if wctx.Err() != nil || elapsed+interval > wait {
			return pending(err)
		}
		if werr := s.sleep(wctx, interval); werr != nil {
			if ctx.Err() != nil {
				return r.carry(classify(ctx.Err()))
			}
			return pending(err)
		}
	}
}

// awaitSettled follows the decision through the signer's status route until
// the deposit executed. absent is set when the signer has no such route.
func (s *Service) awaitSettled(ctx context.Context, r *run, wait time.Duration) (signerapi.Status, bool, error) {
	var out signerapi.Status
	absent := false
	err := s.poll(ctx, r, wait, func(c context.Context) error {
		st, err := s.Signer.Status(c, r.hash)
		if err != nil {
			if signerCode(err) == routeAbsent {
				absent = true
				return nil
			}
			if signerCode(err) == unknownDecision {
				return final{&Failure{Exit: ExitRefused, Code: unknownDecision, Message: "the signer holds nothing for this decision"}}
			}
			return err
		}
		if len(st.Signed) != 0 && !bytes.Equal(st.Signed, r.st.Signed) {
			return final{&Failure{Exit: ExitRefused, Code: "signer_response_invalid", Message: "the signer's signed transaction differs from the stored one"}}
		}
		switch st.State {
		case signerapi.StateExecuted, signerapi.StateRecorded:
			out = st
			return nil
		case signerapi.StateReverted:
			return final{&Failure{Exit: ExitRefused, Code: "deposit_reverted", Message: "the deposit was included and reverted"}}
		case signerapi.StateNotExecuted:
			return final{&Failure{Exit: ExitRefused, Code: "deposit_not_executed", Message: "the deposit was not executed before its deadline: " + st.Detail}}
		case signerapi.StateWrong:
			return final{&Failure{Exit: ExitRefused, Code: "settlement_wrong", Message: "the signer needs its operator: " + st.Detail}}
		}
		return &SignerError{Status: 409, Code: signerapi.CodeNotExecuted, Message: "state " + string(st.State), Retryable: true}
	})
	return out, absent, err
}

// awaitProof asks for the payment proof until the signer releases it, which
// it does only once the deposit executed at its configured level.
func (s *Service) awaitProof(ctx context.Context, r *run, wait time.Duration) (signerapi.PaymentProof, error) {
	req := signerapi.PaymentProofRequest{CommitmentHash: r.hash, Field: PaymentField, Request: signerapi.Request{
		Envelope: r.st.Envelope, Action: r.st.Action, Salt: r.st.Salt, Authorization: r.st.Authorization, Requirements: r.rr,
	}}
	var proof signerapi.PaymentProof
	err := s.poll(ctx, r, wait, func(c context.Context) error {
		p, err := s.Signer.PaymentSignature(c, req)
		proof = p
		return err
	})
	return proof, err
}

func (s *Service) sleep(ctx context.Context, d time.Duration) error {
	if s.Sleep != nil {
		return s.Sleep(ctx, d)
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// parseProofSignature reads "0x" and 130 hex digits: r, s, v.
func parseProofSignature(b []byte) ([65]byte, bool) {
	var out [65]byte
	s := string(b)
	if len(s) != 132 || s[:2] != "0x" {
		return out, false
	}
	raw, err := hex.DecodeString(s[2:])
	if err != nil {
		return out, false
	}
	copy(out[:], raw)
	return out, true
}
