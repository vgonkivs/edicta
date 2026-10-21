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

	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/edenescrow"
	"github.com/vgonkivs/edicta/signer"
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
	raw, err := json.Marshal(ec)
	if err != nil {
		return nil, err
	}
	members[ContextKey] = raw
	return json.Marshal(members)
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

// settle takes an authorized Eden commitment through the flags the request
// set: sign (the signer also sends), then wait for the deposit to execute.
// The signer's answers are checked here against the committed action; none
// is taken on trust.
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
	if !req.wantsSettle() {
		return nil
	}
	wait, _ := s.settleWait(req)

	if req.Sign {
		if uint64(s.now().Unix())+authSkewS >= resp.Expires {
			return r.carry(&Failure{Exit: ExitRefused, Code: "authorization_expired", Message: "the Authorization has expired: commit again"})
		}
		if tx.Deposit.ExpiresAt > resp.Expires {
			return r.carry(&Failure{Exit: ExitRefused, Code: "quote_outlives_authorization",
				Message: "the quote's expiresAt is after the Authorization's expiry: commit again with a longer valid_for"})
		}
		out, err := s.Signer.Sign(ctx, signer.Request{
			Envelope: r.st.Envelope, Action: r.st.Action, Salt: r.st.Salt, Authorization: r.st.Authorization, Requirements: r.rr,
		})
		if err != nil {
			return r.carry(classify(err))
		}
		if out.CommitmentHash != r.hash || out.RailRef != edenescrow.RailRef(out.Signed) {
			return r.carry(&Failure{Exit: ExitRefused, Code: "signer_response_invalid", Message: "the signer answered for another decision or rail_ref"})
		}
		if _, _, err := edenescrow.ParseSigned(tx, out.Signed); err != nil {
			return r.carry(&Failure{Exit: ExitRefused, Code: "signer_response_invalid", Message: fmt.Sprintf("the signed transaction is not the committed one: %v", err)})
		}
		r.st.Signed, r.st.RailRef = out.Signed, out.RailRef
		if f := s.save(r); f != nil {
			return f
		}
	}
	var payer [20]byte
	if len(r.st.Signed) != 0 {
		var err error
		if _, payer, err = edenescrow.ParseSigned(tx, r.st.Signed); err != nil {
			return r.carry(usagef("the stored signed transaction is not the committed one: %v", err))
		}
		resp.SignedTx, resp.RailRef, resp.Payer = r.st.Signed, edenescrow.RailRef(r.st.Signed), "0x"+hex.EncodeToString(payer[:])
	}
	if !req.Record && !req.PaymentSignature {
		return nil
	}
	if len(r.st.Signed) == 0 {
		return r.carry(usagef("nothing was signed for this commitment yet: pass sign and broadcast"))
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
	if who, err := edenescrow.RecoverPersonal(msg, sig); err != nil || who != payer {
		return r.carry(&Failure{Exit: ExitRefused, Code: "signer_response_invalid", Message: "the payment proof was not made by the payer of the signed transaction"})
	}
	resp.Settled = true
	if req.PaymentSignature {
		resp.PaymentSignature = string(proof.Signature)
	}
	return nil
}

// awaitProof asks for the payment proof until the signer releases it, which
// it does only once the deposit executed at its configured level: the
// signer has no other status route. The wait is counted in poll intervals,
// not read from a clock.
func (s *Service) awaitProof(ctx context.Context, r *run, wait time.Duration) (signer.PaymentProof, error) {
	poll := s.PollInterval
	if poll <= 0 {
		poll = defaultPoll
	}
	req := signer.PaymentProofRequest{CommitmentHash: r.hash, Field: PaymentField, Request: signer.Request{
		Envelope: r.st.Envelope, Action: r.st.Action, Salt: r.st.Salt, Authorization: r.st.Authorization, Requirements: r.rr,
	}}
	for elapsed := time.Duration(0); ; elapsed += poll {
		proof, err := s.Signer.PaymentSignature(ctx, req)
		if err == nil {
			return proof, nil
		}
		if cerr := ctx.Err(); cerr != nil {
			return signer.PaymentProof{}, r.carry(classify(cerr))
		}
		var se *SignerError
		if errors.As(err, &se) && !se.Retryable {
			return signer.PaymentProof{}, r.carry(classify(err))
		}
		if elapsed+poll > wait {
			f := classify(err)
			f.Exit, f.Retryable, f.Code = ExitUnavailable, true, "settlement_pending"
			f.Message = fmt.Sprintf("the deposit was not reported executed within %s (continue with the commitment hash): %v", wait, err)
			return signer.PaymentProof{}, r.carry(f)
		}
		if werr := s.sleep(ctx, poll); werr != nil {
			return signer.PaymentProof{}, r.carry(classify(werr))
		}
	}
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
