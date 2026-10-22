// SPDX-License-Identifier: Apache-2.0

// Package commitcmd is the agent side of `edicta commit` and `edicta agent
// serve`: it turns one JSON request into a published payload, an agent-signed
// commitment and a gate Authorization. The agent key stays in the SDK signer;
// the gate never builds or signs a commitment.
package commitcmd

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/vgonkivs/edicta/edenescrow"
	"github.com/vgonkivs/edicta/engine/commitment"
	"github.com/vgonkivs/edicta/gate"
	"github.com/vgonkivs/edicta/sdk"
	"github.com/vgonkivs/edicta/sdk/payload"
)

// Exit codes of `edicta commit`. They are not shared with `edicta verify`.
const (
	ExitOK          = 0
	ExitRefused     = 3
	ExitUnavailable = 6
	ExitUsage       = 64
)

// Modes of a request.
const (
	ModeFast   = "fast"
	ModeStrict = "strict"
)

// MaxRequestBytes bounds one request body.
const MaxRequestBytes = 2 << 20

// MaxJSONDepth bounds the nesting of a request and of a context.
const MaxJSONDepth = 64

const (
	authSkewS           = 30
	defaultAuthTimeout  = 2 * time.Minute
	defaultAuthAttempts = 3
)

// Gate is the authorize call of the API; *edictaapi.Client has it.
type Gate interface {
	AuthorizeWithVerdict(ctx context.Context, envelope, action, salt []byte) (auth, verdict []byte, err error)
}

// BuilderFactory returns a builder for one request. A builder for ModeFast
// accepts a pending reference (it carries the anchor intent verifier); one for
// ModeStrict refuses it. validFor zero keeps the builder's own ttl.
type BuilderFactory func(mode string, validFor time.Duration) (*sdk.Builder, error)

// Service builds, signs and authorizes. It is safe for concurrent use if its
// dependencies are.
type Service struct {
	Builders BuilderFactory
	Gate     Gate
	// DefaultMode applies when a request names none; strict if empty.
	DefaultMode string
	// DefaultValidFor applies when a request names none.
	DefaultValidFor time.Duration
	// GateKeys and GateID are required: an Authorization is never reported
	// as issued before its signature, gate id, action binding and expiry
	// have been checked.
	GateKeys [][]byte
	GateID   string
	Clock    func() time.Time
	// AuthorizeTimeout bounds the authorize step once the payload is
	// published; it ignores the caller's cancellation so that a started
	// authorization is finished and not orphaned. Zero means two minutes.
	AuthorizeTimeout time.Duration
	// AuthorizeAttempts is how many times a retryable authorize failure is
	// repeated with the same envelope. Zero means three.
	AuthorizeAttempts int
	// Wait sleeps between authorize attempts; nil means a short backoff.
	Wait func(ctx context.Context, attempt int) error

	// Signer is the edicta-signer client; nil refuses sign, broadcast,
	// record and payment_signature.
	Signer Signer
	// State keeps the run by commitment hash so that a crash can be resumed;
	// nil keeps nothing and refuses resume_hash.
	State StateStore
	// DefaultWait bounds the settlement wait when a request names none; zero
	// means five minutes.
	DefaultWait time.Duration
	// PollInterval is the pause between settlement polls; zero means two
	// seconds.
	PollInterval time.Duration
	// Sleep pauses between settlement polls; nil uses a timer.
	Sleep func(ctx context.Context, d time.Duration) error
}

// Named is a model or policy identity.
type Named struct {
	ID      string  `json:"id"`
	Version *string `json:"version,omitempty"`
	// Text is the policy text; a model has none.
	Text string `json:"text,omitempty"`
}

// Resume re-sends an already published and signed commitment to the gate,
// without publishing again. The three values come from a failure object.
type Resume struct {
	Envelope []byte `json:"envelope"`
	Action   []byte `json:"action"`
	Salt     []byte `json:"salt"`
}

// Request is the input of `edicta commit` and of POST /v1/commit.
type Request struct {
	ActionType string `json:"action_type"`
	// Action is base64 of the exact action bytes; they are committed as given.
	Action  []byte          `json:"action"`
	Context json.RawMessage `json:"context"`
	Model   Named           `json:"model"`
	Policy  Named           `json:"policy"`
	Mode    string          `json:"mode,omitempty"`
	// ValidFor is a Go duration such as 10m.
	ValidFor string `json:"valid_for,omitempty"`
	// Resume, when set, replaces every field above except Mode, and the
	// quote in Eden.
	Resume *Resume `json:"resume,omitempty"`

	// Eden turns on the Eden input mode: action_type, action and the quote
	// part of the context come from it.
	Eden *EdenInput `json:"eden,omitempty"`
	// Sign asks the signer for the deposit; the signer sends it when it
	// signs, so Broadcast must be set with it.
	Sign      bool `json:"sign,omitempty"`
	Broadcast bool `json:"broadcast,omitempty"`
	// Record waits until the signer reports the deposit executed.
	Record bool `json:"record,omitempty"`
	// PaymentSignature returns the Payment-Signature once it is released.
	PaymentSignature bool `json:"payment_signature,omitempty"`
	// Wait bounds Record and PaymentSignature, a duration such as 5m.
	Wait string `json:"wait,omitempty"`
	// ResumeHash continues a run stored under this commitment hash (64 hex).
	// It replaces every field above except Mode, Eden.PaymentRequired and the
	// settlement flags.
	ResumeHash string `json:"resume_hash,omitempty"`
}

// Response is the output of a successful commit. Byte fields are base64.
type Response struct {
	CommitmentHash string `json:"commitment_hash"`
	PayloadRef     []byte `json:"payload_ref"`
	Mode           string `json:"mode"`
	AnchorDeadline uint64 `json:"anchor_deadline,omitempty"`
	Expires        uint64 `json:"expires"`
	Envelope       []byte `json:"envelope"`
	Authorization  []byte `json:"authorization"`
	PolicyVerdict  []byte `json:"policy_verdict,omitempty"`
	Action         []byte `json:"action"`
	Salt           []byte `json:"salt"`

	// Eden mode.
	Deposit          *edenescrow.DepositView `json:"deposit,omitempty"`
	SignedTx         []byte                  `json:"signed_tx,omitempty"`
	RailRef          string                  `json:"rail_ref,omitempty"`
	Payer            string                  `json:"payer,omitempty"`
	Settled          bool                    `json:"settled,omitempty"`
	PaymentSignature string                  `json:"payment_signature,omitempty"`
	Recorded         bool                    `json:"recorded,omitempty"`
	Receipt          []byte                  `json:"receipt,omitempty"`
	Warning          string                  `json:"warning,omitempty"`
}

// DecodeRequest reads one request strictly: well-formed, bounded nesting, no
// repeated keys (the case-insensitive match of encoding/json included), no
// unknown keys, one value, no trailing data.
func DecodeRequest(r io.Reader) (Request, error) {
	data, err := io.ReadAll(io.LimitReader(r, MaxRequestBytes+1))
	if err != nil {
		return Request{}, usagef("read request: %v", err)
	}
	if len(data) > MaxRequestBytes {
		return Request{}, usagef("request larger than %d bytes", MaxRequestBytes)
	}
	if err := CheckJSON(data); err != nil {
		return Request{}, usagef("request: %v", err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var req Request
	if err := dec.Decode(&req); err != nil {
		return Request{}, usagef("request: %v", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return Request{}, usagef("request: trailing data")
	}
	return req, nil
}

// CheckJSON refuses data that is not one well-formed JSON value, nests deeper
// than MaxJSONDepth, repeats an object key, or has a non-ASCII key. Keys are
// compared with case folded, because encoding/json would merge them into one
// field; its folding also maps some non-ASCII letters (U+017F, U+212A) onto
// ASCII ones, so those keys are refused outright.
func CheckJSON(data []byte) error {
	if !json.Valid(data) {
		return errors.New("not valid JSON")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	var walk func(depth int) error
	walk = func(depth int) error {
		if depth > MaxJSONDepth {
			return fmt.Errorf("nesting deeper than %d", MaxJSONDepth)
		}
		t, err := dec.Token()
		if err != nil {
			return err
		}
		d, ok := t.(json.Delim)
		if !ok {
			return nil
		}
		if d == '[' {
			for dec.More() {
				if err := walk(depth + 1); err != nil {
					return err
				}
			}
			_, err := dec.Token()
			return err
		}
		seen := map[string]bool{}
		for dec.More() {
			k, err := dec.Token()
			if err != nil {
				return err
			}
			key, _ := k.(string)
			for i := 0; i < len(key); i++ {
				if key[i] >= 0x80 {
					return fmt.Errorf("key %q is not ASCII", key)
				}
			}
			folded := strings.ToLower(key)
			if seen[folded] {
				return fmt.Errorf("duplicate key %q", key)
			}
			seen[folded] = true
			if err := walk(depth + 1); err != nil {
				return err
			}
		}
		_, err = dec.Token()
		return err
	}
	return walk(0)
}

func (s *Service) now() time.Time {
	if s.Clock != nil {
		return s.Clock()
	}
	return time.Now()
}

// Commit runs one request. Every error is a *Failure.
func (s *Service) Commit(ctx context.Context, req Request) (Response, error) {
	if s.Builders == nil || s.Gate == nil {
		return Response{}, usagef("service is not configured")
	}
	if len(s.GateKeys) == 0 || s.GateID == "" {
		return Response{}, usagef("no gate key: an Authorization cannot be verified")
	}
	mode := req.Mode
	if mode == "" {
		mode = s.DefaultMode
	}
	if mode == "" {
		mode = ModeStrict
	}
	if mode != ModeFast && mode != ModeStrict {
		return Response{}, usagef("mode must be %q or %q", ModeFast, ModeStrict)
	}

	if f := s.checkEdenFlags(req); f != nil {
		return Response{}, f
	}

	run := &run{mode: mode}
	resumed := false
	switch {
	case req.ResumeHash != "":
		if req.hasBuildFields() || req.Resume != nil || req.Eden != nil && (len(req.Eden.Build) != 0 || req.Eden.Resource != "") {
			return Response{}, usagef("resume_hash takes no field other than mode, the eden quote and the settlement flags")
		}
		st, f := s.loadState(req.ResumeHash)
		if f != nil {
			return Response{}, f
		}
		run.st, run.rr = st, st.Requirements
		if req.Mode == "" && s.DefaultMode == "" && st.Mode != "" {
			run.mode = st.Mode
		}
	case req.Resume != nil:
		r := req.Resume
		if req.hasBuildFields() || req.Eden != nil && (len(req.Eden.Build) != 0 || req.Eden.Resource != "") {
			return Response{}, usagef("resume takes no other field than mode, the eden quote and the settlement flags")
		}
		if len(r.Envelope) == 0 || len(r.Action) == 0 || len(r.Salt) == 0 {
			return Response{}, usagef("resume needs envelope, action and salt")
		}
		run.st = State{Envelope: r.Envelope, Action: r.Action, Salt: r.Salt}
		resumed = true
	default:
		validFor := s.DefaultValidFor
		if req.ValidFor != "" {
			d, err := time.ParseDuration(req.ValidFor)
			if err != nil || d <= 0 {
				return Response{}, usagef("valid_for %q is not a positive duration", req.ValidFor)
			}
			validFor = d
		}
		if req.Eden != nil {
			pre, f := s.prepareEden(req)
			if f != nil {
				return Response{}, f
			}
			req.ActionType, req.Action, req.Context, run.rr = edenescrow.ActionType, pre.action, pre.ctx, pre.rr
		}
		p, err := buildPayload(req)
		if err != nil {
			return Response{}, err
		}
		b, err := s.Builders(mode, validFor)
		if err != nil {
			return Response{}, classify(err)
		}
		res, err := b.Commit(ctx, p)
		if err != nil {
			return Response{}, classify(err)
		}
		run.st = State{Envelope: res.Envelope, Action: res.Action, Salt: res.ActionSalt}
	}
	h, ferr := envelopeHash(run.st.Envelope)
	if ferr != nil {
		return Response{}, ferr
	}
	run.hash, run.hexH = h, hex.EncodeToString(h[:])
	if req.Resume != nil && req.Eden != nil {
		rr, err := edenescrow.DecodePaymentRequired(req.Eden.PaymentRequired)
		if err != nil {
			return Response{}, run.carry(edenUsage("payment_required: %v", err))
		}
		run.rr = rr
	} else if req.ResumeHash != "" && req.Eden != nil && req.Eden.PaymentRequired != "" {
		rr, err := edenescrow.DecodePaymentRequired(req.Eden.PaymentRequired)
		if err != nil || !bytes.Equal(rr, run.rr) {
			return Response{}, run.carry(edenUsage("payment_required differs from the stored quote"))
		}
	}
	if resumed && s.State != nil {
		// What an earlier run stored for this commitment stays: the
		// Authorization and the signed bytes are never overwritten by a
		// resume that carries only the envelope, the action and the salt.
		if old, ok, err := s.State.Load(run.hexH); err != nil {
			return Response{}, run.carry(&Failure{Exit: ExitUnavailable, Code: "state_unavailable", Retryable: true, Message: err.Error()})
		} else if ok && bytes.Equal(old.Envelope, run.st.Envelope) {
			run.st.Authorization, run.st.Signed, run.st.RailRef = old.Authorization, old.Signed, old.RailRef
			if len(run.rr) == 0 {
				run.rr = old.Requirements
			}
		}
	}
	if len(run.rr) != 0 {
		// A wrong quote must not reach the store.
		tx, err := edenescrow.DecodeTxAction(run.st.Action)
		if err != nil {
			return Response{}, run.carry(usagef("the action is not an Eden escrow deposit: %v", err))
		}
		if _, err := edenescrow.CheckRequirements(tx, run.rr, true); err != nil {
			return Response{}, run.carry(usagef("payment_required: %v", err))
		}
	}
	if !resumed && req.ResumeHash == "" {
		if f := s.save(run); f != nil {
			return Response{}, f
		}
	}

	var resp Response
	var err error
	if len(run.st.Authorization) != 0 {
		resp, err = s.describe(run.mode, run.st.Envelope, run.st.Action, run.st.Salt, run.st.Authorization, false)
		if err != nil {
			return Response{}, run.carry(classify(err))
		}
	} else {
		resp, err = s.authorize(ctx, run.mode, run.st.Envelope, run.st.Action, run.st.Salt)
		if err != nil {
			return Response{}, err
		}
		run.st.Authorization = resp.Authorization
		if f := s.save(run); f != nil {
			return Response{}, f
		}
	}
	if resumed && len(run.st.Authorization) != 0 {
		if f := s.save(run); f != nil {
			return Response{}, f
		}
	}
	if req.Eden != nil || len(run.rr) != 0 || req.wantsSettle() {
		if err := s.settle(ctx, req, run, &resp); err != nil {
			return Response{}, err
		}
	}
	return resp, nil
}

func (r Request) hasBuildFields() bool {
	return r.ActionType != "" || len(r.Action) != 0 || len(r.Context) != 0 || r.Model.ID != "" ||
		r.Model.Version != nil || r.Model.Text != "" || r.Policy.ID != "" || r.Policy.Version != nil ||
		r.Policy.Text != "" || r.ValidFor != ""
}

// authorize asks the gate for the Authorization of a commitment that is
// already published. It runs detached from the caller's cancellation: the
// gate may have marked the nonce used by the time the caller gives up. A
// retryable failure is repeated with the same envelope; a nonce replay returns
// the stored Authorization, which is checked like a fresh one.
func (s *Service) authorize(ctx context.Context, mode string, envelope, action, salt []byte) (Response, error) {
	timeout := s.AuthorizeTimeout
	if timeout <= 0 {
		timeout = defaultAuthTimeout
	}
	actx, cancel := context.WithTimeout(context.WithoutCancel(ctx), timeout)
	defer cancel()
	attempts := s.AuthorizeAttempts
	if attempts <= 0 {
		attempts = defaultAuthAttempts
	}
	resume := func(f *Failure) *Failure {
		f.Envelope, f.Action, f.Salt = envelope, action, salt
		if h, err := envelopeHash(envelope); err == nil {
			f.CommitmentHash = hex.EncodeToString(h[:])
		}
		return f
	}
	var auth, verdict []byte
	for i := 1; ; i++ {
		var err error
		auth, verdict, err = s.Gate.AuthorizeWithVerdict(actx, envelope, action, salt)
		if err == nil {
			break
		}
		f := classify(err)
		if errors.Is(err, gate.ErrNonceUsed) && len(f.Stored) > 0 {
			auth, verdict = f.Stored, f.PolicyVerdict
			break
		}
		if f.Exit != ExitUnavailable || i >= attempts {
			return Response{}, resume(f)
		}
		if werr := s.wait(actx, i); werr != nil {
			return Response{}, resume(classify(werr))
		}
	}
	out, err := s.describe(mode, envelope, action, salt, auth, true)
	if err != nil {
		var f *Failure
		if errors.As(err, &f) {
			f.Authorization = auth
			return Response{}, resume(f)
		}
		return Response{}, err
	}
	out.PolicyVerdict = verdict
	return out, nil
}

func (s *Service) wait(ctx context.Context, attempt int) error {
	if s.Wait != nil {
		return s.Wait(ctx, attempt)
	}
	t := time.NewTimer(time.Duration(attempt) * 500 * time.Millisecond)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// describe checks the Authorization against the commitment and the pinned gate
// keys. checkClock is off for an Authorization this program stored earlier:
// the signature and bindings still hold after it expired, and the signing
// step checks the clock itself.
func (s *Service) describe(mode string, envelope, action, salt, auth []byte, checkClock bool) (Response, error) {
	refused := func(code, format string, a ...any) (Response, error) {
		return Response{}, &Failure{Exit: ExitRefused, Code: code, Message: fmt.Sprintf(format, a...)}
	}
	sc, err := commitment.DecodeSigned(envelope)
	if err != nil {
		return Response{}, usagef("envelope: %v", err)
	}
	h, err := commitment.HashOf(&sc.Commitment)
	if err != nil {
		return Response{}, usagef("envelope: %v", err)
	}
	var sa *commitment.SignedAuthorization
	var verr error
	nowS, skew := uint64(s.now().Unix()), uint64(authSkewS)
	if !checkClock {
		nowS, skew = 0, 0
	}
	for _, k := range s.GateKeys {
		sa, _, verr = commitment.VerifyAuthorization(auth, commitment.AuthorizationCheck{
			GatePubKey: k, GateID: s.GateID, ActionType: sc.Commitment.Action.Type,
			Action: action, ActionSalt: salt, Now: nowS, SkewS: skew,
		})
		if verr == nil {
			break
		}
	}
	if verr != nil {
		return refused("authorization_invalid", "the gate's Authorization does not verify: %v", verr)
	}
	a := sa.Authorization
	if !bytes.Equal(a.CommitmentHash, h[:]) {
		return refused("authorization_mismatch", "the Authorization names another commitment")
	}
	got := ModeStrict
	if a.Mode == commitment.ModeFast {
		got = ModeFast
	}
	if mode == ModeStrict && got != ModeStrict {
		return refused("mode_mismatch", "strict mode was requested but the gate authorized in fast mode")
	}
	ref, err := commitment.EncodePayloadRef(sc.Commitment.PayloadRef)
	if err != nil {
		return Response{}, fmt.Errorf("commitcmd: encode payload ref: %w", err)
	}
	return Response{
		CommitmentHash: hex.EncodeToString(h[:]),
		PayloadRef:     ref,
		Mode:           got,
		AnchorDeadline: a.AnchorDeadline,
		Expires:        a.Expires,
		Envelope:       envelope,
		Authorization:  auth,
		Action:         action,
		Salt:           salt,
	}, nil
}

func buildPayload(req Request) (*payload.Payload, error) {
	switch {
	case req.ActionType == "":
		return nil, usagef("action_type is required")
	case len(req.Action) == 0:
		return nil, usagef("action is required (base64 of the exact action bytes)")
	case len(bytes.TrimSpace(req.Context)) == 0 || bytes.Equal(bytes.TrimSpace(req.Context), []byte("null")):
		return nil, usagef("context is required")
	}
	if err := CheckJSON(req.Context); err != nil {
		return nil, usagef("context: %v", err)
	}
	var ctxBuf bytes.Buffer
	if err := json.Compact(&ctxBuf, req.Context); err != nil {
		return nil, usagef("context: %v", err)
	}
	p := &payload.Payload{
		Version: payload.Version,
		Model:   payload.Model{ID: req.Model.ID, Version: req.Model.Version},
		Policy:  payload.Policy{ID: req.Policy.ID, Version: req.Policy.Version},
		Context: payload.Data{MediaType: "application/json", Bytes: ctxBuf.Bytes()},
		Action:  payload.Action{Type: req.ActionType, Data: bytes.Clone(req.Action)},
	}
	if req.Policy.Text != "" {
		p.Policy.Text = []byte(req.Policy.Text)
	}
	// The SDK draws the real salt; a placeholder lets the payload rules run now.
	probe := *p
	probe.Action.Salt = make([]byte, commitment.ActionSaltSize)
	if _, err := payload.Encode(&probe); err != nil {
		return nil, usagef("%v", err)
	}
	return p, nil
}
