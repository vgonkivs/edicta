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
	"time"

	"github.com/vgonkivs/edicta/commitment"
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

const authSkewS = 30

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
	// GatePub and GateID, when set, make the Authorization's signature and
	// gate id checked before it is printed.
	GatePub []byte
	GateID  string
	Clock   func() time.Time
}

// Named is a model or policy identity.
type Named struct {
	ID      string  `json:"id"`
	Version *string `json:"version,omitempty"`
	// Text is the policy text; a model has none.
	Text string `json:"text,omitempty"`
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
}

// DecodeRequest reads one request strictly: no unknown keys, no repeated
// keys, one value, no trailing data.
func DecodeRequest(r io.Reader) (Request, error) {
	data, err := io.ReadAll(io.LimitReader(r, MaxRequestBytes+1))
	if err != nil {
		return Request{}, usagef("read request: %v", err)
	}
	if len(data) > MaxRequestBytes {
		return Request{}, usagef("request larger than %d bytes", MaxRequestBytes)
	}
	if err := noDuplicateKeys(data); err != nil {
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

// noDuplicateKeys refuses a repeated object key at any depth; encoding/json
// would silently keep the last value.
func noDuplicateKeys(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	var walk func() error
	walk = func() error {
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
				if err := walk(); err != nil {
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
			if seen[key] {
				return fmt.Errorf("duplicate key %q", key)
			}
			seen[key] = true
			if err := walk(); err != nil {
				return err
			}
		}
		_, err = dec.Token()
		return err
	}
	return walk()
}

// Commit runs one request. Every error is a *Failure.
func (s *Service) Commit(ctx context.Context, req Request) (Response, error) {
	if s.Builders == nil || s.Gate == nil {
		return Response{}, usagef("service is not configured")
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
	validFor := s.DefaultValidFor
	if req.ValidFor != "" {
		d, err := time.ParseDuration(req.ValidFor)
		if err != nil || d <= 0 {
			return Response{}, usagef("valid_for %q is not a positive duration", req.ValidFor)
		}
		validFor = d
	}
	p, err := buildPayload(req)
	if err != nil {
		return Response{}, err
	}
	b, err := s.Builders(mode, validFor)
	if err != nil {
		return Response{}, usagef("%v", err)
	}
	res, err := b.Commit(ctx, p)
	if err != nil {
		return Response{}, classify(err)
	}
	auth, verdict, err := s.Gate.AuthorizeWithVerdict(ctx, res.Envelope, res.Action, res.ActionSalt)
	if err != nil {
		return Response{}, classify(err)
	}
	out, err := s.describe(mode, res, auth)
	if err != nil {
		return Response{}, err
	}
	out.PolicyVerdict = verdict
	return out, nil
}

func (s *Service) describe(mode string, res *sdk.Result, auth []byte) (Response, error) {
	refused := func(code, format string, a ...any) (Response, error) {
		return Response{}, &Failure{Exit: ExitRefused, Code: code, Message: fmt.Sprintf(format, a...)}
	}
	var sa *commitment.SignedAuthorization
	var err error
	if len(s.GatePub) > 0 {
		now := time.Now
		if s.Clock != nil {
			now = s.Clock
		}
		sa, _, err = commitment.VerifyAuthorization(auth, commitment.AuthorizationCheck{
			GatePubKey: s.GatePub, GateID: s.GateID, ActionType: res.Commitment.Action.Type,
			Action: res.Action, ActionSalt: res.ActionSalt, Now: uint64(now().Unix()), SkewS: authSkewS,
		})
	} else {
		sa, _, err = commitment.DecodeSignedAuthorization(auth)
		if err == nil {
			err = commitment.ValidateAuthorization(&sa.Authorization)
		}
	}
	if err != nil {
		return refused("authorization_invalid", "the gate's Authorization is unusable: %v", err)
	}
	a := sa.Authorization
	if !bytes.Equal(a.CommitmentHash, res.CommitmentHash[:]) {
		return refused("authorization_mismatch", "the Authorization names another commitment")
	}
	got := ModeStrict
	if a.Mode == commitment.ModeFast {
		got = ModeFast
	}
	if mode == ModeStrict && got != ModeStrict {
		return refused("mode_mismatch", "strict mode was requested but the gate authorized in fast mode")
	}
	ref, err := commitment.EncodePayloadRef(res.Commitment.PayloadRef)
	if err != nil {
		return Response{}, fmt.Errorf("commitcmd: encode payload ref: %w", err)
	}
	return Response{
		CommitmentHash: hex.EncodeToString(res.CommitmentHash[:]),
		PayloadRef:     ref,
		Mode:           got,
		AnchorDeadline: a.AnchorDeadline,
		Expires:        a.Expires,
		Envelope:       res.Envelope,
		Authorization:  auth,
		Action:         res.Action,
		Salt:           res.ActionSalt,
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
