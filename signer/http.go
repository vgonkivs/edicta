// SPDX-License-Identifier: Apache-2.0

package signer

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/edenescrow"
	"github.com/vgonkivs/edicta/edictaapi"
)

// Routes of the signer API.
const (
	RouteSign   = "/v1/sign"
	RouteHealth = "/v1/health"
	// RouteRequeue is the operator's route back from state wrong.
	RouteRequeue = "/v1/admin/requeue"
	// RoutePaymentSignature releases the payment proof of a decision the
	// rail executed.
	RoutePaymentSignature = "/v1/payment-signature"
	// RouteStatusPrefix is followed by a commitment hash in 64 lower-case
	// hex digits: GET shows the caller's own decision.
	RouteStatusPrefix = "/v1/status/"
)

// MaxRequirementsSize bounds the payment requirements of a request.
const MaxRequirementsSize = edenescrow.MaxRequirementsSize

// SignLimit bounds a sign request in CBOR: the envelope, the action, the
// salt, the Authorization and the payment requirements with their wrapper
// heads.
const SignLimit = commitment.MaxSignedSize + commitment.MaxActionSize + commitment.ActionSaltSize +
	commitment.MaxAuthorizationSize + MaxRequirementsSize + 48

// PaymentLimit bounds a payment-signature request in CBOR: a sign request,
// the commitment hash and the field.
const PaymentLimit = SignLimit + 32 + maxFieldName + 16

const maxFieldName = 32

// MaxCredentials bounds the API credentials.
const MaxCredentials = 1024

func fieldNameChar(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9'
}

var (
	// SignRequestSchema is the request of POST /v1/sign.
	SignRequestSchema = edictaapi.NewSchema(
		edictaapi.Field{Key: 1, Name: "envelope", Kind: edictaapi.KindBytes, Min: 1, Max: commitment.MaxSignedSize, Required: true},
		edictaapi.Field{Key: 2, Name: "action", Kind: edictaapi.KindBytes, Min: 1, Max: commitment.MaxActionSize, Required: true},
		edictaapi.Field{Key: 3, Name: "action_salt", Kind: edictaapi.KindBytes, Min: commitment.ActionSaltSize, Max: commitment.ActionSaltSize, Required: true},
		edictaapi.Field{Key: 4, Name: "signed_authorization", Kind: edictaapi.KindBytes, Min: 1, Max: commitment.MaxAuthorizationSize, Required: true},
		edictaapi.Field{Key: 5, Name: "payment_required", Kind: edictaapi.KindBytes, Min: 1, Max: MaxRequirementsSize},
	)
	// PaymentRequestSchema is the request of POST /v1/payment-signature.
	PaymentRequestSchema = edictaapi.NewSchema(
		edictaapi.Field{Key: 1, Name: "commitment_hash", Kind: edictaapi.KindBytes, Min: 32, Max: 32, Required: true},
		edictaapi.Field{Key: 2, Name: "field", Kind: edictaapi.KindText, Min: 1, Max: maxFieldName, Charset: fieldNameChar, Required: true},
		edictaapi.Field{Key: 3, Name: "envelope", Kind: edictaapi.KindBytes, Min: 1, Max: commitment.MaxSignedSize, Required: true},
		edictaapi.Field{Key: 4, Name: "action", Kind: edictaapi.KindBytes, Min: 1, Max: commitment.MaxActionSize, Required: true},
		edictaapi.Field{Key: 5, Name: "action_salt", Kind: edictaapi.KindBytes, Min: commitment.ActionSaltSize, Max: commitment.ActionSaltSize, Required: true},
		edictaapi.Field{Key: 6, Name: "signed_authorization", Kind: edictaapi.KindBytes, Min: 1, Max: commitment.MaxAuthorizationSize, Required: true},
		edictaapi.Field{Key: 7, Name: "payment_required", Kind: edictaapi.KindBytes, Min: 1, Max: MaxRequirementsSize},
	)
	// PaymentResponseSchema is the 200 answer of POST /v1/payment-signature.
	PaymentResponseSchema = edictaapi.NewSchema(
		edictaapi.Field{Key: 1, Name: "signature", Kind: edictaapi.KindText, Min: 1, Max: 256, Required: true},
		edictaapi.Field{Key: 2, Name: "message", Kind: edictaapi.KindBytes, Min: 32, Max: 32, Required: true},
		edictaapi.Field{Key: 3, Name: "repeat", Kind: edictaapi.KindUint, Required: true},
	)
	// StatusResponseSchema is the 200 answer of GET /v1/status/{hash}.
	StatusResponseSchema = edictaapi.NewSchema(
		edictaapi.Field{Key: 1, Name: "state", Kind: edictaapi.KindText, Min: 1, Max: 32, Required: true},
		edictaapi.Field{Key: 2, Name: "commitment_hash", Kind: edictaapi.KindBytes, Min: 32, Max: 32, Required: true},
		edictaapi.Field{Key: 3, Name: "sent", Kind: edictaapi.KindUint, Required: true},
		edictaapi.Field{Key: 4, Name: "rail_ref", Kind: edictaapi.KindText, Max: 128},
		edictaapi.Field{Key: 5, Name: "signed_tx", Kind: edictaapi.KindBytes},
		edictaapi.Field{Key: 6, Name: "outcome", Kind: edictaapi.KindText, Max: 64},
		edictaapi.Field{Key: 7, Name: "detail", Kind: edictaapi.KindText, Max: 1024},
		edictaapi.Field{Key: 8, Name: "payment_proof_allowed", Kind: edictaapi.KindUint, Required: true},
		edictaapi.Field{Key: 9, Name: "receipt", Kind: edictaapi.KindBytes},
	)
	// SignResponseSchema is the 200 answer of POST /v1/sign.
	SignResponseSchema = edictaapi.NewSchema(
		edictaapi.Field{Key: 1, Name: "signed_tx", Kind: edictaapi.KindBytes, Min: 1, Required: true},
		edictaapi.Field{Key: 2, Name: "rail_ref", Kind: edictaapi.KindText, Min: 1, Max: 128, Required: true},
		edictaapi.Field{Key: 3, Name: "commitment_hash", Kind: edictaapi.KindBytes, Min: 32, Max: 32, Required: true},
		edictaapi.Field{Key: 4, Name: "repeat", Kind: edictaapi.KindUint, Required: true},
	)
	// RequeueRequestSchema and RequeueResponseSchema are POST
	// /v1/admin/requeue.
	RequeueRequestSchema = edictaapi.NewSchema(
		edictaapi.Field{Key: 1, Name: "commitment_hash", Kind: edictaapi.KindBytes, Min: 32, Max: 32, Required: true},
	)
	RequeueResponseSchema = edictaapi.NewSchema(
		edictaapi.Field{Key: 1, Name: "state", Kind: edictaapi.KindText, Min: 1, Max: 32, Required: true},
	)
	// HealthSchema is the 200 answer of GET /v1/health.
	HealthSchema = edictaapi.NewSchema(
		edictaapi.Field{Key: 1, Name: "status", Kind: edictaapi.KindText, Min: 1, Max: 64, Required: true},
	)
)

// DecodeSignRequest decodes a CBOR sign request with the strict wrapper
// decoder.
func DecodeSignRequest(b []byte) (Request, error) {
	f, err := edictaapi.DecodeWrapper(b, SignRequestSchema)
	if err != nil {
		return Request{}, err
	}
	r := Request{Envelope: f.Bytes(1), Action: f.Bytes(2), Salt: f.Bytes(3), Authorization: f.Bytes(4)}
	if f.Has(5) {
		r.Requirements = f.Bytes(5)
	}
	return r, nil
}

// EncodeSignRequest is the canonical CBOR of a sign request.
func EncodeSignRequest(r Request) []byte {
	items := []edictaapi.Item{
		edictaapi.BytesItem(1, r.Envelope), edictaapi.BytesItem(2, r.Action),
		edictaapi.BytesItem(3, r.Salt), edictaapi.BytesItem(4, r.Authorization),
	}
	if r.Requirements != nil {
		items = append(items, edictaapi.BytesItem(5, r.Requirements))
	}
	return edictaapi.EncodeWrapper(items...)
}

// DecodePaymentRequest decodes a CBOR payment-signature request with the
// strict wrapper decoder.
func DecodePaymentRequest(b []byte) (PaymentProofRequest, error) {
	f, err := edictaapi.DecodeWrapper(b, PaymentRequestSchema)
	if err != nil {
		return PaymentProofRequest{}, err
	}
	r := PaymentProofRequest{Field: f.Text(2), Request: Request{
		Envelope: f.Bytes(3), Action: f.Bytes(4), Salt: f.Bytes(5), Authorization: f.Bytes(6),
	}}
	copy(r.CommitmentHash[:], f.Bytes(1))
	if f.Has(7) {
		r.Requirements = f.Bytes(7)
	}
	return r, nil
}

// EncodePaymentRequest is the canonical CBOR of a payment-signature request.
func EncodePaymentRequest(r PaymentProofRequest) []byte {
	items := []edictaapi.Item{
		edictaapi.BytesItem(1, r.CommitmentHash[:]), edictaapi.TextItem(2, r.Field),
		edictaapi.BytesItem(3, r.Envelope), edictaapi.BytesItem(4, r.Action),
		edictaapi.BytesItem(5, r.Salt), edictaapi.BytesItem(6, r.Authorization),
	}
	if r.Requirements != nil {
		items = append(items, edictaapi.BytesItem(7, r.Requirements))
	}
	return edictaapi.EncodeWrapper(items...)
}

func encodePaymentProof(p PaymentProof) []byte {
	var rep uint64
	if p.Repeat {
		rep = 1
	}
	return edictaapi.EncodeWrapper(
		edictaapi.TextItem(1, string(p.Signature)), edictaapi.BytesItem(2, p.Message[:]), edictaapi.UintItem(3, rep),
	)
}

// DecodePaymentResponse decodes a CBOR 200 answer of POST
// /v1/payment-signature.
func DecodePaymentResponse(b []byte) (PaymentProof, error) {
	f, err := edictaapi.DecodeWrapper(b, PaymentResponseSchema)
	if err != nil {
		return PaymentProof{}, err
	}
	p := PaymentProof{Signature: []byte(f.Text(1))}
	copy(p.Message[:], f.Bytes(2))
	rep, _ := f.Uint(3)
	p.Repeat = rep == 1
	return p, nil
}

func encodeOutput(o Output) []byte {
	var rep uint64
	if o.Repeat {
		rep = 1
	}
	return edictaapi.EncodeWrapper(
		edictaapi.BytesItem(1, o.Signed), edictaapi.TextItem(2, o.RailRef),
		edictaapi.BytesItem(3, o.CommitmentHash[:]), edictaapi.UintItem(4, rep),
	)
}

// DecodeSignResponse decodes a CBOR 200 answer of POST /v1/sign.
func DecodeSignResponse(b []byte) (Output, error) {
	f, err := edictaapi.DecodeWrapper(b, SignResponseSchema)
	if err != nil {
		return Output{}, err
	}
	o := Output{Signed: f.Bytes(1), RailRef: f.Text(2)}
	copy(o.CommitmentHash[:], f.Bytes(3))
	rep, _ := f.Uint(4)
	o.Repeat = rep == 1
	return o, nil
}

// Credential is one bearer token of the API. Agent pins it to one served
// agent key, which the payment-proof route requires; a nil Agent is a
// shared credential, refused while payment proofs are enabled.
type Credential struct {
	Token []byte
	Agent []byte
}

// HTTPOptions configure the API. Every request needs one of the
// credentials.
type HTTPOptions struct {
	// Token is a shared credential, pinned to no agent.
	Token []byte
	// Credentials are more credentials, each pinned or shared.
	Credentials []Credential
	// AllowRemote accepts a Host header that is not loopback. Without it a
	// web page cannot reach the API through DNS rebinding.
	AllowRemote bool
	// RequestTimeout bounds one request; zero means 30 s.
	RequestTimeout time.Duration
	// AdminToken enables the operator routes and is the only token they
	// accept; the agents' token never reaches them. Empty disables them.
	AdminToken []byte
}

// all is every API credential, the shared Token first.
func (o HTTPOptions) all() []Credential {
	out := make([]Credential, 0, len(o.Credentials)+1)
	if o.Token != nil {
		out = append(out, Credential{Token: o.Token})
	}
	return append(out, o.Credentials...)
}

// ValidateBasic checks the stateless fields.
func (o HTTPOptions) ValidateBasic() error {
	creds := o.all()
	switch {
	case len(creds) == 0:
		return errors.New("signer: no API credential: the API never runs without a token")
	case len(creds) > MaxCredentials:
		return fmt.Errorf("signer: %d API credentials, at most %d", len(creds), MaxCredentials)
	}
	for i, c := range creds {
		if len(c.Token) < 16 {
			return fmt.Errorf("signer: API credential %d: the token must be at least 16 bytes", i)
		}
		if c.Agent != nil {
			if err := commitment.CheckPublicKey(c.Agent); err != nil {
				return fmt.Errorf("signer: API credential %d: agent key: %w", i, err)
			}
		}
		for j := range i {
			if subtle.ConstantTimeCompare(c.Token, creds[j].Token) == 1 {
				return fmt.Errorf("signer: API credentials %d and %d share a token", j, i)
			}
		}
		if len(o.AdminToken) > 0 && subtle.ConstantTimeCompare(o.AdminToken, c.Token) == 1 {
			return errors.New("signer: the admin token must differ from every API token")
		}
	}
	if len(o.AdminToken) > 0 && len(o.AdminToken) < 16 {
		return errors.New("signer: the admin token must be at least 16 bytes")
	}
	if o.RequestTimeout < 0 {
		return errors.New("signer: negative request timeout")
	}
	return nil
}

type errRule struct {
	code      string
	err       error
	status    int
	retryable bool
}

// errTable maps refusals to codes, in match order: a dependency failure
// first, since a fail-closed check wraps both its refusal and the cause.
var errTable = []errRule{
	{"signer.ErrUnavailable", ErrUnavailable, 503, true},
	{"signer.ErrExpired", ErrExpired, 410, false},
	{"signer.ErrNotAuthorized", ErrNotAuthorized, 403, false},
	{"signer.ErrPinMismatch", ErrPinMismatch, 403, false},
	{"signer.ErrEscrowCode", ErrEscrowCode, 403, false},
	{"signer.ErrFastModeRefused", ErrFastModeRefused, 403, false},
	{"signer.ErrDigestConflict", ErrDigestConflict, 409, false},
	{"signer.ErrNotRequeueable", ErrNotRequeueable, 409, false},
	{"signer.ErrUnknownDecision", ErrUnknownDecision, 404, false},
	{"signer.ErrRiskLimit", ErrRiskLimit, 429, true},
	{"signer.ErrNotExecuted", ErrNotExecuted, 409, true},
	{"signer.ErrRequirements", ErrRequirements, 422, false},
	{"signer.ErrRequirements", edenescrow.ErrRequirements, 422, false},
	{"edenescrow.ErrMalformed", edenescrow.ErrMalformed, 422, false},
	{"edenescrow.ErrUnknownDomain", edenescrow.ErrUnknownDomain, 422, false},

	{"edictaapi.ErrTokenInvalid", edictaapi.ErrTokenInvalid, 401, false},
	{"edictaapi.ErrRouteNotFound", edictaapi.ErrRouteNotFound, 404, false},
	{"edictaapi.ErrMethodNotAllowed", edictaapi.ErrMethodNotAllowed, 405, false},
	{"edictaapi.ErrMediaType", edictaapi.ErrMediaType, 415, false},
	{"ErrTooLarge", commitment.ErrTooLarge, 413, false},
	{"edictaapi.ErrDeadline", edictaapi.ErrDeadline, 504, true},

	{"ErrMalformed", commitment.ErrMalformed, 400, false},
	{"ErrTrailingData", commitment.ErrTrailingData, 400, false},
	{"ErrFloat", commitment.ErrFloat, 400, false},
	{"ErrSimpleValue", commitment.ErrSimpleValue, 400, false},
	{"ErrTag", commitment.ErrTag, 400, false},
	{"ErrIndefiniteLength", commitment.ErrIndefiniteLength, 400, false},
	{"ErrNonMinimalInt", commitment.ErrNonMinimalInt, 400, false},
	{"ErrNestingTooDeep", commitment.ErrNestingTooDeep, 400, false},
	{"ErrUnsortedMap", commitment.ErrUnsortedMap, 400, false},
	{"ErrDuplicateKey", commitment.ErrDuplicateKey, 400, false},
	{"ErrKeyType", commitment.ErrKeyType, 400, false},
	{"ErrInvalidString", commitment.ErrInvalidString, 400, false},
	{"ErrUnknownKey", commitment.ErrUnknownKey, 400, false},
	{"ErrWrongType", commitment.ErrWrongType, 400, false},
	{"ErrMissingField", commitment.ErrMissingField, 400, false},
	{"ErrFieldSize", commitment.ErrFieldSize, 400, false},
}

func classify(err error) errRule {
	for _, r := range errTable {
		if errors.Is(err, r.err) {
			return r
		}
	}
	return errRule{"signer.ErrInternal", nil, 500, false}
}

// NewHandler serves the signer API: POST /v1/sign and GET /v1/health, in
// CBOR or JSON under the transport rules of the core API. The checks run in
// the order route, method, media type, token, size, decoding, operation.
func NewHandler(s *Service, o HTTPOptions, log *slog.Logger) (http.Handler, error) {
	if err := o.ValidateBasic(); err != nil {
		return nil, err
	}
	if log == nil {
		log = slog.Default()
	}
	if o.RequestTimeout == 0 {
		o.RequestTimeout = 30 * time.Second
	}
	h := &apiHandler{s: s, o: o, log: log}
	for i, c := range o.all() {
		if c.Agent != nil && !s.agentPinned(c.Agent) {
			return nil, fmt.Errorf("signer: API credential %d is pinned to an agent key the signer does not serve", i)
		}
		// With payment proofs on, the credential is what tells one agent
		// from another: the decision's material is public.
		if c.Agent == nil && s.PaymentProofsEnabled() {
			return nil, fmt.Errorf("signer: API credential %d is shared; payment proofs need one credential per agent", i)
		}
		h.creds = append(h.creds, cred{digest: sha256.Sum256(c.Token), agent: bytes.Clone(c.Agent)})
	}
	if len(o.AdminToken) > 0 {
		h.admin = sha256.Sum256(o.AdminToken)
		h.adminOn = true
	}
	return h, nil
}

type cred struct {
	digest [32]byte
	agent  []byte
}

type apiHandler struct {
	s       *Service
	o       HTTPOptions
	creds   []cred
	admin   [32]byte
	adminOn bool
	log     *slog.Logger
}

type answer struct {
	status int
	body   []byte
	schema edictaapi.Schema
	allow  string
}

func (h *apiHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a := h.serve(r)
	ctype := "application/cbor"
	if edictaapi.ResponseIsJSON(r) {
		ctype = "application/json"
		schema := a.schema
		if a.status != 200 {
			schema = edictaapi.ErrorSchema
		}
		js, err := edictaapi.WrapperToJSON(a.body, schema)
		if err != nil {
			h.log.Error("signer: render json", "err", err)
			a.status = 500
			js, _ = edictaapi.WrapperToJSON(edictaapi.ErrorBody("signer.ErrInternal", "internal error", false), edictaapi.ErrorSchema)
		}
		a.body = js
	}
	hd := w.Header()
	hd.Set("Content-Type", ctype)
	hd.Set("Vary", "Accept, Content-Type")
	hd.Set("X-Content-Type-Options", "nosniff")
	hd.Set("Cache-Control", "no-store")
	if a.allow != "" {
		hd.Set("Allow", a.allow)
	}
	w.WriteHeader(a.status)
	_, _ = w.Write(a.body)
}

func (h *apiHandler) fail(err error) answer {
	rule := classify(err)
	msg := err.Error()
	if rule.status == 500 {
		h.log.Error("signer: request failed", "err", err)
		msg = "internal error"
	} else {
		h.log.Info("signer: request refused", "code", rule.code, "err", err)
	}
	return answer{status: rule.status, body: edictaapi.ErrorBody(rule.code, msg, rule.retryable)}
}

func (h *apiHandler) serve(r *http.Request) (a answer) {
	defer func() {
		if p := recover(); p != nil {
			if p == http.ErrAbortHandler {
				panic(p)
			}
			h.log.Error("signer: handler panic", "panic", fmt.Sprint(p))
			a = answer{status: 500, body: edictaapi.ErrorBody("signer.ErrInternal", "internal error", false)}
		}
	}()
	method, admin := http.MethodPost, false
	var statusHash string
	path := r.URL.Path
	switch {
	case strings.HasPrefix(path, RouteStatusPrefix):
		method, statusHash = http.MethodGet, strings.TrimPrefix(path, RouteStatusPrefix)
		path = RouteStatusPrefix
	case path == RouteSign, path == RoutePaymentSignature:
	case path == RouteHealth:
		method = http.MethodGet
	case path == RouteRequeue:
		if !h.adminOn {
			return h.fail(edictaapi.ErrRouteNotFound)
		}
		admin = true
	default:
		return h.fail(edictaapi.ErrRouteNotFound)
	}
	if r.Method != method {
		a := h.fail(edictaapi.ErrMethodNotAllowed)
		a.allow = method
		return a
	}
	isJSON := false
	if method == http.MethodPost {
		var ok bool
		if isJSON, ok = edictaapi.MediaType(r.Header.Get("Content-Type")); !ok {
			return h.fail(edictaapi.ErrMediaType)
		}
	}
	agent, ok := h.caller(r, admin)
	if !ok {
		return h.fail(edictaapi.ErrTokenInvalid)
	}
	if path == RouteStatusPrefix {
		return h.status(r, statusHash, agent)
	}
	if method == http.MethodGet {
		return answer{status: 200, body: edictaapi.EncodeWrapper(edictaapi.TextItem(1, "ok")), schema: HealthSchema}
	}
	switch r.URL.Path {
	case RouteRequeue:
		return h.requeue(r, isJSON)
	case RoutePaymentSignature:
		return h.paymentSignature(r, isJSON, agent)
	}

	limit := uint64(SignLimit)
	if isJSON {
		limit = edictaapi.JSONBodyLimit(limit)
	}
	body, err := readBody(r, limit)
	if err != nil {
		return h.fail(err)
	}
	if isJSON {
		if body, err = edictaapi.JSONToWrapper(body, SignRequestSchema); err != nil {
			return h.fail(err)
		}
		if len(body) > SignLimit {
			return h.fail(fmt.Errorf("%w: body of %d bytes", commitment.ErrTooLarge, len(body)))
		}
	}
	req, err := DecodeSignRequest(body)
	if err != nil {
		return h.fail(err)
	}
	ctx, cancel := context.WithTimeout(r.Context(), h.o.RequestTimeout)
	defer cancel()
	out, err := h.s.SignAs(ctx, req, agent)
	if err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) && r.Context().Err() == nil {
			err = fmt.Errorf("%w: %w", edictaapi.ErrDeadline, err)
		}
		return h.fail(err)
	}
	return answer{status: 200, body: encodeOutput(out), schema: SignResponseSchema}
}

// status shows one decision to the agent whose credential is pinned to it.
// An unknown hash and another agent's decision answer alike.
func (h *apiHandler) status(r *http.Request, name string, agent []byte) answer {
	var ch commitment.Hash
	raw, err := hex.DecodeString(name)
	if err != nil || len(raw) != len(ch) || hex.EncodeToString(raw) != name {
		return h.fail(edictaapi.ErrRouteNotFound)
	}
	copy(ch[:], raw)
	ctx, cancel := context.WithTimeout(r.Context(), h.o.RequestTimeout)
	defer cancel()
	st, err := h.s.Status(ctx, ch, agent)
	if err != nil {
		return h.fail(err)
	}
	var sent, allowed uint64
	if st.Sent {
		sent = 1
	}
	if st.PaymentProofAllowed {
		allowed = 1
	}
	items := []edictaapi.Item{
		edictaapi.TextItem(1, string(st.State)), edictaapi.BytesItem(2, ch[:]), edictaapi.UintItem(3, sent),
	}
	if st.RailRef != "" {
		items = append(items, edictaapi.TextItem(4, st.RailRef))
	}
	if len(st.Signed) != 0 {
		items = append(items, edictaapi.BytesItem(5, st.Signed))
	}
	if st.Outcome != "" {
		items = append(items, edictaapi.TextItem(6, st.Outcome))
	}
	if st.Detail != "" {
		items = append(items, edictaapi.TextItem(7, st.Detail))
	}
	items = append(items, edictaapi.UintItem(8, allowed))
	if len(st.Receipt) != 0 {
		items = append(items, edictaapi.BytesItem(9, st.Receipt))
	}
	return answer{status: 200, body: edictaapi.EncodeWrapper(items...), schema: StatusResponseSchema}
}

const requeueLimit = 64

func (h *apiHandler) requeue(r *http.Request, isJSON bool) answer {
	limit := uint64(requeueLimit)
	if isJSON {
		limit = edictaapi.JSONBodyLimit(limit)
	}
	body, err := readBody(r, limit)
	if err != nil {
		return h.fail(err)
	}
	if isJSON {
		if body, err = edictaapi.JSONToWrapper(body, RequeueRequestSchema); err != nil {
			return h.fail(err)
		}
	}
	f, err := edictaapi.DecodeWrapper(body, RequeueRequestSchema)
	if err != nil {
		return h.fail(err)
	}
	var ch commitment.Hash
	copy(ch[:], f.Bytes(1))
	ctx, cancel := context.WithTimeout(r.Context(), h.o.RequestTimeout)
	defer cancel()
	st, err := h.s.Requeue(ctx, ch)
	if err != nil {
		return h.fail(err)
	}
	return answer{status: 200, body: edictaapi.EncodeWrapper(edictaapi.TextItem(1, string(st))), schema: RequeueResponseSchema}
}

// caller checks the bearer token and, unless remote callers are allowed, a
// loopback Host header, and returns the agent key the credential is pinned
// to (nil for a shared one). Every credential is compared, so the time
// taken does not say which one matched.
func (h *apiHandler) caller(r *http.Request, admin bool) ([]byte, bool) {
	if !h.o.AllowRemote {
		host, _, err := net.SplitHostPort(r.Host)
		if err != nil {
			host = r.Host
		}
		if !IsLoopbackHost(strings.Trim(host, "[]")) {
			return nil, false
		}
	}
	got, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		return nil, false
	}
	g := sha256.Sum256([]byte(got))
	if admin {
		return nil, subtle.ConstantTimeCompare(g[:], h.admin[:]) == 1
	}
	var agent []byte
	found := 0
	for _, c := range h.creds {
		m := subtle.ConstantTimeCompare(g[:], c.digest[:])
		found |= m
		if m == 1 {
			agent = c.agent
		}
	}
	return agent, found == 1
}

func (h *apiHandler) paymentSignature(r *http.Request, isJSON bool, agent []byte) answer {
	limit := uint64(PaymentLimit)
	if isJSON {
		limit = edictaapi.JSONBodyLimit(limit)
	}
	body, err := readBody(r, limit)
	if err != nil {
		return h.fail(err)
	}
	if isJSON {
		if body, err = edictaapi.JSONToWrapper(body, PaymentRequestSchema); err != nil {
			return h.fail(err)
		}
		if len(body) > PaymentLimit {
			return h.fail(fmt.Errorf("%w: body of %d bytes", commitment.ErrTooLarge, len(body)))
		}
	}
	req, err := DecodePaymentRequest(body)
	if err != nil {
		return h.fail(err)
	}
	ctx, cancel := context.WithTimeout(r.Context(), h.o.RequestTimeout)
	defer cancel()
	out, err := h.s.PaymentProof(ctx, req, agent)
	if err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) && r.Context().Err() == nil {
			err = fmt.Errorf("%w: %w", edictaapi.ErrDeadline, err)
		}
		return h.fail(err)
	}
	return answer{status: 200, body: encodePaymentProof(out), schema: PaymentResponseSchema}
}

// IsLoopbackHost reports whether host names the loopback interface.
func IsLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// CheckBind refuses a listen address that is not loopback unless remote
// binding is allowed.
func CheckBind(addr string, allowRemote bool) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("signer: listen address %q is not host:port", addr)
	}
	if !allowRemote && !IsLoopbackHost(host) {
		return fmt.Errorf("signer: listen address %q is not loopback; allow remote binding explicitly", addr)
	}
	return nil
}

func readBody(r *http.Request, limit uint64) ([]byte, error) {
	if r.ContentLength > 0 && uint64(r.ContentLength) > limit {
		return nil, fmt.Errorf("%w: body of %d bytes", commitment.ErrTooLarge, r.ContentLength)
	}
	if r.Body == nil {
		return nil, nil
	}
	b, err := io.ReadAll(io.LimitReader(r.Body, int64(limit)+1))
	if err != nil {
		return nil, fmt.Errorf("%w: reading the body: %v", commitment.ErrMalformed, err)
	}
	if uint64(len(b)) > limit {
		return nil, fmt.Errorf("%w: body above %d bytes", commitment.ErrTooLarge, limit)
	}
	return b, nil
}
