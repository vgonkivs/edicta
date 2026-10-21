// SPDX-License-Identifier: Apache-2.0

package signer

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
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
)

// SignLimit bounds a sign request in CBOR: the envelope, the action, the
// salt and the Authorization with their wrapper heads.
const SignLimit = commitment.MaxSignedSize + commitment.MaxActionSize + commitment.ActionSaltSize +
	commitment.MaxAuthorizationSize + 32

var (
	// SignRequestSchema is the request of POST /v1/sign.
	SignRequestSchema = edictaapi.NewSchema(
		edictaapi.Field{Key: 1, Name: "envelope", Kind: edictaapi.KindBytes, Min: 1, Max: commitment.MaxSignedSize, Required: true},
		edictaapi.Field{Key: 2, Name: "action", Kind: edictaapi.KindBytes, Min: 1, Max: commitment.MaxActionSize, Required: true},
		edictaapi.Field{Key: 3, Name: "action_salt", Kind: edictaapi.KindBytes, Min: commitment.ActionSaltSize, Max: commitment.ActionSaltSize, Required: true},
		edictaapi.Field{Key: 4, Name: "signed_authorization", Kind: edictaapi.KindBytes, Min: 1, Max: commitment.MaxAuthorizationSize, Required: true},
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
	return Request{Envelope: f.Bytes(1), Action: f.Bytes(2), Salt: f.Bytes(3), Authorization: f.Bytes(4)}, nil
}

// EncodeSignRequest is the canonical CBOR of a sign request.
func EncodeSignRequest(r Request) []byte {
	return edictaapi.EncodeWrapper(
		edictaapi.BytesItem(1, r.Envelope), edictaapi.BytesItem(2, r.Action),
		edictaapi.BytesItem(3, r.Salt), edictaapi.BytesItem(4, r.Authorization),
	)
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

// HTTPOptions configure the API.
type HTTPOptions struct {
	// Token is the bearer token every request needs.
	Token []byte
	// AllowRemote accepts a Host header that is not loopback. Without it a
	// web page cannot reach the API through DNS rebinding.
	AllowRemote bool
	// RequestTimeout bounds one request; zero means 30 s.
	RequestTimeout time.Duration
	// AdminToken enables the operator routes and is the only token they
	// accept; the agents' token never reaches them. Empty disables them.
	AdminToken []byte
}

// ValidateBasic checks the stateless fields.
func (o HTTPOptions) ValidateBasic() error {
	if len(o.Token) < 16 {
		return errors.New("signer: the API token must be at least 16 bytes")
	}
	if len(o.AdminToken) > 0 && len(o.AdminToken) < 16 {
		return errors.New("signer: the admin token must be at least 16 bytes")
	}
	if len(o.AdminToken) > 0 && subtle.ConstantTimeCompare(o.AdminToken, o.Token) == 1 {
		return errors.New("signer: the admin token must differ from the API token")
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
	h := &apiHandler{s: s, o: o, want: sha256.Sum256(o.Token), log: log}
	if len(o.AdminToken) > 0 {
		h.admin = sha256.Sum256(o.AdminToken)
		h.adminOn = true
	}
	return h, nil
}

type apiHandler struct {
	s       *Service
	o       HTTPOptions
	want    [32]byte
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
	method, token := http.MethodPost, h.want
	switch r.URL.Path {
	case RouteSign:
	case RouteHealth:
		method = http.MethodGet
	case RouteRequeue:
		if !h.adminOn {
			return h.fail(edictaapi.ErrRouteNotFound)
		}
		token = h.admin
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
	if !h.callerOK(r, token) {
		return h.fail(edictaapi.ErrTokenInvalid)
	}
	if method == http.MethodGet {
		return answer{status: 200, body: edictaapi.EncodeWrapper(edictaapi.TextItem(1, "ok")), schema: HealthSchema}
	}
	if r.URL.Path == RouteRequeue {
		return h.requeue(r, isJSON)
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
	out, err := h.s.Sign(ctx, req)
	if err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) && r.Context().Err() == nil {
			err = fmt.Errorf("%w: %w", edictaapi.ErrDeadline, err)
		}
		return h.fail(err)
	}
	return answer{status: 200, body: encodeOutput(out), schema: SignResponseSchema}
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

// callerOK checks the bearer token and, unless remote callers are allowed, a
// loopback Host header.
func (h *apiHandler) callerOK(r *http.Request, want [32]byte) bool {
	if !h.o.AllowRemote {
		host, _, err := net.SplitHostPort(r.Host)
		if err != nil {
			host = r.Host
		}
		if !IsLoopbackHost(strings.Trim(host, "[]")) {
			return false
		}
	}
	got, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		return false
	}
	g := sha256.Sum256([]byte(got))
	return subtle.ConstantTimeCompare(g[:], want[:]) == 1
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
