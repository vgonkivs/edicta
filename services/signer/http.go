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
	"slices"
	"strings"
	"time"

	"github.com/vgonkivs/edicta/api/edictaapi"
	"github.com/vgonkivs/edicta/api/signerapi"
	"github.com/vgonkivs/edicta/engine/commitment"
)

// MaxCredentials bounds the API credentials.
const MaxCredentials = 1024

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

// signerRules are the signer's own refusals, matched first: a dependency
// failure before all, since a fail-closed check wraps both its refusal and
// the cause.
var signerRules = []errRule{
	{signerapi.CodeUnavailable, ErrUnavailable, 503, true},
	{signerapi.CodeExpired, ErrExpired, 410, false},
	{signerapi.CodeNotAuthorized, ErrNotAuthorized, 403, false},
	{signerapi.CodePinMismatch, ErrPinMismatch, 403, false},
	{signerapi.CodeEscrowCode, ErrEscrowCode, 403, false},
	{signerapi.CodeFastModeRefused, ErrFastModeRefused, 403, false},
	{signerapi.CodeDigestConflict, ErrDigestConflict, 409, false},
	{signerapi.CodeNotRequeueable, ErrNotRequeueable, 409, false},
	{signerapi.CodeUnknownDecision, ErrUnknownDecision, 404, false},
	{signerapi.CodeSharedCredential, ErrSharedCredential, 403, false},
	{signerapi.CodeRiskLimit, ErrRiskLimit, 429, true},
	{signerapi.CodeNotExecuted, ErrNotExecuted, 409, true},
	{signerapi.CodeRequirements, ErrRequirements, 422, false},
}

// transportRules match after the handlers' rules: a rail refusal may wrap
// a decoding error of the action bytes.
var transportRules = []errRule{
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

// errorTable is the match order of the error answers: the signer's
// refusals, the handlers' rules in the handlers' order, then transport and
// encoding errors.
func errorTable(hs []Handler) ([]errRule, error) {
	t := slices.Clone(signerRules)
	for _, h := range hs {
		for i, r := range h.ErrorRules() {
			if r.Err == nil || r.Code == "" || r.Status < 400 || r.Status > 599 {
				return nil, fmt.Errorf("signer: error rule %d of %s: needs an error, a code and a 4xx or 5xx status", i, h.ActionType())
			}
			t = append(t, errRule{r.Code, r.Err, r.Status, false})
		}
	}
	return append(t, transportRules...), nil
}

func (h *apiHandler) classify(err error) errRule {
	for _, r := range h.rules {
		if errors.Is(err, r.err) {
			return r
		}
	}
	return errRule{signerapi.CodeInternal, nil, 500, false}
}

// requestLimits are the body limits of the sign and payment-signature
// routes: the wire's limits less what no served handler takes of the
// payment requirements.
func requestLimits(hs []Handler) (sign, payment uint64, err error) {
	var most int64
	for _, h := range hs {
		n := h.MaxRequestBytes()
		if n < 0 || n > signerapi.MaxRequirementsSize {
			return 0, 0, fmt.Errorf("signer: %s takes %d bytes of payment requirements, the API carries 0 to %d",
				h.ActionType(), n, signerapi.MaxRequirementsSize)
		}
		most = max(most, n)
	}
	cut := uint64(signerapi.MaxRequirementsSize - most)
	return signerapi.SignLimit - cut, signerapi.PaymentLimit - cut, nil
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
	rules, err := errorTable(s.ordered)
	if err != nil {
		return nil, err
	}
	signLimit, paymentLimit, err := requestLimits(s.ordered)
	if err != nil {
		return nil, err
	}
	h := &apiHandler{s: s, o: o, log: log, rules: rules, signLimit: signLimit, paymentLimit: paymentLimit}
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

	rules                   []errRule
	signLimit, paymentLimit uint64
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
			js, _ = edictaapi.WrapperToJSON(edictaapi.ErrorBody(signerapi.CodeInternal, "internal error", false), edictaapi.ErrorSchema)
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
	rule := h.classify(err)
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
			a = answer{status: 500, body: edictaapi.ErrorBody(signerapi.CodeInternal, "internal error", false)}
		}
	}()
	method, admin := http.MethodPost, false
	var statusHash string
	path := r.URL.Path
	switch {
	case strings.HasPrefix(path, signerapi.RouteStatusPrefix):
		method, statusHash = http.MethodGet, strings.TrimPrefix(path, signerapi.RouteStatusPrefix)
		path = signerapi.RouteStatusPrefix
	case path == signerapi.RouteSign, path == signerapi.RoutePaymentSignature:
	case path == signerapi.RouteHealth:
		method = http.MethodGet
	case path == signerapi.RouteRequeue:
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
	if path == signerapi.RouteStatusPrefix {
		return h.status(r, statusHash, agent)
	}
	if method == http.MethodGet {
		return answer{status: 200, body: edictaapi.EncodeWrapper(edictaapi.TextItem(1, "ok")), schema: signerapi.HealthSchema}
	}
	switch r.URL.Path {
	case signerapi.RouteRequeue:
		return h.requeue(r, isJSON)
	case signerapi.RoutePaymentSignature:
		return h.paymentSignature(r, isJSON, agent)
	}

	limit := h.signLimit
	if isJSON {
		limit = edictaapi.JSONBodyLimit(limit)
	}
	body, err := readBody(r, limit)
	if err != nil {
		return h.fail(err)
	}
	if isJSON {
		if body, err = edictaapi.JSONToWrapper(body, signerapi.SignRequestSchema); err != nil {
			return h.fail(err)
		}
		if uint64(len(body)) > h.signLimit {
			return h.fail(fmt.Errorf("%w: body of %d bytes", commitment.ErrTooLarge, len(body)))
		}
	}
	req, err := signerapi.DecodeSignRequest(body)
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
	return answer{status: 200, body: signerapi.EncodeSignResponse(out), schema: signerapi.SignResponseSchema}
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
	return answer{status: 200, body: signerapi.EncodeStatusResponse(ch, st), schema: signerapi.StatusResponseSchema}
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
		if body, err = edictaapi.JSONToWrapper(body, signerapi.RequeueRequestSchema); err != nil {
			return h.fail(err)
		}
	}
	f, err := edictaapi.DecodeWrapper(body, signerapi.RequeueRequestSchema)
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
	return answer{status: 200, body: edictaapi.EncodeWrapper(edictaapi.TextItem(1, string(st))), schema: signerapi.RequeueResponseSchema}
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
	limit := h.paymentLimit
	if isJSON {
		limit = edictaapi.JSONBodyLimit(limit)
	}
	body, err := readBody(r, limit)
	if err != nil {
		return h.fail(err)
	}
	if isJSON {
		if body, err = edictaapi.JSONToWrapper(body, signerapi.PaymentRequestSchema); err != nil {
			return h.fail(err)
		}
		if uint64(len(body)) > h.paymentLimit {
			return h.fail(fmt.Errorf("%w: body of %d bytes", commitment.ErrTooLarge, len(body)))
		}
	}
	req, err := signerapi.DecodePaymentRequest(body)
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
	return answer{status: 200, body: signerapi.EncodePaymentResponse(out), schema: signerapi.PaymentResponseSchema}
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
