// SPDX-License-Identifier: Apache-2.0

package commitcmd

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"net"
	"net/http"
	"slices"
	"strings"
	"time"
)

// ErrBind is returned for a listen address the service refuses.
var ErrBind = errors.New("commitcmd: refusing to listen")

// CheckBind refuses an address that is not loopback unless allowRemote is set.
// The service has no authentication of its own: whoever can reach it can make
// the agent sign.
func CheckBind(addr string, allowRemote bool) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("%w: %q is not host:port", ErrBind, addr)
	}
	if allowRemote || isLoopbackHost(host) {
		return nil
	}
	return fmt.Errorf("%w: %q is not a loopback address (pass the explicit remote flag to override)", ErrBind, addr)
}

func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// Options configure the HTTP service.
type Options struct {
	// AllowRemote permits a bind address that is not loopback. It then needs
	// Token and AllowedHosts: the service signs for the agent, and without
	// them anyone who can reach the port can use the key.
	AllowRemote bool
	// Token is the bearer token callers must present in remote mode.
	Token []byte
	// AllowedHosts are the Host header values (with port) accepted in remote
	// mode.
	AllowedHosts []string
	// AllowedOrigins are the Origin values accepted in remote mode; a request
	// carrying any other Origin is refused (a browser page, not an agent).
	AllowedOrigins []string
	// MaxConcurrent bounds requests in flight; zero means 8. Each request
	// publishes and pays a fee.
	MaxConcurrent int
}

// ValidateBasic checks the stateless fields.
func (o Options) ValidateBasic() error {
	if !o.AllowRemote {
		return nil
	}
	if len(o.Token) == 0 {
		return fmt.Errorf("%w: a remote bind needs a bearer token", ErrBind)
	}
	if len(o.AllowedHosts) == 0 {
		return fmt.Errorf("%w: a remote bind needs a Host allowlist", ErrBind)
	}
	return nil
}

func tokenOK(want []byte, header string) bool {
	got, ok := strings.CutPrefix(header, "Bearer ")
	if !ok {
		return false
	}
	a, b := sha256.Sum256(want), sha256.Sum256([]byte(got))
	return subtle.ConstantTimeCompare(a[:], b[:]) == 1
}

// Handler serves POST /v1/commit. In loopback mode it refuses a Host header
// that is not loopback, which stops a web page from reaching the service
// through DNS rebinding. In remote mode it requires the bearer token, a Host
// from the allowlist and no foreign Origin. A Handler built from invalid
// remote options refuses every request.
func Handler(s *Service, o Options) http.Handler {
	n := o.MaxConcurrent
	if n <= 0 {
		n = 8
	}
	sem := make(chan struct{}, n)
	valid := o.ValidateBasic() == nil
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/commit", func(w http.ResponseWriter, r *http.Request) {
		if !valid {
			writeFailure(w, &Failure{Exit: ExitUsage, Status: http.StatusForbidden, Code: "forbidden", Message: "the service is misconfigured"})
			return
		}
		if f := checkCaller(r, o); f != nil {
			writeFailure(w, f)
			return
		}
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			writeFailure(w, &Failure{Exit: ExitUsage, Status: http.StatusMethodNotAllowed, Code: "method_not_allowed", Message: "use POST"})
			return
		}
		if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/json" {
			writeFailure(w, &Failure{Exit: ExitUsage, Status: http.StatusUnsupportedMediaType, Code: "media_type", Message: "content type must be application/json"})
			return
		}
		select {
		case sem <- struct{}{}:
			defer func() { <-sem }()
		default:
			writeFailure(w, &Failure{Exit: ExitUnavailable, Status: http.StatusTooManyRequests, Code: "busy", Message: "too many requests in flight", Retryable: true})
			return
		}
		req, err := DecodeRequest(http.MaxBytesReader(w, r.Body, MaxRequestBytes))
		if err != nil {
			writeFailure(w, classify(err))
			return
		}
		resp, err := s.Commit(r.Context(), req)
		if err != nil {
			writeFailure(w, classify(err))
			return
		}
		writeJSON(w, http.StatusOK, resp)
	})
	return mux
}

func checkCaller(r *http.Request, o Options) *Failure {
	deny := func(status int, code, msg string) *Failure {
		return &Failure{Exit: ExitUsage, Status: status, Code: code, Message: msg}
	}
	if !o.AllowRemote {
		host, _, err := net.SplitHostPort(r.Host)
		if err != nil {
			host = r.Host
		}
		if !isLoopbackHost(strings.Trim(host, "[]")) {
			return deny(http.StatusForbidden, "host_refused", "the Host header is not loopback")
		}
		return nil
	}
	if !slices.Contains(o.AllowedHosts, r.Host) {
		return deny(http.StatusForbidden, "host_refused", "the Host header is not allowed")
	}
	if origin := r.Header.Get("Origin"); origin != "" && !slices.Contains(o.AllowedOrigins, origin) {
		return deny(http.StatusForbidden, "origin_refused", "the Origin is not allowed")
	}
	if !tokenOK(o.Token, r.Header.Get("Authorization")) {
		return deny(http.StatusUnauthorized, "unauthorized", "missing or invalid bearer token")
	}
	return nil
}

type errorBody struct {
	Code          string `json:"code"`
	Message       string `json:"message"`
	Retryable     bool   `json:"retryable"`
	Stored        []byte `json:"stored,omitempty"`
	PolicyVerdict []byte `json:"policy_verdict,omitempty"`
	Envelope      []byte `json:"envelope,omitempty"`
	Action        []byte `json:"action,omitempty"`
	Salt          []byte `json:"salt,omitempty"`
	Authorization []byte `json:"authorization,omitempty"`
}

// ErrorJSON is the error object `edicta commit` prints on stdout.
func ErrorJSON(f *Failure) ([]byte, error) {
	return json.Marshal(struct {
		Error errorBody `json:"error"`
	}{f.body()})
}

func (f *Failure) body() errorBody {
	return errorBody{Code: f.Code, Message: f.Message, Retryable: f.Retryable, Stored: f.Stored, PolicyVerdict: f.PolicyVerdict,
		Envelope: f.Envelope, Action: f.Action, Salt: f.Salt, Authorization: f.Authorization}
}

func writeFailure(w http.ResponseWriter, f *Failure) {
	writeJSON(w, f.HTTPStatus(), f.body())
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		status, b = http.StatusInternalServerError, []byte(`{"code":"internal","message":"encode response","retryable":false}`)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write(b)
}

// Serve listens on addr until ctx ends. ready, if not nil, gets the bound
// address once the listener is up.
func Serve(ctx context.Context, addr string, s *Service, o Options, ready func(net.Addr)) error {
	if err := CheckBind(addr, o.AllowRemote); err != nil {
		return err
	}
	if err := o.ValidateBasic(); err != nil {
		return err
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	srv := &http.Server{
		Handler:           Handler(s, o),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	if ready != nil {
		ready(ln.Addr())
	}
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
		sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
		<-errc
		return nil
	}
}
