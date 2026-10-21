// SPDX-License-Identifier: Apache-2.0

package commitcmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"net"
	"net/http"
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

// Handler serves POST /v1/commit. With loopbackOnly it also refuses a Host
// header that is not loopback, which stops a web page from reaching the
// service through DNS rebinding.
func Handler(s *Service, loopbackOnly bool) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/commit", func(w http.ResponseWriter, r *http.Request) {
		if loopbackOnly {
			host, _, err := net.SplitHostPort(r.Host)
			if err != nil {
				host = r.Host
			}
			if !isLoopbackHost(strings.Trim(host, "[]")) {
				writeFailure(w, &Failure{Exit: ExitUsage, Status: http.StatusForbidden, Code: "host_refused", Message: "the Host header is not loopback"})
				return
			}
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

type errorBody struct {
	Code          string `json:"code"`
	Message       string `json:"message"`
	Retryable     bool   `json:"retryable"`
	Stored        []byte `json:"stored,omitempty"`
	PolicyVerdict []byte `json:"policy_verdict,omitempty"`
}

// ErrorJSON is the error object `edicta commit` prints on stdout.
func ErrorJSON(f *Failure) ([]byte, error) {
	return json.Marshal(struct {
		Error errorBody `json:"error"`
	}{errorBody{f.Code, f.Message, f.Retryable, f.Stored, f.PolicyVerdict}})
}

func writeFailure(w http.ResponseWriter, f *Failure) {
	writeJSON(w, f.HTTPStatus(), errorBody{f.Code, f.Message, f.Retryable, f.Stored, f.PolicyVerdict})
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
func Serve(ctx context.Context, addr string, s *Service, allowRemote bool, ready func(net.Addr)) error {
	if err := CheckBind(addr, allowRemote); err != nil {
		return err
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	srv := &http.Server{
		Handler:           Handler(s, !allowRemote),
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
