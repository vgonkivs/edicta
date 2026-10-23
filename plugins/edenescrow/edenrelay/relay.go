// SPDX-License-Identifier: Apache-2.0

// Package edenrelay is the client of the payment server's relay route,
// /deposit/send: it posts a signed deposit and reads the answer, which is
// never evidence that the deposit landed.
package edenrelay

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strings"
	"sync/atomic"
	"time"
)

// ErrRelayFault is any relay answer other than a success that names no
// other transaction: an error status, a timeout, an oversized or unreadable
// answer, or a hash other than the rail_ref. The caller then sends the same
// bytes directly. A success is not evidence either.
var ErrRelayFault = errors.New("signer/eden: relay fault")

// ErrNotSent marks a relay fault where the request was never completely
// written to the connection: the payment server cannot have read the
// bytes from this call. It always comes wrapped together with
// ErrRelayFault.
var ErrNotSent = errors.New("the request did not leave this process")

// Relay limits.
const (
	DefaultServerTimeout = 10 * time.Second
	MaxServerTimeout     = 60 * time.Second
	// MaxRelayAnswer bounds the relay's answer; a longer one is a fault and
	// is read no further.
	MaxRelayAnswer = 16384
)

// RelayPath is the payment server's send route under its base URL.
const RelayPath = "/deposit/send"

// HoustonConfig configures the payment server's relay.
type HoustonConfig struct {
	// BaseURL is the payment server, https only.
	BaseURL string
	// Timeout bounds one relay call (ServerTimeout).
	Timeout time.Duration
}

// ApplyDefaults fills the zero fields.
func (c *HoustonConfig) ApplyDefaults() {
	if c.Timeout == 0 {
		c.Timeout = DefaultServerTimeout
	}
}

// ValidateBasic checks the fields alone.
func (c HoustonConfig) ValidateBasic() error {
	u, err := url.Parse(c.BaseURL)
	switch {
	case err != nil:
		return errors.New("signer/eden: relay URL does not parse")
	case u.Scheme != "https":
		return fmt.Errorf("signer/eden: relay URL %q is not https: the signed deposit would travel in clear", c.BaseURL)
	case u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "":
		return fmt.Errorf("signer/eden: relay URL %q must be https://host[/path] only", c.BaseURL)
	case c.Timeout <= 0 || c.Timeout > MaxServerTimeout:
		return fmt.Errorf("signer/eden: relay timeout %v is not in (0, %v]", c.Timeout, MaxServerTimeout)
	}
	return nil
}

// HoustonRelay posts the signed deposit to the payment server's
// /deposit/send. It never asks the server whether the deposit landed: the
// server's status route answers confirmed for any hash on the chain, so it
// is no evidence.
type HoustonRelay struct {
	endpoint string
	timeout  time.Duration
	hc       *http.Client
	log      *slog.Logger
}

// NewHoustonRelay checks the configuration; hc nil is a client that follows
// no redirect, log nil the default logger.
func NewHoustonRelay(cfg HoustonConfig, hc *http.Client, log *slog.Logger) (*HoustonRelay, error) {
	if err := cfg.ValidateBasic(); err != nil {
		return nil, err
	}
	if hc == nil {
		hc = &http.Client{}
	}
	if log == nil {
		log = slog.Default()
	}
	// A redirect could lead off https or to another host; the answer to the
	// first request is the answer.
	c := *hc
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &HoustonRelay{
		endpoint: strings.TrimSuffix(cfg.BaseURL, "/") + RelayPath,
		timeout:  cfg.Timeout, hc: &c, log: log,
	}, nil
}

// deprecationLogged makes the relay's deprecation marker a single log line
// per process, however many answers carry it.
var deprecationLogged atomic.Bool

// Deprecated reports whether a relay answer carries the server's
// deprecation marker: a Deprecation header, or a top-level member
// "deprecation" that is JSON true. It is logged and changes nothing else.
func Deprecated(h http.Header, answer []byte) bool {
	if h.Get("Deprecation") != "" {
		return true
	}
	var top map[string]json.RawMessage
	if json.Unmarshal(answer, &top) != nil {
		return false
	}
	return string(bytes.TrimSpace(top["deprecation"])) == "true"
}

type relayBody struct {
	SignedTx  string `json:"signedTx"`
	PaymentID string `json:"paymentId"`
}

// Send posts {signedTx, paymentId}. Any answer but a 2xx whose body names
// no other transaction is ErrRelayFault; a call whose request was never
// completely written is also ErrNotSent.
func (r *HoustonRelay) Send(ctx context.Context, signed []byte, railRef string, paymentID [32]byte) error {
	body, err := json.Marshal(relayBody{
		SignedTx:  "0x" + hex.EncodeToString(signed),
		PaymentID: "0x" + hex.EncodeToString(paymentID[:]),
	})
	if err != nil {
		return fmt.Errorf("%w: %w: %v", ErrRelayFault, ErrNotSent, err)
	}
	var wrote atomic.Bool
	ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
		WroteRequest: func(i httptrace.WroteRequestInfo) {
			if i.Err == nil {
				wrote.Store(true)
			}
		},
	})
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("%w: %w: %v", ErrRelayFault, ErrNotSent, err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := r.hc.Do(req)
	if err != nil {
		if !wrote.Load() {
			return fmt.Errorf("%w: %w: %v", ErrRelayFault, ErrNotSent, err)
		}
		return fmt.Errorf("%w: %v", ErrRelayFault, err)
	}
	defer resp.Body.Close()
	answer, err := io.ReadAll(io.LimitReader(resp.Body, MaxRelayAnswer+1))
	if err != nil {
		return fmt.Errorf("%w: reading the answer: %v", ErrRelayFault, err)
	}
	if len(answer) > MaxRelayAnswer {
		return fmt.Errorf("%w: answer above %d bytes", ErrRelayFault, MaxRelayAnswer)
	}
	if Deprecated(resp.Header, answer) && deprecationLogged.CompareAndSwap(false, true) {
		r.log.Warn("signer/eden: the payment server marks its relay deprecated; direct broadcast is the default",
			"endpoint", r.endpoint)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("%w: status %d", ErrRelayFault, resp.StatusCode)
	}
	return CheckRelayAnswer(answer, railRef)
}

// Members of a relay answer that may carry the transaction hash, at the top
// level or inside one of the containers.
var (
	relayHashKeys   = []string{"txHash", "hash", "transactionHash"}
	relayContainers = []string{"result", "tx", "transaction"}
)

// CheckRelayAnswer reads a 2xx answer. An empty body is a success. Otherwise
// it must be one JSON object without an error member, and every hash it
// names, at the top level or under result, tx or transaction, must be the
// rail_ref; anything else is ErrRelayFault. The answer moves no state.
func CheckRelayAnswer(answer []byte, railRef string) error {
	if len(bytes.TrimSpace(answer)) == 0 {
		return nil
	}
	if len(answer) > MaxRelayAnswer {
		return fmt.Errorf("%w: answer above %d bytes", ErrRelayFault, MaxRelayAnswer)
	}
	dec := json.NewDecoder(bytes.NewReader(answer))
	dec.UseNumber()
	var top map[string]json.RawMessage
	if err := dec.Decode(&top); err != nil || top == nil {
		return fmt.Errorf("%w: the answer is not a JSON object", ErrRelayFault)
	}
	if _, err := dec.Token(); err != io.EOF {
		return fmt.Errorf("%w: data after the answer", ErrRelayFault)
	}
	if e, ok := top["error"]; ok && string(bytes.TrimSpace(e)) != "null" {
		return fmt.Errorf("%w: the answer carries an error", ErrRelayFault)
	}
	objs := []map[string]json.RawMessage{top}
	for _, k := range relayContainers {
		raw, ok := top[k]
		if !ok {
			continue
		}
		var inner map[string]json.RawMessage
		if json.Unmarshal(raw, &inner) == nil && inner != nil {
			objs = append(objs, inner)
		}
	}
	for _, o := range objs {
		for _, k := range relayHashKeys {
			raw, ok := o[k]
			if !ok {
				continue
			}
			var h string
			if err := json.Unmarshal(raw, &h); err != nil {
				return fmt.Errorf("%w: %s is not a string", ErrRelayFault, k)
			}
			got, ok := strings.CutPrefix(h, "0x")
			if !ok || len(got) != 64 || !strings.EqualFold(got, railRef) {
				return fmt.Errorf("%w: the relay names transaction %.80q, not %s", ErrRelayFault, h, railRef)
			}
			if _, err := hex.DecodeString(got); err != nil {
				return fmt.Errorf("%w: %s is not hex", ErrRelayFault, k)
			}
		}
	}
	return nil
}
