// SPDX-License-Identifier: Apache-2.0

package commitcmd

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/vgonkivs/edicta/celestia/secret"
	"github.com/vgonkivs/edicta/edictaapi"
	"github.com/vgonkivs/edicta/engine/commitment"
	"github.com/vgonkivs/edicta/signer"
)

// Signer is the agent's view of edicta-signer: the two routes `edicta commit`
// uses. The signer, not this program, holds the wallet key and sends the
// transaction.
type Signer interface {
	Sign(ctx context.Context, req signer.Request) (signer.Output, error)
	PaymentSignature(ctx context.Context, req signer.PaymentProofRequest) (signer.PaymentProof, error)
	// Status shows the caller's own decision. A signer without the route
	// answers a SignerError with the route-not-found code.
	Status(ctx context.Context, h commitment.Hash) (signer.Status, error)
}

// SignerError is a refusal or failure the signer answered with.
type SignerError struct {
	Status    int
	Code      string
	Message   string
	Retryable bool
}

func (e *SignerError) Error() string {
	return fmt.Sprintf("signer: %s (status %d): %s", e.Code, e.Status, e.Message)
}

const maxSignerResponse = 1 << 20

// errorSchema is the error body of the core API as the signer sends it.
var errorSchema = edictaapi.NewSchema(
	edictaapi.Field{Key: 1, Name: "code", Kind: edictaapi.KindText, Min: 1, Max: 256, Required: true},
	edictaapi.Field{Key: 2, Name: "message", Kind: edictaapi.KindText, Required: true},
	edictaapi.Field{Key: 3, Name: "retryable", Kind: edictaapi.KindUint, Required: true},
	edictaapi.Field{Key: 4, Name: "stored", Kind: edictaapi.KindBytes},
	edictaapi.Field{Key: 5, Name: "policy_verdict", Kind: edictaapi.KindBytes, Min: 1, Max: 16384},
)

// SignerClient talks CBOR to the signer API with one per-agent credential.
type SignerClient struct {
	base  string
	token secret.Secret
	hc    *http.Client
}

// NewSignerClient returns a client for the signer at baseURL. The token is
// required, and is refused over plain HTTP to a non-loopback host.
func NewSignerClient(baseURL string, token secret.Secret, hc *http.Client) (*SignerClient, error) {
	u, err := url.Parse(baseURL)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, errors.New("commitcmd: signer URL must be an absolute http or https URL")
	}
	if !token.IsSet() {
		return nil, errors.New("commitcmd: the signer needs an API token")
	}
	if u.Scheme == "http" && !loopbackHost(u.Hostname()) {
		return nil, errors.New("commitcmd: refusing to send the signer token over plain HTTP to a non-loopback host")
	}
	if hc == nil {
		hc = &http.Client{Timeout: 60 * time.Second}
	}
	// The token must not follow a redirect to anywhere.
	own := *hc
	own.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	hc = &own
	return &SignerClient{base: strings.TrimRight(u.String(), "/"), token: token, hc: hc}, nil
}

func loopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// Sign calls POST /v1/sign.
func (c *SignerClient) Sign(ctx context.Context, req signer.Request) (signer.Output, error) {
	body, err := c.post(ctx, signer.RouteSign, signer.EncodeSignRequest(req))
	if err != nil {
		return signer.Output{}, err
	}
	out, err := signer.DecodeSignResponse(body)
	if err != nil {
		return signer.Output{}, fmt.Errorf("commitcmd: signer sign response: %w", err)
	}
	return out, nil
}

// PaymentSignature calls POST /v1/payment-signature.
func (c *SignerClient) PaymentSignature(ctx context.Context, req signer.PaymentProofRequest) (signer.PaymentProof, error) {
	body, err := c.post(ctx, signer.RoutePaymentSignature, signer.EncodePaymentRequest(req))
	if err != nil {
		return signer.PaymentProof{}, err
	}
	out, err := signer.DecodePaymentResponse(body)
	if err != nil {
		return signer.PaymentProof{}, fmt.Errorf("commitcmd: signer payment-signature response: %w", err)
	}
	return out, nil
}

// Status calls GET /v1/status/{hash}.
func (c *SignerClient) Status(ctx context.Context, h commitment.Hash) (signer.Status, error) {
	body, err := c.do(ctx, http.MethodGet, signer.RouteStatusPrefix+hex.EncodeToString(h[:]), nil)
	if err != nil {
		return signer.Status{}, err
	}
	st, err := signer.DecodeStatusResponse(body)
	if err != nil {
		return signer.Status{}, fmt.Errorf("commitcmd: signer status response: %w", err)
	}
	return st, nil
}

func (c *SignerClient) post(ctx context.Context, path string, body []byte) ([]byte, error) {
	return c.do(ctx, http.MethodPost, path, body)
}

func (c *SignerClient) do(ctx context.Context, method, path string, body []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("commitcmd: build signer request: %w", err)
	}
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/cbor")
	}
	req.Header.Set("Accept", "application/cbor")
	req.Header.Set("Authorization", "Bearer "+c.token.RevealString())
	resp, err := c.hc.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return nil, fmt.Errorf("commitcmd: signer %s: %w", path, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxSignerResponse+1))
	if err != nil {
		return nil, fmt.Errorf("commitcmd: read signer response: %w", err)
	}
	if len(data) > maxSignerResponse {
		return nil, fmt.Errorf("commitcmd: signer response above %d bytes", maxSignerResponse)
	}
	if resp.StatusCode == http.StatusOK {
		if isJSON, ok := edictaapi.MediaType(resp.Header.Get("Content-Type")); !ok || isJSON {
			return nil, fmt.Errorf("commitcmd: signer %s: unexpected content type %q", path, resp.Header.Get("Content-Type"))
		}
		return data, nil
	}
	f, err := edictaapi.DecodeWrapper(data, errorSchema)
	if err != nil {
		// A proxy page in front of the signer says nothing about the
		// decision: a server-side failure may have come after the signing.
		return nil, &SignerError{Status: resp.StatusCode, Code: "signer.unparsable", Message: "unparsable error response",
			Retryable: resp.StatusCode >= 500 || resp.StatusCode == http.StatusTooManyRequests}
	}
	r, _ := f.Uint(3)
	return nil, &SignerError{Status: resp.StatusCode, Code: f.Text(1), Message: f.Text(2), Retryable: r == 1}
}
