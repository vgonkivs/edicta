package edictaapi

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/gate"
	"github.com/vgonkivs/edicta/sdk"
)

// Secret holds a bearer token. Every formatting and encoding path prints
// "[redacted]". The zero value is no token.
type Secret struct{ b []byte }

const redacted = "[redacted]"

// NewSecret wraps s; the empty string is no token.
func NewSecret(s string) Secret { return Secret{b: []byte(s)} }

func (Secret) String() string               { return redacted }
func (Secret) GoString() string             { return redacted }
func (Secret) MarshalJSON() ([]byte, error) { return []byte(`"` + redacted + `"`), nil }
func (Secret) MarshalText() ([]byte, error) { return []byte(redacted), nil }
func (Secret) LogValue() slog.Value         { return slog.StringValue(redacted) }
func (Secret) Format(f fmt.State, _ rune)   { _, _ = f.Write([]byte(redacted)) }

func (s Secret) isSet() bool { return len(s.b) > 0 }

// PublishSigner signs publish messages for one agent (section 17).
type PublishSigner interface {
	AgentID() string
	// SignPublish signs msg (the output of PublishMessage) with Ed25519.
	SignPublish(ctx context.Context, msg []byte) ([]byte, error)
}

// WaitFunc is called between attempts; attempt is the number of the attempt
// that just failed (1 first) and retryAfter the server's Retry-After (0 if
// absent). A non-nil result stops the retries and is returned.
type WaitFunc func(ctx context.Context, attempt int, retryAfter time.Duration) error

// ClientOption configures NewClient.
type ClientOption func(*Client)

// WithGateID sets the server's gate_id, required by Publish.
func WithGateID(id string) ClientOption { return func(c *Client) { c.gateID = id } }

// WithClock sets the clock that stamps publish requests.
func WithClock(clock gate.Clock) ClientOption { return func(c *Client) { c.clock = clock } }

// WithRetry allows up to maxAttempts requests in total (the first included);
// a request is repeated, unchanged, only when the server answered
// retryable = 1. A nil wait sleeps for Retry-After, or a short backoff.
func WithRetry(maxAttempts int, wait WaitFunc) ClientOption {
	return func(c *Client) {
		c.maxAttempts = max(maxAttempts, 1)
		c.wait = wait
	}
}

// Client is the Go client of the API. It is safe for concurrent use.
type Client struct {
	base        string
	hc          *http.Client
	token       Secret
	signer      PublishSigner
	gateID      string
	clock       gate.Clock
	maxAttempts int
	wait        WaitFunc
}

var _ sdk.Publisher = (*Client)(nil)

// NewClient returns a client for the server at baseURL. signer may be nil, in
// which case Publish fails without sending a request. hc may be nil. A token
// is refused over plain HTTP to a non-loopback host.
func NewClient(baseURL string, token Secret, signer PublishSigner, hc *http.Client, opts ...ClientOption) (*Client, error) {
	u, err := url.Parse(baseURL)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, errors.New("edictaapi: base URL must be an absolute http or https URL")
	}
	if token.isSet() && u.Scheme == "http" && !isLoopback(u.Hostname()) {
		return nil, errors.New("edictaapi: refusing to send a bearer token over plain HTTP to a non-loopback host")
	}
	if hc == nil {
		hc = &http.Client{Timeout: 60 * time.Second}
	}
	c := &Client{base: strings.TrimRight(u.String(), "/"), hc: hc, token: token, signer: signer, maxAttempts: 1}
	for _, o := range opts {
		o(c)
	}
	if c.clock == nil {
		c.clock = systemClock{}
	}
	if c.wait == nil {
		c.wait = defaultWait
	}
	return c, nil
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func defaultWait(ctx context.Context, attempt int, after time.Duration) error {
	d := after
	if d <= 0 {
		d = min(time.Duration(attempt)*250*time.Millisecond, 5*time.Second)
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

// Publish signs and sends blob (rule section 17) and returns the server's
// claim. The request is signed once and resent unchanged on a retry.
func (c *Client) Publish(ctx context.Context, blob []byte) (sdk.Published, error) {
	if c.signer == nil {
		return sdk.Published{}, errors.New("edictaapi: Publish needs a PublishSigner")
	}
	if c.gateID == "" {
		return sdk.Published{}, errors.New("edictaapi: Publish needs the server gate id (WithGateID)")
	}
	now := c.clock.Now().Unix()
	if now < 1 {
		return sdk.Published{}, errors.New("edictaapi: clock before 1970-01-01T00:00:01Z")
	}
	agentID := c.signer.AgentID()
	msg, err := PublishMessage(c.gateID, agentID, uint64(now), blob)
	if err != nil {
		return sdk.Published{}, err
	}
	sig, err := c.signer.SignPublish(ctx, msg)
	if err != nil {
		return sdk.Published{}, fmt.Errorf("edictaapi: sign publish request: %w", err)
	}
	body, err := EncodePublishRequest(PublishRequest{Blob: blob, AgentID: agentID, RequestedAt: uint64(now), Signature: sig})
	if err != nil {
		return sdk.Published{}, err
	}
	out, err := c.do(ctx, http.MethodPost, "/v1/publish", body)
	if err != nil {
		return sdk.Published{}, err
	}
	f, err := decodeFields(out, publishResponseSchema)
	if err != nil {
		return sdk.Published{}, fmt.Errorf("edictaapi: publish response: %w", err)
	}
	ref, err := commitment.DecodePayloadRef(f[1].b)
	if err != nil {
		return sdk.Published{}, fmt.Errorf("edictaapi: publish response payload_ref: %w", err)
	}
	return sdk.Published{Ref: ref, BlockTime: f[2].u, RetentionStart: f[3].u}, nil
}

var (
	publishResponseSchema = []fspec{
		{key: 1, name: "payload_ref", kind: fBytes, min: 1, max: unbounded, required: true},
		{key: 2, name: "block_time", kind: fUint, required: true},
		{key: 3, name: "retention_start", kind: fUint, required: true},
	}
	singleBytesSchema = []fspec{{key: 1, name: "result", kind: fBytes, min: 1, max: unbounded, required: true}}
	errorBodySchema   = []fspec{
		{key: 1, name: "code", kind: fText, min: 1, max: 256, required: true},
		{key: 2, name: "message", kind: fText, max: unbounded, required: true},
		{key: 3, name: "retryable", kind: fUint, required: true},
		{key: 4, name: "stored", kind: fBytes, max: unbounded},
		{key: 5, name: "policy_verdict", kind: fBytes, min: 1, max: 16384},
	}
	authorizeResponseSchema = []fspec{
		{key: 1, name: "result", kind: fBytes, min: 1, max: unbounded, required: true},
		{key: 5, name: "policy_verdict", kind: fBytes, min: 1, max: 16384},
	}
)

// Authorize returns the SignedAuthorization bytes. On ErrNonceUsed the
// *Error may carry the stored one in Stored; verify it like any Authorization.
func (c *Client) Authorize(ctx context.Context, envelope, action, salt []byte) ([]byte, error) {
	auth, _, err := c.AuthorizeWithVerdict(ctx, envelope, action, salt)
	return auth, err
}

// AuthorizeWithVerdict is Authorize that also returns the signed policy
// verdict, nil when the gate has no mandate. On a policy deny the *Error
// carries the deny verdict in PolicyVerdict.
func (c *Client) AuthorizeWithVerdict(ctx context.Context, envelope, action, salt []byte) (auth, verdict []byte, err error) {
	body := encodeMap(kv{key: 1, kind: fBytes, b: envelope}, kv{key: 2, kind: fBytes, b: action}, kv{key: 3, kind: fBytes, b: salt})
	out, err := c.do(ctx, http.MethodPost, "/v1/authorize", body)
	if err != nil {
		return nil, nil, err
	}
	f, err := decodeFields(out, authorizeResponseSchema)
	if err != nil {
		return nil, nil, fmt.Errorf("edictaapi: /v1/authorize response: %w", err)
	}
	if n := f[5]; n != nil {
		verdict = bytes.Clone(n.b)
	}
	return bytes.Clone(f[1].b), verdict, nil
}

// Record returns the SignedReceipt bytes; on ErrReceiptExists Error.Stored
// holds the stored receipt.
func (c *Client) Record(ctx context.Context, envelope []byte, railRef string, pub, sig []byte) ([]byte, error) {
	body := encodeMap(
		kv{key: 1, kind: fBytes, b: envelope},
		kv{key: 2, kind: fText, s: railRef},
		kv{key: 3, kind: fBytes, b: pub},
		kv{key: 4, kind: fBytes, b: sig},
	)
	return c.single(ctx, "/v1/record", body)
}

func (c *Client) single(ctx context.Context, path string, body []byte) ([]byte, error) {
	out, err := c.do(ctx, http.MethodPost, path, body)
	if err != nil {
		return nil, err
	}
	f, err := decodeFields(out, singleBytesSchema)
	if err != nil {
		return nil, fmt.Errorf("edictaapi: %s response: %w", path, err)
	}
	return bytes.Clone(f[1].b), nil
}

// Health returns the server's health. Treat it as information, not as trusted
// configuration.
func (c *Client) Health(ctx context.Context) (HealthInfo, error) {
	out, err := c.do(ctx, http.MethodGet, "/v1/health", nil)
	if err != nil {
		return HealthInfo{}, err
	}
	return decodeHealth(out)
}

// do sends the request, repeating it unchanged while the server answers
// retryable = 1 and attempts remain.
func (c *Client) do(ctx context.Context, method, path string, body []byte) ([]byte, error) {
	for attempt := 1; ; attempt++ {
		out, after, err := c.once(ctx, method, path, body)
		if err == nil {
			return out, nil
		}
		var ae *Error
		if !errors.As(err, &ae) || !ae.Retryable || attempt >= c.maxAttempts {
			return nil, err
		}
		if werr := c.wait(ctx, attempt, after); werr != nil {
			return nil, fmt.Errorf("edictaapi: retry wait after attempt %d: %w (last error: %w)", attempt, werr, err)
		}
	}
}

func (c *Client) once(ctx context.Context, method, path string, body []byte) ([]byte, time.Duration, error) {
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, rd)
	if err != nil {
		return nil, 0, fmt.Errorf("edictaapi: build request: %w", err)
	}
	req.Header.Set("Accept", contentType)
	if body != nil {
		req.Header.Set("Content-Type", contentType)
	}
	if c.token.isSet() {
		req.Header.Set("Authorization", "Bearer "+string(c.token.b))
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		// url.Error carries the URL only, never headers; drop it anyway.
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return nil, 0, fmt.Errorf("edictaapi: %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse+1))
	if err != nil {
		return nil, 0, fmt.Errorf("edictaapi: read response: %w", err)
	}
	if len(data) > maxResponse {
		return nil, 0, fmt.Errorf("edictaapi: response above %d bytes: %w", maxResponse, commitment.ErrTooLarge)
	}
	if resp.StatusCode == http.StatusOK {
		return data, 0, nil
	}
	var after time.Duration
	if s, perr := strconv.ParseUint(resp.Header.Get("Retry-After"), 10, 32); perr == nil {
		after = time.Duration(s) * time.Second
	}
	return nil, after, parseError(resp.StatusCode, data)
}

func parseError(status int, data []byte) *Error {
	f, err := decodeFields(data, errorBodySchema)
	if err != nil || f[3].u > 1 {
		return &Error{Status: status, Code: codeInternal, Message: "unparsable error response"}
	}
	e := &Error{Status: status, Code: string(f[1].b), Message: string(f[2].b), Retryable: f[3].u == 1}
	if n := f[4]; n != nil {
		e.Stored = bytes.Clone(n.b)
	}
	if n := f[5]; n != nil {
		e.PolicyVerdict = bytes.Clone(n.b)
	}
	return e
}
