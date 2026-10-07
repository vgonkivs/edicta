// Package cometrpc reads headers and transactions from a CometBFT RPC node.
// The node is untrusted: headers are rebuilt from their fields so the caller
// recomputes the hash itself, and every answer is held to the height asked.
package cometrpc

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	cmtjson "github.com/cometbft/cometbft/libs/json"
	core "github.com/cometbft/cometbft/types"

	"github.com/vgonkivs/edicta/celestia/inclusion"
	"github.com/vgonkivs/edicta/celestia/railverify"
)

var (
	// ErrBadResponse marks an answer that is not what the call expects.
	ErrBadResponse = errors.New("cometrpc: unusable answer")
	// ErrUnavailable marks a node that did not give an answer: transport
	// errors, non-200 statuses and RPC errors.
	ErrUnavailable = errors.New("cometrpc: source unavailable")
)

const (
	// maxBody is far above any header, block meta list or transaction proof.
	maxBody = 8 << 20
	// maxPerCall is the most headers one /blockchain call returns.
	maxPerCall = 20

	defaultTimeout = 30 * time.Second

	// A busy public node answers 429 or 503 now and then; a few paced
	// retries ride that out without hammering it.
	defaultRetries   = 3
	defaultRetryBase = 500 * time.Millisecond
	maxRetryWait     = 10 * time.Second
)

// Source is one CometBFT RPC endpoint.
type Source struct {
	base string
	host string
	hc   *http.Client

	retries   int
	retryBase time.Duration
}

// New checks the base URL and copies hc, whose redirect policy is replaced:
// redirects are never followed. A nil hc gets a 30 s timeout.
func New(rawURL string, hc *http.Client) (*Source, error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.ContainsAny(rawURL, "?#") {
		return nil, fmt.Errorf("cometrpc: bad url %q", rawURL)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("cometrpc: bad scheme in %q", rawURL)
	}
	host, err := inclusion.SourceHost(rawURL)
	if err != nil {
		return nil, fmt.Errorf("cometrpc: %w", err)
	}
	c := http.Client{Timeout: defaultTimeout}
	if hc != nil {
		c = *hc
	}
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &Source{base: strings.TrimRight(rawURL, "/"), host: host, hc: &c, retries: defaultRetries, retryBase: defaultRetryBase}, nil
}

// WithRetry sets how often a 429 or 503 answer is retried, and the first
// backoff, which doubles each time unless the node sends Retry-After. It is
// for use before the first call.
func (s *Source) WithRetry(retries int, base time.Duration) *Source {
	s.retries, s.retryBase = max(retries, 0), base
	return s
}

// Name is the normalized host, the unit that distinct-source rules count.
func (s *Source) Name() string { return s.host }

type rpcError struct {
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data"`
}

func (e *rpcError) text() string {
	var d string
	_ = json.Unmarshal(e.Data, &d)
	return strings.TrimSpace(e.Message + ": " + d)
}

type envelope struct {
	Result json.RawMessage `json:"result"`
	Error  *rpcError       `json:"error"`
}

// call returns the result member, or the node's RPC error as the second
// value. CometBFT sends RPC errors with a 200 or a 500, so the body is
// looked at before the status.
func (s *Source) call(ctx context.Context, path string, q url.Values) (json.RawMessage, *rpcError, error) {
	for attempt := 0; ; attempt++ {
		r, rerr, wait, busy, err := s.callOnce(ctx, path, q)
		if !busy || attempt >= s.retries {
			return r, rerr, err
		}
		if wait < 0 {
			wait = s.retryBase << attempt
		}
		wait = min(wait, maxRetryWait)
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return nil, nil, fmt.Errorf("cometrpc: %w", ctx.Err())
		case <-t.C:
		}
	}
}

// retryAfter reads a Retry-After given in seconds; -1 means none was given.
func retryAfter(h http.Header) time.Duration {
	n, err := strconv.ParseUint(strings.TrimSpace(h.Get("Retry-After")), 10, 31)
	if err != nil {
		return -1
	}
	return time.Duration(n) * time.Second
}

// callOnce is one request. busy is set for a 429 or 503 that carries no RPC
// error, and wait is then the node's Retry-After, or -1.
func (s *Source) callOnce(ctx context.Context, path string, q url.Values) (res json.RawMessage, rerr *rpcError, wait time.Duration, busy bool, err error) {
	u := s.base + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, nil, 0, false, fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	resp, err := s.hc.Do(req)
	if err != nil {
		if cerr := ctx.Err(); cerr != nil {
			return nil, nil, 0, false, fmt.Errorf("cometrpc: %w", cerr)
		}
		return nil, nil, 0, false, fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		if cerr := ctx.Err(); cerr != nil {
			return nil, nil, 0, false, fmt.Errorf("cometrpc: %w", cerr)
		}
		return nil, nil, 0, false, fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	if len(b) > maxBody {
		return nil, nil, 0, false, fmt.Errorf("%w: answer is larger than %d bytes", ErrBadResponse, maxBody)
	}
	var env envelope
	jerr := json.Unmarshal(b, &env)
	if jerr == nil && env.Error != nil {
		return nil, env.Error, 0, false, nil
	}
	if resp.StatusCode != http.StatusOK {
		busy = resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusServiceUnavailable
		return nil, nil, retryAfter(resp.Header), busy, fmt.Errorf("%w: status %d", ErrUnavailable, resp.StatusCode)
	}
	if jerr != nil || len(env.Result) == 0 {
		return nil, nil, 0, false, fmt.Errorf("%w: not a JSON-RPC result", ErrBadResponse)
	}
	return env.Result, nil, 0, false, nil
}

func (s *Source) result(ctx context.Context, path string, q url.Values) (json.RawMessage, error) {
	r, rerr, err := s.call(ctx, path, q)
	if err != nil {
		return nil, err
	}
	if rerr != nil {
		return nil, fmt.Errorf("%w: %s", ErrUnavailable, rerr.text())
	}
	return r, nil
}

// parseHeight accepts the decimal string CometBFT uses for int64 and nothing
// else.
func parseHeight(s string) (uint64, error) {
	h, err := strconv.ParseUint(s, 10, 63)
	if err != nil || h == 0 || strconv.FormatUint(h, 10) != s {
		return 0, fmt.Errorf("%w: height %q", ErrBadResponse, s)
	}
	return h, nil
}

func (s *Source) status(ctx context.Context) (height uint64, id string, err error) {
	r, err := s.result(ctx, "/status", nil)
	if err != nil {
		return 0, "", err
	}
	var st struct {
		NodeInfo struct {
			ID string `json:"id"`
		} `json:"node_info"`
		SyncInfo struct {
			Latest *string `json:"latest_block_height"`
		} `json:"sync_info"`
	}
	if err := json.Unmarshal(r, &st); err != nil || st.SyncInfo.Latest == nil {
		return 0, "", fmt.Errorf("%w: status", ErrBadResponse)
	}
	h, err := parseHeight(*st.SyncInfo.Latest)
	return h, st.NodeInfo.ID, err
}

// Latest is the node's latest block height.
func (s *Source) Latest(ctx context.Context) (uint64, error) {
	h, _, err := s.status(ctx)
	return h, err
}

// NodeID is the node id of /status, so two host names of one node can be
// told apart from two nodes.
func (s *Source) NodeID(ctx context.Context) (string, error) {
	_, id, err := s.status(ctx)
	if err != nil {
		return "", err
	}
	if b, derr := hex.DecodeString(id); derr != nil || len(b) == 0 {
		return "", fmt.Errorf("%w: node id", ErrBadResponse)
	}
	return id, nil
}

func decodeHeader(raw json.RawMessage, want uint64) (core.Header, error) {
	var h core.Header
	if err := cmtjson.Unmarshal(raw, &h); err != nil {
		return core.Header{}, fmt.Errorf("%w: header: %v", ErrBadResponse, err)
	}
	if h.Height < 1 || uint64(h.Height) != want {
		return core.Header{}, fmt.Errorf("%w: asked for height %d, got %d", ErrBadResponse, want, h.Height)
	}
	return h, nil
}

func encodeHeader(h core.Header) ([]byte, error) {
	p := h.ToProto()
	b, err := p.Marshal()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadResponse, err)
	}
	return b, nil
}

// Header is the protobuf Header at height. The node's block hash is never
// used; the caller hashes the fields.
func (s *Source) Header(ctx context.Context, height uint64) ([]byte, error) {
	r, err := s.result(ctx, "/header", url.Values{"height": {strconv.FormatUint(height, 10)}})
	if err != nil {
		return nil, err
	}
	var res struct {
		Header json.RawMessage `json:"header"`
	}
	if err := json.Unmarshal(r, &res); err != nil || len(res.Header) == 0 {
		return nil, fmt.Errorf("%w: no header", ErrBadResponse)
	}
	h, err := decodeHeader(res.Header, height)
	if err != nil {
		return nil, err
	}
	return encodeHeader(h)
}

// BlockHash is the block hash at height from /commit, which must equal the
// hash recomputed from the header it came with.
func (s *Source) BlockHash(ctx context.Context, height uint64) ([]byte, error) {
	r, err := s.result(ctx, "/commit", url.Values{"height": {strconv.FormatUint(height, 10)}})
	if err != nil {
		return nil, err
	}
	var res struct {
		SignedHeader struct {
			Header json.RawMessage `json:"header"`
			Commit struct {
				BlockID struct {
					Hash string `json:"hash"`
				} `json:"block_id"`
			} `json:"commit"`
		} `json:"signed_header"`
	}
	if err := json.Unmarshal(r, &res); err != nil || len(res.SignedHeader.Header) == 0 {
		return nil, fmt.Errorf("%w: no signed header", ErrBadResponse)
	}
	h, err := decodeHeader(res.SignedHeader.Header, height)
	if err != nil {
		return nil, err
	}
	sum := h.Hash()
	if len(sum) != 32 || !strings.EqualFold(res.SignedHeader.Commit.BlockID.Hash, hex.EncodeToString(sum)) {
		return nil, fmt.Errorf("%w: block id differs from the header hash", ErrBadResponse)
	}
	return sum, nil
}

// Headers returns the protobuf headers lo..hi in ascending order, twenty per
// call. Any gap or surplus fails the whole range.
func (s *Source) Headers(ctx context.Context, lo, hi uint64) ([][]byte, error) {
	if lo == 0 || lo > hi {
		return nil, fmt.Errorf("cometrpc: range %d..%d", lo, hi)
	}
	var out [][]byte
	for from := lo; from <= hi; {
		to := min(from+maxPerCall-1, hi)
		part, err := s.rangeCall(ctx, from, to)
		if err != nil {
			return nil, err
		}
		out = append(out, part...)
		from = to + 1
	}
	return out, nil
}

func (s *Source) rangeCall(ctx context.Context, lo, hi uint64) ([][]byte, error) {
	r, err := s.result(ctx, "/blockchain", url.Values{
		"minHeight": {strconv.FormatUint(lo, 10)}, "maxHeight": {strconv.FormatUint(hi, 10)},
	})
	if err != nil {
		return nil, err
	}
	var res struct {
		Metas []struct {
			Header json.RawMessage `json:"header"`
		} `json:"block_metas"`
	}
	if err := json.Unmarshal(r, &res); err != nil {
		return nil, fmt.Errorf("%w: block metas", ErrBadResponse)
	}
	if uint64(len(res.Metas)) != hi-lo+1 {
		return nil, fmt.Errorf("%w: %d headers for %d..%d", ErrBadResponse, len(res.Metas), lo, hi)
	}
	// The node lists the highest block first.
	out := make([][]byte, len(res.Metas))
	for i, m := range res.Metas {
		h, err := decodeHeader(m.Header, hi-uint64(i))
		if err != nil {
			return nil, err
		}
		b, err := encodeHeader(h)
		if err != nil {
			return nil, err
		}
		out[len(out)-1-i] = b
	}
	return out, nil
}

// Tx reads a transaction by the SHA-256 of its bytes. A failed code is
// returned as a fact; whether it matters is the checker's call.
func (s *Source) Tx(ctx context.Context, hash [32]byte, prove bool) (railverify.RawTx, error) {
	q := url.Values{"hash": {"0x" + hex.EncodeToString(hash[:])}}
	if prove {
		q.Set("prove", "true")
	}
	r, rerr, err := s.call(ctx, "/tx", q)
	if err != nil {
		if errors.Is(err, ErrUnavailable) {
			return railverify.RawTx{}, fmt.Errorf("%w: %w", railverify.ErrTxSourceUnavailable, err)
		}
		return railverify.RawTx{}, err
	}
	if rerr != nil {
		if strings.Contains(strings.ToLower(rerr.text()), "not found") {
			return railverify.RawTx{}, fmt.Errorf("%w: %s", railverify.ErrTxNotFound, rerr.text())
		}
		return railverify.RawTx{}, fmt.Errorf("%w: %s", railverify.ErrTxSourceUnavailable, rerr.text())
	}
	var res struct {
		Height   *string `json:"height"`
		TxResult *struct {
			Code *json.Number `json:"code"`
		} `json:"tx_result"`
		Tx    *string         `json:"tx"`
		Proof json.RawMessage `json:"proof"`
	}
	if err := json.Unmarshal(r, &res); err != nil || res.Height == nil || res.TxResult == nil || res.TxResult.Code == nil || res.Tx == nil {
		return railverify.RawTx{}, fmt.Errorf("%w: transaction fields", ErrBadResponse)
	}
	h, err := parseHeight(*res.Height)
	if err != nil {
		return railverify.RawTx{}, err
	}
	code, err := strconv.ParseUint(res.TxResult.Code.String(), 10, 32)
	if err != nil {
		return railverify.RawTx{}, fmt.Errorf("%w: code", ErrBadResponse)
	}
	b, err := base64.StdEncoding.DecodeString(*res.Tx)
	if err != nil || len(b) == 0 {
		return railverify.RawTx{}, fmt.Errorf("%w: tx", ErrBadResponse)
	}
	out := railverify.RawTx{Bytes: b, Height: h, Code: uint32(code)}
	if prove && len(res.Proof) > 0 && string(res.Proof) != "null" {
		out.Proof = res.Proof
	}
	return out, nil
}
