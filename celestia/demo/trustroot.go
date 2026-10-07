package demo

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// TrustRoot yields the hash of the header at a height from a channel that is
// independent of every data RPC.
type TrustRoot interface {
	Name() string
	// Link is a page a human can check; empty when there is none.
	Link(height uint64) string
	HeaderHash(ctx context.Context, height uint64) ([]byte, error)
}

const maxTrustRootBody = 1 << 20

var errNotYet = errors.New("demo: the trust-root source has no such block yet")

type celenium struct {
	api, page, name string
	hc              *http.Client
}

// NewCeleniumTrustRoot reads block hashes from an explorer API. Both
// templates carry "{height}".
func NewCeleniumTrustRoot(apiTemplate, pageTemplate, name string, hc *http.Client) (TrustRoot, error) {
	if !strings.Contains(apiTemplate, "{height}") || !strings.Contains(pageTemplate, "{height}") || name == "" {
		return nil, fmt.Errorf("%w: trust-root templates need {height} and a name", ErrConfig)
	}
	if hc == nil {
		hc = &http.Client{Timeout: 15 * time.Second}
	}
	return &celenium{api: apiTemplate, page: pageTemplate, name: name, hc: hc}, nil
}

func (c *celenium) Name() string { return c.name }

func (c *celenium) Link(h uint64) string {
	return strings.ReplaceAll(c.page, "{height}", fmt.Sprint(h))
}

func (c *celenium) HeaderHash(ctx context.Context, height uint64) ([]byte, error) {
	u := strings.ReplaceAll(c.api, "{height}", fmt.Sprint(height))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("demo: %s: %w", c.name, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, errNotYet
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("demo: %s answered status %d", c.name, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxTrustRootBody))
	if err != nil {
		return nil, fmt.Errorf("demo: %s: %w", c.name, err)
	}
	var v struct {
		Height *uint64 `json:"height"`
		Hash   string  `json:"hash"`
	}
	if err := json.Unmarshal(body, &v); err != nil {
		return nil, fmt.Errorf("demo: %s: answer is not the expected JSON", c.name)
	}
	if v.Height == nil || *v.Height != height {
		return nil, fmt.Errorf("demo: %s answered for another height than %d", c.name, height)
	}
	h, err := hex.DecodeString(v.Hash)
	if err != nil || len(h) != 32 {
		return nil, fmt.Errorf("demo: %s: hash is not 32 bytes of hex", c.name)
	}
	return h, nil
}

const (
	trustRootRetryFor = 60 * time.Second
	headWaitFor       = 90 * time.Second
)

// trustRoot finds the trusted header for a verify that needs headers up to
// needed. It never asks a data RPC for a hash: the source is --trusted-header,
// the trust-root service, or a line the operator types.
func (r *Runner) trustRoot(ctx context.Context, txHeight uint64) (TrustRootInfo, error) {
	needed := txHeight + 1
	if r.cfg.TrustedHeader != "" {
		h, hash, _ := ParseTrustedHeader(r.cfg.TrustedHeader)
		if h >= needed {
			return r.showRoot(TrustRootInfo{Height: h, Hash: hash, Source: "--trusted-header"}), nil
		}
		r.deps.Screen.Warn(fmt.Sprintf("%v: %d < %d", ErrTrustedHeaderTooLow, h, needed))
		return r.manualRoot(ctx, needed)
	}
	t := txHeight + r.preset.Verify.TrustRootLag
	if err := r.waitHead(ctx, t); err != nil {
		return TrustRootInfo{}, err
	}
	deadline := r.deps.now().Add(trustRootRetryFor)
	var last error
	for {
		hash, err := r.deps.TrustRoot.HeaderHash(ctx, t)
		if err == nil {
			return r.showRoot(TrustRootInfo{Height: t, Hash: hash, Source: r.deps.TrustRoot.Name(), Link: r.deps.TrustRoot.Link(t)}), nil
		}
		if ctx.Err() != nil {
			return TrustRootInfo{}, ctx.Err()
		}
		last = err
		if !r.deps.now().Before(deadline) {
			break
		}
		if err := r.deps.sleep(ctx, 3*time.Second); err != nil {
			return TrustRootInfo{}, err
		}
	}
	r.deps.Screen.Warn(fmt.Sprintf("%s did not give header %d: %v", r.deps.TrustRoot.Name(), t, last))
	return r.manualRoot(ctx, needed)
}

func (r *Runner) waitHead(ctx context.Context, t uint64) error {
	deadline := r.deps.now().Add(headWaitFor)
	for {
		h, _, err := r.deps.Chain.Head(ctx)
		if err == nil && h >= t {
			return nil
		}
		if !r.deps.now().Before(deadline) {
			return coded(ExitInconclusive, fmt.Errorf("demo: the funding node did not reach height %d", t))
		}
		if err := r.deps.sleep(ctx, 2*time.Second); err != nil {
			return err
		}
	}
}

func (r *Runner) manualRoot(ctx context.Context, needed uint64) (TrustRootInfo, error) {
	link := r.deps.TrustRoot.Link(needed)
	r.deps.Screen.Info(fmt.Sprintf("Look up a block at height %d or above from a source you trust: %s", needed, link))
	for {
		line, err := r.deps.Console.ReadLine(ctx, fmt.Sprintf("Enter a trusted header as HEIGHT:HASH (HEIGHT >= %d) from a source you trust, or q:", needed))
		if err != nil {
			return TrustRootInfo{}, err
		}
		line = strings.TrimSpace(line)
		if line == "q" || line == "Q" {
			return TrustRootInfo{}, coded(ExitInconclusive, ErrTrustRootUnavailable)
		}
		h, hash, perr := ParseTrustedHeader(line)
		switch {
		case perr != nil:
			r.deps.Screen.Warn(perr.Error())
		case h < needed:
			r.deps.Screen.Warn(fmt.Sprintf("%v: %d < %d", ErrTrustedHeaderTooLow, h, needed))
		default:
			return r.showRoot(TrustRootInfo{Height: h, Hash: hash, Source: "manual input", Link: r.deps.TrustRoot.Link(h)}), nil
		}
	}
}

func (r *Runner) showRoot(t TrustRootInfo) TrustRootInfo {
	r.deps.Screen.TrustRoot(t)
	return t
}
