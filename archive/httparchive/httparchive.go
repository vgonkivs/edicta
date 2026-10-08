// Package httparchive serves archive records read-only over HTTP and reads
// them back. The wire protocol is a GET of the record's canonical key path
// under a base URL, so any static file server over an fsarchive tree also
// works. The archive is trusted for availability only: the client decodes
// strictly and checks the key, and the verifier does the rest.
package httparchive

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/commitment"
)

var (
	// ErrFault marks an answer that is neither a record nor an absence: a
	// transport error, a redirect, an unexpected status or a cut body.
	ErrFault = errors.New("httparchive: archive fault")
	// ErrTooLarge marks a body longer than the cap of the kind asked for.
	ErrTooLarge = errors.New("httparchive: record is larger than its cap")
)

// Record caps by kind, checked before any parsing.
const (
	maxEvidence        = 1 << 25
	maxDecision        = 69632
	maxAuthorization   = 512
	maxRejection       = 256
	maxPolicyRecord    = 16384 + 64
	maxPolicyClosed    = 36864 + 64
	maxPolicySuccessor = 256
)

// defaultTimeout bounds a read when the caller gives no client of its own.
const defaultTimeout = 5 * time.Minute

// RawSource gives the stored bytes of a record by canonical key path.
// archive.ErrNotFound means the record is absent.
type RawSource interface {
	Raw(ctx context.Context, key string) (io.ReadCloser, error)
}

// NewHandler serves the records of src. It answers GET and HEAD for
// canonical key paths only and 404 for everything else.
func NewHandler(src RawSource) http.Handler { return handler{src: src} }

type handler struct{ src RawSource }

func (h handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	absent := func() {
		// An absent Authorization or marker can appear later.
		w.Header().Set("Cache-Control", "no-store")
		http.Error(w, "not found", http.StatusNotFound)
	}
	// RawPath is set only when the request used an escaping other than the
	// default, which no canonical key needs.
	key, ok := strings.CutPrefix(r.URL.Path, "/")
	if !ok || r.URL.RawPath != "" {
		absent()
		return
	}
	if _, err := archive.ParseKey(key); err != nil {
		absent()
		return
	}
	rc, err := h.src.Raw(r.Context(), key)
	if errors.Is(err, archive.ErrNotFound) {
		absent()
		return
	}
	if err != nil {
		http.Error(w, "archive fault", http.StatusInternalServerError)
		return
	}
	defer rc.Close()
	w.Header().Set("Content-Type", "application/cbor")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodGet {
		_, _ = io.Copy(w, rc)
	}
}

// Client reads records from a base URL. It implements the verifier's reader
// and archive.PayloadStreamer.
type Client struct {
	base string
	hc   *http.Client
}

// NewClient checks the base URL and copies hc, so a caller's client keeps its
// redirect policy. Redirects are never followed.
func NewClient(base string, hc *http.Client) (*Client, error) {
	u, err := url.Parse(base)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil ||
		u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.ContainsAny(base, "?#") {
		return nil, fmt.Errorf("httparchive: bad base url %q", base)
	}
	c := http.Client{Timeout: defaultTimeout}
	if hc != nil {
		c = *hc
	}
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &Client{base: strings.TrimRight(base, "/"), hc: &c}, nil
}

func capOf(k archive.Kind) int64 {
	switch k {
	case archive.KindPayload:
		return archive.MaxRecordSize
	case archive.KindEvidence:
		return maxEvidence
	case archive.KindDecision:
		return maxDecision
	case archive.KindAuthorization:
		return maxAuthorization
	case archive.KindMandate, archive.KindPolicyAllow, archive.KindPolicyDeny, archive.KindPolicyBucket:
		return maxPolicyRecord
	case archive.KindPolicyClosed:
		return maxPolicyClosed
	case archive.KindPolicySuccessor:
		return maxPolicySuccessor
	}
	return maxRejection
}

func (c *Client) get(ctx context.Context, key string) (io.ReadCloser, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+"/"+key, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrFault, err)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		if cerr := ctx.Err(); cerr != nil {
			return nil, cerr
		}
		return nil, fmt.Errorf("%w: %w", ErrFault, err)
	}
	switch resp.StatusCode {
	case http.StatusOK:
		return resp.Body, nil
	case http.StatusNotFound, http.StatusGone:
		resp.Body.Close()
		return nil, fmt.Errorf("%w: %s", archive.ErrNotFound, key)
	}
	resp.Body.Close()
	return nil, fmt.Errorf("%w: %s answered %d", ErrFault, key, resp.StatusCode)
}

func (c *Client) read(ctx context.Context, key string) ([]byte, error) {
	kind, err := archive.ParseKey(key)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", archive.ErrNotFound, err)
	}
	body, err := c.get(ctx, key)
	if err != nil {
		return nil, err
	}
	defer body.Close()
	limit := capOf(kind)
	b, err := io.ReadAll(io.LimitReader(body, limit+1))
	if err != nil {
		if cerr := ctx.Err(); cerr != nil {
			return nil, cerr
		}
		return nil, fmt.Errorf("%w: reading %s: %w", ErrFault, key, err)
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("%w: %s: %w", archive.ErrCorrupt, key, ErrTooLarge)
	}
	return b, nil
}

func (c *Client) record(ctx context.Context, key string) (archive.Record, error) {
	b, err := c.read(ctx, key)
	if err != nil {
		return nil, err
	}
	rec, err := archive.Decode(b)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", key, err)
	}
	if got, err := archive.KeyPath(rec); err != nil || got != key {
		return nil, fmt.Errorf("%w: %s carries key %q", archive.ErrCorrupt, key, got)
	}
	return rec, nil
}

func corruptType(key string) error {
	return fmt.Errorf("%w: %s holds a record of another kind", archive.ErrCorrupt, key)
}

func (c *Client) Payload(ctx context.Context, da commitment.DA, commit []byte) (*archive.PayloadRecord, error) {
	key, err := archive.DataPath(archive.KindPayload, da, commit)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", archive.ErrNotFound, err)
	}
	rec, err := c.record(ctx, key)
	if err != nil {
		return nil, err
	}
	p, ok := rec.(*archive.PayloadRecord)
	if !ok {
		return nil, corruptType(key)
	}
	return p, nil
}

// PayloadReader returns the capped encoded payload record. The caller
// validates it.
func (c *Client) PayloadReader(ctx context.Context, da commitment.DA, commit []byte) (io.ReadCloser, error) {
	key, err := archive.DataPath(archive.KindPayload, da, commit)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", archive.ErrNotFound, err)
	}
	b, err := c.read(ctx, key)
	if err != nil {
		return nil, err
	}
	return io.NopCloser(bytes.NewReader(b)), nil
}

func (c *Client) Evidence(ctx context.Context, da commitment.DA, commit []byte) (*archive.EvidenceRecord, error) {
	key, err := archive.DataPath(archive.KindEvidence, da, commit)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", archive.ErrNotFound, err)
	}
	rec, err := c.record(ctx, key)
	if err != nil {
		return nil, err
	}
	e, ok := rec.(*archive.EvidenceRecord)
	if !ok {
		return nil, corruptType(key)
	}
	return e, nil
}

func (c *Client) Decision(ctx context.Context, h commitment.Hash) (*archive.DecisionRecord, error) {
	key := archive.HashPath(archive.KindDecision, h)
	rec, err := c.record(ctx, key)
	if err != nil {
		return nil, err
	}
	d, ok := rec.(*archive.DecisionRecord)
	if !ok {
		return nil, corruptType(key)
	}
	return d, nil
}

func (c *Client) Authorization(ctx context.Context, h commitment.Hash) (*archive.AuthorizationRecord, error) {
	key := archive.HashPath(archive.KindAuthorization, h)
	rec, err := c.record(ctx, key)
	if err != nil {
		return nil, err
	}
	a, ok := rec.(*archive.AuthorizationRecord)
	if !ok {
		return nil, corruptType(key)
	}
	return a, nil
}

// State derives the record state from reads only. A fault on any read it
// needs is an error, never a state.
func (c *Client) State(ctx context.Context, h commitment.Hash) (archive.DecisionState, error) {
	if _, err := c.Decision(ctx, h); err != nil {
		if errors.Is(err, archive.ErrNotFound) {
			return archive.DecisionState{State: archive.StateAbsent}, nil
		}
		return archive.DecisionState{}, err
	}
	if _, err := c.Authorization(ctx, h); err == nil {
		return archive.DecisionState{State: archive.StateAuthorized}, nil
	} else if !errors.Is(err, archive.ErrNotFound) {
		return archive.DecisionState{}, err
	}
	var marks []*archive.RejectionRecord
	for _, name := range archive.Verdicts() {
		key := "rejection/" + hex.EncodeToString(h[:]) + "/" + name
		rec, err := c.record(ctx, key)
		if errors.Is(err, archive.ErrNotFound) {
			continue
		}
		if err != nil {
			return archive.DecisionState{}, err
		}
		m, ok := rec.(*archive.RejectionRecord)
		if !ok {
			return archive.DecisionState{}, corruptType(key)
		}
		marks = append(marks, m)
	}
	if len(marks) == 0 {
		return archive.DecisionState{State: archive.StatePending}, nil
	}
	sort.Slice(marks, func(i, j int) bool {
		if marks[i].RejectedAt != marks[j].RejectedAt {
			return marks[i].RejectedAt < marks[j].RejectedAt
		}
		return marks[i].Error < marks[j].Error
	})
	st := archive.DecisionState{State: archive.StateRejected}
	for _, m := range marks {
		st.Rejections = append(st.Rejections, m.Error)
	}
	return st, nil
}

func readAs[T archive.Record](ctx context.Context, c *Client, key string) (T, error) {
	var zero T
	rec, err := c.record(ctx, key)
	if err != nil {
		return zero, err
	}
	t, ok := rec.(T)
	if !ok {
		return zero, corruptType(key)
	}
	return t, nil
}

var _ archive.PolicyReader = (*Client)(nil)

func (c *Client) Mandate(ctx context.Context, h commitment.Hash) (*archive.MandateRecord, error) {
	return readAs[*archive.MandateRecord](ctx, c, archive.PolicyHashPath(archive.KindMandate, h))
}

func (c *Client) PolicyAllow(ctx context.Context, h commitment.Hash) (*archive.PolicyAllowRecord, error) {
	return readAs[*archive.PolicyAllowRecord](ctx, c, archive.PolicyHashPath(archive.KindPolicyAllow, h))
}

func (c *Client) PolicyDeny(ctx context.Context, h commitment.Hash, reason string) (*archive.PolicyDenyRecord, error) {
	key, err := archive.PolicyDenyPath(h, reason)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", archive.ErrNotFound, err)
	}
	return readAs[*archive.PolicyDenyRecord](ctx, c, key)
}

func (c *Client) PolicyBucket(ctx context.Context, h commitment.Hash) (*archive.PolicyBucketRecord, error) {
	return readAs[*archive.PolicyBucketRecord](ctx, c, archive.PolicyHashPath(archive.KindPolicyBucket, h))
}

func (c *Client) PolicyClosed(ctx context.Context, h commitment.Hash) (*archive.PolicyClosedRecord, error) {
	return readAs[*archive.PolicyClosedRecord](ctx, c, archive.PolicyHashPath(archive.KindPolicyClosed, h))
}

func (c *Client) PolicySuccessor(ctx context.Context, key commitment.Hash) (*archive.PolicySuccessorRecord, error) {
	return readAs[*archive.PolicySuccessorRecord](ctx, c, archive.PolicyHashPath(archive.KindPolicySuccessor, key))
}
