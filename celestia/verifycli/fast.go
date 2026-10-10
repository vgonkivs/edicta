package verifycli

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"sync"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/celestia/absence"
	"github.com/vgonkivs/edicta/celestia/cometrpc"
	"github.com/vgonkivs/edicta/celestia/headertrust"
	"github.com/vgonkivs/edicta/celestia/node"
	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/verifier"
)

// signedHeaders is the part of the bridge reader that serves the protobuf
// SignedHeader the archive stores.
type signedHeaders interface {
	SignedHeader(ctx context.Context, height uint64) ([]byte, error)
}

// bridgeProofs serves absence proofs from one bridge node: the signed
// header from its header API, the DAH and the namespace data through the
// size-capped Fibre bridge client.
type bridgeProofs struct {
	*node.FibreBridge
	headers signedHeaders
}

func (b bridgeProofs) SignedHeader(ctx context.Context, height uint64) ([]byte, error) {
	return b.headers.SignedHeader(ctx, height)
}

// newProofSource connects to the bridge at rawURL. It is a variable so that
// tests can serve proofs without a network.
var newProofSource = func(ctx context.Context, rawURL string) (absence.ProofSource, string, func(), error) {
	u, err := url.Parse(rawURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, "", nil, fmt.Errorf("--absence-source %q is not an http or https URL", rawURL)
	}
	cfg := node.BridgeConfig{Addr: rawURL, TLS: u.Scheme == "https"}
	fb, err := node.NewFibreBridge(ctx, cfg, node.BridgeLimits{NamespaceDataBytes: absence.MaxHeightBytes})
	if err != nil {
		return nil, "", nil, fmt.Errorf("--absence-source: %w", err)
	}
	rc, r, err := node.NewReadOnly(ctx, cfg)
	if err != nil {
		fb.Close()
		return nil, "", nil, fmt.Errorf("--absence-source: %w", err)
	}
	sh, ok := r.(signedHeaders)
	if !ok {
		fb.Close()
		_ = rc.Close()
		return nil, "", nil, errors.New("--absence-source: the bridge reader serves no signed headers")
	}
	closer := func() {
		fb.Close()
		_ = rc.Close()
	}
	return bridgeProofs{FibreBridge: fb, headers: sh}, u.Hostname(), closer, nil
}

// absenceFetcher builds the online fetcher of --absence-source, with the
// block results of --headers-rpc. It returns nil without the flag.
func absenceFetcher(ctx context.Context, f flags) (*absence.Fetcher, func(), error) {
	if f.absenceSource == "" {
		return nil, func() {}, nil
	}
	proofs, name, closer, err := newProofSource(ctx, f.absenceSource)
	if err != nil {
		return nil, nil, err
	}
	// A proof source that also serves block results is the fallback when no
	// --headers-rpc is given.
	results, _ := proofs.(absence.ResultsSource)
	if f.headersRPC != "" {
		src, err := cometrpc.New(f.headersRPC, nil)
		if err != nil {
			closer()
			return nil, nil, err
		}
		results = src
	}
	fetch, err := absence.NewFetcher(proofs, results, name)
	if err != nil {
		closer()
		return nil, nil, err
	}
	return fetch, closer, nil
}

// pendingChain is the verifier's view of pending references. It remembers
// the reference it was asked about, so that the headers of the archived
// proofs can serve the header walk.
type pendingChain struct {
	*absence.Chain
	window *windowHeaders
}

func (p pendingChain) Header(ctx context.Context, ref commitment.PayloadRef, h uint64) (verifier.ChainHeader, error) {
	p.window.set(ref)
	return p.Chain.Header(ctx, ref, h)
}

func (p pendingChain) Absence(ctx context.Context, ref commitment.PayloadRef, d uint64, c verifier.Confirm) (verifier.AbsenceWindow, error) {
	p.window.set(ref)
	return p.Chain.Absence(ctx, ref, d, c)
}

func newPendingChain(r verifier.Reader, headers absence.HeaderSource, fetch *absence.Fetcher, window *windowHeaders) verifier.PendingChain {
	d := absence.ChainDeps{Headers: headers, Fetch: fetch}
	if ar, ok := r.(archive.AbsenceReader); ok {
		d.Records = ar
	}
	if ir, ok := r.(archive.IntentReader); ok {
		d.Intents = ir
	}
	return pendingChain{Chain: absence.NewChain(d), window: window}
}

// windowHeaders serves the headers held by the archived absence proofs of
// the reference under check: the header at each height and the next header
// of a results proof. They are as untrusted as any other header: the walk
// checks every link.
type windowHeaders struct {
	r archive.AbsenceReader
	// fetch, when set, serves the headers the archive lacks.
	fetch *absence.Fetcher
	mu    sync.Mutex
	ref   *commitment.PayloadRef
}

func (w *windowHeaders) set(ref commitment.PayloadRef) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.ref = &ref
}

func (w *windowHeaders) Header(ctx context.Context, h uint64) ([]byte, error) {
	w.mu.Lock()
	ref := w.ref
	w.mu.Unlock()
	if w.r != nil && ref != nil {
		if rec, err := w.r.Absence(ctx, ref.DA, ref.Commitment, h); err == nil {
			return headertrust.HeaderOfSigned(rec.Header)
		}
		if h > 1 {
			if rec, err := w.r.Absence(ctx, ref.DA, ref.Commitment, h-1); err == nil && rec.NextHeader != nil {
				return headertrust.HeaderOfSigned(rec.NextHeader)
			}
		}
	}
	if w.fetch != nil {
		raw, err := w.fetch.SignedHeader(ctx, h)
		if err != nil {
			return nil, err
		}
		return headertrust.HeaderOfSigned(raw)
	}
	return nil, fmt.Errorf("no absence proof holds the header at %d", h)
}

// firstOf asks each chain in turn.
type firstOf []headertrust.HeaderChain

// Name is the operator of the first chain, which a header that does not link
// is blamed on.
func (c firstOf) Name() string {
	if len(c) > 0 {
		if n, ok := c[0].(interface{ Name() string }); ok {
			return n.Name()
		}
	}
	return ""
}

func (c firstOf) Header(ctx context.Context, h uint64) ([]byte, error) {
	var errs []error
	for _, x := range c {
		b, err := x.Header(ctx, h)
		if err == nil {
			return b, nil
		}
		if cerr := ctx.Err(); cerr != nil {
			return nil, cerr
		}
		errs = append(errs, err)
	}
	return nil, errors.Join(errs...)
}

// fileTrust is the header trust of a trusted header file, which knows its
// checkpoint height.
type fileTrust struct {
	verifier.HeaderTrust
	height uint64
}

func (t fileTrust) CheckpointHeight(context.Context) (uint64, error) { return t.height, nil }

// CheckpointHeight resolves the checkpoint as the first question would.
func (l *lazyTrust) CheckpointHeight(ctx context.Context) (uint64, error) {
	if !l.done {
		l.init(ctx)
	}
	if l.err != nil {
		return 0, l.err
	}
	return l.cpHeight, nil
}
