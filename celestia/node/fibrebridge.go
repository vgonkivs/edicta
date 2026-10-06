package node

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/filecoin-project/go-jsonrpc"

	appfibre "github.com/celestiaorg/celestia-app/v10/fibre"
	"github.com/celestiaorg/celestia-app/v10/pkg/da"
	fibreapi "github.com/celestiaorg/celestia-node/nodebuilder/fibre"
	headerapi "github.com/celestiaorg/celestia-node/nodebuilder/header"
	shareapi "github.com/celestiaorg/celestia-node/nodebuilder/share"
	"github.com/celestiaorg/celestia-node/share/shwap"
	libshare "github.com/celestiaorg/go-square/v4/share"

	"github.com/vgonkivs/edicta/celestia/heightcheck"
)

const (
	// DefaultBridgeNamespaceDataBytes is the namespace data limit when
	// BridgeLimits sets none.
	DefaultBridgeNamespaceDataBytes = 16 << 20
	// headerAnswerBytes bounds a bridge header answer: it holds the DAH, whose
	// roots are at most 2 * 1024 * 90 bytes, and the commit.
	headerAnswerBytes = 8 << 20
	// wireOverhead covers the JSON envelope around a bridge payload.
	wireOverhead = 1 << 20
)

// BridgeLimits bound what one bridge answer may cost in memory.
type BridgeLimits struct {
	// NamespaceDataBytes is the largest encoded namespace data a read may
	// carry; zero takes DefaultBridgeNamespaceDataBytes. The wire form is
	// larger (JSON, base64), and the transport allows for it.
	NamespaceDataBytes uint64
}

// FibreBridge reads the Fibre anchor evidence and blobs from a bridge node
// through JSON-RPC clients whose response bodies are capped, because the
// default client decodes an answer of any size.
type FibreBridge struct {
	header  headerapi.API
	share   shareapi.API
	fibre   fibreapi.API
	closers []jsonrpc.ClientCloser
	nsWire  uint64
	limits  BridgeLimits
}

var _ FibreBridgeReader = (*FibreBridge)(nil)

// NewFibreBridge connects to the bridge node b. Close the result.
func NewFibreBridge(ctx context.Context, b BridgeConfig, lim BridgeLimits) (*FibreBridge, error) {
	if err := b.ValidateBasic(); err != nil {
		return nil, err
	}
	addr, err := BridgeURL(b.Addr, b.TLS)
	if err != nil {
		return nil, err
	}
	if lim.NamespaceDataBytes == 0 {
		lim.NamespaceDataBytes = DefaultBridgeNamespaceDataBytes
	}
	hdr := http.Header{}
	if b.Token != "" {
		hdr.Set("Authorization", "Bearer "+b.Token)
	}
	fb := &FibreBridge{nsWire: wireSize(lim.NamespaceDataBytes), limits: lim}
	hc := &http.Client{Transport: cappedTransport{rt: http.DefaultTransport, limit: headerAnswerBytes}}
	for _, c := range []struct {
		ns  string
		out any
	}{{"header", &fb.header.Internal}, {"share", &fb.share.Internal}, {"fibre", &fb.fibre.Internal}} {
		closer, err := jsonrpc.NewMergeClient(ctx, addr, c.ns, []any{c.out}, hdr, jsonrpc.WithHTTPClient(hc))
		if err != nil {
			fb.Close()
			return nil, wrapCtx(ctx, fmt.Errorf("bridge %s client: %w", c.ns, err))
		}
		fb.closers = append(fb.closers, closer)
	}
	return fb, nil
}

// Limits returns the limits in force, defaults applied.
func (b *FibreBridge) Limits() BridgeLimits { return b.limits }

// Close releases the clients.
func (b *FibreBridge) Close() {
	for _, c := range b.closers {
		c()
	}
	b.closers = nil
}

// wireSize is the body size that a payload of n bytes can take in a JSON
// answer: base64 grows it by a third.
func wireSize(n uint64) uint64 { return n/3*4 + 4 + wireOverhead }

// DAH is the data availability header of the bridge's header at height.
func (b *FibreBridge) DAH(ctx context.Context, height uint64) (*da.DataAvailabilityHeader, error) {
	h, err := b.header.GetByHeight(ctx, height)
	if err != nil {
		return nil, wrapCtx(ctx, err)
	}
	if h == nil {
		return nil, fmt.Errorf("%w: bridge returned no header at height %d", ErrUnavailable, height)
	}
	if err := heightcheck.HeaderHeight(uint64(h.Height()), height); err != nil {
		return nil, heightIgnored(err)
	}
	if h.DAH == nil {
		return nil, fmt.Errorf("%w: bridge header at height %d has no DAH", ErrUnavailable, height)
	}
	return h.DAH, nil
}

// NamespaceData is share.GetNamespaceData(height, namespace).
func (b *FibreBridge) NamespaceData(ctx context.Context, height uint64, ns libshare.Namespace) (shwap.NamespaceData, error) {
	nd, err := b.share.GetNamespaceData(withBodyLimit(ctx, b.nsWire), height, ns)
	if err != nil {
		return nil, wrapCtx(ctx, err)
	}
	return nd, nil
}

// Downloader is the Fibre download of the bridge node, for the fallback.
func (b *FibreBridge) Downloader() FibreDownloader { return bridgeDownloader{b: b} }

type bridgeDownloader struct{ b *FibreBridge }

// Download asks the bridge, which has no height option and uses the head
// validator set. The answer is read up to what maxSize bytes need on the wire.
func (d bridgeDownloader) Download(ctx context.Context, id [33]byte, _ uint64, maxSize uint64) ([]byte, error) {
	r, err := d.b.fibre.Download(withBodyLimit(ctx, wireSize(maxSize)), appfibre.BlobID(id[:]))
	if err != nil {
		return nil, wrapCtx(ctx, err)
	}
	if r == nil {
		return nil, fmt.Errorf("%w: empty bridge download", ErrUnavailable)
	}
	if uint64(len(r.Data)) > maxSize {
		return nil, fmt.Errorf("%w: %w: bridge blob of %d bytes, limit %d", ErrUnavailable, ErrTooLarge, len(r.Data), maxSize)
	}
	return r.Data, nil
}

var errBodyLimit = errors.New("bridge answer above the size limit")

type bodyLimitKey struct{}

// withBodyLimit sets the response body limit of the calls made with ctx.
func withBodyLimit(ctx context.Context, n uint64) context.Context {
	return context.WithValue(ctx, bodyLimitKey{}, n)
}

// cappedTransport fails a response whose body is longer than the limit, which
// is the context's or, without one, the default.
type cappedTransport struct {
	rt    http.RoundTripper
	limit uint64
}

func (t cappedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.rt.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	limit := t.limit
	if v, ok := req.Context().Value(bodyLimitKey{}).(uint64); ok {
		limit = v
	}
	if limit > 1<<62 {
		limit = 1 << 62
	}
	if resp.ContentLength > int64(limit) {
		_ = resp.Body.Close()
		return nil, errBodyLimit
	}
	resp.Body = &limitedBody{rc: resp.Body, left: int64(limit)}
	return resp, nil
}

type limitedBody struct {
	rc   io.ReadCloser
	left int64
}

func (b *limitedBody) Read(p []byte) (int, error) {
	if b.left < 0 {
		return 0, errBodyLimit
	}
	if int64(len(p)) > b.left+1 {
		p = p[:b.left+1]
	}
	n, err := b.rc.Read(p)
	b.left -= int64(n)
	if b.left < 0 {
		return 0, errBodyLimit
	}
	return n, err
}

func (b *limitedBody) Close() error { return b.rc.Close() }
