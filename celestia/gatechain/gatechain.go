package gatechain

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/vgonkivs/edicta/celestia/heightcheck"
	"github.com/vgonkivs/edicta/celestia/node"
	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/dacommit/sharev1"
	"github.com/vgonkivs/edicta/gate"
	"github.com/vgonkivs/edicta/retention"
)

// NoArchive is an archive that holds nothing.
var NoArchive gate.BlobSource = noArchive{}

type noArchive struct{}

func (noArchive) Fetch(context.Context, commitment.PayloadRef, uint64) ([]byte, error) {
	return nil, gate.ErrBlobNotFound
}

// unavailable wraps every error that is not a clean "not found" so the gate
// never mistakes a transport or context failure for an absent anchor.
func unavailable(err error) error {
	return fmt.Errorf("%w: %w", gate.ErrChainUnavailable, err)
}

type headers struct{ r node.Reader }

// NewHeaders reads block times from r.
func NewHeaders(r node.Reader) gate.HeaderSource { return headers{r: r} }

func (h headers) BlockTime(ctx context.Context, height uint64) (uint64, error) {
	if err := ctx.Err(); err != nil {
		return 0, unavailable(err)
	}
	hd, err := h.r.HeaderAt(ctx, height)
	if errors.Is(err, node.ErrNotFound) {
		return 0, fmt.Errorf("%w: block %d: %w", gate.ErrAnchorNotFound, height, err)
	}
	if err != nil {
		return 0, unavailable(err)
	}
	return uint64(hd.Time.Unix()), nil
}

// lookup returns the blob a da = 2 ref names, or notFound if the node has
// none or it differs from the ref in share version, signer or data.
func lookup(ctx context.Context, r node.Reader, ref commitment.PayloadRef, notFound error) (node.Blob, error) {
	if ref.DA != commitment.DACelestiaBlob {
		return node.Blob{}, fmt.Errorf("%w: da %d", notFound, ref.DA)
	}
	if err := ctx.Err(); err != nil {
		return node.Blob{}, unavailable(err)
	}
	b, err := r.Blob(ctx, ref.Height, ref.Namespace, ref.Commitment)
	if errors.Is(err, node.ErrNotFound) {
		return node.Blob{}, fmt.Errorf("%w: %w", notFound, err)
	}
	if err != nil {
		return node.Blob{}, unavailable(err)
	}
	if b.ShareVersion != 1 || !bytes.Equal(b.Signer, ref.Signer) ||
		!bytes.Equal(b.Namespace, ref.Namespace) || !bytes.Equal(b.Commitment, ref.Commitment) {
		return node.Blob{}, fmt.Errorf("%w: blob differs from the reference", notFound)
	}
	// The node's word is not enough: the data must hash to the commitment.
	if err := sharev1.Check(ref, b.Data); err != nil {
		return node.Blob{}, fmt.Errorf("%w: %w", notFound, err)
	}
	return b, nil
}

type anchors struct{ r node.Reader }

// NewAnchors finds anchors by reading the blob from r.
func NewAnchors(r node.Reader) gate.AnchorSource { return anchors{r: r} }

// FindAnchor needs the header at the ref height, the blob, and a commitment
// proof that verifies against that header's data root. A blob without such a
// proof is never an anchor, and a missing or failing proof is unavailable
// rather than absent: the node may simply not be able to prove it.
func (a anchors) FindAnchor(ctx context.Context, ref commitment.PayloadRef) (gate.Anchor, error) {
	if ref.DA != commitment.DACelestiaBlob {
		return gate.Anchor{}, fmt.Errorf("%w: da %d", gate.ErrAnchorNotFound, ref.DA)
	}
	if err := ctx.Err(); err != nil {
		return gate.Anchor{}, unavailable(err)
	}
	hd, err := a.r.HeaderAt(ctx, ref.Height)
	if errors.Is(err, node.ErrNotFound) {
		return gate.Anchor{}, fmt.Errorf("%w: block %d: %w", gate.ErrAnchorNotFound, ref.Height, err)
	}
	if err != nil {
		return gate.Anchor{}, unavailable(err)
	}
	if hd.Height != ref.Height || len(hd.DataRoot) == 0 {
		return gate.Anchor{}, unavailable(fmt.Errorf("header for height %d has height %d and %d data root bytes",
			ref.Height, hd.Height, len(hd.DataRoot)))
	}
	if _, err := lookup(ctx, a.r, ref, gate.ErrAnchorNotFound); err != nil {
		return gate.Anchor{}, err
	}
	p, err := a.r.CommitmentProof(ctx, ref.Height, ref.Namespace, ref.Commitment)
	if err != nil {
		return gate.Anchor{}, unavailable(fmt.Errorf("commitment proof: %w", err))
	}
	if p == nil {
		return gate.Anchor{}, unavailable(errors.New("commitment proof: none"))
	}
	if err := p.Verify(hd.DataRoot, ref.Commitment); err != nil {
		return gate.Anchor{}, unavailable(fmt.Errorf("commitment proof against data root at height %d: %w", ref.Height, err))
	}
	return gate.Anchor{Height: ref.Height}, nil
}

type blobSource struct{ r node.Reader }

// NewBlobSource serves blob bytes from r.
func NewBlobSource(r node.Reader) gate.BlobSource { return blobSource{r: r} }

func (s blobSource) Fetch(ctx context.Context, ref commitment.PayloadRef, maxSize uint64) ([]byte, error) {
	b, err := lookup(ctx, s.r, ref, gate.ErrBlobNotFound)
	if err != nil {
		return nil, err
	}
	data := b.Data
	if maxSize < uint64(len(data)) {
		data = data[:maxSize+1]
	}
	return bytes.Clone(data), nil
}

type params struct{ c node.Consensus }

// NewParams reads chain parameters from c.
func NewParams(c node.Consensus) gate.ChainParams { return params{c: c} }

func (p params) FibreRetention(ctx context.Context, height uint64) (uint64, error) {
	// The consensus seam has no historical read, and the latest value must not
	// stand in for an old one. The gate fails closed for da = 1; the demo
	// allows only da = 2, which never reads this.
	if height > 0 {
		return 0, fmt.Errorf("%w: retention at height %d", node.ErrUnsupported, height)
	}
	fp, err := p.c.FibreParams(ctx)
	if errors.Is(err, node.ErrNotFound) {
		return 0, fmt.Errorf("gatechain: chain has no x/fibre: %w", err)
	}
	if err != nil {
		return 0, unavailable(err)
	}
	return fp.RetentionS, nil
}

type latestSource struct{ c node.Consensus }

// NewRetentionSources reads x/fibre retention from c: the latest value for
// the observer, and a pinned read paired with the height canary. The sample
// bracket is widened by the retention policy's lag, so lag is not applied
// here.
func NewRetentionSources(c node.Consensus, _ uint64) (retention.LatestSource, retention.AtHeightSource) {
	return latestSource{c: c}, atHeightSource{c: c}
}

func (s latestSource) ChainID(ctx context.Context) (string, error) { return s.c.Network(ctx) }

func (s latestSource) LatestSample(ctx context.Context) (retention.Sample, error) {
	id, err := s.c.Network(ctx)
	if err != nil {
		return retention.Sample{}, fmt.Errorf("gatechain: chain id: %w", err)
	}
	a, err := s.c.LatestHeight(ctx)
	if err != nil {
		return retention.Sample{}, fmt.Errorf("gatechain: head before params: %w", err)
	}
	fp, err := s.c.FibreParams(ctx)
	if err != nil {
		return retention.Sample{}, fmt.Errorf("gatechain: params: %w", err)
	}
	b, err := s.c.LatestHeight(ctx)
	if err != nil {
		return retention.Sample{}, fmt.Errorf("gatechain: head after params: %w", err)
	}
	return retention.Sample{ChainID: id, FromHeight: a, ToHeight: b, RetentionS: fp.RetentionS}, nil
}

type atHeightSource struct{ c node.Consensus }

func (s atHeightSource) RetentionAt(ctx context.Context, height uint64) (uint64, error) {
	fp, err := s.c.FibreParamsAt(ctx, height)
	if err != nil {
		return 0, err
	}
	return fp.RetentionS, nil
}

func (s atHeightSource) HonoursHeight(ctx context.Context) (bool, error) {
	st, err := s.c.HeightCanary(ctx)
	switch st {
	case heightcheck.Honoured:
		return true, nil
	case heightcheck.Ignoring:
		return false, nil
	}
	if err == nil {
		err = errors.New("height canary inconclusive")
	}
	return false, fmt.Errorf("gatechain: %w", err)
}
