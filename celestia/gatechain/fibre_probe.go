package gatechain

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/vgonkivs/edicta/celestia/fibrecert"
	"github.com/vgonkivs/edicta/celestia/node"
	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/fibre/fibrecommit"
	"github.com/vgonkivs/edicta/gate"
)

// ErrProbeInconclusive means the capability probe could not decide: no usable
// blob, a timeout or a transport error. A bridge that answered wrongly is
// node.ErrBridgeIncompatible instead.
var ErrProbeInconclusive = errors.New("gatechain: bridge probe inconclusive")

// Defaults of the probe window and margin.
const (
	DefaultProbeWindow = 600
	DefaultProbeMargin = 600 * time.Second
)

// RawDownloader is fibre.Download on a bridge with the raw result returned.
type RawDownloader interface {
	DownloadRaw(ctx context.Context, id [33]byte, maxSize uint64) ([]byte, error)
}

// BridgeProbe checks that a bridge serves fibre.Download in the shape this
// build expects, by downloading one recent blob and recomputing its
// commitment. The version of the bridge is never consulted: integrity comes
// from the recompute of every later answer, and the probe only finds an
// incompatible bridge at start instead of when the fallback is needed.
type BridgeProbe struct {
	// Anchors finds and verifies the probe blob's anchor (header, DAH,
	// namespace data, result code, certificate).
	Anchors *FibreAnchors
	Raw     RawDownloader
	// Committer is the gate's da = 1 committer.
	Committer *fibrecommit.Committer
	// LatestHeight is the head of the consensus endpoint.
	LatestHeight func(ctx context.Context) (uint64, error)
	// RetentionS is the latest x/fibre shard retention.
	RetentionS func(ctx context.Context) (uint64, error)
	Now        func() time.Time
	// Window is how many blocks below the head the probe blob may be; zero is
	// DefaultProbeWindow. Offset keeps it away from the head, which
	// consensus nodes may not hold yet; zero is node.DefaultCanaryOffset.
	Window, Offset uint64
	// Margin is how long the probe blob must stay retained; zero is
	// DefaultProbeMargin.
	Margin time.Duration
}

// ProbeResult names the blob the probe passed with.
type ProbeResult struct {
	Height uint64
	BlobID [33]byte
}

// Run runs the probe. A nil error means the fallback may be enabled.
func (p BridgeProbe) Run(ctx context.Context) (ProbeResult, error) {
	if p.Anchors == nil || p.Raw == nil || p.Committer == nil || p.LatestHeight == nil || p.RetentionS == nil || p.Now == nil {
		return ProbeResult{}, fmt.Errorf("%w: %w: incomplete probe", ErrProbeInconclusive, ErrInvalidConfig)
	}
	window, offset, margin := p.Window, p.Offset, p.Margin
	if window == 0 {
		window = DefaultProbeWindow
	}
	if offset == 0 {
		offset = node.DefaultCanaryOffset
	}
	if margin == 0 {
		margin = DefaultProbeMargin
	}
	inconclusive := func(format string, a ...any) error {
		return fmt.Errorf("%w: %s", ErrProbeInconclusive, fmt.Sprintf(format, a...))
	}
	head, err := p.LatestHeight(ctx)
	if err != nil {
		return ProbeResult{}, inconclusive("latest height: %v", err)
	}
	if head <= offset {
		return ProbeResult{}, inconclusive("head %d is not above the offset %d", head, offset)
	}
	retS, err := p.RetentionS(ctx)
	if err != nil {
		return ProbeResult{}, inconclusive("retention: %v", err)
	}
	// A blob above the committer's cap cannot pass its check, which says
	// nothing about the bridge.
	maxUpload, err := fibrecommit.UploadSize(p.Committer.MaxDataSize())
	if err != nil {
		return ProbeResult{}, inconclusive("committer cap: %v", err)
	}
	lowest := uint64(1)
	if head > window {
		lowest = head - window
	}

	fa, ref, err := p.findBlob(ctx, head-offset, lowest, retS, margin, uint64(maxUpload))
	if err != nil {
		return ProbeResult{}, err
	}
	size := uint64(fa.Promise.BlobSize)
	id := fibrecommit.BlobID([32]byte(ref.Commitment))
	raw, err := p.Raw.DownloadRaw(ctx, id, size)
	if err != nil {
		if errors.Is(err, node.ErrBridgeIncompatible) {
			return ProbeResult{}, err
		}
		return ProbeResult{}, inconclusive("fibre.Download: %v", err)
	}
	data, err := node.ParseDownloadResult(raw)
	if err != nil {
		return ProbeResult{}, fmt.Errorf("%w: %w", node.ErrBridgeIncompatible, err)
	}
	if up, err := fibrecommit.UploadSize(uint64(len(data))); err != nil || uint64(up) != size {
		return ProbeResult{}, fmt.Errorf("%w: blob of %d bytes does not match the promised upload size %d",
			node.ErrBridgeIncompatible, len(data), size)
	}
	if err := p.Committer.Check(ref, data); err != nil {
		return ProbeResult{}, fmt.Errorf("%w: commitment of the downloaded blob: %w", node.ErrBridgeIncompatible, err)
	}
	return ProbeResult{Height: fa.Height, BlobID: id}, nil
}

// findBlob returns the newest anchored blob at a height in [lowest, from]
// that stays retained for margin.
func (p BridgeProbe) findBlob(ctx context.Context, from, lowest, retS uint64, margin time.Duration, maxUpload uint64) (FibreAnchor, commitment.PayloadRef, error) {
	a := p.Anchors
	for h := from; h >= lowest; h-- {
		if err := ctx.Err(); err != nil {
			return FibreAnchor{}, commitment.PayloadRef{}, fmt.Errorf("%w: %w", ErrProbeInconclusive, err)
		}
		vb, err := a.verifyNamespace(ctx, h)
		if err != nil {
			return FibreAnchor{}, commitment.PayloadRef{}, fmt.Errorf("%w: %w", ErrProbeInconclusive, err)
		}
		var cands []fibrecert.PFF
		for _, raw := range vb.txs {
			pff, ok, err := fibrecert.ParsePFF(raw)
			if !ok || err != nil {
				continue
			}
			if fibrecert.CheckBinding(pff.Promise, bindingFor(a.chainID, pff.Promise.Namespace, pff.Promise.Commitment, pff)) != nil {
				continue
			}
			cands = append(cands, pff)
		}
		sort.SliceStable(cands, func(i, j int) bool {
			return cands[i].Promise.CreationTime.After(cands[j].Promise.CreationTime)
		})
		for _, c := range cands {
			ref := commitment.PayloadRef{DA: commitment.DAFibre, Height: h,
				Namespace: c.Promise.Namespace, Commitment: c.Promise.Commitment[:]}
			fa, err := a.findIn(ctx, ref, vb)
			if errors.Is(err, gate.ErrAnchorNotFound) {
				continue
			}
			if err != nil {
				return FibreAnchor{}, commitment.PayloadRef{}, fmt.Errorf("%w: %w", ErrProbeInconclusive, err)
			}
			if uint64(fa.Promise.BlobSize) > maxUpload {
				continue
			}
			if !p.Now().Add(margin).Before(fa.Promise.CreationTime.Add(time.Duration(retS) * time.Second)) {
				continue
			}
			return fa, ref, nil
		}
	}
	return FibreAnchor{}, commitment.PayloadRef{}, fmt.Errorf("%w: no retained anchored blob in heights %d..%d", ErrProbeInconclusive, lowest, from)
}
