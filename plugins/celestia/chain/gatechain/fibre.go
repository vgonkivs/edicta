package gatechain

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/vgonkivs/edicta/engine/commitment"
	"github.com/vgonkivs/edicta/engine/gate"
	"github.com/vgonkivs/edicta/plugins/celestia/fibrecommit"
	"github.com/vgonkivs/edicta/plugins/celestia/node"
)

type fibreBlobs struct {
	a      *FibreAnchors
	direct node.FibreDownloader
	bridge node.FibreDownloader
	c      *fibrecommit.Committer
}

// NewFibreBlobs serves da = 1 blobs: the anchor must exist, then the blob is
// downloaded directly and, if that fails, from the bridge fallback (nil means
// direct only). Nothing is returned unless its size is the one the promise
// paid for and the committer accepts the bytes.
func NewFibreBlobs(a *FibreAnchors, direct, bridge node.FibreDownloader, c *fibrecommit.Committer) gate.BlobSource {
	return &fibreBlobs{a: a, direct: direct, bridge: bridge, c: c}
}

func (s *fibreBlobs) Fetch(ctx context.Context, ref commitment.PayloadRef, maxSize uint64) ([]byte, error) {
	if ref.DA != commitment.DAFibre {
		return nil, fmt.Errorf("%w: da %d", gate.ErrBlobNotFound, ref.DA)
	}
	if s.a == nil || s.direct == nil || s.c == nil {
		return nil, unavailable(fmt.Errorf("%w: incomplete blob source", ErrInvalidConfig))
	}
	fa, err := s.a.Lookup(ctx, ref)
	if err != nil {
		return nil, err
	}
	// maxSize+1 bytes are enough to tell the caller the blob is too big. A
	// blob whose paid upload size exceeds that of maxSize+1 bytes cannot fit.
	limit := uint64(fibrecommit.MaxDataSize)
	if maxSize < limit {
		limit = maxSize + 1
	}
	maxUpload, err := fibrecommit.UploadSize(limit)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", gate.ErrBlobNotFound, err)
	}
	if uint64(fa.Promise.BlobSize) > maxUpload {
		return nil, fmt.Errorf("%w: promised upload size %d needs more than %d bytes", gate.ErrPayloadAboveCap, fa.Promise.BlobSize, limit)
	}

	id := fibrecommit.BlobID([32]byte(ref.Commitment))
	var errs []error
	var oversize []byte
	transport := false
	for _, src := range []struct {
		d      node.FibreDownloader
		direct bool
	}{{s.direct, true}, {s.bridge, false}} {
		if src.d == nil {
			continue
		}
		if err := ctx.Err(); err != nil {
			return nil, unavailable(err)
		}
		// The promise names the upload size, which bounds any honest blob.
		data, err := src.d.Download(ctx, id, fa.Promise.Height, uint64(fa.Promise.BlobSize))
		if err != nil {
			transport = transport || !errors.Is(err, node.ErrNotFound)
			errs = append(errs, err)
			continue
		}
		up, err := fibrecommit.UploadSize(uint64(len(data)))
		if err != nil || up != uint64(fa.Promise.BlobSize) {
			errs = append(errs, fmt.Errorf("blob of %d bytes does not match the promised upload size %d", len(data), fa.Promise.BlobSize))
			continue
		}
		if uint64(len(data)) > maxSize {
			// Only the direct client is bound to the commitment, so only its
			// answer settles that the blob is too big. Encoding it for the
			// committer would only spend memory.
			if !src.direct {
				transport = true
				errs = append(errs, fmt.Errorf("bridge blob of %d bytes is above %d and cannot be verified", len(data), maxSize))
				continue
			}
			if oversize == nil {
				oversize = append([]byte(nil), data[:maxSize+1]...)
			}
			continue
		}
		if err := s.c.Check(ref, data); err != nil {
			errs = append(errs, err)
			continue
		}
		return append([]byte(nil), data...), nil
	}
	if oversize != nil {
		return oversize, nil
	}
	if transport {
		return nil, fmt.Errorf("gatechain: blob download: %w", errors.Join(errs...))
	}
	return nil, fmt.Errorf("%w: %w", gate.ErrBlobNotFound, errors.Join(errs...))
}

func blockUnix(t time.Time) uint64 {
	if s := t.Unix(); s > 0 {
		return uint64(s)
	}
	return 0
}
