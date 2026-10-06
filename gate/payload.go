package gate

import (
	"context"
	"errors"
	"fmt"
	"math"
	"math/bits"

	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/gate/registry"
)

const fibreWeightFactor = 13

// acquirePayload fetches and verifies the payload. The DA path is tried first when the retention
// window holds; the archive path follows, or comes alone when the window
// failed. The nonce is never touched here.
func (g *Gate) acquirePayload(ctx context.Context, c *commitment.Commitment, within bool) (registry.Path, error) {
	var errs []error
	if within {
		err := g.tryPath(ctx, c, registry.PathDA)
		if err == nil {
			return registry.PathDA, nil
		}
		if cerr := ctx.Err(); cerr != nil {
			return 0, fmt.Errorf("gate: %w", cerr)
		}
		errs = append(errs, err)
	}
	err := g.tryPath(ctx, c, registry.PathArchive)
	if err == nil {
		return registry.PathArchive, nil
	}
	if cerr := ctx.Err(); cerr != nil {
		return 0, fmt.Errorf("gate: %w", cerr)
	}
	errs = append(errs, err)
	return 0, pickPayloadError(within, errs)
}

// tryPath fetches the blob from one source and runs the size, hash and DA-commitment checks.
func (g *Gate) tryPath(ctx context.Context, c *commitment.Commitment, path registry.Path) error {
	ref := c.PayloadRef
	src, timeout := g.d.DA, g.cfg.DATimeout
	if path == registry.PathArchive {
		src, timeout = g.d.Archive, g.cfg.ArchiveTimeout
	}
	// The archive is trusted for availability only, so the DA-commitment check is mandatory there.
	// On the DA path da = 2 always needs it; da = 1 has it only when a committer is configured,
	// otherwise the operator's node verifies the commitment.
	committer := g.d.Committers[ref.DA]
	if committer == nil && (path == registry.PathArchive || ref.DA == commitment.DACelestiaBlob) {
		return fmt.Errorf("%w: da %d", ErrArchiveRecomputeUnsupported, ref.DA)
	}

	weight := c.PayloadSize
	if ref.DA == commitment.DAFibre && committer != nil {
		// The recompute holds the blob and its encoding in memory.
		hi, lo := bits.Mul64(c.PayloadSize, fibreWeightFactor)
		weight = lo
		if hi != 0 {
			weight = math.MaxUint64
		}
	}
	held, err := g.sem.acquire(ctx, weight)
	if err != nil {
		return err
	}
	defer g.sem.release(held)

	pctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	blob, err := src.Fetch(pctx, ref, c.PayloadSize)
	if err != nil {
		// A fault of the source says nothing about the payload: it keeps its
		// chain and is not the availability verdict. On the archive path
		// only an absent blob is a verdict; a timeout or any other failure
		// is operational.
		switch {
		case errors.Is(err, ErrArchiveUnavailable):
			return fmt.Errorf("fetch: %w", err)
		case path == registry.PathArchive && !errors.Is(err, ErrBlobNotFound):
			return fmt.Errorf("%w: fetch: %w", ErrArchiveUnavailable, err)
		}
		return fmt.Errorf("%w: fetch: %v", ErrPayloadUnavailable, err)
	}
	if err := commitment.CheckPayload(c, blob); err != nil {
		return err
	}
	if committer != nil {
		if err := committer.Check(ref, blob); err != nil {
			if errors.Is(err, ErrDACommitmentMismatch) {
				return err
			}
			return fmt.Errorf("%w: %v", ErrDACommitmentMismatch, err)
		}
	}
	return nil
}

// pickPayloadError reports the failure with the highest precedence: size,
// hash, DA commitment, unsupported, archive fault, too old, unavailable. The other causes
// stay in the message only, so a lower-precedence sentinel never matches.
func pickPayloadError(within bool, errs []error) error {
	rank := func(err error) int {
		switch {
		case errors.Is(err, commitment.ErrPayloadSizeMismatch):
			return 1
		case errors.Is(err, commitment.ErrPayloadHashMismatch):
			return 2
		case errors.Is(err, ErrDACommitmentMismatch):
			return 3
		case errors.Is(err, ErrArchiveRecomputeUnsupported):
			return 4
		case errors.Is(err, ErrArchiveUnavailable):
			return 5
		}
		return 6
	}
	best, bestRank := errs[0], rank(errs[0])
	for _, e := range errs[1:] {
		if r := rank(e); r < bestRank {
			best, bestRank = e, r
		}
	}
	if bestRank > 5 && !within {
		return fmt.Errorf("%w: %v", ErrAnchorTooOld, best)
	}
	if len(errs) == 1 {
		return best
	}
	other := errs[0]
	if best == errs[0] {
		other = errs[1]
	}
	return fmt.Errorf("%w (other path: %v)", best, other)
}
