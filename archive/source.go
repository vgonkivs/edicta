package archive

import (
	"context"
	"errors"
	"fmt"

	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/gate"
)

type gateSource struct{ r Store }

// NewGateSource serves the gate's archive path from the payload records of r.
// It ignores the namespace and signer of the reference: the gate's recompute
// with the reference fails on any difference.
func NewGateSource(r Store) gate.BlobSource {
	return gateSource{r}
}

func (s gateSource) Fetch(ctx context.Context, ref commitment.PayloadRef, maxSize uint64) ([]byte, error) {
	p, err := s.r.Payload(ctx, ref.DA, ref.Commitment)
	if errors.Is(err, ErrNotFound) {
		return nil, fmt.Errorf("%w: %w", gate.ErrBlobNotFound, err)
	}
	if err != nil {
		return nil, err
	}
	if maxSize < uint64(len(p.Blob)) {
		return p.Blob[:maxSize+1], nil
	}
	return p.Blob, nil
}
