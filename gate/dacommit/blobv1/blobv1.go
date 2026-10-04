// Package blobv1 adapts the shared share-commitment recompute to the gate's
// DACommitter interface (da = 2, share version 1).
package blobv1

import (
	"context"
	"fmt"

	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/dacommit/sharev1"
	"github.com/vgonkivs/edicta/gate"
)

type committer struct{}

// New returns a stateless committer for da = 2. Every other da, and every
// malformed reference or blob, fails with gate.ErrDACommitmentMismatch.
func New() gate.DACommitter { return committer{} }

func (committer) Check(_ context.Context, ref commitment.PayloadRef, blob []byte) error {
	if err := sharev1.Check(ref, blob); err != nil {
		return fmt.Errorf("%w: %w", gate.ErrDACommitmentMismatch, err)
	}
	return nil
}
