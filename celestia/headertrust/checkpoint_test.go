package headertrust_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/celestia/headertrust"
	"github.com/vgonkivs/edicta/verifier"
)

// Every header trust names its checkpoint height, so the verifier can hold
// a pending reference to its anchor deadline.
func TestTrustNamesItsCheckpointHeight(t *testing.T) {
	tr := headertrust.New(headertrust.Checkpoint{Height: 77, Hash: make([]byte, 32)}, nil, nil)
	cp, ok := tr.(verifier.Checkpointer)
	require.True(t, ok)
	h, err := cp.CheckpointHeight(context.Background())
	require.NoError(t, err)
	assert.Equal(t, uint64(77), h)
}
