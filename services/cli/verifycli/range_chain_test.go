package verifycli

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/celestia/cometrpc"
	"github.com/vgonkivs/edicta/celestia/test/cometfake"
)

func blockchainHits(s *cometfake.Server) int {
	n := 0
	for _, h := range s.Hits() {
		if strings.HasPrefix(h, "/blockchain") {
			n++
		}
	}
	return n
}

// The walk goes down from the checkpoint, so a batch ends at the height
// asked for: a walk of n headers costs n / 20 range calls.
func TestRangeChainBatchesEndAtTheAskedHeight(t *testing.T) {
	const lo, hi = uint64(100), uint64(200)
	c := cometfake.BuildChain(chainID, lo, hi)
	srv := cometfake.New(t, c, hi, nodeID(1))
	src, err := cometrpc.New(srv.URL, nil)
	require.NoError(t, err)
	rc := &rangeChain{src: src, top: hi - 1}

	for h := hi - 1; h >= 150; h-- {
		b, err := rc.Header(t.Context(), h)
		require.NoError(t, err, "height %d", h)
		require.Equal(t, c.Raw(t, h), b, "height %d", h)
	}
	assert.Equal(t, 3, blockchainHits(srv), "199..180, 179..160, 159..140")

	t.Run("served bytes are copies", func(t *testing.T) {
		b, err := rc.Header(t.Context(), 150)
		require.NoError(t, err)
		b[0] ^= 0xff
		again, err := rc.Header(t.Context(), 150)
		require.NoError(t, err)
		assert.Equal(t, c.Raw(t, 150), again)
	})
	t.Run("near the lowest height a range starting at h answers", func(t *testing.T) {
		rc := &rangeChain{src: src, top: hi - 1}
		b, err := rc.Header(t.Context(), lo+5)
		require.NoError(t, err)
		assert.Equal(t, c.Raw(t, lo+5), b)
		b, err = rc.Header(t.Context(), lo+6)
		require.NoError(t, err)
		assert.Equal(t, c.Raw(t, lo+6), b)
	})
	t.Run("height zero", func(t *testing.T) {
		rc := &rangeChain{src: src, top: hi - 1}
		_, err := rc.Header(t.Context(), 0)
		require.Error(t, err)
	})
}
