package recorder_test

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/celestia/node"
	"github.com/vgonkivs/edicta/celestia/recorder"
)

// headSwitch is a reader whose head is at height 0 while zero is set, as a
// node that has not synced its first block reports it.
type headSwitch struct {
	*evReader
	zero atomic.Bool
}

func (z *headSwitch) Head(ctx context.Context) (node.Header, error) {
	if z.zero.Load() {
		return node.Header{}, nil
	}
	return z.evReader.Head(ctx)
}

// A head at height 0 lists no intent; it must not count as a finished
// recovery, or the next intent takes the sequence of a live archived one.
func TestFastBlobHeadZeroDoesNotFinishTheRecovery(t *testing.T) {
	f := newBlobFast(t)
	first := f.rec()
	_, err := first.Publish(bg, f.blob)
	require.NoError(t, err)
	require.NoError(t, first.Close(bg))

	rd := &headSwitch{evReader: f.rd}
	rd.zero.Store(true)
	r := f.recRd(rd, 20)
	_, err = r.Publish(bg, []byte("blob B"))
	require.ErrorIs(t, err, recorder.ErrNodeUnavailable)

	rd.zero.Store(false)
	_, err = r.Publish(bg, []byte("blob B"))
	require.NoError(t, err)
	sent := f.node.sends()
	assert.EqualValues(t, 4, txSequence(t, innerTx(sent[len(sent)-1])), "B is signed above the archived intent at 3")
}
