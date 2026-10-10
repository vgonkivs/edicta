package gatechain_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/celestia/gatechain"
	"github.com/vgonkivs/edicta/celestia/node"
)

// paramsByHeight answers a different x/fibre height window at every height
// and remembers the heights asked.
type paramsByHeight struct {
	*intentChain
	asked []uint64
}

func (p *paramsByHeight) FibreParamsAt(_ context.Context, h uint64) (node.FibreParams, error) {
	p.asked = append(p.asked, h)
	return node.FibreParams{RetentionS: 14400, PromiseHeightWindow: h % 997, PromiseTimeoutS: 3600}, nil
}

// For a pending reference the gate bounds the anchor window by the x/fibre
// height window in force at the head it reads, not at h0: inclusion cannot
// vouch for a window the chain has not applied yet.
func TestFibreIntentWindowIsReadAtTheHead(t *testing.T) {
	c := &paramsByHeight{intentChain: newIntentChain(t)}
	v, err := gatechain.NewFibreIntents(c, mochaID)
	require.NoError(t, err)
	ref, rec := liveIntent(c.l)
	f, err := v.VerifyIntent(t.Context(), ref, rec, uint64(len(c.l.payload)))
	require.NoError(t, err)
	require.NotEqual(t, c.head, ref.Height)
	assert.Equal(t, []uint64{c.head}, c.asked)
	assert.Equal(t, c.head%997, f.ChainWindow)
}
