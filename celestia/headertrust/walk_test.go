package headertrust_test

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/celestia/headertrust"
)

// The verified walk is kept between calls: the heights of a window cost one
// walk from the checkpoint, each header read once.
func TestTrustedKeepsTheWalk(t *testing.T) {
	const top = firstHeight + 10
	c := buildChain(firstHeight, top)
	src := c.serve(t, firstHeight, top-1)
	tr := headertrust.New(c.checkpoint(t, top), src, nil)
	ctx := context.Background()

	for _, h := range []uint64{firstHeight + 5, firstHeight + 2, firstHeight + 7, firstHeight + 2, top} {
		res, err := tr.Trusted(ctx, h, c.hash(h))
		require.NoError(t, err, "height %d", h)
		assert.True(t, res.Checked)
	}
	var want []uint64
	for h := top - 1; h >= firstHeight+2; h-- {
		want = append(want, h)
	}
	assert.Equal(t, want, src.reads, "every header read once, from the checkpoint down")

	t.Run("a wrong hash at a walked height is still refused", func(t *testing.T) {
		res, err := tr.Trusted(ctx, firstHeight+5, c.hash(firstHeight+6))
		require.ErrorIs(t, err, headertrust.ErrChainBroken)
		assert.False(t, res.Checked)
	})
}

// A link that fails is not kept: a later call asks for that header again,
// and the verified part above it is not read again.
func TestTrustedRetriesAFailedLink(t *testing.T) {
	const top = firstHeight + 10
	c := buildChain(firstHeight, top)
	ctx := context.Background()

	t.Run("a header that does not link", func(t *testing.T) {
		src := c.serve(t, firstHeight, top-1)
		good := src.byH[firstHeight+4]
		src.byH[firstHeight+4] = encode(t, forged(c, firstHeight+4))
		tr := headertrust.New(c.checkpoint(t, top), src, nil)

		_, err := tr.Trusted(ctx, firstHeight, c.hash(firstHeight))
		require.ErrorIs(t, err, headertrust.ErrChainBroken)
		res, err := tr.Trusted(ctx, firstHeight+6, c.hash(firstHeight+6))
		require.NoError(t, err, "the part above the break stays verified")
		assert.True(t, res.Checked)

		src.byH[firstHeight+4] = good
		src.reads = nil
		res, err = tr.Trusted(ctx, firstHeight, c.hash(firstHeight))
		require.NoError(t, err)
		assert.True(t, res.Checked)
		assert.Equal(t, []uint64{firstHeight + 4, firstHeight + 3, firstHeight + 2, firstHeight + 1, firstHeight}, src.reads)
	})
	t.Run("a source error", func(t *testing.T) {
		src := c.serve(t, firstHeight, top-1)
		tr := headertrust.New(c.checkpoint(t, top), src, nil)
		src.err = errors.New("node unreachable")
		_, err := tr.Trusted(ctx, firstHeight, c.hash(firstHeight))
		require.Error(t, err)
		src.err = nil
		res, err := tr.Trusted(ctx, firstHeight, c.hash(firstHeight))
		require.NoError(t, err)
		assert.True(t, res.Checked)
	})
	t.Run("a cancelled context", func(t *testing.T) {
		src := c.serve(t, firstHeight, top-1)
		tr := headertrust.New(c.checkpoint(t, top), src, nil)
		cctx, cancel := context.WithCancel(ctx)
		cancel()
		_, err := tr.Trusted(cctx, firstHeight, c.hash(firstHeight))
		require.ErrorIs(t, err, context.Canceled)
		res, err := tr.Trusted(ctx, firstHeight, c.hash(firstHeight))
		require.NoError(t, err)
		assert.True(t, res.Checked)
	})
}

// lockedChain serves a fakeChain to concurrent callers.
type lockedChain struct {
	mu sync.Mutex
	f  *fakeChain
}

func (l *lockedChain) Header(ctx context.Context, h uint64) ([]byte, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.f.Header(ctx, h)
}

// The kept walk is shared by concurrent calls; run with -race.
func TestTrustedConcurrentCalls(t *testing.T) {
	const top = firstHeight + 30
	c := buildChain(firstHeight, top)
	src := &lockedChain{f: c.serve(t, firstHeight, top-1)}
	tr := headertrust.New(c.checkpoint(t, top), src, nil)

	var wg sync.WaitGroup
	errs := make(chan error, top-firstHeight+1)
	for h := firstHeight; h <= top; h++ {
		wg.Add(1)
		go func(h uint64) {
			defer wg.Done()
			res, err := tr.Trusted(context.Background(), h, c.hash(h))
			if err == nil && !res.Checked {
				err = errors.New("not checked")
			}
			errs <- err
		}(h)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}
	assert.Len(t, src.f.reads, int(top-firstHeight), "each header read once")
}
