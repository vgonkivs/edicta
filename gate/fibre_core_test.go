package gate_test

import (
	"bytes"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/gate"
	"github.com/vgonkivs/edicta/gate/dacommit/blobv1"
	"github.com/vgonkivs/edicta/gate/registry"
	"github.com/vgonkivs/edicta/test/gatefix"
)

// fibreCommitter stands in for the da = 1 committer, which lives in a module
// the root cannot import. It accepts exactly the blob it is bound to.
type fibreCommitter struct {
	want  []byte
	calls atomic.Int64
}

func (f *fibreCommitter) Check(_ commitment.PayloadRef, blob []byte) error {
	f.calls.Add(1)
	if bytes.Equal(blob, f.want) {
		return nil
	}
	return gate.ErrDACommitmentMismatch
}

func withFibreCommitter(f *fibreCommitter) gatefix.Option {
	return gatefix.WithDeps(func(d *gate.Deps) {
		d.Committers = map[commitment.DA]gate.DACommitter{
			commitment.DAFibre:        f,
			commitment.DACelestiaBlob: blobv1.New(),
		}
	})
}

func withCap(n uint64) gatefix.Option {
	return gatefix.WithConfig(func(c *gate.Config) { c.FibreMaxDataBytes = n })
}

func fibreHappy(t *testing.T, opts ...gatefix.Option) (*gatefix.Env, *commitment.Commitment, []byte) {
	t.Helper()
	e := gatefix.New(t, opts...)
	c := gatefix.FibreTemplate(t)
	e.StageDA(c, gatefix.FibreBlob())
	b, _ := gatefix.Sign(t, "agent1", c)
	return e, c, b
}

func TestFibreCommitterOnDAPath(t *testing.T) {
	t.Run("matching bytes authorize on the DA path", func(t *testing.T) {
		fc := &fibreCommitter{want: gatefix.FibreBlob()}
		e, _, b := fibreHappy(t, withFibreCommitter(fc))
		res, err := e.Authorize(b)
		require.NoError(t, err)
		assert.Equal(t, registry.PathDA, res.Path)
		assert.EqualValues(t, 1, fc.calls.Load())
	})
	t.Run("bytes that pass the hash but not the commitment never authorize", func(t *testing.T) {
		other := gatefix.FibreBlob()
		other[0] ^= 1
		fc := &fibreCommitter{want: other}
		e, c, b := fibreHappy(t, withFibreCommitter(fc))
		res, err := e.Authorize(b)
		e.RequireRejected(c, err, gate.ErrDACommitmentMismatch)
		assert.Empty(t, res.Authorization)
		assert.EqualValues(t, 1, fc.calls.Load(), "the committer ran on the DA path")
	})
	t.Run("a bridge-substituted blob is caught even when the archive holds the right one", func(t *testing.T) {
		good := gatefix.FibreBlob()
		fc := &fibreCommitter{want: good}
		e := gatefix.New(t, withFibreCommitter(fc))
		c := gatefix.FibreTemplate(t)
		e.StageChain(c, gatefix.BlockTime(c), gatefix.BlockTime(c))
		bad := append([]byte(nil), good...)
		bad[3] ^= 1
		e.DA.Put(c.PayloadRef, bad)
		e.Archive.Put(c.PayloadRef, good)
		b, _ := gatefix.Sign(t, "agent1", c)
		res, err := e.Authorize(b)
		require.NoError(t, err)
		assert.Equal(t, registry.PathArchive, res.Path, "falls back to the archive, never accepts the substituted bytes")
	})
	t.Run("no da = 1 committer keeps the delegated behaviour", func(t *testing.T) {
		e, _, b := fibreHappy(t)
		res, err := e.Authorize(b)
		require.NoError(t, err)
		assert.Equal(t, registry.PathDA, res.Path)
	})
}

func TestFibrePayloadCap(t *testing.T) {
	oversized := func(t *testing.T, size uint64) (*commitment.Commitment, []byte) {
		c := gatefix.FibreTemplate(t)
		c.PayloadSize = size
		b, _ := gatefix.Sign(t, "agent1", c)
		return c, b
	}
	t.Run("above the cap: refused before any fetch, nonce untouched", func(t *testing.T) {
		fc := &fibreCommitter{want: gatefix.FibreBlob()}
		e := gatefix.New(t, withFibreCommitter(fc), withCap(1024))
		c, b := oversized(t, 1025)
		e.StageDA(c, gatefix.FibreBlob())
		e.Archive.Put(c.PayloadRef, gatefix.FibreBlob())
		res, err := e.Authorize(b)
		e.RequireRejected(c, err, gate.ErrPayloadAboveCap)
		assert.Empty(t, res.Authorization)
		assert.EqualValues(t, 0, e.DA.Fetches())
		assert.EqualValues(t, 0, e.Archive.Fetches())
		assert.EqualValues(t, 0, fc.calls.Load())
	})
	t.Run("exactly the cap is accepted", func(t *testing.T) {
		fc := &fibreCommitter{want: gatefix.FibreBlob()}
		e, _, b := fibreHappy(t, withFibreCommitter(fc), withCap(1024))
		_, err := e.Authorize(b)
		require.NoError(t, err)
	})
	t.Run("default cap is 16 MiB", func(t *testing.T) {
		fc := &fibreCommitter{want: gatefix.FibreBlob()}
		e := gatefix.New(t, withFibreCommitter(fc))
		c, b := oversized(t, 16<<20+1)
		e.StageDA(c, gatefix.FibreBlob())
		_, err := e.Authorize(b)
		e.RequireRejected(c, err, gate.ErrPayloadAboveCap)
		assert.EqualValues(t, 0, e.DA.Fetches()+e.Archive.Fetches())

		c, b = oversized(t, 16<<20)
		c.Nonce[0] ^= 0x55
		b, _ = gatefix.Sign(t, "agent1", c)
		e.StageChain(c, gatefix.BlockTime(c), gatefix.BlockTime(c))
		_, err = e.Authorize(b)
		require.NotErrorIs(t, err, gate.ErrPayloadAboveCap)
	})
	t.Run("an unsigned oversized envelope is not an oracle", func(t *testing.T) {
		e := gatefix.New(t, withFibreCommitter(&fibreCommitter{want: gatefix.FibreBlob()}), withCap(1024))
		c := gatefix.FibreTemplate(t)
		c.PayloadSize = 1025
		b, _ := gatefix.SignWith(t, gatefix.Key(t, "agent2"), c)
		_, err := e.Authorize(b)
		require.ErrorIs(t, err, commitment.ErrSignatureInvalid)
		assert.NotErrorIs(t, err, gate.ErrPayloadAboveCap)
	})
	t.Run("without a da = 1 committer the cap rule does not apply", func(t *testing.T) {
		e := gatefix.New(t, withCap(1024))
		c := gatefix.FibreTemplate(t)
		c.PayloadSize = 1025
		b, _ := gatefix.Sign(t, "agent1", c)
		e.StageDA(c, gatefix.FibreBlob())
		_, err := e.Authorize(b)
		require.Error(t, err)
		assert.NotErrorIs(t, err, gate.ErrPayloadAboveCap)
		assert.EqualValues(t, 1, e.DA.Fetches(), "the old path still fetches")
	})
	t.Run("da = 2 is not subject to the Fibre cap", func(t *testing.T) {
		e := gatefix.New(t, withFibreCommitter(&fibreCommitter{want: gatefix.FibreBlob()}), withCap(1))
		c := gatefix.Template(t)
		e.StageDA(c, gatefix.Blob(t))
		b, _ := gatefix.Sign(t, "agent1", c)
		_, err := e.Authorize(b)
		require.NoError(t, err)
	})
}

// The da = 1 recompute holds the blob and its encoding in memory, so a
// da = 1 check is charged about 13 times its payload size.
func TestFibreFetchBudgetIsWeighted(t *testing.T) {
	const budget = 20000 // two plain payloads fit, two weighted ones do not
	run := func(t *testing.T, fibre bool) (maxStarted int) {
		fc := &fibreCommitter{want: gatefix.FibreBlob()}
		opts := []gatefix.Option{withFibreCommitter(fc), gatefix.WithConfig(func(c *gate.Config) { c.MaxFetchBytes = budget })}
		e := gatefix.New(t, opts...)
		hold := make(chan struct{})
		var first sync.Once
		e.DA.OnFetch(func() { first.Do(func() { <-hold }) })
		envs := make([][]byte, 2)
		for i := range envs {
			var c *commitment.Commitment
			if fibre {
				c = gatefix.Fresh(gatefix.FibreTemplate(t), byte(i+1))
				e.StageDA(c, gatefix.FibreBlob())
			} else {
				c = gatefix.Fresh(gatefix.Template(t), byte(i+1))
				e.StageDA(c, gatefix.Blob(t))
			}
			envs[i], _ = gatefix.Sign(t, "agent1", c)
		}
		var wg sync.WaitGroup
		for _, b := range envs {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, err := e.Authorize(b)
				assert.NoError(t, err)
			}()
		}
		require.Eventually(t, func() bool { return e.DA.Fetches() >= 1 }, 10*time.Second, time.Millisecond)
		if fibre {
			require.Never(t, func() bool { return e.DA.Fetches() > 1 }, 200*time.Millisecond, 5*time.Millisecond,
				"a second da = 1 fetch started inside the weighted budget")
		} else {
			require.Eventually(t, func() bool { return e.DA.Fetches() >= 2 }, 10*time.Second, time.Millisecond,
				"two small da = 2 fetches fit the budget together")
		}
		close(hold)
		wg.Wait()
		return e.DA.Fetches()
	}
	t.Run("da = 1 checks queue", func(t *testing.T) { assert.Equal(t, 2, run(t, true)) })
	t.Run("da = 2 checks run together", func(t *testing.T) { assert.Equal(t, 2, run(t, false)) })
}

func TestFibreRetentionReadOnlyForDA1(t *testing.T) {
	t.Run("da = 2 with default allowed set never reads it", func(t *testing.T) {
		var cp *countingParams
		e := gatefix.New(t, gatefix.WithDeps(func(d *gate.Deps) {
			cp = &countingParams{inner: d.Params, err: errNoFibre}
			d.Params = cp
		}))
		c := gatefix.Template(t)
		e.StageDA(c, gatefix.Blob(t))
		b, _ := gatefix.Sign(t, "agent1", c)
		res, err := e.Authorize(b)
		require.NoError(t, err)
		assert.NotEmpty(t, res.Authorization)
		assert.EqualValues(t, 0, cp.calls.Load())
	})
	t.Run("da = 1 reads the latest value at height 0", func(t *testing.T) {
		e, c, b := fibreHappy(t)
		e.Chain.FailLatest(errNoFibre)
		_, err := e.Authorize(b)
		e.RequireRejected(c, err, gate.ErrChainUnavailable)
		require.ErrorIs(t, err, errNoFibre)
	})
	t.Run("da = 1 with a zero latest value is invalid params", func(t *testing.T) {
		e, c, b := fibreHappy(t)
		e.Chain.SetLatest(0)
		_, err := e.Authorize(b)
		e.RequireRejected(c, err, commitment.ErrInvalidParams)
	})
}

func TestResultCarriesK2Inputs(t *testing.T) {
	t.Run("da = 1", func(t *testing.T) {
		e := gatefix.New(t)
		c := gatefix.FibreTemplate(t)
		blockTime := gatefix.BlockTime(c)
		start := blockTime - 5
		e.StageChain(c, blockTime, start)
		e.DA.Put(c.PayloadRef, gatefix.FibreBlob())
		e.Chain.SetLatest(14400)
		e.Chain.SetAt(c.PayloadRef.Height, 14300)
		b, _ := gatefix.Sign(t, "agent1", c)
		res, err := e.Authorize(b)
		require.NoError(t, err)
		assert.Equal(t, gate.K2Inputs{
			Now:                gatefix.Now,
			BlockTime:          blockTime,
			RetentionStart:     start,
			RetentionLatestS:   14400,
			RetentionAtHeightS: 14300,
		}, res.K2)
	})
	t.Run("da = 2 has check and block time", func(t *testing.T) {
		e := gatefix.New(t)
		c := gatefix.Template(t)
		e.StageDA(c, gatefix.Blob(t))
		b, _ := gatefix.Sign(t, "agent1", c)
		res, err := e.Authorize(b)
		require.NoError(t, err)
		assert.EqualValues(t, gatefix.Now, res.K2.Now)
		assert.Equal(t, gatefix.BlockTime(c), res.K2.BlockTime)
	})
}

// happyFibre is happy for a da = 1 commitment, the only kind that reads the
// Fibre retention.
func happyFibre(t *testing.T, opts ...gatefix.Option) (*gatefix.Env, *commitment.Commitment, []byte, commitment.Hash) {
	t.Helper()
	e := gatefix.New(t, opts...)
	c := gatefix.FibreTemplate(t)
	e.StageDA(c, gatefix.FibreBlob())
	b, h := gatefix.Sign(t, "agent1", c)
	return e, c, b, h
}
