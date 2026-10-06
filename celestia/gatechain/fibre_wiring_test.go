package gatechain_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	fibretypes "github.com/celestiaorg/celestia-app/v10/x/fibre/types"

	"github.com/vgonkivs/edicta/celestia/gatechain"
	"github.com/vgonkivs/edicta/celestia/node"
	"github.com/vgonkivs/edicta/celestia/nodefake"
	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/gate"
	"github.com/vgonkivs/edicta/retention"
	"github.com/vgonkivs/edicta/retention/memstore"
	"github.com/vgonkivs/edicta/test/gatefix"
	rfix "github.com/vgonkivs/edicta/test/retentionfix"
)

// anchorCost is what the cache charges for the live anchor: its proof, the
// namespace and signer key of the promise, and a fixed overhead.
func anchorCost(t testing.TB, l live, b block) uint64 {
	t.Helper()
	fa, err := anchorsOver(b.chain(t, l), mochaID).Lookup(bg, l.ref())
	require.NoError(t, err)
	return uint64(len(fa.Proof) + len(fa.Promise.Namespace) + len(fa.Promise.SignerKey) + 256)
}

func TestFibreAnchorCacheIsBoundedByBytes(t *testing.T) {
	l := loadLive(t)
	other := mutateTx(t, l.pff, func(m *fibretypes.MsgPayForFibre) { m.PaymentPromise.Commitment[0] ^= 1 })
	b := buildBlock(t, l.pffHeight, l.pff, other)
	cost := anchorCost(t, l, b)
	refB := l.ref()
	refB.Commitment[0] ^= 1
	lookup := func(t *testing.T, a *gatechain.FibreAnchors) {
		t.Helper()
		_, err := a.Lookup(bg, l.ref())
		require.NoError(t, err)
		_, err = a.Lookup(bg, refB)
		require.NoError(t, err)
	}
	withBytes := func(n uint64) func(*gatechain.FibreAnchorOptions) {
		return func(o *gatechain.FibreAnchorOptions) { o.CacheBytes = n }
	}

	t.Run("room for two entries keeps both", func(t *testing.T) {
		c := b.chain(t, l)
		a := anchorsOver(c, mochaID, skipCert, withBytes(2*cost))
		lookup(t, a)
		lookup(t, a)
		assert.Equal(t, 2, c.HeaderReads())
	})
	t.Run("room for one entry evicts the oldest", func(t *testing.T) {
		c := b.chain(t, l)
		a := anchorsOver(c, mochaID, skipCert, withBytes(cost))
		lookup(t, a)
		lookup(t, a)
		assert.Equal(t, 4, c.HeaderReads(), "each lookup pushes the other out")
		_, err := a.Lookup(bg, refB)
		require.NoError(t, err)
		assert.Equal(t, 4, c.HeaderReads(), "the newest entry is still held")
	})
	t.Run("an entry above the whole budget is not kept", func(t *testing.T) {
		c := b.chain(t, l)
		a := anchorsOver(c, mochaID, skipCert, withBytes(cost-1))
		for range 3 {
			_, err := a.Lookup(bg, l.ref())
			require.NoError(t, err)
		}
		assert.Equal(t, 3, c.HeaderReads())
	})
}

func TestFibreAnchorScopeSharesOneReadPerRequest(t *testing.T) {
	l := loadLive(t)
	b := liveBlock(t)

	t.Run("lookups under one scope read once without any cache", func(t *testing.T) {
		c := b.chain(t, l)
		a := anchorsOver(c, mochaID)
		ctx := gatechain.WithAnchorScope(bg)
		for range 3 {
			got, err := a.Lookup(ctx, l.ref())
			require.NoError(t, err)
			assert.Equal(t, l.pffHeight, got.Height)
		}
		assert.Equal(t, 1, c.HeaderReads())
		dah, ns := c.BridgeReads()
		assert.Equal(t, 1, dah)
		assert.Equal(t, 1, ns)
	})
	t.Run("the gate's anchor and payload stages of one request share it", func(t *testing.T) {
		c := b.chain(t, l)
		a := anchorsOver(c, mochaID)
		dl := &fakeDL{data: l.payload}
		src := gatechain.NewFibreBlobs(a, dl, nil, committer(t))
		ctx := gatechain.WithAnchorScope(bg)
		_, err := a.FindAnchor(ctx, l.ref())
		require.NoError(t, err)
		got, err := src.Fetch(ctx, l.ref(), 1<<20)
		require.NoError(t, err)
		assert.Equal(t, l.payload, got)
		assert.Equal(t, 1, c.HeaderReads())
		_, ns := c.BridgeReads()
		assert.Equal(t, 1, ns)
	})
	t.Run("scopes of two requests do not share", func(t *testing.T) {
		c := b.chain(t, l)
		a := anchorsOver(c, mochaID)
		for range 2 {
			_, err := a.Lookup(gatechain.WithAnchorScope(bg), l.ref())
			require.NoError(t, err)
		}
		assert.Equal(t, 2, c.HeaderReads())
	})
	t.Run("a scope does not leak into a plain context", func(t *testing.T) {
		c := b.chain(t, l)
		a := anchorsOver(c, mochaID)
		_, err := a.Lookup(gatechain.WithAnchorScope(bg), l.ref())
		require.NoError(t, err)
		_, err = a.Lookup(bg, l.ref())
		require.NoError(t, err)
		assert.Equal(t, 2, c.HeaderReads())
	})
	t.Run("a failure is not kept in the scope", func(t *testing.T) {
		c := b.chain(t, l)
		a := anchorsOver(c, mochaID)
		ctx := gatechain.WithAnchorScope(bg)
		c.FailBridge = nodefake.ErrInjected
		_, err := a.Lookup(ctx, l.ref())
		requireUnavailable(t, err)
		c.FailBridge = nil
		_, err = a.Lookup(ctx, l.ref())
		require.NoError(t, err)
	})
	t.Run("a missing anchor is not kept either", func(t *testing.T) {
		c := b.chain(t, l)
		a := anchorsOver(c, mochaID)
		ctx := gatechain.WithAnchorScope(bg)
		ref := l.ref()
		ref.Commitment[0] ^= 1
		for range 2 {
			_, err := a.Lookup(ctx, ref)
			requireNotFound(t, err)
		}
		assert.Equal(t, 2, c.HeaderReads())
	})
	t.Run("two references under one scope are two reads", func(t *testing.T) {
		other := mutateTx(t, l.pff, func(m *fibretypes.MsgPayForFibre) { m.PaymentPromise.Commitment[0] ^= 1 })
		c := buildBlock(t, l.pffHeight, l.pff, other).chain(t, l)
		a := anchorsOver(c, mochaID, skipCert)
		ctx := gatechain.WithAnchorScope(bg)
		refB := l.ref()
		refB.Commitment[0] ^= 1
		for _, r := range []commitment.PayloadRef{l.ref(), refB, l.ref(), refB} {
			_, err := a.Lookup(ctx, r)
			require.NoError(t, err)
		}
		assert.Equal(t, 2, c.HeaderReads())
	})
	t.Run("a caller cannot change what the scope holds", func(t *testing.T) {
		a := anchorsOver(b.chain(t, l), mochaID)
		ctx := gatechain.WithAnchorScope(bg)
		first, err := a.Lookup(ctx, l.ref())
		require.NoError(t, err)
		want := append([]byte(nil), first.Proof...)
		first.Proof[10] ^= 0xff
		second, err := a.Lookup(ctx, l.ref())
		require.NoError(t, err)
		assert.Equal(t, want, second.Proof)
	})
	t.Run("concurrent lookups of one request read once", func(t *testing.T) {
		c := b.chain(t, l)
		a := anchorsOver(c, mochaID)
		ctx := gatechain.WithAnchorScope(bg)
		var wg sync.WaitGroup
		for range 8 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, err := a.Lookup(ctx, l.ref())
				assert.NoError(t, err)
			}()
		}
		wg.Wait()
		assert.Equal(t, 1, c.HeaderReads())
	})
}

// stuckReader answers every header read when its context ends.
type stuckReader struct {
	*nodefake.FibreChain
	mu    sync.Mutex
	calls int
}

func (r *stuckReader) Header(ctx context.Context, _ uint64) (node.FibreHeader, error) {
	r.mu.Lock()
	r.calls++
	r.mu.Unlock()
	<-ctx.Done()
	return node.FibreHeader{}, ctx.Err()
}

func TestFibreLookupAppliesItsOwnDeadline(t *testing.T) {
	l := loadLive(t)
	c := liveBlock(t).chain(t, l)

	t.Run("a background context cannot hang a lookup", func(t *testing.T) {
		r := &stuckReader{FibreChain: c}
		a := anchorsOver(r, mochaID, func(o *gatechain.FibreAnchorOptions) { o.LookupTimeout = 20 * time.Millisecond })
		start := time.Now()
		_, err := a.Lookup(context.Background(), l.ref())
		requireUnavailable(t, err)
		assert.Less(t, time.Since(start), 10*time.Second)
	})
	t.Run("a shorter caller deadline wins", func(t *testing.T) {
		r := &stuckReader{FibreChain: c}
		a := anchorsOver(r, mochaID, func(o *gatechain.FibreAnchorOptions) { o.LookupTimeout = time.Hour })
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		defer cancel()
		_, err := a.Lookup(ctx, l.ref())
		requireUnavailable(t, err)
	})
	t.Run("a timed out lookup leaves nothing behind", func(t *testing.T) {
		r := &stuckReader{FibreChain: c}
		a := anchorsOver(r, mochaID, func(o *gatechain.FibreAnchorOptions) {
			o.LookupTimeout = 20 * time.Millisecond
			o.CacheBytes = 1 << 24
		})
		_, err := a.Lookup(gatechain.WithAnchorScope(context.Background()), l.ref())
		requireUnavailable(t, err)
		healthy := anchorsOver(c, mochaID)
		_, err = healthy.Lookup(context.Background(), l.ref())
		require.NoError(t, err)
	})
	t.Run("blob fetch and find anchor pass through the same deadline", func(t *testing.T) {
		r := &stuckReader{FibreChain: c}
		a := anchorsOver(r, mochaID, func(o *gatechain.FibreAnchorOptions) { o.LookupTimeout = 20 * time.Millisecond })
		_, err := a.FindAnchor(context.Background(), l.ref())
		requireUnavailable(t, err)
		_, err = gatechain.NewFibreBlobs(a, &fakeDL{data: l.payload}, nil, committer(t)).Fetch(context.Background(), l.ref(), 1<<20)
		requireUnavailable(t, err)
	})
}

func TestFibreAnchorOptionsBridgeLimits(t *testing.T) {
	o := gatechain.FibreAnchorOptions{MaxReadBytes: 3 << 20}
	assert.Equal(t, node.BridgeLimits{NamespaceDataBytes: 3 << 20}, o.BridgeLimits())
	assert.EqualValues(t, gatechain.DefaultFibreMaxReadBytes, gatechain.FibreAnchorOptions{}.WithDefaults().BridgeLimits().NamespaceDataBytes)
}

func TestFibreHeadersServeThePayForFibreHeaderTime(t *testing.T) {
	const h = uint64(500)
	dataHash := []byte{1, 2, 3}
	at := time.Date(2026, 10, 6, 11, 22, 33, 900_000_000, time.UTC)
	newChain := func() *nodefake.FibreChain {
		c := nodefake.NewFibreChain()
		c.AddHeader(h, dataHash, at)
		return c
	}
	var _ gate.HeaderSource = gatechain.NewFibreHeaders(newChain())

	t.Run("time comes from the consensus header, floored to the second", func(t *testing.T) {
		got, err := gatechain.NewFibreHeaders(newChain()).BlockTime(bg, h)
		require.NoError(t, err)
		assert.EqualValues(t, at.Unix(), got)
	})
	t.Run("a bridge that fails or lies does not matter: it is never read", func(t *testing.T) {
		c := newChain()
		c.FailBridge = nodefake.ErrInjected
		got, err := gatechain.NewFibreHeaders(c).BlockTime(bg, h)
		require.NoError(t, err)
		assert.EqualValues(t, at.Unix(), got)
		dah, ns := c.BridgeReads()
		assert.Zero(t, dah+ns)
	})
	t.Run("the anchor's block time and K1's are the same header", func(t *testing.T) {
		l := loadLive(t)
		c := liveBlock(t).chain(t, l)
		fa, err := anchorsOver(c, mochaID).Lookup(bg, l.ref())
		require.NoError(t, err)
		got, err := gatechain.NewFibreHeaders(c).BlockTime(bg, l.pffHeight)
		require.NoError(t, err)
		assert.Equal(t, fa.BlockTime, got)
	})

	unavailable := map[string]func(c *nodefake.FibreChain){
		"header at another height": func(c *nodefake.FibreChain) { c.AddHeader(h+1, dataHash, at); c.IgnoreHeights(h + 1) },
		"app version 9":            func(c *nodefake.FibreChain) { c.SetAppVersion(h, 9) },
		"app version 11":           func(c *nodefake.FibreChain) { c.SetAppVersion(h, 11) },
		"no time":                  func(c *nodefake.FibreChain) { c.AddHeader(h, dataHash, time.Unix(0, 0)) },
		"before the epoch":         func(c *nodefake.FibreChain) { c.AddHeader(h, dataHash, time.Unix(-5, 0)) },
		"read failure":             func(c *nodefake.FibreChain) { c.Fail = nodefake.ErrInjected },
		"missing header":           func(c *nodefake.FibreChain) { c.IgnoreHeights(h + 7) },
	}
	for name, mod := range unavailable {
		t.Run(name, func(t *testing.T) {
			c := newChain()
			mod(c)
			_, err := gatechain.NewFibreHeaders(c).BlockTime(bg, h)
			requireUnavailable(t, err)
		})
	}
	t.Run("a cancelled context", func(t *testing.T) {
		ctx, cancel := context.WithCancel(bg)
		cancel()
		_, err := gatechain.NewFibreHeaders(newChain()).BlockTime(ctx, h)
		requireUnavailable(t, err)
	})
	t.Run("a nil reader fails closed", func(t *testing.T) {
		_, err := gatechain.NewFibreHeaders(nil).BlockTime(bg, h)
		requireUnavailable(t, err)
	})
}

// observed builds a started observer whose samples cover [from, from+2*step].
func observed(t *testing.T, from, step, retentionS uint64, direct retention.AtHeightSource) *retention.Params {
	t.Helper()
	latest := rfix.Ticking("mocha-5", from, step, func(int) uint64 { return retentionS })
	p, err := retention.NewParams(rfix.Policy, latest, direct, memstore.New(), rfix.NewClock(5000))
	require.NoError(t, err)
	require.NoError(t, p.Start(bg))
	require.NoError(t, p.Observe(bg))
	require.NoError(t, p.Observe(bg))
	return p
}

func TestFibreParamsReportTheRetentionSource(t *testing.T) {
	var _ gate.SourcedChainParams = gatechain.NewFibreParams(nil)

	t.Run("observations only", func(t *testing.T) {
		fp := gatechain.NewFibreParams(observed(t, 100, 10, 3600, nil))
		got, src, err := fp.FibreRetentionSourced(bg, 115)
		require.NoError(t, err)
		assert.EqualValues(t, 3600, got)
		assert.Equal(t, gate.RetentionObserved, src)
		plain, err := fp.FibreRetention(bg, 115)
		require.NoError(t, err)
		assert.Equal(t, got, plain)
	})
	t.Run("both sources", func(t *testing.T) {
		d := &rfix.Direct{Canary: []bool{true}, At: rfix.Const(3000)}
		fp := gatechain.NewFibreParams(observed(t, 100, 10, 3600, d))
		got, src, err := fp.FibreRetentionSourced(bg, 115)
		require.NoError(t, err)
		assert.EqualValues(t, 3000, got, "the lower of the two bounds")
		assert.Equal(t, gate.RetentionBoth, src)
	})
	t.Run("a height no sample covers is an error without a source", func(t *testing.T) {
		fp := gatechain.NewFibreParams(observed(t, 100, 10, 3600, nil))
		got, src, err := fp.FibreRetentionSourced(bg, 99)
		require.Error(t, err)
		assert.Zero(t, got)
		assert.Zero(t, src)
	})
	t.Run("a nil observer fails closed, never panics", func(t *testing.T) {
		fp := gatechain.NewFibreParams(nil)
		_, _, err := fp.FibreRetentionSourced(bg, 115)
		require.Error(t, err)
		_, err = fp.FibreRetention(bg, 0)
		require.Error(t, err)
	})
}

// For da = 1 the gate records where the retention at the anchor height came
// from: with the adapter wired, the source is never "unknown".
func TestGateRecordsAFibreRetentionSource(t *testing.T) {
	c := gatefix.FibreTemplate(t)
	h := c.PayloadRef.Height
	p := observed(t, h-10, 10, 14400, nil)
	e := gatefix.New(t, gatefix.WithDeps(func(d *gate.Deps) { d.Params = gatechain.NewFibreParams(p) }))
	e.StageDA(c, gatefix.FibreBlob())
	b, _ := gatefix.Sign(t, "agent1", c)
	res, err := e.Authorize(b)
	require.NoError(t, err)
	assert.Equal(t, commitment.DAFibre, res.K2.DA)
	assert.NotZero(t, res.K2.RetentionSource, "a gate wired with NewFibreParams records its source")
	assert.Equal(t, gate.RetentionObserved, res.K2.RetentionSource)
	assert.EqualValues(t, 14400, res.K2.RetentionAtHeightS)
}
