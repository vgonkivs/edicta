package node_test

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/celestia/heightcheck"
	"github.com/vgonkivs/edicta/celestia/node"
	"github.com/vgonkivs/edicta/celestia/nodefake"
)

const pinnedBridge = "v0.34.2-mocha"

var errSeam = errors.New("seam failure")

type logRec struct {
	mu   sync.Mutex
	msgs []string
	lvl  []slog.Level
}

func (l *logRec) Enabled(context.Context, slog.Level) bool { return true }
func (l *logRec) Handle(_ context.Context, r slog.Record) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	msg := r.Message
	r.Attrs(func(a slog.Attr) bool { msg += " " + a.Key + "=" + a.Value.String(); return true })
	l.msgs, l.lvl = append(l.msgs, msg), append(l.lvl, r.Level)
	return nil
}
func (l *logRec) WithAttrs([]slog.Attr) slog.Handler { return l }
func (l *logRec) WithGroup(string) slog.Handler      { return l }

func (l *logRec) count(sub string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := 0
	for _, m := range l.msgs {
		if strings.Contains(m, sub) {
			n++
		}
	}
	return n
}

// countingConsensus counts canary runs on the consensus endpoint.
type countingConsensus struct {
	node.Consensus
	canaries   atomic.Int64
	txIndexErr error
}

func (c *countingConsensus) TxIndex(ctx context.Context) error {
	if c.txIndexErr != nil {
		return c.txIndexErr
	}
	return c.Consensus.TxIndex(ctx)
}

func (c *countingConsensus) HeightCanary(ctx context.Context) (heightcheck.Status, error) {
	c.canaries.Add(1)
	return c.Consensus.HeightCanary(ctx)
}

// countingReader counts header reads, which is what the bridge canary does.
type countingReader struct {
	node.Reader
	headers atomic.Int64
}

func (r *countingReader) HeaderAt(ctx context.Context, h uint64) (node.Header, error) {
	r.headers.Add(1)
	return r.Reader.HeaderAt(ctx, h)
}

type fibreRig struct {
	chain  *nodefake.Chain
	cons   *countingConsensus
	reader *countingReader
	log    *logRec
	e      node.FibreExpect
	selfN  atomic.Int64
	buildN atomic.Int64
	nmtN   atomic.Int64
}

func newFibreRig(t *testing.T) *fibreRig {
	t.Helper()
	ch := nodefake.NewChain(make([]byte, 20))
	for _, h := range []uint64{90, 100} {
		ch.AddHeader(node.Header{ChainID: "mocha-5", Height: h, Time: t0, AppVersion: 10, DataRoot: []byte{1}})
	}
	co := nodefake.NewConsensus("mocha-5")
	co.Fibre = &node.FibreParams{RetentionS: 4 * 3600}
	r := &fibreRig{chain: ch, cons: &countingConsensus{Consensus: co}, reader: &countingReader{Reader: ch}, log: &logRec{}}
	r.e = node.FibreExpect{
		Expect:              node.Expect{Now: func() time.Time { return t0 }},
		SelfTest:            func() error { r.selfN.Add(1); return nil },
		CheckBuild:          func() error { r.buildN.Add(1); return nil },
		CheckNMT:            func() error { r.nmtN.Add(1); return nil },
		BridgeVersion:       func(context.Context) (string, error) { return pinnedBridge, nil },
		PinnedBridgeVersion: pinnedBridge,
		Log:                 slog.New(r.log),
	}
	return r
}

func (r *fibreRig) run() (node.FibreStart, error) {
	return node.CheckFibre(context.Background(), r.reader, r.cons, r.e)
}

var errNoIndex = errors.New("tx_index off")

func TestCheckFibrePasses(t *testing.T) {
	r := newFibreRig(t)
	st, err := r.run()
	require.NoError(t, err)
	assert.EqualValues(t, 100, st.Head.Height)
	assert.Equal(t, "mocha-5", st.Head.ChainID)
	assert.True(t, st.BridgeFallback)
	assert.False(t, st.ObservationsOnly)
	assert.EqualValues(t, 1, r.selfN.Load())
	assert.EqualValues(t, 1, r.buildN.Load())
	assert.EqualValues(t, 1, r.nmtN.Load())
}

func TestCheckFibreRefusals(t *testing.T) {
	setApp := func(v uint64) func(*fibreRig) {
		return func(r *fibreRig) {
			for _, h := range []uint64{90, 100} {
				r.chain.AddHeader(node.Header{ChainID: "mocha-5", Height: h, Time: t0, AppVersion: v, DataRoot: []byte{1}})
			}
		}
	}
	cases := []struct {
		name   string
		mutate func(*fibreRig)
		want   error
	}{
		{"app version 9", setApp(9), node.ErrUnsupported},
		{"app version 3, accepted by the generic check", setApp(3), node.ErrUnsupported},
		{"app version 11", setApp(11), node.ErrUnsupported},
		{"chain outside the allowlist", func(r *fibreRig) {
			r.cons.Consensus = func() node.Consensus {
				c := nodefake.NewConsensus("mocha-4")
				c.Fibre = &node.FibreParams{RetentionS: 1}
				return c
			}()
			for _, h := range []uint64{90, 100} {
				r.chain.AddHeader(node.Header{ChainID: "mocha-4", Height: h, Time: t0, AppVersion: 10, DataRoot: []byte{1}})
			}
		}, node.ErrUnsupported},
		{"allowlist that does not list the chain", func(r *fibreRig) { r.e.ChainIDs = []string{"arabica-11"} }, node.ErrUnsupported},
		{"known answers fail", func(r *fibreRig) { r.e.SelfTest = func() error { return errSeam } }, errSeam},
		{"build pin fails", func(r *fibreRig) { r.e.CheckBuild = func() error { return errSeam } }, errSeam},
		{"nmt pin fails", func(r *fibreRig) { r.e.CheckNMT = func() error { return errSeam } }, errSeam},
		{"consensus does not index txs", func(r *fibreRig) {
			r.cons.txIndexErr = fmt.Errorf("%w: %w", node.ErrTxIndexDisabled, errNoIndex)
		}, node.ErrTxIndexDisabled},
		{"x/fibre params unreadable", func(r *fibreRig) {
			c := nodefake.NewConsensus("mocha-5")
			c.Fibre = nil
			r.cons.Consensus = c
		}, node.ErrUnsupported},
		{"generic check fails", func(r *fibreRig) { r.chain.Fail = nodefake.ErrInjected }, node.ErrUnsupported},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := newFibreRig(t)
			tc.mutate(r)
			_, err := r.run()
			require.Error(t, err)
			assert.ErrorIs(t, err, tc.want)
			if tc.want != node.ErrUnsupported {
				assert.ErrorIs(t, err, node.ErrUnsupported, "every refusal is an unsupported setup")
			}
		})
	}
}

func TestCheckFibreNeedsBridgeAndConsensus(t *testing.T) {
	t.Run("no bridge", func(t *testing.T) {
		r := newFibreRig(t)
		_, err := node.CheckFibre(context.Background(), nil, r.cons, r.e)
		require.ErrorIs(t, err, node.ErrUnsupported)
		assert.Zero(t, r.cons.canaries.Load())
	})
	t.Run("no consensus", func(t *testing.T) {
		r := newFibreRig(t)
		_, err := node.CheckFibre(context.Background(), r.reader, nil, r.e)
		require.ErrorIs(t, err, node.ErrUnsupported)
		assert.Zero(t, r.reader.headers.Load())
	})
	t.Run("tx index off stops before the canaries", func(t *testing.T) {
		r := newFibreRig(t)
		r.cons.txIndexErr = node.ErrTxIndexDisabled
		_, err := r.run()
		require.ErrorIs(t, err, node.ErrTxIndexDisabled)
		assert.Zero(t, r.cons.canaries.Load())
	})
}

func TestCheckFibreAllowlist(t *testing.T) {
	t.Run("default is mocha-5", func(t *testing.T) {
		r := newFibreRig(t)
		r.e.ChainIDs = nil
		_, err := r.run()
		require.NoError(t, err)
	})
	t.Run("a configured chain is accepted", func(t *testing.T) {
		r := newFibreRig(t)
		r.e.ChainIDs = []string{"arabica-11", "mocha-5"}
		_, err := r.run()
		require.NoError(t, err)
	})
	t.Run("another chain when allowed", func(t *testing.T) {
		r := newFibreRig(t)
		for _, h := range []uint64{90, 100} {
			r.chain.AddHeader(node.Header{ChainID: "arabica-11", Height: h, Time: t0, AppVersion: 10, DataRoot: []byte{1}})
		}
		c := nodefake.NewConsensus("arabica-11")
		c.Fibre = &node.FibreParams{RetentionS: 4 * 3600}
		r.cons.Consensus = c
		r.e.ChainIDs = []string{"arabica-11"}
		_, err := r.run()
		require.NoError(t, err)
	})
}

func TestCheckFibreBridgeVersion(t *testing.T) {
	cases := []struct {
		name string
		ver  func(context.Context) (string, error)
		pin  string
		want bool
	}{
		{"matches the pin", func(context.Context) (string, error) { return pinnedBridge, nil }, pinnedBridge, true},
		{"differs from the pin", func(context.Context) (string, error) { return "v0.35.0-mocha", nil }, pinnedBridge, false},
		{"empty version", func(context.Context) (string, error) { return "", nil }, pinnedBridge, false},
		{"version unreadable", func(context.Context) (string, error) { return "", errSeam }, pinnedBridge, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := newFibreRig(t)
			r.e.BridgeVersion, r.e.PinnedBridgeVersion = tc.ver, tc.pin
			st, err := r.run()
			require.NoError(t, err, "a bridge mismatch is not a refusal")
			assert.Equal(t, tc.want, st.BridgeFallback)
			if !tc.want {
				assert.Equal(t, 1, r.log.count("fallback disabled"), "the disabled fallback is logged")
				assert.Contains(t, r.log.lvl, slog.LevelWarn)
			}
		})
	}
	t.Run("no bridge configured disables the fallback", func(t *testing.T) {
		r := newFibreRig(t)
		r.e.BridgeVersion, r.e.PinnedBridgeVersion = nil, ""
		st, err := r.run()
		require.NoError(t, err)
		assert.False(t, st.BridgeFallback)
	})
}

func TestCheckFibreRunsExactlyOneCanaryPerEndpoint(t *testing.T) {
	r := newFibreRig(t)
	_, err := r.run()
	require.NoError(t, err)
	assert.EqualValues(t, 1, r.cons.canaries.Load(), "consensus canary")
	assert.EqualValues(t, 1, r.reader.headers.Load(), "bridge canary reads one header")
	assert.Equal(t, 2, r.log.count("height honoured"), "one line per endpoint")
}

func TestCheckFibreObservationsOnlyIsNotARefusal(t *testing.T) {
	r := newFibreRig(t)
	inner := r.cons.Consensus.(*nodefake.Consensus)
	inner.CanaryStatus = heightcheck.Ignoring
	st, err := r.run()
	require.NoError(t, err)
	assert.True(t, st.ObservationsOnly)
	assert.Equal(t, 1, r.log.count("observations-only mode"))
	assert.EqualValues(t, 1, r.cons.canaries.Load())
}

func TestFibreExpectValidateBasic(t *testing.T) {
	valid := func() node.FibreExpect {
		return node.FibreExpect{ChainIDs: []string{"mocha-5"}, BridgeVersion: func(context.Context) (string, error) { return "", nil },
			PinnedBridgeVersion: pinnedBridge}
	}
	require.NoError(t, valid().ValidateBasic())
	cases := []struct {
		name string
		mod  func(*node.FibreExpect)
		ok   bool
	}{
		{"valid", func(*node.FibreExpect) {}, true},
		{"no bridge check", func(e *node.FibreExpect) { e.BridgeVersion, e.PinnedBridgeVersion = nil, "" }, true},
		{"two chains", func(e *node.FibreExpect) { e.ChainIDs = []string{"mocha-5", "arabica-11"} }, true},
		{"longest promise chain id", func(e *node.FibreExpect) { e.ChainIDs = []string{strings.Repeat("c", 20)} }, true},
		{"empty chain id", func(e *node.FibreExpect) { e.ChainIDs = []string{"mocha-5", ""} }, false},
		{"chain id above 20 bytes", func(e *node.FibreExpect) { e.ChainIDs = []string{strings.Repeat("c", 21)} }, false},
		{"duplicate chain id", func(e *node.FibreExpect) { e.ChainIDs = []string{"mocha-5", "mocha-5"} }, false},
		{"version check without a pin", func(e *node.FibreExpect) { e.PinnedBridgeVersion = "" }, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := valid()
			tc.mod(&e)
			err := e.ValidateBasic()
			if tc.ok {
				require.NoError(t, err)
				return
			}
			require.ErrorIs(t, err, node.ErrInvalidConfig)
		})
	}
	t.Run("defaults take mocha-5", func(t *testing.T) {
		e := node.FibreExpect{}.WithDefaults()
		assert.Equal(t, []string{"mocha-5"}, e.ChainIDs)
		require.NoError(t, e.ValidateBasic())
	})
	t.Run("defaults keep a configured list", func(t *testing.T) {
		e := node.FibreExpect{ChainIDs: []string{"arabica-11"}}.WithDefaults()
		assert.Equal(t, []string{"arabica-11"}, e.ChainIDs)
	})
	t.Run("defaults set the nmt check", func(t *testing.T) {
		assert.NotNil(t, node.FibreExpect{}.WithDefaults().CheckNMT)
	})
	t.Run("CheckFibre refuses an invalid config before any call", func(t *testing.T) {
		r := newFibreRig(t)
		r.e.ChainIDs = []string{""}
		_, err := r.run()
		require.ErrorIs(t, err, node.ErrInvalidConfig)
		assert.Zero(t, r.selfN.Load()+r.buildN.Load()+r.nmtN.Load())
		assert.Zero(t, r.cons.canaries.Load())
	})
}
