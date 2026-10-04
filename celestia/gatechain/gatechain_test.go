package gatechain_test

import (
	"bytes"
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/celestia/gatechain"
	"github.com/vgonkivs/edicta/celestia/node"
	"github.com/vgonkivs/edicta/celestia/nodefake"
	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/dacommit/sharev1"
	"github.com/vgonkivs/edicta/gate"
)

var (
	bg     = context.Background()
	ns     = append(append([]byte{0}, make([]byte, 18)...), bytes.Repeat([]byte{7}, 10)...)
	signer = bytes.Repeat([]byte{9}, 20)
	other  = bytes.Repeat([]byte{4}, 20)
	// The sub-second part checks flooring.
	t0   = time.Date(2026, 10, 4, 12, 0, 0, 700_000_000, time.UTC)
	data = []byte("committed payload")
)

const H = uint64(150)

var (
	_ gate.HeaderSource = gatechain.NewHeaders(nil)
	_ gate.AnchorSource = gatechain.NewAnchors(nil)
	_ gate.BlobSource   = gatechain.NewBlobSource(nil)
	_ gate.ChainParams  = gatechain.NewParams(nil)
	_ gate.BlobSource   = gatechain.NoArchive
)

func comm(t *testing.T, d []byte) []byte {
	t.Helper()
	c, err := sharev1.Commitment(ns, signer, d)
	require.NoError(t, err)
	return c
}

func ref(t *testing.T) commitment.PayloadRef {
	return commitment.PayloadRef{DA: commitment.DACelestiaBlob, Namespace: ns,
		Commitment: comm(t, data), Height: H, Signer: signer}
}

func chain(t *testing.T, mut func(*node.Blob)) *nodefake.Chain {
	c := nodefake.NewChain(signer)
	c.AddHeader(node.Header{ChainID: "devnet-1", Height: H, Time: t0})
	b := node.Blob{Namespace: ns, Data: bytes.Clone(data), ShareVersion: 1, Signer: signer, Commitment: comm(t, data)}
	if mut != nil {
		mut(&b)
	}
	c.AddBlob(H, b, nil)
	return c
}

func TestBlockTime(t *testing.T) {
	c := chain(t, nil)
	h := gatechain.NewHeaders(c)
	got, err := h.BlockTime(bg, H)
	require.NoError(t, err)
	assert.EqualValues(t, t0.Unix(), got, "floored to seconds")

	_, err = h.BlockTime(bg, H+10)
	require.ErrorIs(t, err, gate.ErrAnchorNotFound, "future block")
}

func TestLookupsMapNodeErrors(t *testing.T) {
	fails := []struct {
		name string
		err  error
	}{
		{"deadline", context.DeadlineExceeded},
		{"unavailable", node.ErrUnavailable},
		{"unknown", nodefake.ErrInjected},
	}
	for _, f := range fails {
		t.Run(f.name, func(t *testing.T) {
			c := chain(t, nil)
			c.Fail = f.err
			r := ref(t)

			_, err := gatechain.NewHeaders(c).BlockTime(bg, H)
			require.ErrorIs(t, err, gate.ErrChainUnavailable)
			assert.NotErrorIs(t, err, gate.ErrAnchorNotFound)

			_, err = gatechain.NewAnchors(c).FindAnchor(bg, r)
			require.ErrorIs(t, err, gate.ErrChainUnavailable)
			assert.NotErrorIs(t, err, gate.ErrAnchorNotFound)

			_, err = gatechain.NewBlobSource(c).Fetch(bg, r, 1<<20)
			require.ErrorIs(t, err, gate.ErrChainUnavailable)
			assert.NotErrorIs(t, err, gate.ErrBlobNotFound)
		})
	}
	t.Run("cancelled context stays a context error", func(t *testing.T) {
		c := chain(t, nil)
		c.Fail = context.Canceled
		_, err := gatechain.NewAnchors(c).FindAnchor(bg, ref(t))
		require.ErrorIs(t, err, context.Canceled)
		assert.NotErrorIs(t, err, gate.ErrAnchorNotFound)
		_, err = gatechain.NewBlobSource(c).Fetch(bg, ref(t), 1<<20)
		require.ErrorIs(t, err, context.Canceled)
		assert.NotErrorIs(t, err, gate.ErrBlobNotFound)
	})
	t.Run("cancelled before the call", func(t *testing.T) {
		ctx, cancel := context.WithCancel(bg)
		cancel()
		c := chain(t, nil)
		_, err := gatechain.NewAnchors(c).FindAnchor(ctx, ref(t))
		require.Error(t, err)
		assert.NotErrorIs(t, err, gate.ErrAnchorNotFound)
	})
}

func TestFindAnchor(t *testing.T) {
	v0 := func(b *node.Blob) { b.ShareVersion = 0; b.Signer = nil }
	cases := []struct {
		name string
		mut  func(*node.Blob)
		edit func(*commitment.PayloadRef)
		ok   bool
	}{
		{"match", nil, nil, true},
		{"share version 0 on chain", v0, nil, false},
		{"other signer on chain", func(b *node.Blob) { b.Signer = other }, nil, false},
		{"ref names other signer", nil, func(r *commitment.PayloadRef) { r.Signer = other }, false},
		{"node data differs from commitment", func(b *node.Blob) { b.Data = append(bytes.Clone(b.Data), 1) }, nil, false},
		{"node commitment field differs", func(b *node.Blob) { b.Commitment = bytes.Repeat([]byte{1}, 32) }, nil, false},
		{"da 1 ref", nil, func(r *commitment.PayloadRef) { r.DA = commitment.DAFibre }, false},
		{"other height", nil, func(r *commitment.PayloadRef) { r.Height = H + 1 }, false},
		{"other namespace", nil, func(r *commitment.PayloadRef) {
			r.Namespace = append(append([]byte{0}, make([]byte, 18)...), bytes.Repeat([]byte{8}, 10)...)
		}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := chain(t, tc.mut)
			r := ref(t)
			if tc.edit != nil {
				tc.edit(&r)
			}
			a, err := gatechain.NewAnchors(c).FindAnchor(bg, r)
			if tc.ok {
				require.NoError(t, err)
				assert.Equal(t, gate.Anchor{Height: H, RetentionStart: 0}, a)
				return
			}
			require.ErrorIs(t, err, gate.ErrAnchorNotFound)
		})
	}
}

func TestBlobSource(t *testing.T) {
	t.Run("returns the bytes", func(t *testing.T) {
		got, err := gatechain.NewBlobSource(chain(t, nil)).Fetch(bg, ref(t), 1<<20)
		require.NoError(t, err)
		assert.Equal(t, data, got)
	})
	t.Run("reads at most max+1", func(t *testing.T) {
		got, err := gatechain.NewBlobSource(chain(t, nil)).Fetch(bg, ref(t), 4)
		require.NoError(t, err)
		assert.Len(t, got, 5, "max+1 lets the caller see the overflow")
	})
	t.Run("absent is ErrBlobNotFound", func(t *testing.T) {
		r := ref(t)
		r.Height = H + 1
		_, err := gatechain.NewBlobSource(chain(t, nil)).Fetch(bg, r, 1<<20)
		require.ErrorIs(t, err, gate.ErrBlobNotFound)
	})
	t.Run("wrong signer or share version is not found", func(t *testing.T) {
		for _, mut := range []func(*node.Blob){
			func(b *node.Blob) { b.Signer = other },
			func(b *node.Blob) { b.ShareVersion = 0; b.Signer = nil },
		} {
			_, err := gatechain.NewBlobSource(chain(t, mut)).Fetch(bg, ref(t), 1<<20)
			require.ErrorIs(t, err, gate.ErrBlobNotFound)
		}
	})
	t.Run("da 1 ref is not served", func(t *testing.T) {
		r := ref(t)
		r.DA = commitment.DAFibre
		_, err := gatechain.NewBlobSource(chain(t, nil)).Fetch(bg, r, 1<<20)
		require.Error(t, err)
	})
	t.Run("NoArchive knows nothing", func(t *testing.T) {
		_, err := gatechain.NoArchive.Fetch(bg, ref(t), 1<<20)
		require.ErrorIs(t, err, gate.ErrBlobNotFound)
	})
}

func TestFibreRetention(t *testing.T) {
	t.Run("present", func(t *testing.T) {
		cs := nodefake.NewConsensus("devnet-1")
		cs.Fibre = &node.FibreParams{RetentionS: 14400}
		got, err := gatechain.NewParams(cs).FibreRetention(bg, 0)
		require.NoError(t, err)
		assert.EqualValues(t, 14400, got)
	})
	t.Run("absent module errors, never a substitute", func(t *testing.T) {
		cs := nodefake.NewConsensus("devnet-1")
		got, err := gatechain.NewParams(cs).FibreRetention(bg, 0)
		require.Error(t, err)
		require.ErrorIs(t, err, node.ErrNotFound)
		assert.Zero(t, got)
	})
	t.Run("height above zero never falls back to the latest value", func(t *testing.T) {
		cs := nodefake.NewConsensus("devnet-1")
		cs.Fibre = &node.FibreParams{RetentionS: 14400}
		_, err := gatechain.NewParams(cs).FibreRetention(bg, 5)
		require.Error(t, err)
	})
	t.Run("transport failure", func(t *testing.T) {
		cs := nodefake.NewConsensus("devnet-1")
		cs.Fibre = &node.FibreParams{RetentionS: 1}
		cs.Fail = context.DeadlineExceeded
		_, err := gatechain.NewParams(cs).FibreRetention(bg, 0)
		require.ErrorIs(t, err, context.DeadlineExceeded)
	})
}

type countingConsensus struct {
	*nodefake.Consensus
	fibreCalls atomic.Int32
}

func (c *countingConsensus) FibreParams(ctx context.Context) (node.FibreParams, error) {
	c.fibreCalls.Add(1)
	return c.Consensus.FibreParams(ctx)
}

func TestPreflightWithChainParams(t *testing.T) {
	cases := []struct {
		name    string
		allowed []commitment.DA
		fibre   bool
		wantErr bool
		calls   int32
	}{
		{"only da2, no x/fibre: never read", []commitment.DA{2}, false, false, 0},
		{"only da2, x/fibre present: never read", []commitment.DA{2}, true, false, 0},
		{"da1 allowed, x/fibre present", []commitment.DA{1, 2}, true, false, 1},
		{"da1 allowed, no x/fibre: refuse to start", []commitment.DA{1, 2}, false, true, 1},
		{"default set, no x/fibre: refuse to start", nil, false, true, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cs := &countingConsensus{Consensus: nodefake.NewConsensus("devnet-1")}
			if tc.fibre {
				cs.Fibre = &node.FibreParams{RetentionS: 14400}
			}
			cfg := gate.DefaultConfig()
			cfg.AllowedDA = tc.allowed
			err := gate.Preflight(bg, cfg, gate.Deps{Params: gatechain.NewParams(cs)})
			if tc.wantErr {
				require.ErrorIs(t, err, gate.ErrInvalidConfig)
				assert.ErrorIs(t, err, node.ErrNotFound)
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, tc.calls, cs.fibreCalls.Load())
		})
	}
}
