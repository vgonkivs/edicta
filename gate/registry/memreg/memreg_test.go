package memreg_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/gate/registry"
	"github.com/vgonkivs/edicta/gate/registry/memreg"
	"github.com/vgonkivs/edicta/gate/registry/regtest"
)

func TestConformance(t *testing.T) {
	regtest.Run(t, func(t *testing.T, epoch uint64) registry.Registry {
		r, err := memreg.New(epoch)
		require.NoError(t, err)
		return r
	})
}

var _ registry.Lister = (*memreg.Registry)(nil)

func listEntry(pub, nonce byte) registry.Entry {
	var k registry.Key
	k.PubKey[0], k.Nonce[0] = pub, nonce
	return registry.Entry{Key: k, CommitmentHash: commitment.Hash{pub, nonce}, ActionHash: commitment.Hash{pub, nonce, 2},
		Path: registry.PathDA, AuthorizedAt: 5000, ValidUntil: 6000 + uint64(pub), Authorization: []byte{0xa2, pub, nonce}}
}

func TestList(t *testing.T) {
	ctx := context.Background()
	newReg := func(t *testing.T) *memreg.Registry {
		r, err := memreg.New(100)
		require.NoError(t, err)
		return r
	}
	// Inserted out of key order, two nonces under one key.
	in := []registry.Entry{listEntry(3, 1), listEntry(1, 9), listEntry(2, 0), listEntry(1, 2), listEntry(5, 5)}
	want := []registry.Entry{listEntry(1, 2), listEntry(1, 9), listEntry(2, 0), listEntry(3, 1), listEntry(5, 5)}

	fill := func(t *testing.T) *memreg.Registry {
		r := newReg(t)
		for _, e := range in {
			require.NoError(t, r.Consume(ctx, e, 60))
		}
		return r
	}
	page := func(t *testing.T, r registry.Lister, n int) []registry.Entry {
		var all []registry.Entry
		var after *registry.Key
		for i := 0; i < 20; i++ {
			got, err := r.List(ctx, after, n)
			require.NoError(t, err)
			require.LessOrEqual(t, len(got), n)
			if len(got) == 0 {
				return all
			}
			all = append(all, got...)
			k := got[len(got)-1].Key
			after = &k
		}
		require.FailNow(t, "paging does not terminate")
		return nil
	}

	t.Run("empty", func(t *testing.T) {
		got, err := newReg(t).List(ctx, nil, 10)
		require.NoError(t, err)
		assert.Empty(t, got)
	})
	t.Run("every entry in key order, any page size", func(t *testing.T) {
		r := fill(t)
		for _, n := range []int{1, 2, 3, 5, 100} {
			assert.Equal(t, want, page(t, r, n), "page size %d", n)
		}
	})
	t.Run("after a key that is absent starts after its position", func(t *testing.T) {
		r := fill(t)
		k := listEntry(2, 7).Key
		got, err := r.List(ctx, &k, 10)
		require.NoError(t, err)
		assert.Equal(t, want[3:], got)
	})
	t.Run("after the last key is empty", func(t *testing.T) {
		r := fill(t)
		k := want[len(want)-1].Key
		got, err := r.List(ctx, &k, 10)
		require.NoError(t, err)
		assert.Empty(t, got)
	})
	t.Run("entries carry the receipt", func(t *testing.T) {
		r := fill(t)
		e := want[2]
		require.NoError(t, r.AttachReceipt(ctx, e.Key, e.CommitmentHash, []byte("rcpt")))
		got, err := r.List(ctx, nil, 10)
		require.NoError(t, err)
		assert.Equal(t, []byte("rcpt"), got[2].Receipt)
		assert.Nil(t, got[0].Receipt)
	})
	t.Run("pruned entries are gone", func(t *testing.T) {
		r := fill(t)
		_, err := r.Prune(ctx, 6003)
		require.NoError(t, err)
		got, err := r.List(ctx, nil, 10)
		require.NoError(t, err)
		assert.Equal(t, want[3:], got)
	})
	t.Run("a returned entry is a copy", func(t *testing.T) {
		r := fill(t)
		got, err := r.List(ctx, nil, 1)
		require.NoError(t, err)
		got[0].Authorization[0] ^= 0xff
		again, err := r.List(ctx, nil, 1)
		require.NoError(t, err)
		assert.Equal(t, want[0], again[0])
	})
	t.Run("a cancelled context is an error or complete", func(t *testing.T) {
		r := fill(t)
		c, cancel := context.WithCancel(ctx)
		cancel()
		got, err := r.List(c, nil, 10)
		if err != nil {
			require.ErrorIs(t, err, context.Canceled)
			return
		}
		assert.Equal(t, want, got)
	})
}
