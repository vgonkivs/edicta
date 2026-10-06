package boltreg_test

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/gate/registry"
	"github.com/vgonkivs/edicta/gate/registry/boltreg"
	"github.com/vgonkivs/edicta/gate/registry/regtest"
)

var _ registry.Lister = (*boltreg.Registry)(nil)

func listEntry(pub, nonce byte) registry.Entry {
	var k registry.Key
	k.PubKey[0], k.Nonce[0] = pub, nonce
	return registry.Entry{Key: k, CommitmentHash: commitment.Hash{pub, nonce}, ActionHash: commitment.Hash{pub, nonce, 2},
		Path: registry.PathDA, AuthorizedAt: 5000, ValidUntil: 6000 + uint64(pub), Authorization: []byte{0xa2, pub, nonce}}
}

func pageAll(t *testing.T, r registry.Lister, n int) []registry.Entry {
	t.Helper()
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

func TestList(t *testing.T) {
	in := []registry.Entry{listEntry(3, 1), listEntry(1, 9), listEntry(2, 0), listEntry(1, 2), listEntry(5, 5)}
	want := []registry.Entry{listEntry(1, 2), listEntry(1, 9), listEntry(2, 0), listEntry(3, 1), listEntry(5, 5)}
	open := func(t *testing.T) (*boltreg.Registry, string) {
		path := filepath.Join(t.TempDir(), "n.db")
		r, err := boltreg.Open(path, 100)
		require.NoError(t, err)
		t.Cleanup(func() { _ = r.Close() })
		for _, e := range in {
			require.NoError(t, r.Consume(ctx, e, regtest.Tolerance))
		}
		return r, path
	}

	t.Run("empty", func(t *testing.T) {
		r, err := boltreg.Open(filepath.Join(t.TempDir(), "n.db"), 100)
		require.NoError(t, err)
		defer r.Close()
		got, err := r.List(ctx, nil, 10)
		require.NoError(t, err)
		assert.Empty(t, got)
	})
	t.Run("every entry in key order, any page size", func(t *testing.T) {
		r, _ := open(t)
		for _, n := range []int{1, 2, 3, 5, 100} {
			assert.Equal(t, want, pageAll(t, r, n), "page size %d", n)
		}
	})
	t.Run("after an absent key", func(t *testing.T) {
		r, _ := open(t)
		k := listEntry(2, 7).Key
		got, err := r.List(ctx, &k, 10)
		require.NoError(t, err)
		assert.Equal(t, want[3:], got)
	})
	t.Run("after the last key is empty", func(t *testing.T) {
		r, _ := open(t)
		k := want[len(want)-1].Key
		got, err := r.List(ctx, &k, 10)
		require.NoError(t, err)
		assert.Empty(t, got)
	})
	t.Run("the receipt is listed", func(t *testing.T) {
		r, _ := open(t)
		e := want[1]
		require.NoError(t, r.AttachReceipt(ctx, e.Key, e.CommitmentHash, []byte("rcpt")))
		got, err := r.List(ctx, nil, 10)
		require.NoError(t, err)
		assert.Equal(t, []byte("rcpt"), got[1].Receipt)
	})
	t.Run("pruned entries are gone", func(t *testing.T) {
		r, _ := open(t)
		_, err := r.Prune(ctx, 6003)
		require.NoError(t, err)
		assert.Equal(t, want[3:], pageAll(t, r, 2))
	})
	t.Run("works across a restart", func(t *testing.T) {
		r, path := open(t)
		before := pageAll(t, r, 2)
		require.NoError(t, r.Close())
		r2, err := boltreg.Open(path, 99999)
		require.NoError(t, err)
		defer r2.Close()
		assert.Equal(t, before, pageAll(t, r2, 2))
		assert.Equal(t, want, pageAll(t, r2, 100))
		k := want[1].Key
		got, err := r2.List(ctx, &k, 2)
		require.NoError(t, err)
		assert.Equal(t, want[2:4], got)
	})
	t.Run("a listing does not block Consume", func(t *testing.T) {
		r, _ := open(t)
		_, err := r.List(ctx, nil, 2)
		require.NoError(t, err)
		require.NoError(t, r.Consume(ctx, listEntry(4, 4), regtest.Tolerance))
		assert.Len(t, pageAll(t, r, 10), len(want)+1)
	})
}
