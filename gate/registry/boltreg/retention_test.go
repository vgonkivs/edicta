package boltreg_test

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/gate/registry"
	"github.com/vgonkivs/edicta/gate/registry/boltreg"
	"github.com/vgonkivs/edicta/retention"
	"github.com/vgonkivs/edicta/test/retentionfix"
	"github.com/vgonkivs/edicta/test/retentionstore"
)

func TestRetentionConformance(t *testing.T) {
	retentionstore.Run(t, func(t *testing.T) *retentionstore.Handle {
		path := filepath.Join(t.TempDir(), "gate.db")
		r, err := boltreg.Open(path, 100)
		require.NoError(t, err)
		t.Cleanup(func() { _ = r.Close() })
		return &retentionstore.Handle{
			Store: r.RetentionStore(),
			Reopen: func() retention.Store {
				require.NoError(t, r.Close())
				r, err = boltreg.Open(path, 100)
				require.NoError(t, err)
				return r.RetentionStore()
			},
		}
	})
}

func openAt(t *testing.T) (*boltreg.Registry, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "gate.db")
	r, err := boltreg.Open(path, 100)
	require.NoError(t, err)
	t.Cleanup(func() { _ = r.Close() })
	return r, path
}

func TestRetentionLeavesNonceBucketsUntouched(t *testing.T) {
	r, _ := openAt(t)
	require.NoError(t, r.Consume(ctx, entry(1), 10))
	require.NoError(t, r.Consume(ctx, entry(2), 10))
	_, before := r.DumpTop()
	require.NotEmpty(t, before)

	st := r.RetentionStore()
	require.NoError(t, st.Bind(ctx, "mocha-5"))
	for i := range 5 {
		h := uint64(100 + 30*i)
		require.NoError(t, st.Append(ctx, retentionfix.S(h, h, uint64(10+i%2), 5000+uint64(30*i)), retentionfix.Policy))
	}
	_, err := st.Prune(ctx, 1<<40)
	require.NoError(t, err)

	names, after := r.DumpTop()
	assert.Equal(t, before, after, "entries and meta, including schema_version, must stay byte-identical")
	assert.Contains(t, names, "entries")
	assert.Contains(t, names, "meta")
	assert.Contains(t, names, "fibre_retention")
	m, err := r.Meta(ctx)
	require.NoError(t, err)
	assert.Equal(t, uint64(100), m.Epoch)
}

func TestNonceOperationsDoNotTouchRetention(t *testing.T) {
	r, path := openAt(t)
	st := r.RetentionStore()
	require.NoError(t, st.Bind(ctx, "mocha-5"))
	require.NoError(t, st.Append(ctx, retentionfix.S(100, 100, 7, 5000), retentionfix.Policy))
	want, _, err := st.Last(ctx)
	require.NoError(t, err)

	require.NoError(t, r.Consume(ctx, entry(3), 10))
	_, err = r.Prune(ctx, 1<<40)
	require.NoError(t, err)
	require.NoError(t, r.Close())

	r2, err := boltreg.Open(path, 100)
	require.NoError(t, err)
	defer r2.Close()
	got, have, err := r2.RetentionStore().Last(ctx)
	require.NoError(t, err)
	require.True(t, have)
	assert.Equal(t, want, got)
}

func TestFileWithoutRetentionBucketIsUsable(t *testing.T) {
	r, path := openAt(t)
	require.NoError(t, r.Consume(ctx, entry(4), 10))
	require.NoError(t, r.Close())

	r2, err := boltreg.Open(path, 100)
	require.NoError(t, err)
	defer r2.Close()
	st := r2.RetentionStore()
	_, have, err := st.Last(ctx)
	require.NoError(t, err)
	assert.False(t, have)
	require.NoError(t, st.Bind(ctx, "mocha-5"))
	got, err := r2.Get(ctx, entry(4).Key)
	require.NoError(t, err)
	assert.Equal(t, entry(4), got)
}

func TestCorruptRetentionIsIsolated(t *testing.T) {
	corrupt := map[string]func(t *testing.T, r *boltreg.Registry){
		"garbage runs": func(t *testing.T, r *boltreg.Registry) {
			n, err := r.CorruptRetentionRuns()
			require.NoError(t, err)
			require.NotZero(t, n)
		},
		"bad schema": func(t *testing.T, r *boltreg.Registry) {
			require.NoError(t, r.SetRetentionRaw("meta", "schema", []byte{1, 2, 3}))
		},
	}
	for name, damage := range corrupt {
		t.Run(name, func(t *testing.T) {
			r, path := openAt(t)
			st := r.RetentionStore()
			require.NoError(t, st.Bind(ctx, "mocha-5"))
			require.NoError(t, st.Append(ctx, retentionfix.S(100, 100, 7, 5000), retentionfix.Policy))
			require.NoError(t, r.Consume(ctx, entry(5), 10))
			damage(t, r)

			_, _, err := st.Last(ctx)
			require.ErrorIs(t, err, retention.ErrStoreCorrupt)
			_, err = st.Segment(ctx, 100)
			require.ErrorIs(t, err, retention.ErrStoreCorrupt)
			err = st.Append(ctx, retentionfix.S(130, 130, 7, 5030), retentionfix.Policy)
			require.ErrorIs(t, err, retention.ErrStoreCorrupt)

			require.NoError(t, r.Consume(ctx, entry(6), 10), "nonce writes keep working")
			got, err := r.Get(ctx, entry(5).Key)
			require.NoError(t, err)
			assert.Equal(t, entry(5), got)
			_, err = r.Meta(ctx)
			require.NoError(t, err)
			require.ErrorIs(t, r.Consume(ctx, entry(6), 10), registry.ErrExists, "the nonce stays used")

			require.NoError(t, r.Close())
			r2, err := boltreg.Open(path, 100)
			require.NoError(t, err, "a damaged retention bucket must not stop the registry opening")
			defer r2.Close()
			_, err = r2.Get(ctx, entry(5).Key)
			require.NoError(t, err)
		})
	}
}
