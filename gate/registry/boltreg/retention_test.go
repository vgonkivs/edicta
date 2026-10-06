package boltreg_test

import (
	"encoding/binary"
	"path/filepath"
	"testing"

	"github.com/fxamacker/cbor/v2"
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

func rawRun(t *testing.T, seg uint64, f map[int]uint64) (key, val []byte) {
	t.Helper()
	enc, err := cbor.CoreDetEncOptions().EncMode()
	require.NoError(t, err)
	val, err = enc.Marshal(f)
	require.NoError(t, err)
	key = make([]byte, 16)
	binary.BigEndian.PutUint64(key, seg)
	binary.BigEndian.PutUint64(key[8:], f[2])
	return key, val
}

func TestInconsistentStoredRunIsCorrupt(t *testing.T) {
	base := func() map[int]uint64 {
		return map[int]uint64{1: 1, 2: 100, 3: 100, 4: 100, 5: 100, 6: 7, 7: 5000, 8: 5000}
	}
	cases := []struct {
		name string
		edit func(f map[int]uint64)
		ok   bool
	}{
		{"consistent run", func(map[int]uint64) {}, true},
		{"first from above last from", func(f map[int]uint64) { f[2] = 200 }, false},
		{"first to above last to", func(f map[int]uint64) { f[3], f[5] = 150, 100 }, false},
		{"first at above last at", func(f map[int]uint64) { f[7] = 6000 }, false},
		{"from above to at the first sample", func(f map[int]uint64) { f[2], f[4] = 100, 100; f[3] = 90 }, false},
		{"from above to at the last sample", func(f map[int]uint64) { f[4], f[5] = 120, 110 }, false},
		{"segment zero", func(f map[int]uint64) { f[1] = 0 }, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, _ := openAt(t)
			st := r.RetentionStore()
			require.NoError(t, st.Bind(ctx, "mocha-5"))
			f := base()
			tc.edit(f)
			seg := f[1]
			k, v := rawRun(t, seg, f)
			require.NoError(t, r.SetRetentionRaw("runs", string(k), v))

			_, _, err := st.Last(ctx)
			_, serr := st.Segment(ctx, 100)
			if tc.ok {
				require.NoError(t, err)
				require.NoError(t, serr)
				return
			}
			require.ErrorIs(t, err, retention.ErrStoreCorrupt)
			require.ErrorIs(t, serr, retention.ErrStoreCorrupt)
		})
	}
}
