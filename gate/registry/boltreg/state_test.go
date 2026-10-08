package boltreg_test

import (
	"encoding/binary"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/gate/registry"
	"github.com/vgonkivs/edicta/gate/registry/boltreg"
	"github.com/vgonkivs/edicta/gate/registry/regtest"
)

func TestStateConformance(t *testing.T) {
	regtest.RunState(t, func(t *testing.T, epoch uint64) registry.StateRegistry {
		r, err := boltreg.Open(filepath.Join(t.TempDir(), "nonces.db"), epoch)
		require.NoError(t, err)
		t.Cleanup(func() { _ = r.Close() })
		return r
	})
}

func TestSchemaOneIsUpgradedInPlace(t *testing.T) {
	path := filepath.Join(t.TempDir(), "n.db")
	r, err := boltreg.Open(path, 100)
	require.NoError(t, err)
	require.NoError(t, r.Consume(ctx, entry(1), regtest.Tolerance))
	one := make([]byte, 8)
	binary.BigEndian.PutUint64(one, 1)
	require.NoError(t, r.SetMetaRaw("schema_version", one))
	require.NoError(t, r.Close())

	r, err = boltreg.Open(path, 100)
	require.NoError(t, err)
	defer r.Close()
	got, err := r.Get(ctx, entry(1).Key)
	require.NoError(t, err)
	require.Equal(t, entry(1), got)
	m, err := r.Meta(ctx)
	require.NoError(t, err)
	require.EqualValues(t, 100, m.Epoch)
	var k registry.StateKey
	c := registry.NewStateCell([]byte{1})
	require.NoError(t, r.UpdateState(ctx, registry.StateTx{Key: k, Next: c}))
}

func TestStateSurvivesReopenAndRefusalIsAtomic(t *testing.T) {
	path := filepath.Join(t.TempDir(), "n.db")
	r, err := boltreg.Open(path, 100)
	require.NoError(t, err)
	var k registry.StateKey
	k[0] = 1
	c1, c2 := registry.NewStateCell([]byte{1}), registry.NewStateCell([]byte{2})
	require.NoError(t, r.ConsumeState(ctx, entry(1), regtest.Tolerance, registry.StateTx{Key: k, Next: c1}))
	err = r.ConsumeState(ctx, entry(2), regtest.Tolerance, registry.StateTx{Key: k, Next: c2})
	require.ErrorIs(t, err, registry.ErrStateConflict)
	require.NoError(t, r.Close())

	r, err = boltreg.Open(path, 100)
	require.NoError(t, err)
	defer r.Close()
	got, err := r.State(ctx, k)
	require.NoError(t, err)
	require.Equal(t, c1, got)
	_, err = r.Get(ctx, entry(1).Key)
	require.NoError(t, err)
	_, err = r.Get(ctx, entry(2).Key)
	require.ErrorIs(t, err, registry.ErrNotFound)
}
