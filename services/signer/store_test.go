// SPDX-License-Identifier: Apache-2.0

package signer_test

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/engine/commitment"
	"github.com/vgonkivs/edicta/services/signer"
)

func admitAll(signer.Totals) error { return nil }

func TestBoltStoreReserveIsOnceAndCountsInOneWrite(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "s.db")
	st, err := signer.OpenBoltStore(path)
	require.NoError(t, err)

	h := commitment.Hash{0x01}
	e := signer.Entry{CommitmentHash: h, Digest: [32]byte{0xaa}, Value: []byte{5}, Fee: []byte{7}, ReservedAt: 1000, State: signer.StateReserved}
	_, existing, err := st.Reserve(ctx, e, 0, admitAll)
	require.NoError(t, err)
	assert.False(t, existing)

	called := false
	other := e
	other.Digest = [32]byte{0xbb}
	got, existing, err := st.Reserve(ctx, other, 0, func(signer.Totals) error { called = true; return nil })
	require.NoError(t, err)
	assert.True(t, existing)
	assert.False(t, called, "a stored decision is never counted again")
	assert.Equal(t, e.Digest, got.Digest)

	// A refused admission stores nothing.
	refused := errors.New("cap")
	var seen signer.Totals
	_, _, err = st.Reserve(ctx, signer.Entry{CommitmentHash: commitment.Hash{0x02}, Value: []byte{1}, Fee: []byte{1}, ReservedAt: 1001},
		0, func(t signer.Totals) error { seen = t; return refused })
	require.ErrorIs(t, err, refused)
	assert.Equal(t, int64(5), seen.Value.Int64())
	assert.Equal(t, int64(7), seen.Fee.Int64())
	_, ok, err := st.Get(ctx, commitment.Hash{0x02})
	require.NoError(t, err)
	assert.False(t, ok)

	// Out of the window, the amount no longer counts; the entry stays.
	_, _, err = st.Reserve(ctx, signer.Entry{CommitmentHash: commitment.Hash{0x03}, ReservedAt: 5000}, 1001,
		func(t signer.Totals) error { seen = t; return nil })
	require.NoError(t, err)
	assert.Zero(t, seen.Value.Sign())

	// Durable across a reopen.
	require.NoError(t, st.Close())
	st, err = signer.OpenBoltStore(path)
	require.NoError(t, err)
	defer st.Close()
	got, ok, err = st.Get(ctx, h)
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, e.Digest, got.Digest)
}

func TestBoltStoreSignedBytesNeverChange(t *testing.T) {
	ctx := context.Background()
	st, err := signer.OpenBoltStore(filepath.Join(t.TempDir(), "s.db"))
	require.NoError(t, err)
	defer st.Close()
	h := commitment.Hash{0x01}
	_, _, err = st.Reserve(ctx, signer.Entry{CommitmentHash: h, Digest: [32]byte{1}}, 0, admitAll)
	require.NoError(t, err)

	_, err = st.Update(ctx, h, func(e *signer.Entry) error {
		e.Signed, e.RailRef, e.State = []byte{1, 2, 3}, "ref", signer.StateSigned
		return nil
	})
	require.NoError(t, err)
	_, err = st.Update(ctx, h, func(e *signer.Entry) error { e.Signed = []byte{9}; return nil })
	require.Error(t, err)
	_, err = st.Update(ctx, h, func(e *signer.Entry) error { e.Digest = [32]byte{2}; return nil })
	require.Error(t, err)
	_, err = st.Update(ctx, h, func(e *signer.Entry) error { e.Value = []byte{1}; return nil })
	require.Error(t, err)
	got, err := st.Update(ctx, h, func(e *signer.Entry) error { e.State = signer.StateExecuted; return nil })
	require.NoError(t, err)
	assert.Equal(t, []byte{1, 2, 3}, got.Signed)

	list, err := st.Unfinished(ctx, signer.StateExecuted)
	require.NoError(t, err)
	assert.Len(t, list, 1)
}

func TestBoltStoreRefusesASecondProcess(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s.db")
	st, err := signer.OpenBoltStore(path)
	require.NoError(t, err)
	defer st.Close()
	_, err = signer.OpenBoltStore(path)
	require.Error(t, err)
}
