// SPDX-License-Identifier: Apache-2.0

package rlp_test

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/internal/evm/rlp"
)

func h(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	require.NoError(t, err)
	return b
}

// The examples of the RLP specification.
func TestEncodings(t *testing.T) {
	dog := rlp.AppendString(nil, []byte("dog"))
	cat := rlp.AppendString(nil, []byte("cat"))
	lorem := []byte("Lorem ipsum dolor sit amet, consectetur adipisicing elit")
	for _, c := range []struct {
		got  []byte
		want string
	}{
		{dog, "83646f67"},
		{rlp.AppendList(nil, cat, dog), "c88363617483646f67"},
		{rlp.AppendString(nil, nil), "80"},
		{rlp.AppendList(nil), "c0"},
		{rlp.AppendUint64(nil, 0), "80"},
		{rlp.AppendString(nil, []byte{0}), "00"},
		{rlp.AppendUint64(nil, 15), "0f"},
		{rlp.AppendUint64(nil, 1024), "820400"},
		{rlp.AppendUint64(nil, 0x80), "8180"},
		{rlp.AppendUint64(nil, ^uint64(0)), "88ffffffffffffffff"},
		{rlp.AppendList(nil, rlp.AppendList(nil), rlp.AppendList(nil, rlp.AppendList(nil)), rlp.AppendList(nil, rlp.AppendList(nil), rlp.AppendList(nil, rlp.AppendList(nil)))), "c7c0c1c0c3c0c1c0"},
		{rlp.AppendString(nil, lorem), "b838" + hex.EncodeToString(lorem)},
		{rlp.AppendString([]byte{0x02}, []byte("dog")), "0283646f67"},
	} {
		assert.Equal(t, c.want, hex.EncodeToString(c.got))
	}
	long := rlp.AppendString(nil, make([]byte, 0x10000))
	assert.Equal(t, "ba010000", hex.EncodeToString(long[:4]))
}

func TestNextReadsItems(t *testing.T) {
	in := h(t, "c88363617483646f6701")
	it, rest, err := rlp.Next(in)
	require.NoError(t, err)
	assert.True(t, it.List)
	assert.Equal(t, in[:9], it.Raw)
	assert.Equal(t, in[1:9], it.Payload)
	assert.Equal(t, []byte{0x01}, rest)

	first, rest, err := rlp.Next(it.Payload)
	require.NoError(t, err)
	assert.False(t, first.List)
	assert.Equal(t, []byte("cat"), first.Payload)
	assert.Equal(t, h(t, "83636174"), first.Raw)
	assert.Equal(t, h(t, "83646f67"), rest)

	single, rest, err := rlp.Next([]byte{0x7f})
	require.NoError(t, err)
	assert.Equal(t, []byte{0x7f}, single.Payload)
	assert.Equal(t, []byte{0x7f}, single.Raw)
	assert.Empty(t, rest)
}

func TestNextRefuses(t *testing.T) {
	for _, c := range []struct {
		in   string
		want error
		text string
	}{
		{"", rlp.ErrTruncated, "rlp: truncated item"},
		{"83646f", rlp.ErrTruncated, "rlp: item extends past its input"},
		{"b9", rlp.ErrTruncated, "rlp: truncated length"},
		{"b901", rlp.ErrTruncated, "rlp: truncated length"},
		{"bfffffffffffffffff", rlp.ErrTruncated, "rlp: item extends past its input"},
		{"8100", rlp.ErrNonCanonical, "rlp: a single byte below 0x80 must encode itself"},
		{"817f", rlp.ErrNonCanonical, "rlp: a single byte below 0x80 must encode itself"},
		{"b800", rlp.ErrNonCanonical, "rlp: length with a leading zero byte"},
		{"b90038", rlp.ErrNonCanonical, "rlp: length with a leading zero byte"},
		{"b837", rlp.ErrNonCanonical, "rlp: long form for 55 bytes"},
		{"f801", rlp.ErrNonCanonical, "rlp: long form for 1 bytes"},
	} {
		_, _, err := rlp.Next(h(t, c.in))
		require.ErrorIs(t, err, c.want, c.in)
		assert.Equal(t, c.text, err.Error(), c.in)
	}
	// One byte at or above 0x80 needs its header.
	it, _, err := rlp.Next(h(t, "8180"))
	require.NoError(t, err)
	assert.Equal(t, []byte{0x80}, it.Payload)
}

func FuzzNextRoundTrip(f *testing.F) {
	f.Add([]byte{}, []byte("dog"))
	f.Add(bytes.Repeat([]byte{1}, 56), []byte{0x80})
	f.Add([]byte{0xf8, 0x38}, []byte{0})
	f.Fuzz(func(t *testing.T, a, b []byte) {
		enc := rlp.AppendList(nil, rlp.AppendString(nil, a), rlp.AppendString(nil, b))
		it, rest, err := rlp.Next(enc)
		require.NoError(t, err)
		require.Empty(t, rest)
		require.True(t, it.List)
		x, r, err := rlp.Next(it.Payload)
		require.NoError(t, err)
		require.True(t, bytes.Equal(a, x.Payload))
		y, r, err := rlp.Next(r)
		require.NoError(t, err)
		require.Empty(t, r)
		require.True(t, bytes.Equal(b, y.Payload))

		// Arbitrary input: no panic, and an accepted item re-encodes to itself.
		it, rest, err = rlp.Next(a)
		if err != nil {
			return
		}
		require.Equal(t, a, append(append([]byte{}, it.Raw...), rest...))
		if it.List {
			require.Equal(t, it.Raw, rlp.AppendList(nil, it.Payload))
		} else {
			require.Equal(t, it.Raw, rlp.AppendString(nil, it.Payload))
		}
	})
}
