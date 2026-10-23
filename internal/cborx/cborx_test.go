// SPDX-License-Identifier: Apache-2.0

package cborx_test

import (
	"fmt"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/internal/cborx"
)

func literalDec(t testing.TB, l cborx.Limits) cbor.DecMode {
	m, err := cbor.DecOptions{
		DupMapKey:         cbor.DupMapKeyEnforcedAPF,
		IndefLength:       cbor.IndefLengthForbidden,
		TagsMd:            cbor.TagsForbidden,
		UTF8:              cbor.UTF8RejectInvalid,
		ExtraReturnErrors: cbor.ExtraDecErrorUnknownField,
		MaxNestedLevels:   l.MaxNestedLevels,
		MaxArrayElements:  l.MaxArrayElements,
		MaxMapPairs:       l.MaxMapPairs,
	}.DecMode()
	require.NoError(t, err)
	return m
}

func TestStrictDecModeOptions(t *testing.T) {
	for _, l := range []cborx.Limits{{4, 16, 16}, {6, 1024, 1024}} {
		m, err := cborx.StrictDecMode(l)
		require.NoError(t, err)
		assert.Equal(t, literalDec(t, l).DecOptions(), m.DecOptions())
	}
}

func TestStrictDecModeRefusesLimitsOutOfRange(t *testing.T) {
	_, err := cborx.StrictDecMode(cborx.Limits{MaxNestedLevels: 1, MaxArrayElements: 16, MaxMapPairs: 16})
	assert.Error(t, err)
}

func TestCanonicalEncModeOptions(t *testing.T) {
	for _, nilEmpty := range []bool{false, true} {
		o := cbor.CoreDetEncOptions()
		o.IndefLength = cbor.IndefLengthForbidden
		if nilEmpty {
			o.NilContainers = cbor.NilContainerAsEmpty
		}
		want, err := o.EncMode()
		require.NoError(t, err)
		got, err := cborx.CanonicalEncMode(nilEmpty)
		require.NoError(t, err)
		assert.Equal(t, want.EncOptions(), got.EncOptions())
	}
	// Without the flag the encoder is exactly the library's core
	// deterministic one.
	core, err := cbor.CoreDetEncOptions().EncMode()
	require.NoError(t, err)
	got, err := cborx.CanonicalEncMode(false)
	require.NoError(t, err)
	assert.Equal(t, core.EncOptions(), got.EncOptions())
}

func TestCanonicalEncModeNilContainers(t *testing.T) {
	type v struct {
		B []byte `cbor:"1,keyasint"`
	}
	plain, err := cborx.CanonicalEncMode(false)
	require.NoError(t, err)
	empty, err := cborx.CanonicalEncMode(true)
	require.NoError(t, err)
	b, err := plain.Marshal(v{})
	require.NoError(t, err)
	assert.Equal(t, []byte{0xa1, 0x01, 0xf6}, b)
	b, err = empty.Marshal(v{})
	require.NoError(t, err)
	assert.Equal(t, []byte{0xa1, 0x01, 0x40}, b)
}

type shape struct {
	A uint64            `cbor:"1,keyasint"`
	B string            `cbor:"2,keyasint,omitempty"`
	C []byte            `cbor:"3,keyasint,omitempty"`
	D []uint64          `cbor:"4,keyasint,omitempty"`
	E map[string]uint64 `cbor:"5,keyasint,omitempty"`
}

func FuzzStrictDecModeMatchesLiteral(f *testing.F) {
	for _, s := range [][]byte{{0xa1, 0x01, 0x01}, {0xa2, 0x01, 0x01, 0x01, 0x02}, {0xbf, 0xff}, {0xc1, 0x01}, {0x62, 0xff, 0xfe}, {0xa1, 0x09, 0x01}} {
		f.Add(s)
	}
	l := cborx.Limits{MaxNestedLevels: 4, MaxArrayElements: 16, MaxMapPairs: 16}
	old := literalDec(f, l)
	m, err := cborx.StrictDecMode(l)
	require.NoError(f, err)
	f.Fuzz(func(t *testing.T, b []byte) {
		var x, y any
		e1, e2 := old.Unmarshal(b, &x), m.Unmarshal(b, &y)
		require.Equal(t, e1 == nil, e2 == nil)
		if e1 != nil {
			require.Equal(t, e1.Error(), e2.Error())
		}
		// NaN != NaN, so the decoded values are compared as printed.
		require.Equal(t, fmt.Sprintf("%#v", x), fmt.Sprintf("%#v", y))
		var s1, s2 shape
		e1, e2 = old.Unmarshal(b, &s1), m.Unmarshal(b, &s2)
		require.Equal(t, e1 == nil, e2 == nil)
		if e1 != nil {
			require.Equal(t, e1.Error(), e2.Error())
		}
		require.Equal(t, s1, s2)
	})
}
