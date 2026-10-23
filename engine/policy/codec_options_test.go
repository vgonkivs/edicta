// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"
)

func pinnedEncOptions(t *testing.T) cbor.EncOptions {
	m, err := cbor.EncOptions{
		Sort:          cbor.SortCoreDeterministic,
		ShortestFloat: cbor.ShortestFloat16,
		NilContainers: cbor.NilContainerAsEmpty,
		IndefLength:   cbor.IndefLengthForbidden,
	}.EncMode()
	require.NoError(t, err)
	return m.EncOptions()
}

func pinnedDecOptions(t *testing.T) cbor.DecOptions {
	m, err := cbor.DecOptions{
		DupMapKey:         cbor.DupMapKeyEnforcedAPF,
		IndefLength:       cbor.IndefLengthForbidden,
		TagsMd:            cbor.TagsForbidden,
		UTF8:              cbor.UTF8RejectInvalid,
		ExtraReturnErrors: cbor.ExtraDecErrorUnknownField,
		MaxNestedLevels:   6,
		MaxArrayElements:  1024,
		MaxMapPairs:       1024,
	}.DecMode()
	require.NoError(t, err)
	return m.DecOptions()
}

// The codec options are the ones the format was frozen with; a shared
// helper must reproduce them exactly.
func TestCodecOptionsPinned(t *testing.T) {
	require.NoError(t, codecErr)
	require.Equal(t, pinnedEncOptions(t), encMode.EncOptions())
	require.Equal(t, pinnedDecOptions(t), decMode.DecOptions())
}
