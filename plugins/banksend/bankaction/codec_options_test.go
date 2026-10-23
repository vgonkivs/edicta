// SPDX-License-Identifier: Apache-2.0

package bankaction

import (
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"
)

func pinnedEncOptions(t *testing.T) cbor.EncOptions {
	o := cbor.CoreDetEncOptions()
	o.IndefLength = cbor.IndefLengthForbidden
	m, err := o.EncMode()
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
		MaxNestedLevels:   4,
		MaxArrayElements:  16,
		MaxMapPairs:       16,
	}.DecMode()
	require.NoError(t, err)
	return m.DecOptions()
}

// The codec options are the ones the format was frozen with; a shared
// helper must reproduce them exactly.
func TestCodecOptionsPinned(t *testing.T) {
	require.NoError(t, encModeErr)
	require.NoError(t, decModeErr)
	require.Equal(t, pinnedEncOptions(t), encMode.EncOptions())
	require.Equal(t, pinnedDecOptions(t), decMode.DecOptions())
}
