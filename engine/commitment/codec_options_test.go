// SPDX-License-Identifier: Apache-2.0

package commitment

import (
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"
)

func pinnedEncOptions(t *testing.T) cbor.EncOptions {
	o := cbor.CoreDetEncOptions()
	o.IndefLength = cbor.IndefLengthForbidden
	o.NilContainers = cbor.NilContainerAsEmpty
	m, err := o.EncMode()
	require.NoError(t, err)
	return m.EncOptions()
}

// The encoder options are the ones the format was frozen with; a shared
// helper must reproduce them exactly.
func TestCodecOptionsPinned(t *testing.T) {
	require.NoError(t, encModeErr)
	require.Equal(t, pinnedEncOptions(t), encMode.EncOptions())
}
