// SPDX-License-Identifier: Apache-2.0

package boltreg

import (
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"
)

// The retention record codecs keep the options they were written with; a
// shared helper must reproduce them exactly.
func TestRetentionCodecOptionsPinned(t *testing.T) {
	require.NoError(t, retCodecErr)
	enc, err := cbor.CoreDetEncOptions().EncMode()
	require.NoError(t, err)
	dec, err := cbor.DecOptions{DupMapKey: cbor.DupMapKeyEnforcedAPF, ExtraReturnErrors: cbor.ExtraDecErrorUnknownField}.DecMode()
	require.NoError(t, err)
	require.Equal(t, enc.EncOptions(), retEnc.EncOptions())
	require.Equal(t, dec.DecOptions(), retDec.DecOptions())
}
