// SPDX-License-Identifier: Apache-2.0

package verifycli

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWithPresetSources(t *testing.T) {
	t.Run("the public source is added, the placeholder own node is not", func(t *testing.T) {
		got, err := withPresetSources("eden-mainnet", nil, nil)
		require.NoError(t, err)
		assert.Equal(t, []string{"gateway=https://rpc.eden.gateway.fm"}, got)
	})
	t.Run("a host already given is not added twice", func(t *testing.T) {
		have := []string{"mine=https://rpc.eden.gateway.fm/"}
		got, err := withPresetSources("eden-mainnet", have, nil)
		require.NoError(t, err)
		assert.Equal(t, have, got)
		got, err = withPresetSources("eden-mainnet", nil, []string{"https://RPC.eden.gateway.fm:443/x"})
		require.NoError(t, err)
		assert.Empty(t, got)
	})
	t.Run("the testnet preset brings no usable source of its own", func(t *testing.T) {
		got, err := withPresetSources("eden-testnet", []string{"a=https://a.example"}, nil)
		require.NoError(t, err)
		assert.Equal(t, []string{"a=https://a.example"}, got)
	})
	t.Run("only Eden presets", func(t *testing.T) {
		for _, name := range []string{"base-sepolia", "none", "nope", "eden"} {
			_, err := withPresetSources(name, nil, nil)
			require.Error(t, err, name)
		}
	})
}

func TestSettlementPresetNeedsSettlement(t *testing.T) {
	err := settlementFlags{preset: "eden-mainnet"}.validate("verify", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--settlement-preset")
}
