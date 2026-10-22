// SPDX-License-Identifier: Apache-2.0

package config_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/celestia/config"
)

// edicta.toml refuses the Eden presets, so its refusal messages name only the
// USDC settlements and point Eden users to the signer file.
func TestSettlementRefusalHintsMatchWhatTheFileAccepts(t *testing.T) {
	for _, name := range []string{config.SettlementBase, "nope"} {
		_, err := config.Builtin{}.Settlement(name)
		require.ErrorIs(t, err, config.ErrPreset, name)
		assert.Contains(t, err.Error(), "base-sepolia", name)
		assert.Contains(t, err.Error(), "edicta-signer", name)
		assert.NotContains(t, err.Error(), `"eden-mainnet"`, name)
	}
}
