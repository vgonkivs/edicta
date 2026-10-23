// SPDX-License-Identifier: Apache-2.0

package initcmd_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/config"
	"github.com/vgonkivs/edicta/services/cli/initcmd"
)

func TestMainnetAndEdenPresetsWriteNothingUntilTheOperatorFillsThemIn(t *testing.T) {
	for name, preset := range map[string]string{
		"mainnet placeholders":     "celestia-mainnet+none",
		"eden is not a USDC chain": "mocha+eden-mainnet",
		"eden testnet on mainnet":  "celestia-mainnet+eden-testnet",
	} {
		t.Run(name, func(t *testing.T) {
			home := filepath.Join(t.TempDir(), "edicta")
			_, err := initcmd.Run(context.Background(), initcmd.Config{Home: home, Preset: preset}, healthyEnv("mocha-5"), nil)
			require.ErrorIs(t, err, config.ErrConfig)
			assert.NoDirExists(t, home)
		})
	}
}
