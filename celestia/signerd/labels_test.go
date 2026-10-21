// SPDX-License-Identifier: Apache-2.0

package signerd_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/celestia/signerd"
)

// Sources take OPERATOR=URL; the label must be printable ASCII without
// spaces.
func TestConfigOperatorLabels(t *testing.T) {
	f, payer := newFiles(t)
	check := func(rpc, extra string) error {
		text := configText(f, payer, rpc)
		if extra != "" {
			text = strings.Replace(text, "rpc = ", extra+"\nrpc = ", 1)
		}
		cfg, err := signerd.ParseConfig([]byte(text))
		require.NoError(t, err)
		cfg.ApplyDefaults()
		return cfg.ValidateBasic()
	}
	require.NoError(t, check("own=http://127.0.0.1:1", `settlement_rpc = ["gateway=https://rpc.eden.gateway.fm/"]`))
	require.NoError(t, check("http://127.0.0.1:1/?a=b", ""))
	assert.Error(t, check("bad label=http://127.0.0.1:1", ""))
	assert.Error(t, check("own=ftp://127.0.0.1:1", ""))
	assert.Error(t, check("http://127.0.0.1:1", `settlement_rpc = ["gw=not a url"]`))
}
