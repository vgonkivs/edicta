// SPDX-License-Identifier: Apache-2.0

package signerd_test

import (
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/celestia/signerd"
)

var chainSources = regexp.MustCompile(`(?m)^(chain_id|rpc|settlement_rpc) = .*\n`)

// presetText is the payment configuration without the chain's id and sources.
func presetText(t *testing.T) string {
	t.Helper()
	f, payer := newFiles(t)
	text := paymentText(t, f, payer, "http://127.0.0.1:1", "https://rpc.eden.gateway.fm/")
	require.Regexp(t, chainSources, text)
	return chainSources.ReplaceAllString(text, "")
}

// A chain preset supplies the chain id and the sources, the first of which
// is a placeholder for the operator's own node: nothing validates until the
// operator replaces it.
func TestChainPresetFillsTheChainButRefusesThePlaceholder(t *testing.T) {
	text := strings.Replace(presetText(t), "[[chain]]\n", "[[chain]]\npreset = \"eden-mainnet\"\n", 1)

	cfg, err := signerd.ParseConfig([]byte(text))
	require.NoError(t, err)
	cfg.ApplyDefaults()
	require.Len(t, cfg.Chains, 1)
	assert.EqualValues(t, 714, cfg.Chains[0].ChainID)
	assert.Contains(t, cfg.Chains[0].RPC, "own-node=")
	assert.Equal(t, []string{"gateway=https://rpc.eden.gateway.fm"}, cfg.Chains[0].SettlementRPC)

	err = cfg.ValidateBasic()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "placeholder")
}

func TestChainPresetYieldsToWrittenSources(t *testing.T) {
	text := presetText(t)
	text = strings.Replace(text, "[[chain]]\n", "[[chain]]\npreset = \"eden-mainnet\"\nchain_id = 714\nrpc = \"own=http://127.0.0.1:1\"\nsettlement_rpc = [\"gateway=https://rpc.eden.gateway.fm/\"]\n", 1)
	require.NoError(t, validate(text))
}

func TestChainPresetRefusals(t *testing.T) {
	for name, tc := range map[string]struct{ lines, want string }{
		"a chain id of another chain":   {"preset = \"eden-mainnet\"\nchain_id = 3735928814\nrpc = \"own=http://127.0.0.1:1\"\nsettlement_rpc = [\"gateway=https://rpc.eden.gateway.fm/\"]", "is for chain 714"},
		"an unknown preset":             {"preset = \"eden-nope\"\nchain_id = 714", "preset"},
		"a non-Eden preset":             {"preset = \"base-sepolia\"\nchain_id = 714\nrpc = \"own=http://127.0.0.1:1\"\nsettlement_rpc = [\"gateway=https://rpc.eden.gateway.fm/\"]", "not an Eden preset"},
		"a placeholder written by hand": {"chain_id = 714\nrpc = \"own=https://x.operator-fills-this-in.invalid\"\nsettlement_rpc = [\"gateway=https://rpc.eden.gateway.fm/\"]", "placeholder"},
	} {
		t.Run(name, func(t *testing.T) {
			text := strings.Replace(presetText(t), "[[chain]]\n", "[[chain]]\n"+tc.lines+"\n", 1)
			err := validate(text)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
		})
	}
}

// The operator replaces only the placeholder own node; the preset still
// supplies the public source, so L1 has its two operators.
func TestChainPresetKeepsThePublicSourceWhenOwnRPCIsWritten(t *testing.T) {
	text := strings.Replace(presetText(t), "[[chain]]\n", "[[chain]]\npreset = \"eden-mainnet\"\nrpc = \"own=http://127.0.0.1:1\"\n", 1)
	require.NoError(t, validate(text))

	cfg, err := signerd.ParseConfig([]byte(text))
	require.NoError(t, err)
	cfg.ApplyDefaults()
	assert.Equal(t, []string{"gateway=https://rpc.eden.gateway.fm"}, cfg.Chains[0].SettlementRPC)

	other := strings.Replace(text, "preset = \"eden-mainnet\"\n", "preset = \"eden-mainnet\"\nsettlement_rpc = [\"mine=https://eden.example.org\"]\n", 1)
	cfg, err = signerd.ParseConfig([]byte(other))
	require.NoError(t, err)
	cfg.ApplyDefaults()
	assert.Equal(t, []string{"mine=https://eden.example.org"}, cfg.Chains[0].SettlementRPC, "written sources win")
}
