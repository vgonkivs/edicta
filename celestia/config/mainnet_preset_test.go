// SPDX-License-Identifier: Apache-2.0

package config_test

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/celestia/config"
	"github.com/vgonkivs/edicta/plugins/edenescrow"
)

func TestIsPlaceholder(t *testing.T) {
	for addr, want := range map[string]bool{
		"bridge.operator-fills-this-in.invalid":            true,
		"consensus-grpc.operator-fills-this-in.invalid:90": true,
		"https://x.invalid/path":                           true,
		"own-node=https://eden-rpc.example.INVALID":        true,
		"https://host.invalid./":                           true,
		"https://rpc.eden.gateway.fm":                      false,
		"gateway=https://rpc.eden.gateway.fm":              false,
		"grpc-mocha.pops.one:9090":                         false,
		"public-endpoint.celestia-mocha.quiknode.pro":      false,
		"https://invalid.example.org":                      false,
		"https://example.org/?q=a.invalid":                 false,
		"":                                                 false,
	} {
		assert.Equal(t, want, config.IsPlaceholder(addr), "%q", addr)
	}
}

func TestCelestiaMainnetPreset(t *testing.T) {
	p, err := config.Builtin{}.Celestia(config.CelestiaMainnet)
	require.NoError(t, err)
	assert.Equal(t, "celestia", p.ChainID)
	assert.NotZero(t, p.Version)
	assert.Empty(t, p.FaucetURL, "mainnet has no faucet")
	assert.NotEmpty(t, p.CometRPC)
	for _, u := range p.CometRPC {
		assert.False(t, config.IsPlaceholder(u), u)
	}
	assert.True(t, config.IsPlaceholder(p.Bridge.Addr), "the bridge is the operator's to fill in")
	assert.True(t, config.IsPlaceholder(p.ConsensusGRPC.Addr), "the gRPC endpoint is the operator's to fill in")

	q, err := config.Builtin{}.Celestia(config.CelestiaMainnet)
	require.NoError(t, err)
	q.CometRPC[0] = "changed"
	assert.NotEqual(t, "changed", p.CometRPC[0], "each call returns its own copy")
}

func mainnetConfig(t *testing.T, ov map[string]string) config.Config {
	t.Helper()
	all := map[string]string{"network.celestia": "celestia-mainnet", "network.settlement": "none"}
	for k, v := range ov {
		all[k] = v
	}
	c, err := config.Parse([]byte(selfHosted), all)
	require.NoError(t, err)
	require.NoError(t, c.ApplyDefaults(config.Builtin{}))
	return c
}

func TestMainnetNetworkRefusesPlaceholdersUntilFilled(t *testing.T) {
	c := mainnetConfig(t, nil)
	assert.Equal(t, "celestia", c.Network.ChainID)
	err := c.Network.ValidateBasic()
	require.ErrorIs(t, err, config.ErrConfig)
	assert.Contains(t, err.Error(), "placeholder")

	c = mainnetConfig(t, map[string]string{"network.bridge.addr": `"bridge.example.org"`})
	err = c.Network.ValidateBasic()
	require.ErrorIs(t, err, config.ErrConfig)
	assert.Contains(t, err.Error(), "consensus_grpc")

	c = mainnetConfig(t, map[string]string{
		"network.bridge.addr":         `"bridge.example.org"`,
		"network.consensus_grpc.addr": `"grpc.example.org:9090"`,
	})
	require.NoError(t, c.Network.ValidateBasic())

	c = mainnetConfig(t, map[string]string{
		"network.bridge.addr":         `"bridge.example.org"`,
		"network.consensus_grpc.addr": `"grpc.example.org:9090"`,
		"network.comet_rpc":           `["https://x.invalid"]`,
	})
	require.ErrorIs(t, c.Network.ValidateBasic(), config.ErrConfig)
}

func TestEdenPresetsCarryTheCompiledEscrowTable(t *testing.T) {
	for name, chain := range map[string]uint64{config.SettlementEdenMainnet: 714, config.SettlementEdenTestnet: 3735928814} {
		p, err := config.Builtin{}.Settlement(name)
		require.NoError(t, err, name)
		row, ok := edenescrow.Lookup(chain)
		require.True(t, ok, name)
		assert.Equal(t, chain, p.EVMChainID, name)
		assert.Equal(t, "0x"+hex.EncodeToString(row.Escrow[:]), p.Escrow, name)
		assert.Equal(t, "0x"+hex.EncodeToString(row.CodeHash[:]), p.EscrowCodeHash, name)
		assert.True(t, p.IsEscrow(), name)
		require.NotEmpty(t, p.RPC, name)
		assert.True(t, config.IsPlaceholder(p.RPC[0]), "%s: the first source is the operator's own node", name)
		assert.Empty(t, p.USDC.Address, name)
	}
	main, err := config.Builtin{}.Settlement(config.SettlementEdenMainnet)
	require.NoError(t, err)
	assert.Equal(t, "0x65d77c98e73dfbea91ecb72b27c9753e186a94c8", main.Escrow)
	test, err := config.Builtin{}.Settlement(config.SettlementEdenTestnet)
	require.NoError(t, err)
	assert.Equal(t, "0xe851a9b22d949ae005f65e1ba97c9b0c18354e5d", test.Escrow)
	assert.Equal(t, main.EscrowCodeHash, test.EscrowCodeHash)

	usdc, err := config.Builtin{}.Settlement(config.SettlementBaseSepolia)
	require.NoError(t, err)
	assert.False(t, usdc.IsEscrow())
}

func TestEdenSettlementIsNotConfiguredInTheUSDCFile(t *testing.T) {
	for _, s := range []string{config.SettlementEdenMainnet, config.SettlementEdenTestnet} {
		c, err := config.Parse([]byte(selfHosted), map[string]string{"network.settlement": s})
		require.NoError(t, err)
		require.NoError(t, c.ApplyDefaults(config.Builtin{}))
		err = c.Network.ValidateBasic()
		require.ErrorIs(t, err, config.ErrConfig, s)
		assert.Contains(t, err.Error(), "edicta-signer", s)
	}
}

func TestPresetVersionsCoverTheNewPresets(t *testing.T) {
	c := mainnetConfig(t, map[string]string{"network.settlement": config.SettlementEdenMainnet})
	v, err := c.Versions(config.Builtin{})
	require.NoError(t, err)
	assert.NotZero(t, v.Celestia)
	assert.NotZero(t, v.Settlement)
}
