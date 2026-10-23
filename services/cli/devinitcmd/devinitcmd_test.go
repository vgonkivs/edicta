// SPDX-License-Identifier: Apache-2.0

//go:build edictadev

package devinitcmd

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	payer       = "0x5fcec1e1aafdccff8031034663665008c0de7fc3"
	facilitator = "0xfc463b645cfd4946034511b2da28db73e7b2c029"
	escrow      = "0x00000000000000000000000000000000000000e5"
)

type genesisDoc struct {
	Config map[string]any `json:"config"`
	Alloc  map[string]struct {
		Balance string `json:"balance"`
		Code    string `json:"code"`
	} `json:"alloc"`
}

func parse(t *testing.T, raw []byte) genesisDoc {
	t.Helper()
	var g genesisDoc
	require.NoError(t, json.Unmarshal(raw, &g))
	return g
}

func TestEdenGenesisFundsTheDevAccounts(t *testing.T) {
	raw, err := buildEdenGenesis(31337, payer, facilitator, escrowSlot{})
	require.NoError(t, err)
	g := parse(t, raw)

	assert.EqualValues(t, 31337, g.Config["chainId"])
	assert.EqualValues(t, 0, g.Config["pragueTime"])
	assert.EqualValues(t, 0, g.Config["osakaTime"])
	require.Len(t, g.Alloc, 2, "no escrow entry while the slot is a placeholder")
	assert.Equal(t, "0x3635c9adc5dea00000", g.Alloc[strings.TrimPrefix(payer, "0x")].Balance, "1000 TIA")
	assert.Equal(t, "0x8ac7230489e80000", g.Alloc[strings.TrimPrefix(facilitator, "0x")].Balance, "10 TIA")
}

func TestEdenGenesisCarriesTheEscrowCodeWhenGiven(t *testing.T) {
	raw, err := buildEdenGenesis(31337, payer, facilitator, escrowSlot{Address: escrow, Code: []byte{0x60, 0x80}})
	require.NoError(t, err)
	g := parse(t, raw)
	e := g.Alloc[strings.TrimPrefix(escrow, "0x")]
	assert.Equal(t, "0x6080", e.Code)
	assert.Equal(t, "0x0", e.Balance)
}

func TestEdenGenesisRefusesBadInput(t *testing.T) {
	cases := map[string]struct {
		chain       uint64
		payer, fac  string
		slot        escrowSlot
		errContains string
	}{
		"zero chain":        {0, payer, facilitator, escrowSlot{}, "chain id"},
		"short payer":       {1, "0x12", facilitator, escrowSlot{}, "payer"},
		"code, no address":  {1, payer, facilitator, escrowSlot{Code: []byte{1}}, "go together"},
		"address, no code":  {1, payer, facilitator, escrowSlot{Address: escrow}, "go together"},
		"bad escrow":        {1, payer, facilitator, escrowSlot{Address: "0xzz", Code: []byte{1}}, "escrow address"},
		"escrow on payer":   {1, payer, facilitator, escrowSlot{Address: payer, Code: []byte{1}}, "collides"},
		"upper-case dup":    {1, payer, facilitator, escrowSlot{Address: "0x" + strings.ToUpper(payer[2:]), Code: []byte{1}}, "collides"},
		"short facilitator": {1, payer, "nope", escrowSlot{}, "facilitator"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := buildEdenGenesis(c.chain, c.payer, c.fac, c.slot)
			require.Error(t, err)
			assert.Contains(t, err.Error(), c.errContains)
		})
	}
}

func TestRunWritesOnceAndMarksThePlaceholder(t *testing.T) {
	home := filepath.Join(t.TempDir(), "dev")
	var first bytes.Buffer
	require.NoError(t, run([]string{"--home", home}, &first, io.Discard))
	assert.Contains(t, first.String(), "DEV ONLY")
	assert.Contains(t, first.String(), "edicta-dev-1")
	assert.Contains(t, first.String(), "31337")
	assert.Contains(t, first.String(), "PLACEHOLDER")
	assert.Contains(t, first.String(), "(created)")

	genesis := filepath.Join(home, "genesis", "eden-genesis.json")
	before, err := os.ReadFile(genesis)
	require.NoError(t, err)

	var second bytes.Buffer
	require.NoError(t, run([]string{"--home", home}, &second, io.Discard))
	assert.Contains(t, second.String(), "(exists)")
	after, err := os.ReadFile(genesis)
	require.NoError(t, err)
	assert.Equal(t, before, after)

	jwt, err := os.ReadFile(filepath.Join(home, "genesis", "jwt.hex"))
	require.NoError(t, err)
	assert.Len(t, strings.TrimSpace(string(jwt)), 64)
}

func TestRunPutsTheEscrowCodeInTheGenesis(t *testing.T) {
	home := filepath.Join(t.TempDir(), "dev")
	code := filepath.Join(t.TempDir(), "escrow.hex")
	require.NoError(t, os.WriteFile(code, []byte("0x6080\n"), 0o600))
	var out bytes.Buffer
	require.NoError(t, run([]string{"--home", home, "--escrow-address", escrow, "--escrow-code-file", code}, &out, io.Discard))
	assert.NotContains(t, out.String(), "PLACEHOLDER")

	raw, err := os.ReadFile(filepath.Join(home, "genesis", "eden-genesis.json"))
	require.NoError(t, err)
	assert.Equal(t, "0x6080", parse(t, raw).Alloc[strings.TrimPrefix(escrow, "0x")].Code)
}

func TestRunRefusesBadFlags(t *testing.T) {
	var out bytes.Buffer
	assert.Error(t, run([]string{}, &out, io.Discard), "home is required")
	assert.Error(t, run([]string{"--home", t.TempDir(), "--escrow-address", escrow}, &out, io.Discard), "address without code")
	assert.Error(t, run([]string{"--home", t.TempDir(), "extra"}, &out, io.Discard))
}
