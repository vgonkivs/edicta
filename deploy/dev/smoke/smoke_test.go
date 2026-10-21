// SPDX-License-Identifier: Apache-2.0

//go:build composesmoke

// Package smoke checks a running dev stack. It is skipped unless the build tag
// composesmoke is set and EDICTA_DEV_SMOKE=1, so unit test runs stay free of
// the network and of docker:
//
//	cd deploy/dev && docker compose --profile dev up -d --build --wait
//	EDICTA_DEV_SMOKE=1 go test -tags composesmoke -count=1 ./deploy/dev/smoke
package smoke

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/edictaapi"
)

const (
	devCelestiaChainID = "edicta-dev-1"
	devGateID          = "edicta-dev-gate"
	devNamespaceID     = "edictadev1"
	devEdenChainIDHex  = "0x7a69"
	payerWeiHex        = "0x3635c9adc5dea00000"
)

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func requireStack(t *testing.T) {
	t.Helper()
	if os.Getenv("EDICTA_DEV_SMOKE") != "1" {
		t.Skip("set EDICTA_DEV_SMOKE=1 with the dev stack up to run this")
	}
}

// compose runs docker compose in deploy/dev.
func compose(t *testing.T, args ...string) string {
	t.Helper()
	dir, err := filepath.Abs("..")
	require.NoError(t, err)
	cmd := exec.Command("docker", append([]string{"compose", "--profile", "dev"}, args...)...)
	cmd.Dir = dir
	var out, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &stderr
	require.NoError(t, cmd.Run(), stderr.String())
	return out.String()
}

func ethCall(t *testing.T, method string, params ...any) string {
	t.Helper()
	if params == nil {
		params = []any{}
	}
	body, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
	require.NoError(t, err)
	url := "http://127.0.0.1:" + env("EDEN_RPC_PORT", "18545")
	resp, err := http.Post(url, "application/json", bytes.NewReader(body))
	require.NoError(t, err)
	defer resp.Body.Close()
	var out struct {
		Result string `json:"result"`
		Error  any    `json:"error"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
	require.Nil(t, out.Error)
	return out.Result
}

func hexNum(t *testing.T, s string) uint64 {
	t.Helper()
	n, err := strconv.ParseUint(strings.TrimPrefix(s, "0x"), 16, 64)
	require.NoError(t, err)
	return n
}

func TestEdenDevChain(t *testing.T) {
	requireStack(t)
	require.Equal(t, devEdenChainIDHex, ethCall(t, "eth_chainId"))

	first := hexNum(t, ethCall(t, "eth_blockNumber"))
	require.Eventually(t, func() bool { return hexNum(t, ethCall(t, "eth_blockNumber")) > first }, 15*time.Second, 500*time.Millisecond,
		"the sequencer produces blocks")

	accounts := compose(t, "exec", "-T", "edictad", "cat", "/dev-home/accounts.env")
	var payer string
	for _, l := range strings.Split(accounts, "\n") {
		if v, ok := strings.CutPrefix(l, "PAYER_ADDRESS="); ok {
			payer = v
		}
	}
	require.NotEmpty(t, payer)
	require.Equal(t, payerWeiHex, ethCall(t, "eth_getBalance", payer, "latest"), "the payer is prefunded with 1000 TIA")
}

func TestCelestiaDevnet(t *testing.T) {
	requireStack(t)
	status := func() (chain, app string, height uint64) {
		out := compose(t, "exec", "-T", "celestia", "wget", "-qO-", "http://127.0.0.1:26657/status")
		var s struct {
			Result struct {
				NodeInfo struct {
					Network  string `json:"network"`
					Protocol struct {
						App string `json:"app"`
					} `json:"protocol_version"`
				} `json:"node_info"`
				SyncInfo struct {
					Height string `json:"latest_block_height"`
				} `json:"sync_info"`
			} `json:"result"`
		}
		require.NoError(t, json.Unmarshal([]byte(out), &s))
		h, err := strconv.ParseUint(s.Result.SyncInfo.Height, 10, 64)
		require.NoError(t, err)
		return s.Result.NodeInfo.Network, s.Result.NodeInfo.Protocol.App, h
	}
	chain, app, h0 := status()
	require.Equal(t, devCelestiaChainID, chain)
	require.Equal(t, "10", app, "the devnet runs app version 10")
	require.Eventually(t, func() bool { _, _, h := status(); return h > h0 }, 30*time.Second, time.Second,
		"the devnet produces blocks")
}

func TestEdictadFastMode(t *testing.T) {
	requireStack(t)
	c, err := edictaapi.NewClient("http://127.0.0.1:"+env("EDICTAD_PORT", "18480"), edictaapi.NewSecret(""), nil, nil)
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	h, err := c.Health(ctx)
	require.NoError(t, err)
	require.Equal(t, devCelestiaChainID, h.ChainID)
	require.Equal(t, devGateID, h.GateID)
	require.NotZero(t, h.HeadHeight)
	require.Len(t, h.GatePubKey, 32)
	require.Contains(t, h.AllowedDA, uint64(2), "fast mode serves da = 2")
	require.True(t, strings.HasSuffix(hex.EncodeToString(h.Namespace), hex.EncodeToString([]byte(devNamespaceID))))
	fmt.Println("edictad health: head", h.HeadHeight, "status", h.Status)
}
