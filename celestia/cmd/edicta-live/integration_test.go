//go:build integration

package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/celestia/node"
	"github.com/vgonkivs/edicta/celestia/secret"
	"github.com/vgonkivs/edicta/examples/tia-transfer/pricefeed"
)

// End-to-end run against a real edictad and a real network. It skips unless
// the environment is set, and it spends fees and funds, so it also needs
// EDICTA_LIVE_WRITE=1. Nothing is read from the repository; secrets only from
// files.
//
//	EDICTA_API_URL                     edictad base URL (required)
//	EDICTA_API_TOKEN_FILE              edictad bearer token file (optional)
//	EDICTA_GATE_PUBKEY                 pin of the gate public key, 64 hex (advised)
//	EDICTA_BN_ADDR, _TOKEN_FILE, _TLS  bridge node (same names as the node tests)
//	EDICTA_CORE_GRPC, _TOKEN_FILE, _TLS consensus gRPC
//	EDICTA_AGENT_ID, EDICTA_AGENT_KEY_FILE
//	EDICTA_EXECUTOR_KEYRING_DIR, EDICTA_EXECUTOR_KEY, EDICTA_EXECUTOR_PASSPHRASE_FILE
//	EDICTA_EXECUTOR_ED25519_FILE       record-request key (its public key is in edictad's executor_keys)
//	EDICTA_UP_ADDR, EDICTA_DOWN_ADDR   destinations of the two branches
//	EDICTA_LIVE_WRITE                  "1" to allow spending
//
// The price is scripted here (the command never takes a fake feed): the first
// reading is the baseline and the second moves it by 2 percent, so the
// decision is made at once.
func liveConfig(t *testing.T) Config {
	t.Helper()
	api := os.Getenv("EDICTA_API_URL")
	if api == "" {
		t.Skip("EDICTA_API_URL not set")
	}
	if os.Getenv("EDICTA_LIVE_WRITE") != "1" {
		t.Skip("EDICTA_LIVE_WRITE=1 is required: this test publishes a blob and moves funds")
	}
	need := func(name string) string {
		v := os.Getenv(name)
		require.NotEmptyf(t, v, "%s is required", name)
		return v
	}
	c := Config{
		APIURL: api, APITokenFile: os.Getenv("EDICTA_API_TOKEN_FILE"), GatePubKey: os.Getenv("EDICTA_GATE_PUBKEY"),
		BridgeAddr: need("EDICTA_BN_ADDR"), BridgeTokenFile: os.Getenv("EDICTA_BN_TOKEN_FILE"), BridgeTLS: os.Getenv("EDICTA_BN_TLS") == "1",
		GRPCAddr: need("EDICTA_CORE_GRPC"), GRPCTokenFile: os.Getenv("EDICTA_CORE_TOKEN_FILE"), GRPCTLS: os.Getenv("EDICTA_CORE_TLS") == "1",
		Inclusion: "self",
		AgentID:   need("EDICTA_AGENT_ID"), AgentKeyFile: need("EDICTA_AGENT_KEY_FILE"),
		GenRecipient: filepath.Join(t.TempDir(), "recipient.key"),
		StrategyID:   "edicta-live-it", ThresholdBP: 100, MaxDecisions: 1,
		PollInterval: time.Second, Timeout: 20 * time.Minute, SkewS: defaultSkewS,
		PriceSource: "coingecko", PriceAsset: "celestia", PriceQuote: "USD",
		UpAddr: need("EDICTA_UP_ADDR"), UpAmount: 1, DownAddr: need("EDICTA_DOWN_ADDR"), DownAmount: 1,
		ExecKeyringDir: need("EDICTA_EXECUTOR_KEYRING_DIR"), ExecKeyName: need("EDICTA_EXECUTOR_KEY"),
		ExecPassFile: need("EDICTA_EXECUTOR_PASSPHRASE_FILE"), ExecEd25519File: need("EDICTA_EXECUTOR_ED25519_FILE"),
		GasLimit: 150000, Fee: 500, MaxFee: 1000, Rebroadcast: 10 * time.Second,
	}
	require.NoError(t, c.Validate())
	return c
}

func scriptedMove() *pricefeed.Fake {
	f := pricefeed.NewFake()
	now := uint64(time.Now().Unix())
	for _, p := range []uint64{100_00000000, 102_00000000} {
		f.Push(pricefeed.Observation{Source: "scripted:integration-test", AssetID: "celestia", Quote: "USD",
			Price: p, ObservedAt: now, FetchedAt: now})
	}
	return f
}

func runLive(t *testing.T, c Config) *Evidence {
	t.Helper()
	var got []*Evidence
	var logs bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Minute)
	defer cancel()
	err := live(ctx, c, runEnv{Out: &bytes.Buffer{}, Log: &logs, Stdin: os.Stdin, Feed: scriptedMove(),
		Collected: func(e *Evidence) { got = append(got, e) }})
	t.Log(logs.String())
	require.NoError(t, err)
	require.Len(t, got, 1)
	return got[0]
}

// TestLiveEndToEnd checks acceptance criterion 5: a blob at height H, the
// transfer at a height above H with memo = commitment_hash, and the
// Authorization and receipt verified.
func TestLiveEndToEnd(t *testing.T) {
	c := liveConfig(t)
	ev := runLive(t, c)

	require.NoError(t, ev.Check())
	assert.Greater(t, ev.Transfer.Height, ev.BlobHeight, "transfer is included above the blob height")
	assert.Equal(t, ev.CommitmentHash, ev.Transfer.Memo, "memo is the commitment_hash")
	assert.True(t, ev.Authorization.Verified)
	assert.True(t, ev.Receipt.Verified)
	assert.Zero(t, ev.Transfer.Code)

	// Ask the chain again, independently of the run.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	tok := func(p string) string {
		if p == "" {
			return ""
		}
		s, err := secret.FromFile(p)
		require.NoError(t, err)
		return s.RevealString()
	}
	cons, err := node.NewConsensus(node.GRPCConfig{Addr: c.GRPCAddr, TLS: c.GRPCTLS, Token: tok(c.GRPCTokenFile), AllowInsecureToken: loopbackAddr(c.GRPCAddr)})
	require.NoError(t, err)
	defer cons.Close()
	raw, err := hex.DecodeString(ev.Transfer.TxHash)
	require.NoError(t, err)
	var h [32]byte
	copy(h[:], raw)
	st, err := cons.Tx(ctx, h)
	require.NoError(t, err)
	require.True(t, st.Found)
	assert.Equal(t, ev.Transfer.Height, st.Height)
	assert.Zero(t, st.Code)

	rc, rd, err := node.NewReadOnly(ctx, node.BridgeConfig{Addr: c.BridgeAddr, Token: tok(c.BridgeTokenFile), TLS: c.BridgeTLS})
	require.NoError(t, err)
	defer rc.Close()
	hd, err := rd.HeaderAt(ctx, ev.BlobHeight)
	require.NoError(t, err)
	assert.Equal(t, uint64(hd.Time.Unix()), ev.BlobTime, "block time at H")
	assert.Equal(t, ev.ChainID, hd.ChainID)
}

// TestLiveDryRun publishes and authorizes but does not broadcast.
func TestLiveDryRun(t *testing.T) {
	c := liveConfig(t)
	c.DryRun = true
	ev := runLive(t, c)
	require.NoError(t, ev.Check())
	assert.True(t, ev.DryRun)
	assert.False(t, ev.Transfer.Broadcast)
	assert.Zero(t, ev.Transfer.Height)
	assert.Equal(t, ev.CommitmentHash, ev.Transfer.Memo)
}
