//go:build integration

package node

import (
	"bytes"
	"context"
	"encoding/hex"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	libshare "github.com/celestiaorg/go-square/v4/share"

	"github.com/celestiaorg/celestia-node/blob"

	"github.com/vgonkivs/edicta/celestia/secret"
)

// Environment (nothing is read from the repository; secrets only from files):
//
//	EDICTA_BN_ADDR            bridge node JSON-RPC address (required)
//	EDICTA_BN_TOKEN_FILE      file holding the bridge token (optional)
//	EDICTA_BN_TLS             "1" to use TLS to the bridge node
//	EDICTA_CORE_GRPC          consensus gRPC address (required)
//	EDICTA_CORE_TOKEN_FILE    file holding the gRPC x-token (optional)
//	EDICTA_CORE_TLS           "1" to use TLS to the consensus node
//	EDICTA_KEYRING_DIR        keyring directory (submit test)
//	EDICTA_KEY_NAME           key name in it (submit test)
//	EDICTA_KEYRING_BACKEND    "file" (default) or "test"
//	EDICTA_ALLOW_TEST_KEYRING "1" to permit the test backend
//	EDICTA_PASSPHRASE_FILE    file holding the file-backend passphrase
//	EDICTA_NAMESPACE          58 hex characters (submit test)
//	EDICTA_SUBMIT             "1" to allow spending a fee on a real blob
func liveCfg(t *testing.T) (BridgeConfig, GRPCConfig) {
	t.Helper()
	bn, core := os.Getenv("EDICTA_BN_ADDR"), os.Getenv("EDICTA_CORE_GRPC")
	if bn == "" || core == "" {
		t.Skip("EDICTA_BN_ADDR and EDICTA_CORE_GRPC not set")
	}
	tok := func(env string) string {
		p := os.Getenv(env)
		if p == "" {
			return ""
		}
		s, err := secret.FromFile(p)
		require.NoError(t, err)
		return s.RevealString()
	}
	return BridgeConfig{Addr: bn, Token: tok("EDICTA_BN_TOKEN_FILE"), TLS: os.Getenv("EDICTA_BN_TLS") == "1", AllowInsecureToken: LoopbackAddr(bn)},
		GRPCConfig{Addr: core, Token: tok("EDICTA_CORE_TOKEN_FILE"), TLS: os.Getenv("EDICTA_CORE_TLS") == "1",
			AllowInsecureToken: LoopbackAddr(core)}
}

func TestLiveCheck(t *testing.T) {
	b, g := liveCfg(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	rc, rd, err := NewReadOnly(ctx, b)
	require.NoError(t, err)
	defer rc.Close()
	cons, err := NewConsensus(g)
	require.NoError(t, err)
	defer cons.Close()

	head, err := Check(ctx, rd, cons, Expect{})
	require.NoError(t, err)
	t.Logf("chain %s height %d app %d", head.ChainID, head.Height, head.AppVersion)
	_, err = cons.BondDenom(ctx)
	require.NoError(t, err)
	_, err = cons.Bech32Prefix(ctx)
	require.NoError(t, err)
	if _, err := cons.FibreParams(ctx); err != nil {
		require.ErrorIs(t, err, ErrNotFound)
	}
}

func TestLiveSubmit(t *testing.T) {
	b, g := liveCfg(t)
	if os.Getenv("EDICTA_SUBMIT") != "1" {
		t.Skip("EDICTA_SUBMIT is not 1: this test spends a fee")
	}
	nsHex := os.Getenv("EDICTA_NAMESPACE")
	dir, name := os.Getenv("EDICTA_KEYRING_DIR"), os.Getenv("EDICTA_KEY_NAME")
	if nsHex == "" || dir == "" || name == "" {
		t.Skip("EDICTA_NAMESPACE, EDICTA_KEYRING_DIR, EDICTA_KEY_NAME not set")
	}
	ns, err := hex.DecodeString(nsHex)
	require.NoError(t, err)
	backend := os.Getenv("EDICTA_KEYRING_BACKEND")
	if backend == "" {
		backend = "file"
	}
	var pass []byte
	if p := os.Getenv("EDICTA_PASSPHRASE_FILE"); p != "" {
		s, err := secret.FromFile(p)
		require.NoError(t, err)
		pass = s.Reveal()
	}
	kr, err := OpenKeyring(KeyringConfig{Dir: dir, Name: name, Backend: backend,
		AllowTest: os.Getenv("EDICTA_ALLOW_TEST_KEYRING") == "1", Passphrase: pass})
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	cons, err := NewConsensus(g)
	require.NoError(t, err)
	defer cons.Close()
	network, err := cons.Network(ctx)
	require.NoError(t, err)
	c, rd, sub, err := NewSigning(ctx, b, g, kr, name, network)
	require.NoError(t, err)
	defer c.Close()

	signer, err := sub.Address(ctx)
	require.NoError(t, err)
	data := []byte("edicta integration " + time.Now().UTC().Format(time.RFC3339Nano))
	h, err := sub.SubmitBlob(ctx, ns, data)
	require.NoError(t, err)

	lns, err := libshare.NewNamespaceFromBytes(ns)
	require.NoError(t, err)
	local, err := blob.NewBlobV1(lns, data, signer)
	require.NoError(t, err)
	var got Blob
	for i := 0; i < 60; i++ {
		got, err = rd.Blob(ctx, h, ns, local.Commitment)
		if err == nil {
			break
		}
		require.ErrorIs(t, err, ErrNotFound)
		time.Sleep(time.Second)
	}
	require.NoError(t, err)
	require.Equal(t, data, got.Data)
	require.True(t, bytes.Equal(signer, got.Signer))
	require.EqualValues(t, 1, got.ShareVersion)
	t.Logf("blob at height %d", h)
}
