package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/cosmos/cosmos-sdk/crypto/keyring"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/celestia/edictad"
	"github.com/vgonkivs/edicta/celestia/node"
	"github.com/vgonkivs/edicta/celestia/nodefake"
)

// adapters must run the compatibility check on the read-only reader and the
// consensus client before starting the signing client (TxClient and Fibre
// client). A refusal ends adapters with that error and closes what was opened.

type callLog struct {
	mu sync.Mutex
	l  []string
}

func (c *callLog) add(s string) { c.mu.Lock(); c.l = append(c.l, s); c.mu.Unlock() }
func (c *callLog) calls() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.l...)
}

type fakeConn struct {
	*nodefake.Consensus
	log *callLog
}

func (f fakeConn) Close() error { f.log.add("close consensus"); return nil }

type fakeCloser struct {
	log  *callLog
	name string
}

func (f fakeCloser) Close() error { f.log.add("close " + f.name); return nil }

type noSubmitter struct{}

func (noSubmitter) Address(context.Context) ([]byte, error) { return make([]byte, 20), nil }
func (noSubmitter) SubmitBlob(context.Context, []byte, []byte) (uint64, error) {
	return 0, errors.New("unused")
}

func recorderCfg(t *testing.T) edictad.Config {
	t.Helper()
	dir := t.TempDir()
	execPub, _, kerr := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, kerr)
	pass := filepath.Join(dir, "keyring.pass")
	require.NoError(t, os.WriteFile(pass, []byte("pw\n"), 0o600))
	ns := "00" + strings.Repeat("00", 18) + strings.Repeat("07", 10)
	toml := fmt.Sprintf(`
[network]
da = "celestia_blob"
chain_id = ""
min_app_version = 3
max_app_version = 10
[network.bridge]
addr = "bn.invalid:26658"
token_file = ""
tls = false
[network.consensus_grpc]
addr = "127.0.0.1:9090"
token_file = ""
tls = false
[recorder]
enabled = true
namespace = %q
keyring_dir = %q
keyring_backend = "file"
key_name = "recorder"
passphrase_file = %q
max_blob_bytes = 1048576
[recorder.quota]
blobs_per_hour = 60
bytes_per_day = 67108864
[archive]
dir = %q
[gate]
gate_id = "gate-1"
key_file = %q
registry_path = %q
action_types = ["application/vnd.edicta.test.v0+cbor"]
allowlist_file = %q
executor_keys = [%q]
anchor_verifier = "self"
[http]
listen = "127.0.0.1:0"
tls_cert_file = ""
tls_key_file = ""
authorize_token_file = ""
record_token_file = ""
allow_insecure = false
`, ns, filepath.Join(dir, "kr"), pass, filepath.Join(dir, "archive"), filepath.Join(dir, "gate.key"), filepath.Join(dir, "reg.db"),
		filepath.Join(dir, "agents.toml"), hex.EncodeToString(execPub))
	cfg, err := edictad.ParseConfig([]byte(toml))
	require.NoError(t, err)
	return cfg
}

func stubSeams(t *testing.T, log *callLog, checkErr error) {
	t.Helper()
	oc, oro, ock, okr, osg := newConsensusFn, newReadOnlyFn, checkFn, openKeyringFn, newSigningFn
	t.Cleanup(func() { newConsensusFn, newReadOnlyFn, checkFn, openKeyringFn, newSigningFn = oc, oro, ock, okr, osg })
	chain := nodefake.NewChain(nil)
	cons := nodefake.NewConsensus("chain-1")
	newConsensusFn = func(node.GRPCConfig) (consensusConn, error) {
		log.add("new consensus")
		return fakeConn{cons, log}, nil
	}
	newReadOnlyFn = func(context.Context, node.BridgeConfig) (io.Closer, node.Reader, error) {
		log.add("new read-only")
		return fakeCloser{log, "read-only"}, chain, nil
	}
	checkFn = func(context.Context, node.Reader, node.Consensus, node.Expect) (node.Header, error) {
		log.add("check")
		return node.Header{ChainID: "chain-1"}, checkErr
	}
	openKeyringFn = func(node.KeyringConfig) (keyring.Keyring, error) {
		log.add("open keyring")
		return keyring.NewInMemory(nil), nil
	}
	newSigningFn = func(context.Context, node.BridgeConfig, node.GRPCConfig, keyring.Keyring, string, string) (io.Closer, node.Reader, node.Submitter, error) {
		log.add("new signing")
		return fakeCloser{log, "signing"}, chain, noSubmitter{}, nil
	}
}

func indexOf(l []string, s string) int {
	for i, x := range l {
		if x == s {
			return i
		}
	}
	return -1
}

func TestCompatibilityCheckRunsBeforeTheSigningClient(t *testing.T) {
	var log callLog
	stubSeams(t, &log, nil)
	_, _, _, closeAll, err := adapters(context.Background(), recorderCfg(t), slog.New(slog.NewTextHandler(io.Discard, nil)))
	require.NoError(t, err)
	defer closeAll()
	calls := log.calls()
	chk, sign := indexOf(calls, "check"), indexOf(calls, "new signing")
	require.GreaterOrEqual(t, chk, 0, "calls: %v", calls)
	require.GreaterOrEqual(t, sign, 0, "calls: %v", calls)
	assert.Less(t, chk, sign, "calls: %v", calls)
}

func TestIncompatibleChainNeverStartsTheSigningClient(t *testing.T) {
	var log callLog
	stubSeams(t, &log, fmt.Errorf("%w: no x/valaddr", node.ErrUnsupported))
	_, _, _, closeAll, err := adapters(context.Background(), recorderCfg(t), slog.New(slog.NewTextHandler(io.Discard, nil)))
	require.ErrorIs(t, err, node.ErrUnsupported, "a clear compatibility error, not one from client.New")
	if closeAll != nil {
		closeAll()
	}
	calls := log.calls()
	assert.Equal(t, -1, indexOf(calls, "new signing"), "calls: %v", calls)
	assert.GreaterOrEqual(t, indexOf(calls, "close consensus"), 0, "what was opened is closed: %v", calls)
	assert.GreaterOrEqual(t, indexOf(calls, "close read-only"), 0, "what was opened is closed: %v", calls)
}
