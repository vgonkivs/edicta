package wire

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cosmos/cosmos-sdk/crypto/keyring"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/celestia/edictad"
	"github.com/vgonkivs/edicta/celestia/node"
	"github.com/vgonkivs/edicta/celestia/nodefake"
	"github.com/vgonkivs/edicta/celestia/test/fibrefix"
)

const consensusAddr = "127.0.0.1:9090"

// recConsensus is a consensus fake that reads Fibre anchors and answers as the
// own node the Recorder reads from.
type recConsensus struct {
	*nodefake.Consensus
	*nodefake.FibreNode
}

func (c recConsensus) Network(ctx context.Context) (string, error) { return c.Consensus.Network(ctx) }
func (c recConsensus) LatestHeight(ctx context.Context) (uint64, error) {
	return c.FibreNode.LatestHeight(ctx)
}
func (c recConsensus) FibreParams(ctx context.Context) (node.FibreParams, error) {
	return c.FibreNode.FibreParams(ctx)
}

func fibreRecorderCfg(t *testing.T) edictad.Config {
	t.Helper()
	dir := t.TempDir()
	pass := filepath.Join(dir, "keyring.pass")
	require.NoError(t, os.WriteFile(pass, []byte("pw\n"), 0o600))
	ns := "00" + strings.Repeat("00", 18) + strings.Repeat("07", 10)
	cfg, err := edictad.ParseConfig([]byte(fmt.Sprintf(`
[network]
da = "fibre"
fibre_chain_ids = ["mocha-5"]
[network.bridge]
addr = "bn.invalid:26658"
token_file = ""
tls = false
[network.consensus_grpc]
addr = %q
token_file = ""
tls = false
[recorder]
enabled = true
namespace = %q
keyring_dir = %q
keyring_backend = "file"
key_name = "recorder"
passphrase_file = %q
own_node = true
[recorder.quota]
blobs_per_hour = 60
bytes_per_day = 67108864
[fibre]
max_data_bytes = 1048576
max_read_bytes = 2097152
[archive]
dir = %q
[gate]
gate_id = "gate-1"
key_file = "/nonexistent/gate.key"
registry_path = "/nonexistent/reg.db"
action_types = ["application/vnd.edicta.test.v0+cbor"]
allowlist_file = "/nonexistent/agents.toml"
executor_keys = [%q]
anchor_verifier = "self"
[http]
listen = "127.0.0.1:0"
`, consensusAddr, ns, filepath.Join(dir, "kr"), pass, filepath.Join(dir, "archive"), execKey(t))))
	require.NoError(t, err)
	return cfg
}

type fibreSigningCalls struct {
	built    int
	keyName  string
	network  string
	closer   *countCloser
	sub      *nodefake.FibreSubmitter
	keyrings int
}

type countCloser struct{ n atomic.Int32 }

func (c *countCloser) Close() error { c.n.Add(1); return nil }

func stubFibreSigning(t *testing.T) *fibreSigningCalls {
	t.Helper()
	fs := &fibreSigningCalls{closer: &countCloser{}, sub: &nodefake.FibreSubmitter{Addr: make([]byte, 20), Endpt: consensusAddr}}
	ok, ocn, ofs := openKeyringFn, newConsensusFn, newFibreSigningFn
	t.Cleanup(func() { openKeyringFn, newConsensusFn, newFibreSigningFn = ok, ocn, ofs })
	openKeyringFn = func(node.KeyringConfig) (keyring.Keyring, error) {
		fs.keyrings++
		return keyring.NewInMemory(nil), nil
	}
	newFibreSigningFn = func(_ context.Context, _ node.BridgeConfig, g node.GRPCConfig, _ keyring.Keyring,
		keyName, network string) (io.Closer, node.Reader, node.FibreSubmitter, error) {
		fs.built++
		fs.keyName, fs.network = keyName, network
		fs.sub.Endpt = g.Addr
		return fs.closer, nodefake.NewChain(nil), fs.sub, nil
	}
	return fs
}

func newRecConsensus(t *testing.T) recConsensus {
	t.Helper()
	n := nodefake.NewFibreNode(consensusAddr, func(uint64) time.Time { return time.Unix(1, 0) }, fibrefix.BuildBlock(t))
	return recConsensus{Consensus: nodefake.NewConsensus("mocha-5"), FibreNode: n}
}

func TestFibreRecorderAdaptersBuildTheSigningPath(t *testing.T) {
	fbs := stubFibreSeams(t)
	fs := stubFibreSigning(t)
	cons := newRecConsensus(t)
	cfg := fibreRecorderCfg(t)

	fd, closeAll, err := fibreAdapters(context.Background(), cfg, cons, slog.New(slog.NewTextHandler(io.Discard, nil)))
	require.NoError(t, err)

	assert.Equal(t, 1, fs.built)
	assert.Equal(t, "recorder", fs.keyName)
	assert.Equal(t, "mocha-5", fs.network, "the chain id the consensus node reports")
	assert.Same(t, fs.sub, fd.Submitter)
	require.NotNil(t, fd.RecorderChain)
	assert.Equal(t, fd.Submitter.Endpoint(), fd.RecorderChain.Addr(), "reads and submits go to one node")
	assert.Equal(t, fs.closer, fd.SigningCloser)

	closeAll()
	assert.Zero(t, fs.closer.n.Load(), "the daemon closes the signing client, in order, at shutdown")
	assert.EqualValues(t, 1, fbs.bridge.closed.Load())
}

func TestFibreAdaptersWithoutTheRecorderBuildNoSigningPath(t *testing.T) {
	stubFibreSeams(t)
	fs := stubFibreSigning(t)
	fd, closeAll, err := fibreAdapters(context.Background(), fibreCfg(t, false), newFibreConsensus(), slog.Default())
	require.NoError(t, err)
	defer closeAll()
	assert.Zero(t, fs.built)
	assert.Nil(t, fd.Submitter)
	assert.Nil(t, fd.RecorderChain)
	assert.Nil(t, fd.SigningCloser)
}

func TestFibreRecorderAdaptersRefusals(t *testing.T) {
	t.Run("consensus client is not an own-node reader", func(t *testing.T) {
		stubFibreSeams(t)
		fs := stubFibreSigning(t)
		_, _, err := fibreAdapters(context.Background(), fibreRecorderCfg(t), newFibreConsensus(), slog.Default())
		require.Error(t, err)
		assert.Zero(t, fs.built, "no signing client is dialled")
	})
	t.Run("signing client fails and the others are closed", func(t *testing.T) {
		fbs := stubFibreSeams(t)
		stubFibreSigning(t)
		newFibreSigningFn = func(context.Context, node.BridgeConfig, node.GRPCConfig, keyring.Keyring, string, string) (io.Closer, node.Reader, node.FibreSubmitter, error) {
			return nil, nil, nil, errors.New("no signing")
		}
		_, _, err := fibreAdapters(context.Background(), fibreRecorderCfg(t), newRecConsensus(t), slog.Default())
		require.Error(t, err)
		assert.EqualValues(t, 1, fbs.bridge.closed.Load())
		assert.EqualValues(t, 1, fbs.direct.closed.Load())
	})
}

// With da = fibre the blob compatibility check and the blob signing client
// are not used: the Fibre check runs in Start.
func TestAdaptersSkipTheBlobSigningPathForFibre(t *testing.T) {
	var log callLog
	stubSeams(t, &log, nil)
	rd, cons, sub, closeAll, err := adapters(context.Background(), fibreRecorderCfg(t), slog.New(slog.NewTextHandler(io.Discard, nil)))
	require.NoError(t, err)
	defer closeAll()
	assert.NotNil(t, rd)
	assert.NotNil(t, cons)
	assert.Nil(t, sub)
	calls := log.calls()
	assert.Equal(t, -1, indexOf(calls, "check"), "calls: %v", calls)
	assert.Equal(t, -1, indexOf(calls, "new signing"), "calls: %v", calls)
}
