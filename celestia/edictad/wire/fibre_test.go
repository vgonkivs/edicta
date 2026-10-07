package wire

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log/slog"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/celestia/edictad"
	"github.com/vgonkivs/edicta/celestia/gatechain"
	"github.com/vgonkivs/edicta/celestia/node"
	"github.com/vgonkivs/edicta/celestia/nodefake"
)

type fakeFibreBridge struct {
	*nodefake.FibreChain
	dl     node.FibreDownloader
	raw    atomic.Int32
	closed atomic.Int32
}

func (b *fakeFibreBridge) Downloader() node.FibreDownloader { return b.dl }
func (b *fakeFibreBridge) DownloadRaw(context.Context, [33]byte, uint64) ([]byte, error) {
	b.raw.Add(1)
	return nil, errors.New("unused")
}
func (b *fakeFibreBridge) Close() { b.closed.Add(1) }

type fakeFibreDirect struct {
	*nodefake.Downloader
	closed atomic.Int32
}

func (d *fakeFibreDirect) Close(context.Context) error { d.closed.Add(1); return nil }

// fibreConsensus is a consensus fake that also reads Fibre anchors.
type fibreConsensus struct {
	*nodefake.Consensus
	*nodefake.FibreChain
}

func execKey(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	return hex.EncodeToString(pub)
}

func fibreCfg(t *testing.T, fallback bool) edictad.Config {
	t.Helper()
	s := strings.Replace(`
[network]
da = "fibre"
fibre_chain_ids = ["mocha-5"]
[network.bridge]
addr = "bn.invalid:26658"
token_file = ""
tls = false
[network.consensus_grpc]
addr = "127.0.0.1:9090"
token_file = ""
tls = false
[recorder]
enabled = false
[fibre]
max_data_bytes = 1048576
max_read_bytes = 2097152
FALLBACK
[archive]
dir = "/nonexistent/archive"
[gate]
gate_id = "gate-1"
key_file = "/nonexistent/gate.key"
registry_path = "/nonexistent/reg.db"
action_types = ["application/vnd.edicta.test.v0+cbor"]
allowlist_file = "/nonexistent/agents.toml"
executor_keys = ["`+execKey(t)+`"]
anchor_verifier = "self"
[http]
listen = "127.0.0.1:0"
`, "FALLBACK", map[bool]string{true: "bridge_fallback = true", false: ""}[fallback], 1)
	cfg, err := edictad.ParseConfig([]byte(s))
	require.NoError(t, err)
	return cfg
}

type fibreSeams struct {
	bridge *fakeFibreBridge
	direct *fakeFibreDirect
	lim    node.BridgeLimits
	built  []string
}

func stubFibreSeams(t *testing.T) *fibreSeams {
	t.Helper()
	fs := &fibreSeams{
		bridge: &fakeFibreBridge{FibreChain: nodefake.NewFibreChain(), dl: nodefake.NewDownloader()},
		direct: &fakeFibreDirect{Downloader: nodefake.NewDownloader()},
	}
	ob, od := newFibreBridgeFn, newFibreDirectFn
	t.Cleanup(func() { newFibreBridgeFn, newFibreDirectFn = ob, od })
	newFibreBridgeFn = func(_ context.Context, _ node.BridgeConfig, lim node.BridgeLimits) (fibreBridge, error) {
		fs.built = append(fs.built, "bridge")
		fs.lim = lim
		return fs.bridge, nil
	}
	newFibreDirectFn = func(context.Context, node.GRPCConfig) (fibreDirect, error) {
		fs.built = append(fs.built, "direct")
		return fs.direct, nil
	}
	return fs
}

func newFibreConsensus() *fibreConsensus {
	return &fibreConsensus{Consensus: nodefake.NewConsensus("mocha-5"), FibreChain: nodefake.NewFibreChain()}
}

func TestFibreAdaptersWithoutTheFallback(t *testing.T) {
	fs := stubFibreSeams(t)
	cfg := fibreCfg(t, false)
	cons := newFibreConsensus()
	fd, closeAll, err := fibreAdapters(context.Background(), cfg, cons, slog.Default())
	require.NoError(t, err)

	assert.Equal(t, cfg.FibreBridgeLimits(), fs.lim, "the bridge reads with the limit the gate is configured with")
	assert.EqualValues(t, 2097152, fs.lim.NamespaceDataBytes)
	assert.Same(t, cons.FibreChain, fd.Chain.(*fibreConsensus).FibreChain)
	assert.NotNil(t, fd.Bridge)
	assert.NotNil(t, fd.Direct)
	require.NotNil(t, fd.Committer)
	assert.EqualValues(t, 1048576, fd.Committer.MaxDataSize())
	assert.Nil(t, fd.Fallback, "no fallback unless asked for")
	assert.Nil(t, fd.BridgeCompat, "and no probe")

	closeAll()
	assert.EqualValues(t, 1, fs.bridge.closed.Load())
	assert.EqualValues(t, 1, fs.direct.closed.Load())
	assert.Zero(t, fs.bridge.raw.Load(), "nothing is downloaded at wiring time")
}

func TestFibreAdaptersWithTheFallback(t *testing.T) {
	fs := stubFibreSeams(t)
	fd, closeAll, err := fibreAdapters(context.Background(), fibreCfg(t, true), newFibreConsensus(), slog.Default())
	require.NoError(t, err)
	defer closeAll()
	assert.Same(t, fs.bridge.dl, fd.Fallback, "the fallback is the bridge's own downloader")
	require.NotNil(t, fd.BridgeCompat)
	assert.Zero(t, fs.bridge.raw.Load(), "the probe runs at start, not at wiring time")
}

func TestFibreAdaptersRefusals(t *testing.T) {
	t.Run("consensus client cannot read Fibre anchors", func(t *testing.T) {
		fs := stubFibreSeams(t)
		_, _, err := fibreAdapters(context.Background(), fibreCfg(t, false), nodefake.NewConsensus("mocha-5"), slog.Default())
		require.Error(t, err)
		assert.Empty(t, fs.built, "nothing is dialled")
	})
	t.Run("bridge fails", func(t *testing.T) {
		fs := stubFibreSeams(t)
		newFibreBridgeFn = func(context.Context, node.BridgeConfig, node.BridgeLimits) (fibreBridge, error) {
			return nil, errors.New("no bridge")
		}
		_, _, err := fibreAdapters(context.Background(), fibreCfg(t, false), newFibreConsensus(), slog.Default())
		require.Error(t, err)
		assert.Zero(t, fs.direct.closed.Load())
		assert.NotContains(t, fs.built, "direct")
	})
	t.Run("download client fails and the bridge is closed", func(t *testing.T) {
		fs := stubFibreSeams(t)
		newFibreDirectFn = func(context.Context, node.GRPCConfig) (fibreDirect, error) { return nil, errors.New("no direct") }
		_, _, err := fibreAdapters(context.Background(), fibreCfg(t, false), newFibreConsensus(), slog.Default())
		require.Error(t, err)
		assert.EqualValues(t, 1, fs.bridge.closed.Load())
	})
}

func TestBridgeCompatNeverPassesWithoutAnAnchoredBlob(t *testing.T) {
	var logs bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logs, nil))

	t.Run("empty chain is inconclusive", func(t *testing.T) {
		fs := stubFibreSeams(t)
		cons := newFibreConsensus()
		cons.Fibre = &node.FibreParams{RetentionS: 3600}
		cons.SetHeight(1000)
		fd, closeAll, err := fibreAdapters(context.Background(), fibreCfg(t, true), cons, log)
		require.NoError(t, err)
		defer closeAll()
		err = fd.BridgeCompat(context.Background())
		require.ErrorIs(t, err, gatechain.ErrProbeInconclusive)
		assert.NotErrorIs(t, err, node.ErrBridgeIncompatible)
		assert.Zero(t, fs.bridge.raw.Load(), "no blob was found, so nothing is downloaded")
		assert.NotContains(t, logs.String(), "probe passed")
	})
	t.Run("unreadable head is inconclusive", func(t *testing.T) {
		stubFibreSeams(t)
		cons := newFibreConsensus() // no latest height set
		cons.Fibre = &node.FibreParams{RetentionS: 3600}
		fd, closeAll, err := fibreAdapters(context.Background(), fibreCfg(t, true), cons, log)
		require.NoError(t, err)
		defer closeAll()
		require.ErrorIs(t, fd.BridgeCompat(context.Background()), gatechain.ErrProbeInconclusive)
	})
	t.Run("unreadable chain id is an error", func(t *testing.T) {
		stubFibreSeams(t)
		cons := newFibreConsensus()
		cons.Consensus.Fail = node.ErrUnavailable
		fd, closeAll, err := fibreAdapters(context.Background(), fibreCfg(t, true), cons, log)
		require.NoError(t, err)
		defer closeAll()
		require.Error(t, fd.BridgeCompat(context.Background()))
	})
}
