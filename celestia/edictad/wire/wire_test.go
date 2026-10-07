package wire

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/celestia/edictad"
	"github.com/vgonkivs/edicta/celestia/node"
)

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

// fibreConn is a consensus client with the Fibre readers and a Close.
type fibreConn struct {
	*fibreConsensus
	log *callLog
}

func (f fibreConn) Close() error { f.log.add("close consensus"); return nil }

func TestAdaptersBlobDepsMatchTheDaemonWiring(t *testing.T) {
	var log callLog
	stubSeams(t, &log, nil)
	deps, closeAll, err := Adapters(context.Background(), recorderCfg(t), quiet)
	require.NoError(t, err)
	assert.NotNil(t, deps.Reader)
	assert.NotNil(t, deps.Consensus)
	assert.NotNil(t, deps.Submitter, "the Recorder is enabled")
	assert.Same(t, quiet, deps.Logger)
	assert.Nil(t, deps.Fibre)
	calls := log.calls()
	assert.Less(t, indexOf(calls, "check"), indexOf(calls, "new signing"), "calls: %v", calls)

	closeAll()
	calls = log.calls()
	for _, c := range []string{"close signing", "close read-only", "close consensus"} {
		assert.GreaterOrEqual(t, indexOf(calls, c), 0, "%s in %v", c, calls)
	}
}

func TestAdaptersWithoutTheRecorderHaveNoSubmitter(t *testing.T) {
	var log callLog
	stubSeams(t, &log, nil)
	cfg := recorderCfg(t)
	cfg.Recorder.Enabled = false
	deps, closeAll, err := Adapters(context.Background(), cfg, quiet)
	require.NoError(t, err)
	defer closeAll()
	assert.Nil(t, deps.Submitter)
	assert.Equal(t, -1, indexOf(log.calls(), "new signing"))
}

func TestAdaptersErrorLeavesNothingOpen(t *testing.T) {
	var log callLog
	stubSeams(t, &log, node.ErrUnsupported)
	deps, closeAll, err := Adapters(context.Background(), recorderCfg(t), quiet)
	require.ErrorIs(t, err, node.ErrUnsupported)
	require.NotNil(t, closeAll, "safe to call after an error")
	closeAll()
	assert.Equal(t, edictad.Deps{}, deps)
	assert.GreaterOrEqual(t, indexOf(log.calls(), "close consensus"), 0)
}

func TestAdaptersFibreDepsAndOrderedClose(t *testing.T) {
	var log callLog
	stubSeams(t, &log, nil)
	fbs := stubFibreSeams(t)
	newConsensusFn = func(node.GRPCConfig) (consensusConn, error) {
		return fibreConn{newFibreConsensus(), &log}, nil
	}
	cfg := fibreCfg(t, false)
	deps, closeAll, err := Adapters(context.Background(), cfg, quiet)
	require.NoError(t, err)
	require.NotNil(t, deps.Fibre)
	assert.NotNil(t, deps.Fibre.Bridge)
	assert.NotNil(t, deps.Fibre.Direct)
	assert.Nil(t, deps.Submitter)

	closeAll()
	assert.EqualValues(t, 1, fbs.bridge.closed.Load(), "the Fibre clients are closed with the rest")
	assert.EqualValues(t, 1, fbs.direct.closed.Load())
	assert.GreaterOrEqual(t, indexOf(log.calls(), "close consensus"), 0)
}

func TestAdaptersFibreFailureClosesTheBaseConnections(t *testing.T) {
	var log callLog
	stubSeams(t, &log, nil)
	stubFibreSeams(t)
	// A plain consensus fake cannot read Fibre anchors.
	deps, closeAll, err := Adapters(context.Background(), fibreCfg(t, false), quiet)
	require.Error(t, err)
	closeAll()
	assert.Equal(t, edictad.Deps{}, deps)
	calls := log.calls()
	assert.GreaterOrEqual(t, indexOf(calls, "close consensus"), 0, "calls: %v", calls)
	assert.GreaterOrEqual(t, indexOf(calls, "close read-only"), 0, "calls: %v", calls)
}
