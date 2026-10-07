package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/celestia/node"
	"github.com/vgonkivs/edicta/celestia/nodefake"
)

func stubFibreCheck(t *testing.T, err error) *int {
	t.Helper()
	var calls int
	old := checkFibreFn
	t.Cleanup(func() { checkFibreFn = old })
	checkFibreFn = func(_ context.Context, _ node.Reader, _ node.Consensus, e node.FibreExpect) error {
		calls++
		assert.Len(t, e.Namespace, 29, "the check is told the Recorder's namespace")
		return err
	}
	return &calls
}

// An incompatible chain is refused before the download clients or the signing
// client exist.
func TestFibreWiringRefusesAnIncompatibleChainBeforeAnyDial(t *testing.T) {
	fbs := stubFibreSeams(t)
	fs := stubFibreSigning(t)
	calls := stubFibreCheck(t, node.ErrUnsupported)

	_, _, err := fibreWiring(context.Background(), fibreRecorderCfg(t), nodefake.NewChain(nil), newRecConsensus(t), slog.Default())
	require.ErrorIs(t, err, node.ErrUnsupported)
	assert.Equal(t, 1, *calls)
	assert.Zero(t, fs.built, "no signing client")
	assert.Zero(t, fs.keyrings, "no keyring")
	assert.Empty(t, fbs.built, "no bridge or download client")
}

func TestFibreWiringChecksThenBuilds(t *testing.T) {
	stubFibreSeams(t)
	fs := stubFibreSigning(t)
	calls := stubFibreCheck(t, nil)

	fd, closeAll, err := fibreWiring(context.Background(), fibreRecorderCfg(t), nodefake.NewChain(nil), newRecConsensus(t), slog.New(slog.NewTextHandler(io.Discard, nil)))
	require.NoError(t, err)
	defer closeAll()
	assert.Equal(t, 1, *calls)
	assert.Equal(t, 1, fs.built)
	assert.NotNil(t, fd.SigningCloser)
}

func TestFibreWiringWithoutTheRecorderRunsNoCheck(t *testing.T) {
	stubFibreSeams(t)
	fs := stubFibreSigning(t)
	stubFibreCheck(t, errors.New("must not run"))

	_, closeAll, err := fibreWiring(context.Background(), fibreCfg(t, false), nodefake.NewChain(nil), newFibreConsensus(), slog.Default())
	require.NoError(t, err)
	defer closeAll()
	assert.Zero(t, fs.built)
}
