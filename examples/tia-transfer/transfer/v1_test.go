package transfer_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/examples/tia-transfer/transfer"
)

func strictV1(a *commitment.Authorization) { a.Version, a.Mode = 1, commitment.ModeStrict }
func fastV1(a *commitment.Authorization) {
	a.Version, a.Mode, a.AnchorDeadline = 1, commitment.ModeFast, 4200100
}

// includingRig is a rig whose rail includes the transfer two blocks on.
func includingRig(t *testing.T, mods ...func(*transfer.Config)) *rig {
	r := newRig(t, mods...)
	r.rail.includeAt = headH + 2
	return r
}

func TestExecutorAcceptsAuthorizationV1(t *testing.T) {
	r := includingRig(t)
	action := actionBytes(t, chainID, validMsg())
	_, err := r.exec.Execute(bg, goodAuth(t, chash(1), action, strictV1), action)
	require.NoError(t, err)

	r = includingRig(t)
	_, err = r.exec.Execute(bg, goodAuth(t, chash(2), action, fastV1), action)
	require.NoError(t, err, "fast mode is accepted by default")
}

func TestExecutorRefusesFastModeWhenConfigured(t *testing.T) {
	r := includingRig(t, func(c *transfer.Config) { c.RefuseFastMode = true })
	action := actionBytes(t, chainID, validMsg())
	_, err := r.exec.Execute(bg, goodAuth(t, chash(1), action, fastV1), action)
	require.ErrorIs(t, err, transfer.ErrFastModeRefused)
	assert.Zero(t, r.rail.signCalls(), "nothing signed")
	assert.Empty(t, r.store.calls(), "no record begun")

	_, err = r.exec.Execute(bg, goodAuth(t, chash(2), action, strictV1), action)
	require.NoError(t, err, "strict mode still runs")
}

func TestExecutorAcceptVersions(t *testing.T) {
	action := actionBytes(t, chainID, validMsg())
	r := newRig(t, func(c *transfer.Config) { c.AcceptVersions = []uint64{0} })
	_, err := r.exec.Execute(bg, goodAuth(t, chash(1), action, strictV1), action)
	require.ErrorIs(t, err, commitment.ErrUnsupportedVersion)

	r = newRig(t, func(c *transfer.Config) { c.AcceptVersions = []uint64{1} })
	_, err = r.exec.Execute(bg, goodAuth(t, chash(1), action), action)
	require.ErrorIs(t, err, commitment.ErrUnsupportedVersion)
}
