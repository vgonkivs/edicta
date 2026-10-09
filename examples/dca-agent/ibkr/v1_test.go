package ibkr_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/examples/dca-agent/ibkr"
	"github.com/vgonkivs/edicta/examples/dca-agent/ibkrorder"
)

func strictV1(a *commitment.Authorization) { a.Version, a.Mode = 1, commitment.ModeStrict }
func fastV1(a *commitment.Authorization) {
	a.Version, a.Mode, a.AnchorDeadline = 1, commitment.ModeFast, 4200100
}

func TestExecuteAuthorizationV1(t *testing.T) {
	for name, opt := range map[string]authOpt{"strict": strictV1, "fast": fastV1} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t)
			action := encode(t, validOrder())
			auth := authorize(t, gateKey(7), chash(0x21), ibkrorder.ActionType, action, opt)
			_, err := r.exec.Execute(context.Background(), auth, action)
			require.NoError(t, err)
			assert.Equal(t, 1, r.broker.PlaceCalls())
		})
	}
}

func TestExecuteRefusesFastModeWhenConfigured(t *testing.T) {
	r := newRig(t, func(c *ibkr.ExecutorConfig) { c.RefuseFastMode = true })
	action := encode(t, validOrder())
	auth := authorize(t, gateKey(7), chash(0x22), ibkrorder.ActionType, action, fastV1)
	_, err := r.exec.Execute(context.Background(), auth, action)
	require.ErrorIs(t, err, ibkr.ErrFastModeRefused)
	assert.Zero(t, r.broker.PlaceCalls())

	auth = authorize(t, gateKey(7), chash(0x23), ibkrorder.ActionType, action, strictV1)
	_, err = r.exec.Execute(context.Background(), auth, action)
	require.NoError(t, err)
}

func TestExecuteAcceptVersions(t *testing.T) {
	action := encode(t, validOrder())
	r := newRig(t, func(c *ibkr.ExecutorConfig) { c.AcceptVersions = []uint64{0} })
	_, err := r.exec.Execute(context.Background(), authorize(t, gateKey(7), chash(0x24), ibkrorder.ActionType, action, strictV1), action)
	require.ErrorIs(t, err, commitment.ErrUnsupportedVersion)

	_, err = ibkr.NewExecutor(ibkr.ExecutorConfig{AcceptVersions: []uint64{2}}, nil, nil, nil)
	require.ErrorIs(t, err, ibkr.ErrInvalidConfig)
}
