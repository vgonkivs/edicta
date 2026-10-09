package ibkr_test

import (
	"bytes"
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
			_, err := r.exec.Execute(context.Background(), auth, action, testSalt)
			require.NoError(t, err)
			assert.Equal(t, 1, r.broker.PlaceCalls())
		})
	}
}

func TestExecuteRefusesFastModeWhenConfigured(t *testing.T) {
	r := newRig(t, func(c *ibkr.ExecutorConfig) { c.RefuseFastMode = true })
	action := encode(t, validOrder())
	auth := authorize(t, gateKey(7), chash(0x22), ibkrorder.ActionType, action, fastV1)
	_, err := r.exec.Execute(context.Background(), auth, action, testSalt)
	require.ErrorIs(t, err, ibkr.ErrFastModeRefused)
	assert.Zero(t, r.broker.PlaceCalls())

	auth = authorize(t, gateKey(7), chash(0x23), ibkrorder.ActionType, action, strictV1)
	_, err = r.exec.Execute(context.Background(), auth, action, testSalt)
	require.NoError(t, err)
}

// The executor hashes the bytes with the salt presented beside them: a
// missing salt is an integration fault, a wrong one is another order.
func TestExecuteActionSalt(t *testing.T) {
	action := encode(t, validOrder())
	wrong := bytes.Clone(testSalt)
	wrong[0] ^= 1
	for _, tc := range []struct {
		name string
		salt []byte
		want error
	}{
		{"missing", nil, commitment.ErrMissingField},
		{"33 bytes", append(bytes.Clone(testSalt), 0), commitment.ErrFieldSize},
		{"wrong", wrong, commitment.ErrActionMismatch},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newRig(t)
			_, err := r.exec.Execute(context.Background(), authorize(t, gateKey(7), chash(0x24), ibkrorder.ActionType, action), action, tc.salt)
			require.ErrorIs(t, err, tc.want)
			assert.Zero(t, r.broker.PlaceCalls())
		})
	}
}
