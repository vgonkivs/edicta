package transfer_test

import (
	"bytes"
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
	_, err := r.exec.Execute(bg, goodAuth(t, chash(1), action, strictV1), action, testSalt)
	require.NoError(t, err)

	r = includingRig(t)
	_, err = r.exec.Execute(bg, goodAuth(t, chash(2), action, fastV1), action, testSalt)
	require.NoError(t, err, "fast mode is accepted by default")
}

func TestExecutorRefusesFastModeWhenConfigured(t *testing.T) {
	r := includingRig(t, func(c *transfer.Config) { c.RefuseFastMode = true })
	action := actionBytes(t, chainID, validMsg())
	_, err := r.exec.Execute(bg, goodAuth(t, chash(1), action, fastV1), action, testSalt)
	require.ErrorIs(t, err, transfer.ErrFastModeRefused)
	assert.Zero(t, r.rail.signCalls(), "nothing signed")
	assert.Empty(t, r.store.calls(), "no record begun")

	_, err = r.exec.Execute(bg, goodAuth(t, chash(2), action, strictV1), action, testSalt)
	require.NoError(t, err, "strict mode still runs")
}

// The executor hashes the bytes with the salt presented beside them: a
// missing salt is an integration fault, a wrong one is another action.
func TestExecutorActionSalt(t *testing.T) {
	action := actionBytes(t, chainID, validMsg())
	wrong := bytes.Clone(testSalt)
	wrong[0] ^= 1
	for _, tc := range []struct {
		name string
		salt []byte
		want error
	}{
		{"missing", nil, commitment.ErrMissingField},
		{"31 bytes", testSalt[:31], commitment.ErrFieldSize},
		{"wrong", wrong, commitment.ErrActionMismatch},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := includingRig(t)
			_, err := r.exec.Execute(bg, goodAuth(t, chash(1), action), action, tc.salt)
			require.ErrorIs(t, err, tc.want)
			assert.Zero(t, r.rail.signCalls(), "nothing signed")
		})
	}
}
