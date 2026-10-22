// SPDX-License-Identifier: Apache-2.0

package commitment_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/engine/commitment"
	"github.com/vgonkivs/edicta/test/gatefix"
)

func TestUndefinedDA(t *testing.T) {
	known := func(d commitment.DA) bool { return d == commitment.DAFibre || d == commitment.DACelestiaBlob }
	c := gatefix.Template(t)

	env, _ := gatefix.Sign(t, "agent1", c)
	_, ok := commitment.UndefinedDA(env, known)
	assert.False(t, ok, "a defined da is read strictly")

	c4 := gatefix.Clone(c)
	c4.PayloadRef.DA = 5
	env, _ = gatefix.Sign(t, "agent1", c4)
	da, ok := commitment.UndefinedDA(env, known)
	require.True(t, ok)
	assert.EqualValues(t, 5, da)

	c4.Version = 2
	env, _ = gatefix.Sign(t, "agent1", c4)
	_, ok = commitment.UndefinedDA(env, known)
	assert.False(t, ok, "an earlier static failure keeps the strict verdict")

	_, ok = commitment.UndefinedDA(env[:len(env)-1], known)
	assert.False(t, ok)
}
