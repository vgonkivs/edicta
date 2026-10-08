package policy_test

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/policy"
)

func TestCounterScalesAreBounded(t *testing.T) {
	m, _ := testMandate(t)
	canon, err := policy.EncodeMandate(m)
	require.NoError(t, err)
	h := policy.HashMandate(canon)

	c := policy.NewCounter(m, h)
	for i := len(c.Scales); i < policy.MaxScales; i++ {
		c.Scales[fmt.Sprintf("pad:%d", i)] = 2
	}
	_, err = policy.EncodeCounter(c)
	require.NoError(t, err)
	back, err := policy.DecodeCounter(mustEncode(t, c))
	require.NoError(t, err)
	require.Len(t, back.Scales, policy.MaxScales)

	c.Scales["pad:over"] = 2
	_, err = policy.EncodeCounter(c)
	require.ErrorIs(t, err, policy.ErrCounterInvalid)

	delete(c.Scales, "pad:over")
	next := *m
	next.Version = m.Version + 1
	next.Assets = append([]policy.AssetRule(nil), m.Assets...)
	next.Assets[0].Asset = "new:asset"
	before := c.Version
	require.ErrorIs(t, c.Adopt(&next, h), policy.ErrScalesFull)
	require.Equal(t, before, c.Version)
	require.Len(t, c.Scales, policy.MaxScales)
	require.NotContains(t, c.Scales, "new:asset")
}

func mustEncode(t *testing.T, c *policy.Counter) []byte {
	t.Helper()
	b, err := policy.EncodeCounter(c)
	require.NoError(t, err)
	return b
}
