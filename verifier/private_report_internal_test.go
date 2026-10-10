package verifier

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/policy"
)

// Without a key the report carries the public state hashes, keys 20 and 14,
// and marks the private content as unknown.
func TestKeylessPrivateInfoCarriesThePublicStateHashes(t *testing.T) {
	c, d := loadPrivCase(t, "private_with_key_pass")
	c.Config.AuditorKeys = nil
	v, arch := privVerifier(t, c, d)
	in := c.input(t, d)
	out, err := v.checkPolicy(t.Context(), in)
	require.NoError(t, err)
	require.NotNil(t, out.Info)
	assert.True(t, out.Info.ContentPrivate)

	rec, err := arch.PolicyAllow(t.Context(), in.Hash)
	require.NoError(t, err)
	sv, _, err := policy.DecodeSignedVerdict(rec.SignedVerdict)
	require.NoError(t, err)
	assert.Equal(t, sv.Verdict.BlindPrevStateHash, out.Info.PrevStateHash[:])
	assert.Equal(t, sv.Verdict.NewStateHash, out.Info.NewStateHash[:])

	c, d = loadPrivCase(t, "private_with_key_pass")
	v, _ = privVerifier(t, c, d)
	out, err = v.checkPolicy(t.Context(), c.input(t, d))
	require.NoError(t, err)
	assert.False(t, out.Info.ContentPrivate, "an opened PrivatePart is known content")
}
