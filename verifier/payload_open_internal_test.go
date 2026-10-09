package verifier

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/sdk"
	"github.com/vgonkivs/edicta/sdk/blob"
	"github.com/vgonkivs/edicta/test/sdkfix"
)

// With a recipient key the payload check opens the payload and runs O8; a
// key that unwraps nothing leaves the payload unopened, which is no finding.
func TestOpenPayloadWithAuditorKey(t *testing.T) {
	v := sdkfix.Load(t)
	c := v.Case0(t)
	s, err := commitment.DecodeSigned(c.Envelope)
	require.NoError(t, err)
	k := v.Key(t, c.Recipients[0].Key)

	r := &run{v: &Verifier{cfg: Config{PayloadKeys: []blob.RecipientKey{k.OpenKey(true)}}}, c: &s.Commitment, sig: s.Signature}
	o, err := r.openPayload(c.Blob)
	require.NoError(t, err)
	require.NotNil(t, o)
	assert.Equal(t, c.ActionSalt, o.Payload.Action.Salt)

	other := v.Key(t, "rcpt-04")
	r.v.cfg.PayloadKeys = []blob.RecipientKey{other.OpenKey(false)}
	o, err = r.openPayload(c.Blob)
	require.NoError(t, err)
	assert.Nil(t, o, "a key that opens nothing is not a finding")
}

// A payload whose action contradicts the agent's own signed commitment is
// an O8 failure, reported as such.
func TestOpenPayloadO8Failure(t *testing.T) {
	v := sdkfix.Load(t)
	for _, rj := range v.Rejects {
		if rj.Expect != "sdk.ErrPayloadMismatch" {
			continue
		}
		env := v.EnvelopeFor(t, rj.Blob, rj.PlaintextHash, rj.ActionType, rj.ActionHash)
		s, err := commitment.DecodeSigned(env)
		require.NoError(t, err)
		k := v.Key(t, rj.Key)
		r := &run{v: &Verifier{cfg: Config{PayloadKeys: []blob.RecipientKey{k.OpenKey(false)}}}, c: &s.Commitment, sig: s.Signature}
		_, err = r.openPayload(rj.Blob)
		require.ErrorIs(t, err, sdk.ErrPayloadMismatch, rj.ID)
		return
	}
	require.FailNow(t, "no O8 reject vector")
}
