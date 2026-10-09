package verifier_test

import (
	"bytes"
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/gate"
	"github.com/vgonkivs/edicta/sdk"
	"github.com/vgonkivs/edicta/sdk/blob"
	"github.com/vgonkivs/edicta/sdk/payload"
	"github.com/vgonkivs/edicta/test/gatefix"
	"github.com/vgonkivs/edicta/test/sdkfix"
	"github.com/vgonkivs/edicta/verifier"
)

// sealedParts is a da = 2 decision whose payload opens with a vector
// recipient key and carries payloadSalt as its action salt. The archive
// stores the payload without the share commitment check.
func sealedParts(t *testing.T, payloadSalt []byte) (*parts, blob.RecipientKey) {
	t.Helper()
	sv := sdkfix.Load(t)
	c0 := sv.Case0(t)
	key := sv.Key(t, c0.Recipients[0].Key)
	p := newParts(t)

	pl := *c0.Payload
	pl.Action = payload.Action{Type: p.c.Action.Type, Data: bytes.Clone(p.action), Salt: bytes.Clone(payloadSalt)}
	pt, err := payload.Encode(&pl)
	require.NoError(t, err)
	raw, bsalt, err := blob.Seal(pt, []blob.Recipient{key.Recipient()})
	require.NoError(t, err)

	c := gatefix.Clone(p.c)
	sum := sha256.Sum256(raw)
	c.CiphertextHash = sum[:]
	c.PayloadSize = uint64(len(raw))
	ph := commitment.PlaintextHash(bsalt, pt)
	c.PlaintextHash = ph[:]
	p.c = c
	p.env, p.hash = gatefix.Sign(t, "agent1", c)
	p.blob = raw
	p.permissive = true
	p.auth = signAuth(t, gateKey(t), p.hash, c, commitment.PathDA, authExpires)
	return p, key.OpenKey(true)
}

func sealedRig(t *testing.T, p *parts, keys ...blob.RecipientKey) *rig {
	t.Helper()
	r := newRig(t, p)
	r.deps.Committers = map[commitment.DA]gate.DACommitter{commitment.DACelestiaBlob: acceptAll{}}
	r.deps.Config.PayloadKeys = keys
	return r
}

// The payload keys reach the verifier through New: a payload whose action
// salt contradicts the agent's own commitment fails the payload check, while
// the action check still passes from the decision record.
func TestVerifyPayloadKeysThroughNew(t *testing.T) {
	bad := bytes.Clone(gatefix.Salt(t))
	bad[0] ^= 0x80

	t.Run("honest payload", func(t *testing.T) {
		p, key := sealedParts(t, gatefix.Salt(t))
		rep := sealedRig(t, p, key).verify(t)
		passed(t, rep, verifier.CheckPayload)
		passed(t, rep, verifier.CheckAction)
		assert.Equal(t, verifier.VerdictValid, rep.Verdict)
	})

	t.Run("payload salt contradicts the commitment", func(t *testing.T) {
		p, key := sealedParts(t, bad)
		rep := sealedRig(t, p, key).verify(t)
		c := failed(t, rep, verifier.CheckPayload)
		require.ErrorIs(t, c.Err, verifier.ErrPayloadInvalid)
		require.ErrorIs(t, c.Err, sdk.ErrPayloadMismatch)
		passed(t, rep, verifier.CheckAction)
		assert.Equal(t, verifier.ActionSourceDecisionRecord, rep.ActionSource)
		assert.Equal(t, verifier.VerdictInvalid, rep.Verdict)
	})

	t.Run("without a key the payload is not opened", func(t *testing.T) {
		p, _ := sealedParts(t, bad)
		rep := sealedRig(t, p).verify(t)
		passed(t, rep, verifier.CheckPayload)
	})
}
