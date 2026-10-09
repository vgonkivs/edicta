package gate_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/test/gatefix"
)

// FuzzAuthorize: Authorize never panics, rejects only with known sentinels,
// returns an Authorization only for an envelope that passes the stateless
// verification with exactly the committed bytes, and answers a second
// submission with the same bytes.
func FuzzAuthorize(f *testing.F) {
	var vf, rf struct {
		Cases []struct {
			EnvelopeHex string `json:"envelope_hex"`
		} `json:"cases"`
	}
	gatefix.ReadVector(f, "valid.json", &vf)
	gatefix.ReadVector(f, "reject.json", &rf)
	action := gatefix.Action(f)
	for _, c := range vf.Cases {
		f.Add(gatefix.MustHex(f, c.EnvelopeHex), action)
	}
	for _, c := range rf.Cases {
		f.Add(gatefix.MustHex(f, c.EnvelopeHex), action)
	}
	seed, _ := gatefix.Sign(f, "agent1", gatefix.Template(f))
	f.Add(seed, action)
	f.Add(seed, []byte{})
	f.Add(seed, action[:len(action)-1])
	f.Add([]byte{}, action)
	f.Add([]byte{0xa0}, []byte{})

	blob := gatefix.Blob(f)
	f.Fuzz(func(t *testing.T, data, presented []byte) {
		e := gatefix.New(t)
		if s, err := commitment.DecodeSigned(data); err == nil {
			e.StageDA(&s.Commitment, blob)
		}
		res, err := e.AuthorizeWith(data, presented)
		if err != nil {
			require.Truef(t, gatefix.IsKnown(err), "rejection without a known sentinel: %v", err)
			require.Nil(t, res.Authorization, "a rejection carried an Authorization")
			return
		}
		require.NotEmpty(t, res.Authorization, "authorized without an Authorization")
		p := commitment.Params{FibreRetentionS: 14400, BlobRetentionS: 14400, SkewS: 30}
		s, _, verr := commitment.VerifyForGate(data, gatefix.Now, e.Cfg.Scope, p)
		require.NoError(t, verr, "authorized an envelope that fails verification")
		require.NoError(t, commitment.CheckAction(&s.Commitment, presented, gatefix.Salt(t)), "authorized bytes other than the committed ones")
		_, _, aerr := commitment.VerifyAuthorization(res.Authorization, commitment.AuthorizationCheck{
			GatePubKey: gatefix.Pub(t, "gate1"), GateID: gatefix.GateID, ActionType: s.Commitment.Action.Type,
			Action: presented, ActionSalt: gatefix.Salt(t), Now: gatefix.Now, SkewS: 30,
		})
		require.NoError(t, aerr)

		again, err := e.AuthorizeWith(data, presented)
		require.True(t, gatefix.IsKnown(err) && err != nil, "second submission must report the used nonce")
		require.Equal(t, res.Authorization, again.Authorization)
	})
}
