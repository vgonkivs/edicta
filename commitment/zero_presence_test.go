package commitment_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/commitment"
)

// A present zero is a different value from an absent key, not a second
// encoding of it: decoding keeps it, re-encoding gives the input bytes back,
// and static validation refuses it with the rule's own sentinel.
func TestPresentAnchorZeroRoundTripsAndFailsStatic(t *testing.T) {
	var rf struct {
		Cases []struct {
			ID          string `json:"id"`
			CBORHex     string `json:"commitment_cbor_hex"`
			EnvelopeHex string `json:"envelope_hex"`
		} `json:"cases"`
	}
	loadJSON(t, "reject.json", &rf)
	for _, rc := range rf.Cases {
		if rc.ID != "anchor_0" {
			continue
		}
		canon := mustHex(t, rc.CBORHex)
		c, err := commitment.Decode(canon)
		require.NoError(t, err)
		re, err := commitment.Encode(c)
		require.NoError(t, err)
		assert.Equal(t, canon, re, "re-encode is byte-identical")

		s, err := commitment.DecodeSigned(mustHex(t, rc.EnvelopeHex))
		require.NoError(t, err)
		err = commitment.ValidateStatic(&s.Commitment, commitment.DefaultParams())
		require.ErrorIs(t, err, commitment.ErrInvalidEnum)
		require.NotErrorIs(t, err, commitment.ErrNonCanonical)
		return
	}
	require.FailNow(t, "no anchor_0 vector")
}

func TestPresentAnchorDeadlineZeroRoundTripsAndFailsStatic(t *testing.T) {
	var af struct {
		Reject []struct {
			ID      string `json:"id"`
			SignedH string `json:"signed_authorization_hex"`
			AuthH   string `json:"authorization_cbor_hex"`
		} `json:"reject"`
	}
	loadJSON(t, "authorization.json", &af)
	for _, rc := range af.Reject {
		if rc.ID != "auth_v1_deadline_0" {
			continue
		}
		sa, _, err := commitment.DecodeSignedAuthorization(mustHex(t, rc.SignedH))
		require.NoError(t, err, "the present zero is a stage S refusal, not a decoding one")
		re, err := commitment.EncodeAuthorization(&sa.Authorization)
		require.NoError(t, err)
		assert.Equal(t, mustHex(t, rc.AuthH), re, "re-encode is byte-identical")
		err = commitment.ValidateAuthorization(&sa.Authorization)
		require.ErrorIs(t, err, commitment.ErrZeroValue)
		require.NotErrorIs(t, err, commitment.ErrNonCanonical)
		return
	}
	require.FailNow(t, "no auth_v1_deadline_0 vector")
}
