package commitment_test

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/commitment"
)

func TestLimitVectors(t *testing.T) {
	var lf struct {
		Limits map[string]string `json:"limits"`
		Cases  []struct {
			ID                     string    `json:"id"`
			EnvelopeHex            string    `json:"envelope_hex"`
			SignedAuthorizationHex string    `json:"signed_authorization_hex"`
			Size                   string    `json:"size"`
			Now                    string    `json:"now"`
			Gate                   *jsonGate `json:"gate"`
			Expect                 string    `json:"expect"`
			ExpectError            string    `json:"expect_error"`
		} `json:"cases"`
	}
	loadJSON(t, "limits.json", &lf)
	require.NotEmpty(t, lf.Cases)
	assert.EqualValues(t, commitment.MaxSignedSize, u64(t, lf.Limits["max_signed_size"]))
	assert.EqualValues(t, commitment.MaxCommitmentSize, u64(t, lf.Limits["max_commitment_size"]))
	assert.EqualValues(t, commitment.MaxAuthorizationSize, u64(t, lf.Limits["max_authorization_size"]))
	params := toParams(t, loadValid(t).Params)

	for _, lc := range lf.Cases {
		t.Run(lc.ID, func(t *testing.T) {
			var err error
			if lc.SignedAuthorizationHex != "" {
				b := mustHex(t, lc.SignedAuthorizationHex)
				require.Len(t, b, int(u64(t, lc.Size)))
				_, _, err = commitment.DecodeSignedAuthorization(b)
			} else {
				b := mustHex(t, lc.EnvelopeHex)
				require.Len(t, b, int(u64(t, lc.Size)))
				gate := commitment.GateScope{GateID: "gate-paper-1", ActionTypes: []string{"application/x"}}
				if lc.Gate != nil {
					gate = toGate(t, *lc.Gate)
				}
				_, _, err = commitment.VerifyForGate(b, u64(t, lc.Now), gate, params)
			}
			if lc.Expect == "accept" {
				require.NoError(t, err)
				return
			}
			assertSentinel(t, err, lc.ExpectError)
		})
	}
}

func TestActionVectors(t *testing.T) {
	var af struct {
		Tag   string `json:"tag"`
		Cases []struct {
			ID            string `json:"id"`
			ActionType    string `json:"action_type"`
			PreimageHex   string `json:"preimage_hex"`
			ActionHashHex string `json:"action_hash_hex"`
			actionSpec
		} `json:"cases"`
		Reject []struct {
			ID                     string `json:"id"`
			ActionType             string `json:"action_type"`
			CommittedActionHashHex string `json:"committed_action_hash_hex"`
			ExpectError            string `json:"expect_error"`
			actionSpec
		} `json:"reject"`
	}
	loadJSON(t, "action.json", &af)
	require.NotEmpty(t, af.Cases)
	require.NotEmpty(t, af.Reject)
	assert.Equal(t, af.Tag, hex.EncodeToString(append([]byte{byte(len(commitment.TagAction))}, commitment.TagAction...)))
	for _, ac := range af.Cases {
		t.Run(ac.ID, func(t *testing.T) {
			action, salt := actionBytes(t, ac.actionSpec), actionSalt(t, ac.actionSpec)
			h, err := commitment.ActionHash(ac.ActionType, salt, action)
			require.NoError(t, err)
			assert.Equal(t, ac.ActionHashHex, hex.EncodeToString(h[:]))
			if ac.PreimageHex != "" {
				sum := sha256.Sum256(mustHex(t, ac.PreimageHex))
				assert.Equal(t, ac.ActionHashHex, hex.EncodeToString(sum[:]), "preimage")
			}
		})
	}
	for _, rc := range af.Reject {
		t.Run(rc.ID, func(t *testing.T) {
			c := &commitment.Commitment{Action: commitment.Action{Type: rc.ActionType, Hash: mustHex(t, rc.CommittedActionHashHex)}}
			err := commitment.CheckAction(c, actionBytes(t, rc.actionSpec), actionSalt(t, rc.actionSpec))
			assertSentinel(t, err, rc.ExpectError)
		})
	}
}

func TestAnchorZeroNeverDecodesAsIncluded(t *testing.T) {
	var rf rejectFile
	loadJSON(t, "reject.json", &rf)
	for _, rc := range rf.Cases {
		if rc.ID != "anchor_0" {
			continue
		}
		s, err := commitment.DecodeSigned(mustHex(t, rc.EnvelopeHex))
		require.NoError(t, err, "the present zero is a stage S refusal, not a decoding one")
		assert.False(t, s.Commitment.PayloadRef.Pending())
		require.ErrorIs(t, commitment.ValidateStatic(&s.Commitment, commitment.DefaultParams()), commitment.ErrInvalidEnum)
		return
	}
	require.FailNow(t, "no anchor_0 vector")
}

func TestInMemoryShapes(t *testing.T) {
	vf := loadValid(t)
	params := toParams(t, vf.Params)
	base := toCommitment(t, validCaseByID(t, vf, "v1_minimal_included_fibre").Input)

	short := *base
	short.MandateRef = make([]byte, 31)
	require.ErrorIs(t, commitment.ValidateStatic(&short, params), commitment.ErrFieldSize)

	v0 := *base
	v0.Version = 0
	require.ErrorIs(t, commitment.ValidateStatic(&v0, params), commitment.ErrUnsupportedVersion)

	pending := *base
	pending.PayloadRef.Anchor = commitment.AnchorPending
	require.NoError(t, commitment.ValidateStatic(&pending, params))
	b, err := commitment.EncodePayloadRef(pending.PayloadRef)
	require.NoError(t, err)
	ref, err := commitment.DecodePayloadRef(b)
	require.NoError(t, err)
	assert.True(t, ref.Pending(), "the standalone reference carries the pending form")
	pending.PayloadRef.Anchor = 1
	_, err = commitment.EncodePayloadRef(pending.PayloadRef)
	require.ErrorIs(t, err, commitment.ErrInvalidEnum)

	a := &commitment.Authorization{Version: 1, CommitmentHash: make([]byte, 32), ActionHash: make([]byte, 32),
		GateID: "g", Expires: 1, Path: commitment.PathDA, Mode: commitment.ModeStrict, AnchorDeadline: 9}
	require.ErrorIs(t, commitment.ValidateAuthorization(a), commitment.ErrUnknownKey)
	a.Mode = commitment.ModeFast
	require.NoError(t, commitment.ValidateAuthorization(a))
	a.AnchorDeadline = 0
	require.ErrorIs(t, commitment.ValidateAuthorization(a), commitment.ErrMissingField)
	a.Mode = 0
	require.ErrorIs(t, commitment.ValidateAuthorization(a), commitment.ErrInvalidEnum)
	a.Version, a.Mode = 0, commitment.ModeStrict
	require.ErrorIs(t, commitment.ValidateAuthorization(a), commitment.ErrUnsupportedVersion)
}
