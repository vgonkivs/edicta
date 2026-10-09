package commitment_test

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/commitment"
)

const vectorDirV1 = "../spec/vectors/v1"

func loadJSONV1(t testing.TB, name string, v any) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(vectorDirV1, name))
	require.NoError(t, err, "read vector file")
	require.NoErrorf(t, json.Unmarshal(b, v), "parse %s", name)
}

type jsonInputV1 struct {
	jsonInput
	Anchor     string
	MandateRef string
}

// UnmarshalJSON reads the v1 keys next to the embedded v0 input.
func (in *jsonInputV1) UnmarshalJSON(b []byte) error {
	if err := json.Unmarshal(b, &in.jsonInput); err != nil {
		return err
	}
	var extra struct {
		PayloadRef struct {
			Anchor string `json:"anchor"`
		} `json:"payload_ref"`
		MandateRef string `json:"mandate_ref"`
	}
	if err := json.Unmarshal(b, &extra); err != nil {
		return err
	}
	in.Anchor = extra.PayloadRef.Anchor
	in.MandateRef = extra.MandateRef
	return nil
}

func toCommitmentV1(t testing.TB, in jsonInputV1) *commitment.Commitment {
	c := toCommitment(t, in.jsonInput)
	if in.Anchor != "" {
		c.PayloadRef.Anchor = u64(t, in.Anchor)
	}
	c.MandateRef = optHex(t, in.MandateRef)
	return c
}

type validCaseV1 struct {
	ID                string      `json:"id"`
	Input             jsonInputV1 `json:"input"`
	CommitmentCBORHex string      `json:"commitment_cbor_hex"`
	CommitmentHashHex string      `json:"commitment_hash_hex"`
	Signer            string      `json:"signer"`
	SignedTags        string      `json:"signed_tags"`
	SignedMessageHex  string      `json:"signed_message_hex"`
	SignatureHex      string      `json:"signature_hex"`
	EnvelopeHex       string      `json:"envelope_hex"`
	Now               string      `json:"now"`
	Pending           bool        `json:"pending"`
	Gate              *jsonGate   `json:"gate"`
	ActionType        string      `json:"action_type"`
	ActionHashHex     string      `json:"action_hash_hex"`
	actionSpec
}

type validFileV1 struct {
	Params jsonParams    `json:"params"`
	Gate   jsonGate      `json:"gate"`
	Cases  []validCaseV1 `json:"cases"`
}

func loadValidV1(t testing.TB) validFileV1 {
	var vf validFileV1
	loadJSONV1(t, "valid.json", &vf)
	return vf
}

func TestV1ValidVectors(t *testing.T) {
	vf := loadValidV1(t)
	require.Len(t, vf.Cases, 7)
	agent1 := loadKey(t, "agent1")
	params := toParams(t, vf.Params)

	for _, vc := range vf.Cases {
		t.Run(vc.ID, func(t *testing.T) {
			require.Equal(t, "agent1", vc.Signer)
			require.Equal(t, "v1", vc.SignedTags)
			c := toCommitmentV1(t, vc.Input)
			require.EqualValues(t, commitment.VersionV1, c.Version)
			wantCanon := mustHex(t, vc.CommitmentCBORHex)
			envelope := mustHex(t, vc.EnvelopeHex)

			canon, err := commitment.Encode(c)
			require.NoError(t, err)
			assert.Equal(t, vc.CommitmentCBORHex, hex.EncodeToString(canon))

			h, err := commitment.HashOf(c)
			require.NoError(t, err)
			assert.Equal(t, vc.CommitmentHashHex, hex.EncodeToString(h[:]))
			assert.Equal(t, h, commitment.HashCanonicalFor(commitment.VersionV1, wantCanon))
			assert.EqualValues(t, commitment.VersionV1, commitment.CanonicalVersion(wantCanon))
			assert.NotEqual(t, h, commitment.HashCanonical(wantCanon), "v1 bytes never hash under the v0 tag")

			msg := commitment.SignedMessage(c.Version, h)
			require.Len(t, msg, 46)
			assert.Equal(t, vc.SignedMessageHex, hex.EncodeToString(msg))

			s, sh, err := commitment.Sign(agent1, c)
			require.NoError(t, err)
			assert.Equal(t, h, sh)
			assert.Equal(t, vc.SignatureHex, hex.EncodeToString(s.Signature))
			enc, err := commitment.EncodeSigned(s)
			require.NoError(t, err)
			assert.Equal(t, vc.EnvelopeHex, hex.EncodeToString(enc))

			dec, err := commitment.DecodeSigned(envelope)
			require.NoError(t, err)
			assert.Equal(t, c, &dec.Commitment)
			assert.Equal(t, vc.Pending, dec.Commitment.PayloadRef.Pending())

			bare, err := commitment.Decode(wantCanon)
			require.NoError(t, err)
			assert.Equal(t, c, bare)

			gate := toGate(t, vf.Gate)
			if vc.Gate != nil {
				gate = toGate(t, *vc.Gate)
			}
			_, gh, err := commitment.VerifyForGate(envelope, u64(t, vc.Now), gate, params)
			require.NoError(t, err)
			assert.Equal(t, h, gh)

			ah, err := commitment.ActionHash(vc.ActionType, actionBytes(t, vc.actionSpec))
			require.NoError(t, err)
			assert.Equal(t, vc.ActionHashHex, hex.EncodeToString(ah[:]))
			assert.Equal(t, vc.ActionHashHex, hex.EncodeToString(c.Action.Hash))

			_, err = commitment.FrozenV0Reader(envelope)
			assert.Error(t, err, "a frozen v0 reader refuses every v1 commitment")
		})
	}
}

type rejectCaseV1 struct {
	ID          string    `json:"id"`
	Stage       string    `json:"stage"`
	Rule        string    `json:"rule"`
	Reader      string    `json:"reader"`
	EnvelopeHex string    `json:"envelope_hex"`
	Now         string    `json:"now"`
	Gate        *jsonGate `json:"gate"`
	ExpectError string    `json:"expect_error"`
}

func TestV1RejectVectors(t *testing.T) {
	var rf struct {
		Params jsonParams     `json:"params"`
		Gate   jsonGate       `json:"gate"`
		Cases  []rejectCaseV1 `json:"cases"`
	}
	loadJSONV1(t, "reject.json", &rf)
	require.NotEmpty(t, rf.Cases)
	params := toParams(t, rf.Params)

	for _, rc := range rf.Cases {
		t.Run(rc.ID, func(t *testing.T) {
			envelope := mustHex(t, rc.EnvelopeHex)
			var err error
			switch rc.Reader {
			case "v1":
				gate := toGate(t, rf.Gate)
				if rc.Gate != nil {
					gate = toGate(t, *rc.Gate)
				}
				_, _, err = commitment.VerifyForGate(envelope, u64(t, rc.Now), gate, params)
			case "v0":
				_, err = commitment.FrozenV0Reader(envelope)
			default:
				require.FailNow(t, "unknown reader "+rc.Reader)
			}
			assertSentinel(t, err, rc.ExpectError)
		})
	}
}

type authorizationInputV1 struct {
	authorizationInput
	Mode           string
	AnchorDeadline string
}

func (in *authorizationInputV1) UnmarshalJSON(b []byte) error {
	if err := json.Unmarshal(b, &in.authorizationInput); err != nil {
		return err
	}
	var extra struct {
		Mode           string `json:"mode"`
		AnchorDeadline string `json:"anchor_deadline"`
	}
	if err := json.Unmarshal(b, &extra); err != nil {
		return err
	}
	in.Mode, in.AnchorDeadline = extra.Mode, extra.AnchorDeadline
	return nil
}

type authorizationCheckV1 struct {
	authorizationCheck
	AcceptVersions []string
}

func (c *authorizationCheckV1) UnmarshalJSON(b []byte) error {
	if err := json.Unmarshal(b, &c.authorizationCheck); err != nil {
		return err
	}
	var extra struct {
		AcceptVersions []string `json:"accept_versions"`
	}
	if err := json.Unmarshal(b, &extra); err != nil {
		return err
	}
	c.AcceptVersions = extra.AcceptVersions
	return nil
}

func toAuthorizationCheckV1(t testing.TB, c authorizationCheckV1) commitment.AuthorizationCheck {
	chk := toAuthorizationCheck(t, c.authorizationCheck)
	for _, v := range c.AcceptVersions {
		chk.AcceptVersions = append(chk.AcceptVersions, u64(t, v))
	}
	return chk
}

func TestV1AuthorizationVectors(t *testing.T) {
	var af struct {
		Cases []struct {
			ID                     string               `json:"id"`
			CommitmentRef          string               `json:"commitment_ref"`
			Signer                 string               `json:"signer"`
			SignedTags             string               `json:"signed_tags"`
			Input                  authorizationInputV1 `json:"input"`
			AuthorizationCBORHex   string               `json:"authorization_cbor_hex"`
			AuthorizationHashHex   string               `json:"authorization_hash_hex"`
			SignedMessageHex       string               `json:"signed_message_hex"`
			SignatureHex           string               `json:"signature_hex"`
			SignedAuthorizationHex string               `json:"signed_authorization_hex"`
			Check                  authorizationCheckV1 `json:"check"`
		} `json:"cases"`
		Reject []struct {
			ID                     string               `json:"id"`
			Executor               string               `json:"executor"`
			SignedAuthorizationHex string               `json:"signed_authorization_hex"`
			Check                  authorizationCheckV1 `json:"check"`
			ExpectError            string               `json:"expect_error"`
		} `json:"reject"`
	}
	loadJSONV1(t, "authorization.json", &af)
	require.NotEmpty(t, af.Cases)
	require.NotEmpty(t, af.Reject)
	gate1 := loadKey(t, "gate1")
	vf := loadValidV1(t)

	for _, ac := range af.Cases {
		t.Run(ac.ID, func(t *testing.T) {
			require.Equal(t, "gate1", ac.Signer)
			require.Equal(t, "v1", ac.SignedTags)
			a := toAuthorization(t, ac.Input.authorizationInput)
			a.Mode = u64(t, ac.Input.Mode)
			if ac.Input.AnchorDeadline != "" {
				a.AnchorDeadline = u64(t, ac.Input.AnchorDeadline)
			}
			canon, err := commitment.EncodeAuthorization(a)
			require.NoError(t, err)
			assert.Equal(t, ac.AuthorizationCBORHex, hex.EncodeToString(canon))
			h := commitment.HashAuthorizationFor(a.Version, canon)
			assert.Equal(t, ac.AuthorizationHashHex, hex.EncodeToString(h[:]))
			msg := commitment.AuthorizationSigningMessageFor(a.Version, h)
			require.Len(t, msg, 60)
			assert.Equal(t, ac.SignedMessageHex, hex.EncodeToString(msg))
			sig := ed25519.Sign(gate1, msg)
			assert.Equal(t, ac.SignatureHex, hex.EncodeToString(sig))
			signed, err := commitment.EncodeSignedAuthorization(&commitment.SignedAuthorization{Authorization: *a, Signature: sig})
			require.NoError(t, err)
			assert.Equal(t, ac.SignedAuthorizationHex, hex.EncodeToString(signed))
			require.LessOrEqual(t, len(signed), commitment.MaxAuthorizationSize)

			sa, dh, err := commitment.DecodeSignedAuthorization(signed)
			require.NoError(t, err)
			assert.Equal(t, a, &sa.Authorization)
			assert.Equal(t, h, dh)
			require.NoError(t, commitment.ValidateAuthorization(a, nil))
			if ac.Check.GateID != "" {
				_, _, err = commitment.VerifyAuthorization(signed, toAuthorizationCheckV1(t, ac.Check))
				require.NoError(t, err)
			}

			_, _, err = commitment.FrozenV0AuthorizationReader(signed)
			require.ErrorIs(t, err, commitment.ErrUnknownKey, "a v0 executor refuses every Authorization v1")

			if ac.CommitmentRef != "" {
				for _, vc := range vf.Cases {
					if vc.ID != ac.CommitmentRef {
						continue
					}
					assert.Equal(t, vc.CommitmentHashHex, ac.Input.CommitmentHash)
					wantMode := uint64(commitment.ModeStrict)
					if vc.Pending {
						wantMode = commitment.ModeFast
					}
					assert.Equal(t, wantMode, a.Mode, "mode follows the reference form")
				}
			}
		})
	}

	for _, rc := range af.Reject {
		t.Run(rc.ID, func(t *testing.T) {
			b := mustHex(t, rc.SignedAuthorizationHex)
			var err error
			switch rc.Executor {
			case "v1":
				_, _, err = commitment.VerifyAuthorization(b, toAuthorizationCheckV1(t, rc.Check))
			case "v0":
				_, _, err = commitment.FrozenV0AuthorizationReader(b)
			default:
				require.FailNow(t, "unknown executor "+rc.Executor)
			}
			assertSentinel(t, err, rc.ExpectError)
		})
	}
}

func TestV1LimitVectors(t *testing.T) {
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
	loadJSONV1(t, "limits.json", &lf)
	require.NotEmpty(t, lf.Cases)
	assert.EqualValues(t, commitment.MaxSignedSize, u64(t, lf.Limits["max_signed_size"]))
	assert.EqualValues(t, commitment.MaxCommitmentSize, u64(t, lf.Limits["max_commitment_size"]))
	assert.EqualValues(t, commitment.MaxAuthorizationSize, u64(t, lf.Limits["max_authorization_size"]))
	params := toParams(t, loadValidV1(t).Params)

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

func TestV1AnchorZeroNeverDecodesAsIncluded(t *testing.T) {
	var rf struct {
		Cases []rejectCaseV1 `json:"cases"`
	}
	loadJSONV1(t, "reject.json", &rf)
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

func TestV1InMemoryShapes(t *testing.T) {
	vf := loadValidV1(t)
	params := toParams(t, vf.Params)
	var base *commitment.Commitment
	for _, vc := range vf.Cases {
		if vc.ID == "v1_minimal_included_fibre" {
			base = toCommitmentV1(t, vc.Input)
		}
	}
	require.NotNil(t, base)

	v0 := *base
	v0.Version = commitment.VersionV0
	v0.MandateRef = make([]byte, 32)
	require.ErrorIs(t, commitment.ValidateStatic(&v0, params), commitment.ErrUnknownKey)
	v0.MandateRef = nil
	v0.PayloadRef.Anchor = commitment.AnchorPending
	require.ErrorIs(t, commitment.ValidateStatic(&v0, params), commitment.ErrUnknownKey)

	short := *base
	short.MandateRef = make([]byte, 31)
	require.ErrorIs(t, commitment.ValidateStatic(&short, params), commitment.ErrFieldSize)

	pending := *base
	pending.PayloadRef.Anchor = commitment.AnchorPending
	require.NoError(t, commitment.ValidateStatic(&pending, params))
	_, err := commitment.EncodePayloadRef(pending.PayloadRef)
	require.ErrorIs(t, err, commitment.ErrUnknownKey, "the standalone reference keeps its v0 form")

	a := &commitment.Authorization{Version: 1, CommitmentHash: make([]byte, 32), ActionHash: make([]byte, 32),
		GateID: "g", Expires: 1, Path: commitment.PathDA, Mode: commitment.ModeStrict, AnchorDeadline: 9}
	require.ErrorIs(t, commitment.ValidateAuthorization(a, nil), commitment.ErrUnknownKey)
	a.Mode = commitment.ModeFast
	require.NoError(t, commitment.ValidateAuthorization(a, nil))
	a.AnchorDeadline = 0
	require.ErrorIs(t, commitment.ValidateAuthorization(a, nil), commitment.ErrMissingField)
	a.Version, a.Mode = 0, 0
	require.NoError(t, commitment.ValidateAuthorization(a, nil))
	a.Mode = commitment.ModeStrict
	require.ErrorIs(t, commitment.ValidateAuthorization(a, nil), commitment.ErrUnknownKey)
}
