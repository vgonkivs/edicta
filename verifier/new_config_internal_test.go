package verifier

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/gate"
	"github.com/vgonkivs/edicta/policy"
	"github.com/vgonkivs/edicta/principalsig"
	"github.com/vgonkivs/edicta/sdk/blob"
	"github.com/vgonkivs/edicta/test/gatefix"
	"github.com/vgonkivs/edicta/test/sdkfix"
)

// The embedded nil interfaces satisfy New's non-nil checks; these tests
// never reach them.
type unusedReader struct{ Reader }
type unusedCommitter struct{ gate.DACommitter }
type unusedAnchor struct{ AnchorVerifier }

func newForTest(t *testing.T, cfg Config) *Verifier {
	t.Helper()
	v, err := New(Deps{
		Config:     cfg,
		Archive:    unusedReader{},
		Committers: map[commitment.DA]gate.DACommitter{commitment.DACelestiaBlob: unusedCommitter{}},
		Anchors:    map[commitment.DA]AnchorVerifier{commitment.DACelestiaBlob: unusedAnchor{}},
	})
	require.NoError(t, err)
	return v
}

// Every Config field must reach the verifier. A new field that New does not
// copy fails here once it is set below.
func TestNewKeepsEveryConfigField(t *testing.T) {
	sv := sdkfix.Load(t)
	key := sv.Key(t, sv.Case0(t).Recipients[0].Key)
	cfg := Config{
		Params:           commitment.DefaultParams(),
		GateKeys:         []ed25519.PublicKey{gatefix.Key(t, "gate1").Public().(ed25519.PublicKey)},
		PrincipalKeys:    []policy.PrincipalID{{Principal: gatefix.Pub(t, "agent2")}},
		PrincipalSchemes: []principalsig.Scheme{principalsig.Ed25519},
		RequirePolicy:    true,
		PolicyFull:       true,
		MaxWalkSteps:     7,
		Evidence:         [][]byte{{1, 2, 3}},
		PayloadKeys:      []blob.RecipientKey{key.OpenKey(true)},
		AuditorKeys:      []blob.RecipientKey{key.OpenKey(false)},
	}
	in := reflect.ValueOf(cfg)
	for i := range in.NumField() {
		require.Falsef(t, in.Field(i).IsZero(), "set Config.%s in this test", in.Type().Field(i).Name)
	}
	got := reflect.ValueOf(newForTest(t, cfg).cfg)
	for i := range got.NumField() {
		name := got.Type().Field(i).Name
		assert.Truef(t, reflect.DeepEqual(in.Field(i).Interface(), got.Field(i).Interface()), "New drops Config.%s", name)
	}
}

// The payload-vs-archive salt mismatch vector on a verifier built by New: the
// payload key opens a payload, and a salt that differs from the archive copy
// leaves the action unchecked as a bad copy. Two salts that both hash to the
// committed action need a collision, so the case uses the vector's salt.
func TestSaltMismatchThroughNew(t *testing.T) {
	sv := sdkfix.Load(t)
	c0 := sv.Case0(t)
	key := sv.Key(t, c0.Recipients[0].Key)
	v := newForTest(t, Config{
		Params:      commitment.Params{FibreRetentionS: 14400, BlobRetentionS: 14400, SkewS: 30},
		GateKeys:    []ed25519.PublicKey{gatefix.Key(t, "gate1").Public().(ed25519.PublicKey)},
		PayloadKeys: []blob.RecipientKey{key.OpenKey(true)},
	})

	s0, err := commitment.DecodeSigned(c0.Envelope)
	require.NoError(t, err)
	o, err := (&run{v: v, c: &s0.Commitment, sig: s0.Signature}).openPayload(c0.Blob)
	require.NoError(t, err)
	require.NotNil(t, o, "the key given to New opens the payload")

	raw, err := os.ReadFile("../spec/vectors/v1/verify.json")
	require.NoError(t, err)
	var d actionVectors
	require.NoError(t, json.Unmarshal(raw, &d))
	ran := false
	for _, c := range d.Cases {
		if c.ID != "payload_archive_salt_mismatch" {
			continue
		}
		ran = true
		b, err := hex.DecodeString(d.Records[c.Decision].CBORHex)
		require.NoError(t, err)
		decoded, err := archive.Decode(b)
		require.NoError(t, err)
		dec := decoded.(*archive.DecisionRecord)
		s, err := commitment.DecodeSigned(dec.Envelope)
		require.NoError(t, err)
		h, err := commitment.HashOf(&s.Commitment)
		require.NoError(t, err)

		r := &run{v: v, h: h}
		require.True(t, r.envelope(dec))
		r.checkAction(dec)
		salt, err := hex.DecodeString(c.PayloadSalt)
		require.NoError(t, err)
		r.compareSalt(salt)
		got, ok := r.rep.Check(CheckAction)
		require.True(t, ok)
		assert.Equal(t, StatusUnchecked, got.Status, "%v", got.Err)
		assert.Equal(t, ReasonSourceCorrupt, got.Reason)
		assert.Equal(t, Reason(c.Expect.Action.Reason), got.Reason)
	}
	require.True(t, ran)
}
