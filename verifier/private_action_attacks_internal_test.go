package verifier

import (
	"bytes"
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/policy"
	"github.com/vgonkivs/edicta/policy/privatebox"
	"github.com/vgonkivs/edicta/sdk/blob"
)

type privateActionFixture struct {
	dec     *archive.DecisionRecord
	rec     *archive.PrivateBlobRecord
	h       commitment.Hash
	sks     map[string]*ecdh.PrivateKey
	auditor []policy.Auditor
}

func loadPrivateAction(t *testing.T) privateActionFixture {
	raw, err := os.ReadFile("../spec/vectors/v1/verify.json")
	require.NoError(t, err)
	var d struct {
		Records map[string]struct {
			CBORHex string `json:"record_cbor_hex"`
		} `json:"records"`
	}
	require.NoError(t, json.Unmarshal(raw, &d))
	dec, err := archive.Decode(unhex(t, d.Records["decision_private_fibre"].CBORHex))
	require.NoError(t, err)
	rec, err := archive.Decode(unhex(t, d.Records["private_action_fibre"].CBORHex))
	require.NoError(t, err)
	s, err := commitment.DecodeSigned(dec.(*archive.DecisionRecord).Envelope)
	require.NoError(t, err)
	h, err := commitment.HashOf(&s.Commitment)
	require.NoError(t, err)

	var keys struct {
		Keys map[string]struct {
			SK string `json:"sk_hex"`
		} `json:"auditor_keys"`
	}
	praw, err := os.ReadFile("../spec/vectors/policy/private.json")
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(praw, &keys))
	f := privateActionFixture{dec: dec.(*archive.DecisionRecord), rec: rec.(*archive.PrivateBlobRecord), h: h, sks: map[string]*ecdh.PrivateKey{}}
	for name, k := range keys.Keys {
		sk, err := ecdh.X25519().NewPrivateKey(unhex(t, k.SK))
		require.NoError(t, err)
		f.sks[name] = sk
		if name == "auditor-1" || name == "auditor-2" {
			pub := sk.PublicKey().Bytes()
			f.auditor = append(f.auditor, policy.Auditor{Kid: policy.AuditorKid(pub), Pubkey: pub, Label: name})
		}
	}
	require.Len(t, f.auditor, 2)
	return f
}

// check runs the action check over the decision and the given kind 15
// record with the given auditor keys.
func (f privateActionFixture) check(t *testing.T, rec *archive.PrivateBlobRecord, keys ...*ecdh.PrivateKey) Check {
	t.Helper()
	files := map[string][]byte{}
	for _, r := range []archive.Record{f.dec, rec} {
		b, err := archive.Encode(r)
		require.NoError(t, err)
		p, err := archive.KeyPath(r)
		require.NoError(t, err)
		files[p] = b
	}
	cfg := Config{Params: commitment.Params{FibreRetentionS: 14400, BlobRetentionS: 14400, SkewS: 30}}
	for _, k := range keys {
		rk, err := blob.NewRecipientKey(k)
		require.NoError(t, err)
		cfg.AuditorKeys = append(cfg.AuditorKeys, rk)
	}
	v := &Verifier{cfg: cfg, archive: pathArchive{files: files}}
	r := &run{v: v, h: f.h, ctx: t.Context()}
	require.True(t, r.envelope(f.dec))
	require.NoError(t, r.checkAction(f.dec))
	got, ok := r.rep.Check(CheckAction)
	require.True(t, ok)
	return got
}

func (f privateActionFixture) reseal(t *testing.T, plaintext []byte) *archive.PrivateBlobRecord {
	env, err := privatebox.Sealer{}.Seal(policy.PrivateAction, plaintext, f.auditor)
	require.NoError(t, err)
	return &archive.PrivateBlobRecord{PlaintextKind: policy.PrivateAction, Hash: bytes.Clone(f.rec.Hash), Envelope: env}
}

// TestPrivateActionTampering: with an auditor key the action check opens
// the kind 15 action and recomputes the salted hash; any change of the
// envelope or of its plaintext is source_corrupt, and a key the envelope
// does not list is policy_private, never a crash or a pass.
func TestPrivateActionTampering(t *testing.T) {
	f := loadPrivateAction(t)
	a1 := f.sks["auditor-1"]
	o, err := privatebox.NewOpener(a1)
	require.NoError(t, err)
	pt, _, err := o.Open(policy.PrivateAction, f.rec.Envelope)
	require.NoError(t, err)
	require.Greater(t, len(pt), commitment.ActionSaltSize)
	salt, action := pt[:commitment.ActionSaltSize], pt[commitment.ActionSaltSize:]

	ok := f.check(t, f.rec, a1)
	require.Equal(t, StatusPass, ok.Status, "control: %v", ok.Err)

	flipped := *f.rec
	flipped.Envelope = bytes.Clone(f.rec.Envelope)
	flipped.Envelope[len(flipped.Envelope)-1] ^= 1

	otherSalt := sha256.Sum256([]byte("another salt"))
	otherAction := append(bytes.Clone(action[:len(action)-1]), action[len(action)-1]^1)
	stranger, err := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{7}, 32))
	require.NoError(t, err)

	for name, tc := range map[string]struct {
		rec    *archive.PrivateBlobRecord
		keys   []*ecdh.PrivateKey
		status Status
		reason Reason
	}{
		"envelope byte flipped":        {&flipped, []*ecdh.PrivateKey{a1}, StatusUnchecked, ReasonSourceCorrupt},
		"resealed with another salt":   {f.reseal(t, append(otherSalt[:], action...)), []*ecdh.PrivateKey{a1}, StatusUnchecked, ReasonSourceCorrupt},
		"resealed with another action": {f.reseal(t, append(bytes.Clone(salt), otherAction...)), []*ecdh.PrivateKey{a1}, StatusUnchecked, ReasonSourceCorrupt},
		"salt only":                    {f.reseal(t, bytes.Clone(salt)), []*ecdh.PrivateKey{a1}, StatusUnchecked, ReasonSourceCorrupt},
		"honest reseal":                {f.reseal(t, bytes.Clone(pt)), []*ecdh.PrivateKey{a1}, StatusPass, ""},
		"a key the envelope lacks":     {f.rec, []*ecdh.PrivateKey{stranger}, StatusUnchecked, ReasonPolicyPrivate},
		"auditor-3 is not listed":      {f.rec, []*ecdh.PrivateKey{f.sks["auditor-3"]}, StatusUnchecked, ReasonPolicyPrivate},
		"a stranger, then auditor-2":   {f.rec, []*ecdh.PrivateKey{stranger, f.sks["auditor-2"]}, StatusPass, ""},
	} {
		t.Run(name, func(t *testing.T) {
			var keys []*ecdh.PrivateKey
			for _, k := range tc.keys {
				require.NotNil(t, k)
				keys = append(keys, k)
			}
			got := f.check(t, tc.rec, keys...)
			assert.Equal(t, tc.status, got.Status, "%v", got.Err)
			assert.Equal(t, tc.reason, got.Reason)
		})
	}
}
