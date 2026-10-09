package policy_test

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/policy"
)

type privateDoc struct {
	Tags      map[string]string `json:"tags"`
	Envelopes []struct {
		ID        string `json:"id"`
		Kind      string `json:"plaintext_kind"`
		Plaintext string `json:"plaintext_cbor_hex"`
	} `json:"envelopes"`
	Verdict struct {
		Signed        string   `json:"signed_verdict_hex"`
		VerdictHash   string   `json:"verdict_hash_hex"`
		PublicKeys    []string `json:"public_keys"`
		PrivateHash   string   `json:"private_hash_hex"`
		PrevStateHash string   `json:"prev_state_hash_hex"`
		Part          string   `json:"private_part_cbor_hex"`
		PrevState     string   `json:"prev_state_cbor_hex"`
		Reject        []struct {
			ID     string `json:"id"`
			Signed string `json:"signed_verdict_hex"`
			Cause  string `json:"cause"`
		} `json:"reject"`
	} `json:"private_verdict"`
	Deny struct {
		Signed     string   `json:"signed_verdict_hex"`
		PublicKeys []string `json:"public_keys"`
		WithKey    struct {
			Part   string `json:"private_part_cbor_hex"`
			Reason string `json:"reason"`
		} `json:"with_key"`
		Second struct {
			Reason string `json:"reason"`
			Signed string `json:"signed_verdict_hex"`
			Part   string `json:"private_part_cbor_hex"`
		} `json:"second_deny"`
		Retry struct {
			Reason      string `json:"reason"`
			Signed      string `json:"signed_verdict_hex"`
			PrivateHash string `json:"private_hash_hex"`
		} `json:"same_reason_retry"`
	} `json:"private_deny"`
	Blinding []struct {
		ID          string `json:"id"`
		State       string `json:"state_cbor_hex"`
		Salt        string `json:"state_salt_hex"`
		StateHash   string `json:"state_hash_hex"`
		StateHashP  string `json:"state_hash_p_hex"`
		GenesisHash string `json:"genesis_hash_hex"`
		BucketHash  string `json:"bucket_hash_hex"`
		ClosedRoot  string `json:"closed_root_hex"`
		Key         string `json:"key_hex"`
		PartA       string `json:"private_part_a_cbor_hex"`
		HashA       string `json:"private_hash_a_hex"`
		PartB       string `json:"private_part_b_cbor_hex"`
		HashB       string `json:"private_hash_b_hex"`
	} `json:"blinding"`
	Gate struct {
		Key string `json:"gate_pubkey_hex"`
	} `json:"gate"`
}

func loadPrivate(t testing.TB) privateDoc {
	var d privateDoc
	readVec(t, "private.json", &d)
	return d
}

func TestPrivateTags(t *testing.T) {
	d := loadPrivate(t)
	assert.Equal(t, policy.TagPrivatePart, d.Tags["private-part"])
	assert.Equal(t, policy.TagPrivateAEAD, d.Tags["private"])
	assert.Equal(t, policy.TagPrivateDEK, d.Tags["private-dek"])
	assert.Equal(t, policy.TagStateBlind, d.Tags["state-blind"])
	assert.Equal(t, policy.TagBlindKey, d.Tags["blind-key"])
	assert.Equal(t, policy.TagAuditorKid, d.Tags["auditor-kid"])
}

// stateSalt is the state_salt of the vectors' private mandate.
func stateSalt(t *testing.T, d privateDoc) []byte {
	for _, e := range d.Envelopes {
		if e.Kind == "1" {
			sm, _, err := policy.DecodeSignedMandate(hx(t, e.Plaintext))
			require.NoError(t, err)
			require.Len(t, sm.Mandate.StateSalt, 32)
			return sm.Mandate.StateSalt
		}
	}
	require.FailNow(t, "no mandate envelope")
	return nil
}

func keyNumbers(t *testing.T, v *policy.Verdict) []string {
	set := map[int]bool{1: true, 2: true, 3: true, 4: true, 5: true, 6: true, 7: true}
	for k, ok := range map[int]bool{
		8: v.Reason != "", 9: v.Extractor != "", 10: v.Facts != nil, 11: v.AnchorTime != 0, 12: v.EvalTime != 0,
		13: v.PrevState != nil, 14: v.NewStateHash != nil, 15: v.PrevCommitmentHash != nil, 16: v.PrevVerdictHash != nil,
		17: v.DecidedAt != 0, 18: v.GateClock != 0, 19: v.PrivateHash != nil, 20: v.BlindPrevStateHash != nil,
	} {
		set[k] = ok
	}
	var out []string
	for _, k := range []int{1, 14, 15, 16, 19, 2, 20, 3, 4, 5, 6, 7} {
		if set[k] {
			out = append(out, map[int]string{1: "1", 2: "2", 3: "3", 4: "4", 5: "5", 6: "6", 7: "7", 14: "14", 15: "15", 16: "16", 19: "19", 20: "20"}[k])
		}
	}
	for k := 8; k <= 13; k++ {
		require.False(t, set[k], "key %d", k)
	}
	require.False(t, set[17] || set[18])
	return out
}

func TestPrivateVerdictVector(t *testing.T) {
	d := loadPrivate(t)
	salt := stateSalt(t, d)
	sv, h, err := policy.VerifyVerdict(hx(t, d.Verdict.Signed), hx(t, d.Gate.Key))
	require.NoError(t, err)
	assert.Equal(t, hx(t, d.Verdict.VerdictHash), h[:])
	v := &sv.Verdict
	require.True(t, v.Private())
	assert.Equal(t, d.Verdict.PublicKeys, keyNumbers(t, v))
	assert.Equal(t, hx(t, d.Verdict.PrivateHash), v.PrivateHash)
	assert.Equal(t, hx(t, d.Verdict.PrevStateHash), v.BlindPrevStateHash)

	part, err := policy.DecodePrivatePart(hx(t, d.Verdict.Part))
	require.NoError(t, err)
	ph := policy.PrivateHash(hx(t, d.Verdict.Part))
	assert.Equal(t, v.PrivateHash, ph[:])
	merged, err := policy.MergeVerdict(v, part)
	require.NoError(t, err)
	assert.False(t, merged.Private())
	assert.Equal(t, hx(t, d.Verdict.PrevState), mustState(t, merged.PrevState))
	blind, err := policy.NewSaltHasher(salt).StateHash(merged.PrevState)
	require.NoError(t, err)
	assert.Equal(t, v.BlindPrevStateHash, blind[:], "key 20 is state_hash_p(prev_state)")

	// Splitting the merged verdict with the part's salt gives back the
	// signed private form.
	again, part2, err := policy.SplitVerdict(merged, part.Salt, policy.NewSaltHasher(salt))
	require.NoError(t, err)
	assert.Equal(t, v, again)
	assert.Equal(t, part, part2)

	// A part that does not hash to private_hash does not merge.
	other := *part
	other.Salt = bytes.Repeat([]byte{1}, 32)
	_, err = policy.MergeVerdict(v, &other)
	require.ErrorIs(t, err, policy.ErrVerdictInvalid)
}

func mustState(t *testing.T, s *policy.State) []byte {
	b, err := policy.EncodeState(s)
	require.NoError(t, err)
	return b
}

func TestPrivateVerdictRejects(t *testing.T) {
	d := loadPrivate(t)
	require.Len(t, d.Verdict.Reject, 13)
	causes := map[string]error{"ErrUnknownKey": commitment.ErrUnknownKey, "ErrMissingField": commitment.ErrMissingField}
	for _, r := range d.Verdict.Reject {
		t.Run(r.ID, func(t *testing.T) {
			_, _, err := policy.DecodeSignedVerdict(hx(t, r.Signed))
			require.ErrorIs(t, err, policy.ErrVerdictInvalid)
			require.ErrorIs(t, err, causes[r.Cause])
		})
	}
}

func TestPrivateDenyVectors(t *testing.T) {
	d := loadPrivate(t)
	gk := hx(t, d.Gate.Key)
	sv, _, err := policy.VerifyVerdict(hx(t, d.Deny.Signed), gk)
	require.NoError(t, err)
	assert.Equal(t, d.Deny.PublicKeys, keyNumbers(t, &sv.Verdict))
	part, err := policy.DecodePrivatePart(hx(t, d.Deny.WithKey.Part))
	require.NoError(t, err)
	merged, err := policy.MergeVerdict(&sv.Verdict, part)
	require.NoError(t, err)
	assert.Equal(t, d.Deny.WithKey.Reason, merged.Reason)

	second, _, err := policy.VerifyVerdict(hx(t, d.Deny.Second.Signed), gk)
	require.NoError(t, err)
	p2, err := policy.DecodePrivatePart(hx(t, d.Deny.Second.Part))
	require.NoError(t, err)
	m2, err := policy.MergeVerdict(&second.Verdict, p2)
	require.NoError(t, err)
	assert.Equal(t, d.Deny.Second.Reason, m2.Reason)
	assert.Equal(t, uint64(1), m2.GateClock)
	assert.NotEqual(t, sv.Verdict.PrivateHash, second.Verdict.PrivateHash)

	retry, _, err := policy.VerifyVerdict(hx(t, d.Deny.Retry.Signed), gk)
	require.NoError(t, err)
	assert.Equal(t, hx(t, d.Deny.Retry.PrivateHash), retry.Verdict.PrivateHash)
	assert.NotEqual(t, sv.Verdict.PrivateHash, retry.Verdict.PrivateHash, "a fresh salt gives a fresh private_hash")
}

func TestPrivateBlindingVectors(t *testing.T) {
	d := loadPrivate(t)
	require.Len(t, d.Blinding, 5)
	for _, b := range d.Blinding {
		t.Run(b.ID, func(t *testing.T) {
			h := policy.NewSaltHasher(hx(t, b.Salt))
			switch b.ID {
			case "state_hash_blind_vs_public", "state_hash_blind_genesis":
				s, err := policy.DecodeState(hx(t, b.State))
				require.NoError(t, err)
				p, err := h.StateHash(s)
				require.NoError(t, err)
				assert.Equal(t, hx(t, b.StateHashP), p[:])
				pub, err := policy.NewSaltHasher(nil).StateHash(s)
				require.NoError(t, err)
				if b.GenesisHash != "" {
					assert.Equal(t, hx(t, b.GenesisHash), pub[:])
					g := policy.GenesisStateHash()
					assert.Equal(t, g, p)
				} else {
					assert.Equal(t, hx(t, b.StateHash), pub[:])
				}
			case "blind_key_bucket":
				k := h.BlobKey(policy.PrivateBucket, commitment.Hash(hx(t, b.BucketHash)))
				assert.Equal(t, hx(t, b.Key), k[:])
			case "blind_key_closed":
				k := h.BlobKey(policy.PrivateClosedSet, commitment.Hash(hx(t, b.ClosedRoot)))
				assert.Equal(t, hx(t, b.Key), k[:])
			case "private_part_salt":
				a, err := policy.DecodePrivatePart(hx(t, b.PartA))
				require.NoError(t, err)
				bb, err := policy.DecodePrivatePart(hx(t, b.PartB))
				require.NoError(t, err)
				a.Salt, bb.Salt = nil, nil
				assert.Equal(t, a, bb, "equal content")
				ha, hb := policy.PrivateHash(hx(t, b.PartA)), policy.PrivateHash(hx(t, b.PartB))
				assert.Equal(t, hx(t, b.HashA), ha[:])
				assert.Equal(t, hx(t, b.HashB), hb[:])
				assert.NotEqual(t, ha, hb)
			default:
				require.FailNow(t, "unknown blinding case "+b.ID)
			}
		})
	}
}

func TestPublicHasherNeverBlinds(t *testing.T) {
	h := policy.NewStateHasher(nil)
	assert.False(t, h.Private())
	k := commitment.Hash{1}
	assert.Equal(t, k, h.BlobKey(policy.PrivateBucket, k))
	p := policy.NewSaltHasher(bytes.Repeat([]byte{2}, 32))
	assert.Equal(t, k, p.BlobKey(policy.PrivatePartKind, k), "only buckets and closed sets are blinded")
	assert.NotEqual(t, k, p.BlobKey(policy.PrivateBucket, k))
}

func TestCounterRefusesAnotherStateSalt(t *testing.T) {
	m := &policy.Mandate{MandateID: bytes.Repeat([]byte{1}, 16), Version: 1, StateSalt: bytes.Repeat([]byte{3}, 32),
		Auditors: []policy.Auditor{{}}, Assets: []policy.AssetRule{{Asset: "a", Scale: 2}}}
	c := policy.NewCounter(m, commitment.Hash{1})
	assert.Equal(t, m.StateSalt, c.StateSalt)
	next := *m
	next.Version = 2
	next.StateSalt = bytes.Repeat([]byte{4}, 32)
	require.ErrorIs(t, c.Adopt(&next, commitment.Hash{2}), policy.ErrStateSaltChanged)
	assert.EqualValues(t, 1, c.Version, "a refusal leaves the cell unchanged")
	next.StateSalt, next.Auditors = nil, nil
	require.ErrorIs(t, c.Adopt(&next, commitment.Hash{2}), policy.ErrStateSaltChanged, "no switch to public mode")
	next.StateSalt = m.StateSalt
	require.NoError(t, c.Adopt(&next, commitment.Hash{2}))
	assert.Equal(t, m.StateSalt, c.StateSalt)
}

func TestPlaintextHashKinds(t *testing.T) {
	_, err := policy.PlaintextHash(policy.PrivateAction, make([]byte, 32), "a/b")
	require.Error(t, err, "an action plaintext is the salt and at least one byte")
	_, err = policy.PlaintextHash(6, []byte{1}, "")
	require.ErrorIs(t, err, commitment.ErrInvalidEnum)
	set := policy.EmptyClosedSet()
	b, err := policy.EncodeClosedSet(&set)
	require.NoError(t, err)
	h, err := policy.PlaintextHash(policy.PrivateClosedSet, b, "")
	require.NoError(t, err)
	assert.Equal(t, policy.HashClosedSetBytes(b), h)
}
