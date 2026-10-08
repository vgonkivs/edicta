package policy_test

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/policy"
)

func readVec(t testing.TB, name string, v any) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "spec", "vectors", "policy", name))
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(b, v))
}

func hx(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	require.NoError(t, err)
	return b
}

func u64(t testing.TB, s string) uint64 {
	t.Helper()
	if s == "" {
		return 0
	}
	v, err := strconv.ParseUint(s, 10, 64)
	require.NoError(t, err)
	return v
}

type jFacts struct {
	Kind      string `json:"kind"`
	Asset     string `json:"asset"`
	Amount    string `json:"amount"`
	Scale     string `json:"scale"`
	Recipient string `json:"recipient"`
}

func (j jFacts) facts(t testing.TB) policy.Facts {
	return policy.Facts{Kind: j.Kind, Asset: j.Asset, Amount: hx(t, j.Amount), Scale: u64(t, j.Scale), Recipient: j.Recipient}
}

type jMandate struct {
	Format    string   `json:"format"`
	Principal string   `json:"principal"`
	GateID    string   `json:"gate_id"`
	Agents    []string `json:"agents"`
	NotBefore string   `json:"not_before"`
	NotAfter  string   `json:"not_after"`
	Assets    []struct {
		Asset        string `json:"asset"`
		Scale        string `json:"scale"`
		PerActionMax string `json:"per_action_max"`
		Periods      []struct {
			Hours string `json:"hours"`
			Max   string `json:"max"`
		} `json:"periods"`
		Recipients []string `json:"recipients"`
	} `json:"assets"`
	CountLimits []struct {
		Hours    string `json:"hours"`
		MaxCount string `json:"max_count"`
	} `json:"count_limits"`
	MandateID      string   `json:"mandate_id"`
	Version        string   `json:"version"`
	MaxDecisionAge string   `json:"max_decision_age"`
	MinSpacing     string   `json:"min_spacing"`
	Kinds          []string `json:"kinds"`
}

func (j jMandate) mandate(t testing.TB) *policy.Mandate {
	m := &policy.Mandate{
		Format: u64(t, j.Format), Principal: hx(t, j.Principal), GateID: j.GateID,
		NotBefore: u64(t, j.NotBefore), NotAfter: u64(t, j.NotAfter), MandateID: hx(t, j.MandateID),
		Version: u64(t, j.Version), MaxDecisionAge: u64(t, j.MaxDecisionAge), MinSpacing: u64(t, j.MinSpacing), Kinds: j.Kinds,
	}
	for _, a := range j.Agents {
		m.Agents = append(m.Agents, hx(t, a))
	}
	for _, a := range j.Assets {
		r := policy.AssetRule{Asset: a.Asset, Scale: u64(t, a.Scale), Recipients: a.Recipients}
		if a.PerActionMax != "" {
			r.PerActionMax = hx(t, a.PerActionMax)
		}
		for _, p := range a.Periods {
			r.Periods = append(r.Periods, policy.PeriodLimit{Hours: u64(t, p.Hours), Max: hx(t, p.Max)})
		}
		m.Assets = append(m.Assets, r)
	}
	for _, c := range j.CountLimits {
		m.CountLimits = append(m.CountLimits, policy.CountLimit{Hours: u64(t, c.Hours), MaxCount: u64(t, c.MaxCount)})
	}
	return m
}

func TestFactsVectors(t *testing.T) {
	var f struct {
		Cases []struct {
			ID      string `json:"id"`
			Input   jFacts `json:"input"`
			CborHex string `json:"cbor_hex"`
		} `json:"cases"`
		Reject []struct {
			ID      string `json:"id"`
			CborHex string `json:"cbor_hex"`
		} `json:"reject"`
	}
	readVec(t, "facts.json", &f)
	require.NotEmpty(t, f.Cases)
	for _, c := range f.Cases {
		t.Run(c.ID, func(t *testing.T) {
			in := c.Input.facts(t)
			enc, err := policy.EncodeFacts(&in)
			require.NoError(t, err)
			require.Equal(t, c.CborHex, hex.EncodeToString(enc))
			got, err := policy.DecodeFacts(enc)
			require.NoError(t, err)
			require.Equal(t, in, got)
		})
	}
	for _, r := range f.Reject {
		t.Run(r.ID, func(t *testing.T) {
			_, err := policy.DecodeFacts(hx(t, r.CborHex))
			require.ErrorIs(t, err, policy.ErrFactsInvalid)
		})
	}
}

func TestMandateVectors(t *testing.T) {
	var f struct {
		Tags map[string]string `json:"tags"`
		Keys map[string]struct {
			SeedHex string `json:"seed_hex"`
		} `json:"keys"`
		Cases []struct {
			ID               string   `json:"id"`
			Signer           string   `json:"signer"`
			Input            jMandate `json:"input"`
			MandateCbor      string   `json:"mandate_cbor_hex"`
			MandateHash      string   `json:"mandate_hash_hex"`
			SignedMessage    string   `json:"signed_message_hex"`
			Signature        string   `json:"signature_hex"`
			SignedMandateHex string   `json:"signed_mandate_hex"`
			CounterKey       string   `json:"counter_key_hex"`
		} `json:"cases"`
		Reject []struct {
			ID          string `json:"id"`
			SignedHex   string `json:"signed_mandate_hex"`
			ExpectError string `json:"expect_error"`
		} `json:"reject"`
	}
	readVec(t, "mandate.json", &f)
	require.Equal(t, f.Tags["mandate"], policy.TagMandate)
	require.Equal(t, f.Tags["mandate-sig"], policy.TagMandateSig)
	require.Equal(t, f.Tags["verdict"], policy.TagVerdict)
	require.Equal(t, f.Tags["verdict-sig"], policy.TagVerdictSig)
	require.Equal(t, f.Tags["bucket"], policy.TagBucket)
	require.Equal(t, f.Tags["closed"], policy.TagClosed)
	require.Equal(t, f.Tags["state"], policy.TagState)
	require.Equal(t, f.Tags["counter"], policy.TagCounter)
	require.Equal(t, f.Tags["successor"], policy.TagSuccessor)
	for _, c := range f.Cases {
		t.Run(c.ID, func(t *testing.T) {
			m := c.Input.mandate(t)
			canon, err := policy.EncodeMandate(m)
			require.NoError(t, err)
			require.Equal(t, c.MandateCbor, hex.EncodeToString(canon))
			h := policy.HashMandate(canon)
			require.Equal(t, c.MandateHash, hex.EncodeToString(h[:]))
			require.Equal(t, c.SignedMessage, hex.EncodeToString(policy.MandateSigningMessage(h)))
			priv := ed25519.NewKeyFromSeed(hx(t, f.Keys[c.Signer].SeedHex))
			signed, h2, err := policy.SignMandate(priv, m)
			require.NoError(t, err)
			require.Equal(t, h, h2)
			require.Equal(t, c.SignedMandateHex, hex.EncodeToString(signed))
			sm, h3, err := policy.VerifyMandate(signed)
			require.NoError(t, err)
			require.Equal(t, h, h3)
			require.Equal(t, c.Signature, hex.EncodeToString(sm.Signature))
			ck := sm.Mandate.CounterKey()
			require.Equal(t, c.CounterKey, hex.EncodeToString(ck[:]))
		})
	}
	for _, r := range f.Reject {
		t.Run(r.ID, func(t *testing.T) {
			_, _, err := policy.VerifyMandate(hx(t, r.SignedHex))
			switch r.ExpectError {
			case "ErrMandateSignature":
				require.ErrorIs(t, err, policy.ErrMandateSignature)
			default:
				require.ErrorIs(t, err, policy.ErrMandateInvalid)
			}
		})
	}
}

func TestRenderVectors(t *testing.T) {
	var m struct {
		Cases []struct {
			ID    string   `json:"id"`
			Input jMandate `json:"input"`
		} `json:"cases"`
	}
	readVec(t, "mandate.json", &m)
	byID := map[string]*policy.Mandate{}
	for _, c := range m.Cases {
		byID[c.ID] = c.Input.mandate(t)
	}
	var f struct {
		Cases []struct {
			ID         string    `json:"id"`
			MandateRef string    `json:"mandate_ref"`
			Input      *jMandate `json:"input"`
			Text       string    `json:"text"`
		} `json:"cases"`
	}
	readVec(t, "render.json", &f)
	require.NotEmpty(t, f.Cases)
	for _, c := range f.Cases {
		t.Run(c.ID, func(t *testing.T) {
			mm := byID[c.MandateRef]
			if c.Input != nil {
				mm = c.Input.mandate(t)
			}
			require.NotNil(t, mm)
			require.Equal(t, c.Text, policy.Render(mm))
		})
	}
}

func TestStateVectors(t *testing.T) {
	var f struct {
		Genesis struct {
			StateCbor string `json:"state_cbor_hex"`
			StateHash string `json:"state_hash_hex"`
			EmptySet  string `json:"empty_closed_set_cbor_hex"`
			EmptyRoot string `json:"empty_closed_root_hex"`
		} `json:"genesis"`
		Buckets []struct {
			ID   string `json:"id"`
			CBOR string `json:"cbor_hex"`
			Hash string `json:"bucket_hash_hex"`
		} `json:"buckets"`
		ClosedSets []struct {
			ID       string `json:"id"`
			CBOR     string `json:"cbor_hex"`
			Root     string `json:"closed_root_hex"`
			Size     string `json:"cbor_size"`
			CborHash string `json:"cbor_sha256_hex"`
		} `json:"closed_sets"`
		States []struct {
			ID   string `json:"id"`
			CBOR string `json:"cbor_hex"`
			Hash string `json:"state_hash_hex"`
		} `json:"states"`
		Reject []struct {
			ID        string `json:"id"`
			Structure string `json:"structure"`
			CBOR      string `json:"cbor_hex"`
		} `json:"reject"`
	}
	readVec(t, "state.json", &f)
	g := policy.GenesisLedger()
	enc, err := policy.EncodeState(&g.State)
	require.NoError(t, err)
	require.Equal(t, f.Genesis.StateCbor, hex.EncodeToString(enc))
	h := policy.HashStateBytes(enc)
	require.Equal(t, f.Genesis.StateHash, hex.EncodeToString(h[:]))
	set := policy.EmptyClosedSet()
	enc, err = policy.EncodeClosedSet(&set)
	require.NoError(t, err)
	require.Equal(t, f.Genesis.EmptySet, hex.EncodeToString(enc))
	require.Equal(t, f.Genesis.EmptyRoot, hex.EncodeToString(g.State.ClosedRoot))

	for _, c := range f.Buckets {
		b, err := policy.DecodeBucket(hx(t, c.CBOR))
		require.NoError(t, err, c.ID)
		h, err := policy.HashBucket(b)
		require.NoError(t, err)
		require.Equal(t, c.Hash, hex.EncodeToString(h[:]), c.ID)
	}
	for _, c := range f.ClosedSets {
		if c.CBOR == "" {
			big := policy.ClosedSet{Format: 1}
			for i := uint64(0); i < 767; i++ {
				hh := sha256.Sum256([]byte("edicta/policy/v1 test ref|" + strconv.FormatUint(i, 10)))
				big.Buckets = append(big.Buckets, policy.ClosedRef{Index: 8589934592 + i, Hash: hh[:]})
			}
			enc, err := policy.EncodeClosedSet(&big)
			require.NoError(t, err)
			require.Equal(t, u64(t, c.Size), uint64(len(enc)))
			sum := sha256.Sum256(enc)
			require.Equal(t, c.CborHash, hex.EncodeToString(sum[:]))
			_, err = policy.DecodeClosedSet(enc)
			require.NoError(t, err)
			h, err := policy.HashClosedSet(&big)
			require.NoError(t, err)
			require.Equal(t, c.Root, hex.EncodeToString(h[:]))
			continue
		}
		s, err := policy.DecodeClosedSet(hx(t, c.CBOR))
		require.NoError(t, err, c.ID)
		h, err := policy.HashClosedSet(s)
		require.NoError(t, err)
		require.Equal(t, c.Root, hex.EncodeToString(h[:]), c.ID)
	}
	for _, c := range f.States {
		s, err := policy.DecodeState(hx(t, c.CBOR))
		require.NoError(t, err, c.ID)
		h, err := policy.HashState(s)
		require.NoError(t, err)
		require.Equal(t, c.Hash, hex.EncodeToString(h[:]), c.ID)
	}
	for _, r := range f.Reject {
		b := hx(t, r.CBOR)
		var err error
		switch r.Structure {
		case "bucket":
			_, err = policy.DecodeBucket(b)
		case "closed_set":
			_, err = policy.DecodeClosedSet(b)
		case "state":
			_, err = policy.DecodeState(b)
		default:
			t.Fatalf("structure %q", r.Structure)
		}
		require.ErrorIs(t, err, policy.ErrStateInvalid, r.ID)
	}
}

func TestStateCoverage(t *testing.T) {
	var f struct {
		Coverage struct{ A, B string } `json:"coverage"`
		States   []struct {
			ID   string `json:"id"`
			CBOR string `json:"cbor_hex"`
		} `json:"states"`
	}
	readVec(t, "state.json", &f)
	hashes := map[string]string{}
	for _, s := range f.States {
		st, err := policy.DecodeState(hx(t, s.CBOR))
		require.NoError(t, err)
		h, _ := policy.HashState(st)
		hashes[s.ID] = hex.EncodeToString(h[:])
	}
	require.NotEmpty(t, hashes[f.Coverage.A])
	require.NotEqual(t, hashes[f.Coverage.A], hashes[f.Coverage.B])
}

type jStep struct {
	Facts   jFacts `json:"facts"`
	TH      string `json:"t_h"`
	Repeat  string `json:"repeat"`
	THStart string `json:"t_h_start"`
	THStep  string `json:"t_h_step"`
	Expect  struct {
		Allow         bool   `json:"allow"`
		AllowAll      bool   `json:"allow_all"`
		Deny          string `json:"deny"`
		Cause         string `json:"cause"`
		EvalTime      string `json:"eval_time"`
		NewHash       string `json:"new_state_hash_hex"`
		NewState      string `json:"new_state_cbor_hex"`
		RolledOver    bool   `json:"rolled_over"`
		Closed        string `json:"closed"`
		ClosedBucket  string `json:"closed_bucket_hash_hex"`
		ClosedSetCbor string `json:"closed_set_cbor_hex"`
		StateHash     string `json:"state_hash_hex"`
		ClosedRoot    string `json:"closed_root_hex"`
		OldestClosed  string `json:"oldest_closed_index"`
	} `json:"expect"`
}

func admit(t testing.TB, m *policy.Mandate, f policy.Facts) policy.Admission {
	i := m.AssetRuleFor(f.Asset)
	require.GreaterOrEqual(t, i, 0)
	return policy.Admission{Facts: f, Asset: i}
}

func TestEngineVectors(t *testing.T) {
	var f struct {
		Scenarios []struct {
			ID      string   `json:"id"`
			Mandate jMandate `json:"mandate"`
			Start   *struct {
				State   string   `json:"state_cbor_hex"`
				Set     string   `json:"closed_set_cbor_hex"`
				Buckets []string `json:"buckets_cbor_hex"`
			} `json:"start"`
			Steps []jStep `json:"steps"`
			Final struct {
				State string `json:"state_cbor_hex"`
				Hash  string `json:"state_hash_hex"`
			} `json:"final"`
		} `json:"scenarios"`
	}
	readVec(t, "engine.json", &f)
	require.NotEmpty(t, f.Scenarios)
	for _, sc := range f.Scenarios {
		t.Run(sc.ID, func(t *testing.T) {
			m := sc.Mandate.mandate(t)
			l := policy.GenesisLedger()
			if sc.Start != nil {
				st, err := policy.DecodeState(hx(t, sc.Start.State))
				require.NoError(t, err)
				set, err := policy.DecodeClosedSet(hx(t, sc.Start.Set))
				require.NoError(t, err)
				var bs []policy.Bucket
				for _, b := range sc.Start.Buckets {
					bk, err := policy.DecodeBucket(hx(t, b))
					require.NoError(t, err)
					bs = append(bs, *bk)
				}
				l, err = policy.NewLedger(*st, bs, *set)
				require.NoError(t, err)
			}
			for si, s := range sc.Steps {
				facts := s.Facts.facts(t)
				a := admit(t, m, facts)
				if s.Repeat != "" {
					n := int(u64(t, s.Repeat))
					th := u64(t, s.THStart)
					for i := 0; i < n; i++ {
						step, err := policy.Evaluate(m, l, a, th)
						require.NoError(t, err, "repeat %d", i)
						l = step.Next
						th += u64(t, s.THStep)
					}
					h, err := l.StateHash()
					require.NoError(t, err)
					require.Equal(t, s.Expect.StateHash, hex.EncodeToString(h[:]))
					require.Equal(t, u64(t, s.Expect.Closed), uint64(len(l.Set.Buckets)))
					require.Equal(t, u64(t, s.Expect.OldestClosed), l.Set.Buckets[0].Index)
					require.Equal(t, s.Expect.ClosedRoot, hex.EncodeToString(l.State.ClosedRoot))
					continue
				}
				step, err := policy.Evaluate(m, l, a, u64(t, s.TH))
				if s.Expect.Deny != "" {
					require.Error(t, err, "step %d", si)
					require.Equal(t, s.Expect.Deny, policy.ReasonOf(err), "step %d", si)
					require.ErrorIs(t, err, policy.ErrDenied)
					if s.Expect.Cause != "" {
						var hf *policy.HistoryFullError
						require.ErrorAs(t, err, &hf)
						require.Equal(t, s.Expect.Cause, hf.Cause)
					}
					continue
				}
				require.NoError(t, err, "step %d", si)
				require.Equal(t, u64(t, s.Expect.EvalTime), step.EvalTime)
				require.Equal(t, s.Expect.NewHash, hex.EncodeToString(step.NewHash[:]))
				enc, err := policy.EncodeState(&step.Next.State)
				require.NoError(t, err)
				require.Equal(t, s.Expect.NewState, hex.EncodeToString(enc))
				require.Equal(t, s.Expect.RolledOver, step.ClosedBucket != nil)
				require.Equal(t, u64(t, s.Expect.Closed), uint64(len(step.Next.Set.Buckets)))
				if step.ClosedBucket != nil {
					bh, err := policy.HashBucket(step.ClosedBucket)
					require.NoError(t, err)
					require.Equal(t, s.Expect.ClosedBucket, hex.EncodeToString(bh[:]))
					sc, err := policy.EncodeClosedSet(step.ClosedSet)
					require.NoError(t, err)
					require.Equal(t, s.Expect.ClosedSetCbor, hex.EncodeToString(sc))
				}
				l = step.Next
				require.NoError(t, l.Validate())
			}
			enc, err := policy.EncodeState(&l.State)
			require.NoError(t, err)
			require.Equal(t, sc.Final.State, hex.EncodeToString(enc))
			h, err := l.StateHash()
			require.NoError(t, err)
			require.Equal(t, sc.Final.Hash, hex.EncodeToString(h[:]))
		})
	}
}

func TestVerdictRecords(t *testing.T) {
	var f struct {
		Gate struct {
			Pub string `json:"gate_pubkey_hex"`
		} `json:"gate"`
		Records map[string]string `json:"records"`
	}
	readVec(t, "verify.json", &f)
	gatePub := hx(t, f.Gate.Pub)
	var allows, denies, mandates int
	for path, recHex := range f.Records {
		var rec map[uint64]any
		require.NoError(t, cbor.Unmarshal(hx(t, recHex), &rec))
		body, _ := rec[3].([]byte)
		switch {
		case len(path) > 10 && path[:10] == "policy-all", len(path) > 11 && path[:11] == "policy-deny":
			sv, h, err := policy.VerifyVerdict(body, gatePub)
			require.NoError(t, err, path)
			canon, err := policy.EncodeVerdict(&sv.Verdict)
			require.NoError(t, err)
			require.Equal(t, h, policy.HashVerdict(canon))
			again, err := policy.EncodeSignedVerdict(sv)
			require.NoError(t, err)
			require.Equal(t, body, again)
			if sv.Verdict.Outcome == policy.OutcomeAllow {
				allows++
				_, ok := sv.Verdict.Delta()
				require.True(t, ok)
				_, ok = sv.Verdict.PrevStateHash()
				require.True(t, ok)
			} else {
				denies++
			}
			bad := append([]byte(nil), body...)
			bad[len(bad)-1] ^= 1
			_, _, err = policy.VerifyVerdict(bad, gatePub)
			require.Error(t, err)
		case len(path) > 7 && path[:7] == "mandate":
			mandates++
			_, _, err := policy.VerifyMandate(body)
			require.NoError(t, err, path)
		}
	}
	require.Positive(t, allows)
	require.Positive(t, denies)
	require.Positive(t, mandates)
}
