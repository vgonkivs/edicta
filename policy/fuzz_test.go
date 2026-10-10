package policy_test

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"regexp"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/policy"
)

func FuzzDecodeSignedMandate(f *testing.F) {
	m, _ := testMandate(f)
	m.CountLimits = []policy.CountLimit{{Hours: 3, MaxCount: 4}}
	m.MinSpacing = 60
	seed := sha256.Sum256([]byte("p"))
	good, _, err := policy.SignMandate(ed25519.NewKeyFromSeed(seed[:]), m)
	require.NoError(f, err)
	f.Add(good)
	f.Add(good[:len(good)/2])
	f.Add([]byte{})
	f.Add([]byte{0xa2, 0x01, 0xa0, 0x02, 0x40})
	f.Fuzz(func(t *testing.T, b []byte) {
		sm, h, err := policy.DecodeSignedMandate(b)
		if err != nil {
			return
		}
		again, err := policy.EncodeMandate(&sm.Mandate)
		require.NoError(t, err, "a decoded mandate encodes")
		require.Equal(t, h, policy.HashMandate(again), "the hash is over the canonical bytes")
		require.NoError(t, sm.Mandate.ValidateBasic())
		_ = policy.Render(&sm.Mandate)
		_, _, verr := policy.VerifyMandate(b)
		_ = verr
	})
}

func FuzzDecodeSignedVerdict(f *testing.F) {
	m, _ := testMandate(f)
	step, err := policy.Evaluate(m, policy.GenesisLedger(), admission(5), 7200)
	require.NoError(f, err)
	prev := policy.GenesisLedger().State
	facts := admission(5).Facts
	v := policy.Verdict{
		Format: 1, GateID: "g", MandateHash: make([]byte, 32), CommitmentHash: make([]byte, 32), ActionHash: make([]byte, 32),
		AgentPubKey: make([]byte, 32), Outcome: policy.OutcomeAllow, Extractor: "t/x/v1", Facts: &facts,
		AnchorTime: 7200, EvalTime: 7200, PrevState: &prev, NewStateHash: step.NewHash[:], DecidedAt: 7300,
	}
	enc, err := policy.EncodeSignedVerdict(&policy.SignedVerdict{Verdict: v, Signature: make([]byte, 64)})
	require.NoError(f, err)
	deny := policy.Verdict{
		Format: 1, GateID: "g", MandateHash: make([]byte, 32), CommitmentHash: make([]byte, 32), ActionHash: make([]byte, 32),
		AgentPubKey: make([]byte, 32), Outcome: policy.OutcomeDeny, Reason: "ErrAmountAboveMax", DecidedAt: 7300,
	}
	denc, err := policy.EncodeSignedVerdict(&policy.SignedVerdict{Verdict: deny, Signature: make([]byte, 64)})
	if err == nil {
		f.Add(denc)
	}
	f.Add(enc)
	f.Add(enc[:len(enc)-3])
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		sv, h, err := policy.DecodeSignedVerdict(b)
		if err != nil {
			return
		}
		again, err := policy.EncodeSignedVerdict(sv)
		require.NoError(t, err)
		require.Equal(t, b, again, "decoding accepts canonical bytes only")
		canon, err := policy.EncodeVerdict(&sv.Verdict)
		require.NoError(t, err)
		require.Equal(t, h, policy.HashVerdict(canon))
		if sv.Verdict.Outcome == policy.OutcomeAllow {
			require.NotNil(t, sv.Verdict.Facts)
			require.NotNil(t, sv.Verdict.PrevState)
			_, _ = sv.Verdict.PrevStateHash()
			_, _ = sv.Verdict.Delta()
		}
	})
}

// FuzzDecodePrivatePart: the strict decoder accepts canonical bytes only, a
// part it accepts hashes and merges deterministically, and nothing panics.
func FuzzDecodePrivatePart(f *testing.F) {
	raw, err := os.ReadFile("../spec/vectors/policy/private.json")
	require.NoError(f, err)
	for _, m := range regexp.MustCompile(`"private_part_cbor_hex": "([0-9a-f]*)"`).FindAllSubmatch(raw, -1) {
		b, err := hex.DecodeString(string(m[1]))
		require.NoError(f, err)
		f.Add(b)
		f.Add(b[:len(b)/2])
	}
	f.Add([]byte{})
	f.Add([]byte{0xa2, 0x01, 0x01, 0x02, 0x40})
	priv := &policy.Verdict{
		Format: 1, GateID: "g", MandateHash: make([]byte, 32), CommitmentHash: make([]byte, 32), ActionHash: make([]byte, 32),
		AgentPubKey: make([]byte, 32), Outcome: policy.OutcomeDeny, PrivateHash: make([]byte, 32),
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		p, err := policy.DecodePrivatePart(b)
		if err != nil {
			require.ErrorIs(t, err, policy.ErrVerdictInvalid)
			return
		}
		again, err := policy.EncodePrivatePart(p)
		require.NoError(t, err)
		require.Equal(t, b, again, "decoding accepts canonical bytes only")
		require.Equal(t, policy.PrivateHash(b), policy.PrivateHash(again))
		_, _ = policy.MergeVerdict(priv, p)
		_ = policy.MergeUnchecked(priv, p)
	})
}
