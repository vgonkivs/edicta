package verifycli

import (
	"context"
	"encoding/json"
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/archive/fsarchive"
	"github.com/vgonkivs/edicta/celestia/policyext/tiatransfer"
	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/gate"
	"github.com/vgonkivs/edicta/gate/dacommit/blobv1"
	"github.com/vgonkivs/edicta/policy"
	"github.com/vgonkivs/edicta/test/gatefix"
)

// addPolicy archives a mandate and the gate's signed allow for the bank
// scenario. The state step is computed under a permissive mandate; with
// otherRecipient the archived mandate allows only another recipient, which
// makes a gate-signed allow that breaks it.
func addPolicy(t *testing.T, s *scenario, otherRecipient bool) ed25519.PublicKey {
	t.Helper()
	principalPub, principal, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	x := tiatransfer.New()
	f, err := x.Extract(s.action)
	require.NoError(t, err)

	mk := func(restrict bool) *policy.Mandate {
		m := &policy.Mandate{
			Format: 1, Principal: principalPub, GateID: gatefix.GateID,
			Agents:    [][]byte{gatefix.Pub(t, "agent1")},
			NotBefore: blockTime - 86400, NotAfter: blockTime + 86400,
			MandateID: make([]byte, 16), Version: 1,
			Assets: []policy.AssetRule{{Asset: f.Asset, Scale: f.Scale, PerActionMax: policy.AmountFromUint64(1 << 40)}},
		}
		if restrict {
			m.Assets[0].Recipients = []string{"cosmos:mocha-4:celestia1other"}
		}
		return m
	}
	evalM, archM := mk(false), mk(otherRecipient)
	xs, err := policy.NewExtractors(x)
	require.NoError(t, err)

	c := decisionOf(t, s)
	adm, err := policy.Admit(evalM, xs, policy.Decision{
		AgentPubKey: c.AgentPubKey, ActionType: c.Action.Type, Action: s.action, ValidUntil: c.ValidUntil,
	})
	require.NoError(t, err)
	genesis := policy.GenesisLedger()
	step, err := policy.Evaluate(evalM, genesis, adm, blockTime)
	require.NoError(t, err)

	mb, mh, err := policy.SignMandate(principal, archM)
	require.NoError(t, err)

	prev := genesis.State
	fc := adm.Facts
	v := policy.Verdict{
		Format: 1, GateID: gatefix.GateID, MandateHash: mh[:], CommitmentHash: s.hash[:],
		ActionHash: c.Action.Hash, AgentPubKey: c.AgentPubKey, Outcome: policy.OutcomeAllow, DecidedAt: authorizedAt,
		Extractor: adm.ExtractorID, Facts: &fc, AnchorTime: blockTime, EvalTime: step.EvalTime,
		PrevState: &prev, NewStateHash: step.NewHash[:],
	}
	canon, err := policy.EncodeVerdict(&v)
	require.NoError(t, err)
	vh := policy.HashVerdict(canon)
	sig := ed25519.Sign(gatefix.Key(t, "gate1"), policy.VerdictSigningMessage(vh))
	vb, err := policy.EncodeSignedVerdict(&policy.SignedVerdict{Verdict: v, Signature: sig})
	require.NoError(t, err)

	set := policy.EmptyClosedSet()
	sb, err := policy.EncodeClosedSet(&set)
	require.NoError(t, err)

	st, err := fsarchive.Open(s.archiveDir, map[commitment.DA]gate.DACommitter{commitment.DACelestiaBlob: blobv1.New()})
	require.NoError(t, err)
	for _, r := range []archive.Record{
		&archive.MandateRecord{SignedMandate: mb},
		&archive.PolicyClosedRecord{ClosedSet: sb},
		&archive.PolicyAllowRecord{SignedVerdict: vb},
	} {
		_, err := st.Put(context.Background(), r)
		require.NoError(t, err)
	}
	return principalPub
}

func decisionOf(t *testing.T, s *scenario) *commitment.Commitment {
	t.Helper()
	st, err := fsarchive.Open(s.archiveDir, map[commitment.DA]gate.DACommitter{commitment.DACelestiaBlob: blobv1.New()})
	require.NoError(t, err)
	d, err := st.Decision(context.Background(), s.hash)
	require.NoError(t, err)
	sc, err := commitment.DecodeSigned(d.Envelope)
	require.NoError(t, err)
	return &sc.Commitment
}

func TestVerifyPolicyDecisionThroughTheTiaTransferExtractor(t *testing.T) {
	s := newScenario(t, scenarioOpts{bank: true})
	pub := addPolicy(t, s, false)
	trusted := s.chain.trustedFile(t, checkpointH, nil)

	code, out := exec(t, s.args("verify", "--trusted", trusted, "--principal-key", hexOf(pub), "--require-policy"))
	assert.Equal(t, exitValid, code, out)
	assert.Contains(t, out, "[ok] policy")
	assert.Contains(t, out, "verdict: valid")
}

func TestVerifyPolicyAllowAboveTheMandateIsInvalid(t *testing.T) {
	s := newScenario(t, scenarioOpts{bank: true})
	pub := addPolicy(t, s, true)
	trusted := s.chain.trustedFile(t, checkpointH, nil)

	code, out := exec(t, s.args("verify", "--trusted", trusted, "--principal-key", hexOf(pub), "--require-policy"))
	assert.Equal(t, exitInvalid, code, out)
	assert.Contains(t, out, "[FAIL] policy")
}

func TestVerifyPolicyWithoutPrincipalKeyIsNotValid(t *testing.T) {
	s := newScenario(t, scenarioOpts{bank: true})
	addPolicy(t, s, false)
	trusted := s.chain.trustedFile(t, checkpointH, nil)

	code, out := exec(t, s.args("verify", "--trusted", trusted, "--require-policy"))
	assert.Equal(t, exitUnchecked, code, out)
	assert.NotContains(t, out, "verdict: valid")
}

func TestVerifyPolicyFullGenesisChainReportsTheWalk(t *testing.T) {
	s := newScenario(t, scenarioOpts{bank: true})
	pub := addPolicy(t, s, false)
	trusted := s.chain.trustedFile(t, checkpointH, nil)
	args := s.args("verify", "--trusted", trusted, "--principal-key", hexOf(pub), "--require-policy", "--policy-full")

	code, out := exec(t, args)
	assert.Equal(t, exitValid, code, out)
	assert.Contains(t, out, "gate integrity walk: last 1 of 1 verdicts checked (seq 0 to 0, 0 of at most 10000 steps, ended at genesis)")
	assert.NotContains(t, out, "advice:")

	code, out = exec(t, append(args, "--max-walk-steps", "1", "--json"))
	assert.Equal(t, exitValid, code, out)
	var doc struct {
		GateIntegrity integrityView `json:"gate_integrity"`
	}
	require.NoError(t, json.Unmarshal([]byte(out), &doc))
	assert.Equal(t, "ok", doc.GateIntegrity.Status)
	assert.Equal(t, &walkView{MaxSteps: 1, End: "genesis", Total: 1}, doc.GateIntegrity.Walk)

	code, out = exec(t, append(args, "--max-walk-steps", "0"))
	assert.Equal(t, exitUsage, code, out)
}
