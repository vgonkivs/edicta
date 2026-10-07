package verifier_test

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/test/gatefix"
	"github.com/vgonkivs/edicta/verifier"
)

const reasonsPath = "../spec/vectors/verifier/reasons.json"

type reasonsDoc struct {
	Revision string `json:"revision"`
	Reasons  []struct {
		Name    string   `json:"name"`
		Checks  []string `json:"checks"`
		Meaning string   `json:"meaning"`
		Advice  string   `json:"advice"`
	} `json:"reasons"`
	Cases    []reasonCase `json:"cases"`
	Boundary []reasonCase `json:"boundary"`
}

type reasonCase struct {
	ID     string   `json:"id"`
	Refs   []string `json:"refs"`
	Expect struct {
		Check       string  `json:"check"`
		Status      string  `json:"status"`
		Reason      *string `json:"reason"`
		RecordState string  `json:"record_state"`
		Verdict     string  `json:"verdict"`
		Exit        string  `json:"exit"`
	} `json:"expect"`
}

func loadReasons(t testing.TB) reasonsDoc {
	t.Helper()
	raw, err := os.ReadFile(reasonsPath)
	require.NoError(t, err)
	var d reasonsDoc
	require.NoError(t, json.Unmarshal(raw, &d))
	require.Equal(t, "v0-draft.28", d.Revision)
	return d
}

func exitOf(v verifier.Verdict) string {
	return map[verifier.Verdict]string{
		verifier.VerdictValid: "0", verifier.VerdictInvalid: "1", verifier.VerdictUnchecked: "2", verifier.VerdictNotAuthorized: "3",
	}[v]
}

// The closed enum of the code is the spec's: names, checks, meaning, advice.
func TestReasonEnumIsTheSpecs(t *testing.T) {
	d := loadReasons(t)
	got := verifier.Reasons()
	require.Len(t, got, len(d.Reasons))
	for i, want := range d.Reasons {
		assert.Equal(t, want.Name, string(got[i].Reason))
		assert.Equal(t, want.Checks, got[i].Checks, want.Name)
		assert.Equal(t, want.Meaning, got[i].Meaning, want.Name)
		assert.Equal(t, want.Advice, got[i].Advice, want.Name)
		info, ok := got[i].Reason.Info()
		assert.True(t, ok)
		assert.Equal(t, got[i], info)
	}
	_, ok := verifier.Reason("made_up").Info()
	assert.False(t, ok)
}

// Cases that need a network, a CLI or a chain are exercised where those live;
// the case must still name a reason of the enum, and execution cases must
// point at an outcome case with that cause.
var coveredElsewhere = map[string]string{
	"payload_wrong_commitment": "TestVerifyTamperedItems", "payload_record_undecodable": "archive readers",
	"evidence_other_height": "TestVerifyTamperedItems (evidence)", "fibre_certificate_fails": "TestDA1ProofFormAndEarlierCandidatesReachTheReport",
	"fibre_anchor_proof_fails": "verifycli TestDA1TamperedEvidenceIsInconclusive", "receipt_signature_altered": "TestReceipt",
	"online_header_not_linking": "verifycli TestOnlineHeaderThatDoesNotLinkIsTheSourcesFault", "header_sources_down": "verifycli TestOnlineCheckpointSources",
	"checkpoint_below_anchor": "verifycli TestVerifyHeaderTrustFailures", "checkpoint_quorum_short": "headertrust TestAgreedCheckpointReasons",
	"checkpoint_sources_disagree": "headertrust TestAgreedCheckpointReasons", "replay_form0_earlier": "TestReplayPromiseCreationRules",
	"replay_path_inconsistent": "TestReplayReproducesThePath", "run_timeout": "TestExecutionCheckerErrorsAreClassified",
}

func TestReasonVectors(t *testing.T) {
	d := loadReasons(t)
	known := map[string]bool{}
	for _, r := range d.Reasons {
		known[r.Name] = true
	}
	builders := map[string]func(t *testing.T) (verifier.Report, verifier.ReplayReport){
		"decision_absent": func(t *testing.T) (verifier.Report, verifier.ReplayReport) {
			r := newRig(t, newParts(t))
			var h commitment.Hash
			h[0] = 9
			rep, err := r.verifier(t).Verify(t.Context(), h)
			require.NoError(t, err)
			return rep, verifier.ReplayReport{}
		},
		"payload_absent": func(t *testing.T) (verifier.Report, verifier.ReplayReport) {
			p := newParts(t)
			p.blob = nil
			return newRig(t, p).verify(t), verifier.ReplayReport{}
		},
		"evidence_absent": func(t *testing.T) (verifier.Report, verifier.ReplayReport) {
			r := newRig(t, newParts(t))
			r.deps.Archive = noEvidence{r.store}
			return r.verify(t), verifier.ReplayReport{}
		},
		"action_bytes_altered": func(t *testing.T) (verifier.Report, verifier.ReplayReport) {
			p := newParts(t)
			p.action[0] ^= 1
			return newRig(t, p).verify(t), verifier.ReplayReport{}
		},
		"agent_signature_altered": func(t *testing.T) (verifier.Report, verifier.ReplayReport) {
			p := newParts(t)
			p.env[len(p.env)-1] ^= 1
			return newRig(t, p).verify(t), verifier.ReplayReport{}
		},
		"authorization_signature_altered": func(t *testing.T) (verifier.Report, verifier.ReplayReport) {
			p := newParts(t)
			p.auth[len(p.auth)-1] ^= 1
			return newRig(t, p).verify(t), verifier.ReplayReport{}
		},
		"archived_header_not_linking": func(t *testing.T) (verifier.Report, verifier.ReplayReport) {
			r := newRig(t, newParts(t))
			r.trust.hashes = map[uint64][]byte{}
			return r.verify(t), verifier.ReplayReport{}
		},
		"da_not_supported": func(t *testing.T) (verifier.Report, verifier.ReplayReport) {
			r := newRig(t, newParts(t))
			r.deps.Anchors[commitment.DACelestiaBlob] = declines{}
			return r.verify(t), verifier.ReplayReport{}
		},
		"no_trusted_header": func(t *testing.T) (verifier.Report, verifier.ReplayReport) {
			r := newRig(t, newParts(t))
			r.deps.Trust = nil
			return r.verify(t), verifier.ReplayReport{}
		},
		"cross_check_disagrees": func(t *testing.T) (verifier.Report, verifier.ReplayReport) {
			r := newRig(t, newParts(t))
			r.trust.res.CrossCheck = "mismatch"
			return r.verify(t), verifier.ReplayReport{}
		},
		"anchor_time_blocked": func(t *testing.T) (verifier.Report, verifier.ReplayReport) {
			p := newParts(t)
			r := newRig(t, p)
			r.deps.Trust = nil
			r.anchor.blockTime = p.c.IssuedAt + r.deps.Config.Params.SkewS + 1
			return r.verify(t), verifier.ReplayReport{}
		},
		"receipt_other_decision": func(t *testing.T) (verifier.Report, verifier.ReplayReport) {
			p := newParts(t)
			b := signReceipt(t, gateKey(t), p, func(rc *commitment.Receipt) {
				rc.CommitmentHash[0] ^= 1
				reSignRequest(t, rc)
			})
			return newRig(t, p).verify(t, verifier.WithReceipt(b)), verifier.ReplayReport{}
		},
		"replay_no_k2": func(t *testing.T) (verifier.Report, verifier.ReplayReport) {
			p := newParts(t)
			p.k2 = nil
			rr := replay(t, newRig(t, p))
			return rr.Report, rr
		},
		"no_execution_checker": func(t *testing.T) (verifier.Report, verifier.ReplayReport) {
			p := newParts(t)
			r := newRig(t, p)
			return r.verify(t, verifier.WithReceipt(validReceipt(t, p)), verifier.WithExecutionCheck()), verifier.ReplayReport{}
		},
		"execution_blocked": func(t *testing.T) (verifier.Report, verifier.ReplayReport) {
			r := newRig(t, newParts(t))
			return r.verify(t, verifier.WithExecutionCheck()), verifier.ReplayReport{}
		},
	}

	outcomes := loadOutcomesCauses(t)
	seen := map[string]bool{}
	for _, c := range d.Cases {
		seen[*c.Expect.Reason] = true
		t.Run(c.ID, func(t *testing.T) {
			require.NotNil(t, c.Expect.Reason)
			assert.True(t, known[*c.Expect.Reason], "the reason is in the enum")
			assert.Equal(t, "unchecked", c.Expect.Status)
			assert.Equal(t, "unchecked", c.Expect.Verdict)
			assert.Equal(t, "2", c.Expect.Exit)

			if strings.HasPrefix(c.ID, "execution_") && len(c.Refs) == 1 && strings.Contains(c.Refs[0], "execution_outcomes.json#") {
				id := c.Refs[0][strings.Index(c.Refs[0], "#")+1:]
				assert.Equal(t, *c.Expect.Reason, outcomes[id], "the outcome case has this cause")
				return
			}
			b, ok := builders[c.ID]
			if !ok {
				assert.Contains(t, coveredElsewhere, c.ID, "every case is built here or covered elsewhere")
				return
			}
			rep, _ := b(t)
			chk := verifier.CheckName(c.Expect.Check)
			got, present := rep.Check(chk)
			require.True(t, present, "check %s", chk)
			assert.Equal(t, verifier.StatusUnchecked, got.Status, "%v", got.Err)
			assert.Equal(t, verifier.Reason(*c.Expect.Reason), got.Reason)
			assert.Equal(t, verifier.VerdictUnchecked, rep.Verdict)
			assert.Equal(t, c.Expect.Exit, exitOf(rep.Verdict))
			want := c.Expect.RecordState
			if want == "unknown" {
				want = "absent"
			}
			assert.Equal(t, want, rep.State.String())
		})
	}
	for _, r := range d.Reasons {
		assert.True(t, seen[r.Name] || r.Name == "", "reason %s has a case", r.Name)
	}
}

// The verified data that proves a violation stays a fail.
func TestReasonBoundaryCases(t *testing.T) {
	d := loadReasons(t)
	require.NotEmpty(t, d.Boundary)
	for _, c := range d.Boundary {
		t.Run(c.ID, func(t *testing.T) {
			assert.Equal(t, "fail", c.Expect.Status)
			assert.Nil(t, c.Expect.Reason, "a finding has no reason of the closed set")
			assert.Equal(t, "invalid", c.Expect.Verdict)
			assert.Equal(t, "1", c.Expect.Exit)
			var rep verifier.Report
			switch c.ID {
			case "commitment_rule_broken":
				p := newParts(t)
				cc := gatefix.Clone(p.c)
				cc.ValidUntil = cc.IssuedAt + 3601
				p.c = cc
				p.env, p.hash = gatefix.Sign(t, "agent1", cc)
				p.auth = signAuth(t, gateKey(t), p.hash, cc, commitment.PathDA, authExpires)
				rep = newRig(t, p).verify(t)
			case "agent_key_small_order":
				t.Skip("covered by the commitment package vectors")
			case "issued_before_anchor":
				p := newParts(t)
				r := newRig(t, p)
				r.anchor.blockTime = p.c.IssuedAt + r.deps.Config.Params.SkewS + 1
				rep = r.verify(t)
			case "payload_action_differs":
				t.Skip("the verifier holds no payload key to open it")
			case "execution_body_mismatch":
				e := newExecRig(t, newParts(t), nil)
				e.chk.err = verifier.ErrExecutionViolation
				rep = e.run(t)
			}
			got, ok := rep.Check(verifier.CheckName(c.Expect.Check))
			require.True(t, ok)
			assert.Equal(t, verifier.StatusFail, got.Status)
			assert.Equal(t, verifier.VerdictInvalid, rep.Verdict)
			assert.Equal(t, archive.StateAuthorized, rep.State)
		})
	}
}

func loadOutcomesCauses(t testing.TB) map[string]string {
	t.Helper()
	raw, err := os.ReadFile("../spec/vectors/verifier/execution_outcomes.json")
	require.NoError(t, err)
	var d struct {
		Cases []struct {
			ID     string `json:"id"`
			Expect struct {
				Cause string `json:"cause"`
			} `json:"expect"`
		} `json:"cases"`
	}
	require.NoError(t, json.Unmarshal(raw, &d))
	out := map[string]string{}
	for _, c := range d.Cases {
		out[c.ID] = c.Expect.Cause
	}
	return out
}

// noEvidence is an archive copy that lacks the evidence record.
type noEvidence struct{ verifier.Reader }

func (noEvidence) Evidence(context.Context, commitment.DA, []byte) (*archive.EvidenceRecord, error) {
	return nil, archive.ErrNotFound
}
