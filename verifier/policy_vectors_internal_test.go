package verifier

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/policy"
)

type vecCase struct {
	ID       string `json:"id"`
	Decision struct {
		CommitmentHash string `json:"commitment_hash_hex"`
		Agent          string `json:"agent_pubkey_hex"`
		ActionType     string `json:"action_type"`
		Action         string `json:"action_hex"`
		ActionHash     string `json:"action_hash_hex"`
		ValidUntil     string `json:"valid_until"`
		GateID         string `json:"gate_id"`
	} `json:"decision"`
	TH     *string `json:"t_h"`
	Config struct {
		RequirePolicy bool              `json:"require_policy"`
		PolicyFull    bool              `json:"policy_full"`
		MaxWalkSteps  *string           `json:"max_walk_steps"`
		Principals    []string          `json:"principal_keys"`
		Extractors    map[string]string `json:"extractors"`
		Evidence      []string          `json:"evidence"`
	} `json:"config"`
	Archive []string          `json:"archive"`
	Corrupt map[string]string `json:"corrupt"`
	Expect  struct {
		Policy struct {
			Status string `json:"status"`
			Rule   string `json:"rule"`
			Reason string `json:"reason"`
		} `json:"policy"`
		Integrity struct {
			Status   string   `json:"status"`
			Reason   *string  `json:"reason"`
			Evidence []string `json:"evidence"`
			Walk     *struct {
				MaxSteps string `json:"max_steps"`
				Steps    string `json:"steps"`
				FromSeq  string `json:"from_seq"`
				ToSeq    string `json:"to_seq"`
				Total    string `json:"total"`
				End      string `json:"end"`
			} `json:"walk"`
		} `json:"gate_integrity"`
		Verdict string `json:"verdict"`
		Exit    string `json:"exit"`
	} `json:"expect"`
}

type vecDoc struct {
	Gate struct {
		ID  string `json:"gate_id"`
		Key string `json:"gate_pubkey_hex"`
	} `json:"gate"`
	Extractors map[string]string `json:"extractors"`
	Records    map[string]string `json:"records"`
	Cases      []vecCase         `json:"cases"`
}

func unhex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	require.NoError(t, err)
	return b
}

func loadVec(t testing.TB) vecDoc {
	t.Helper()
	raw, err := os.ReadFile("../spec/vectors/policy/verify.json")
	require.NoError(t, err)
	var d vecDoc
	require.NoError(t, json.Unmarshal(raw, &d))
	return d
}

type factsExtractor struct{ id, typ string }

func (x factsExtractor) ID() string         { return x.id }
func (x factsExtractor) ActionType() string { return x.typ }
func (x factsExtractor) Extract(b []byte) (policy.Facts, error) {
	return policy.DecodeFacts(b)
}

// vecArchive serves the policy records of one case like a store does: a
// record that does not decode or carry its key is ErrCorrupt.
type vecArchive struct {
	Reader
	files map[string][]byte
}

func (a vecArchive) get(path string) (archive.Record, error) {
	b, ok := a.files[path]
	if !ok {
		return nil, archive.ErrNotFound
	}
	rec, err := archive.Decode(b)
	if err != nil {
		return nil, err
	}
	if got, err := archive.KeyPath(rec); err != nil || got != path {
		return nil, archive.ErrCorrupt
	}
	return rec, nil
}

func (a vecArchive) Mandate(_ context.Context, h commitment.Hash) (*archive.MandateRecord, error) {
	r, err := a.get(archive.PolicyHashPath(archive.KindMandate, h))
	if err != nil {
		return nil, err
	}
	return r.(*archive.MandateRecord), nil
}

func (a vecArchive) PolicyAllow(_ context.Context, h commitment.Hash) (*archive.PolicyAllowRecord, error) {
	r, err := a.get(archive.PolicyHashPath(archive.KindPolicyAllow, h))
	if err != nil {
		return nil, err
	}
	return r.(*archive.PolicyAllowRecord), nil
}

func (a vecArchive) PolicyDeny(_ context.Context, h commitment.Hash, reason string) (*archive.PolicyDenyRecord, error) {
	p, err := archive.PolicyDenyPath(h, reason)
	if err != nil {
		return nil, archive.ErrNotFound
	}
	r, err := a.get(p)
	if err != nil {
		return nil, err
	}
	return r.(*archive.PolicyDenyRecord), nil
}

func (a vecArchive) PolicyBucket(_ context.Context, h commitment.Hash) (*archive.PolicyBucketRecord, error) {
	r, err := a.get(archive.PolicyHashPath(archive.KindPolicyBucket, h))
	if err != nil {
		return nil, err
	}
	return r.(*archive.PolicyBucketRecord), nil
}

func (a vecArchive) PolicyClosed(_ context.Context, h commitment.Hash) (*archive.PolicyClosedRecord, error) {
	r, err := a.get(archive.PolicyHashPath(archive.KindPolicyClosed, h))
	if err != nil {
		return nil, err
	}
	return r.(*archive.PolicyClosedRecord), nil
}

func (a vecArchive) PolicySuccessor(_ context.Context, h commitment.Hash) (*archive.PolicySuccessorRecord, error) {
	r, err := a.get(archive.PolicyHashPath(archive.KindPolicySuccessor, h))
	if err != nil {
		return nil, err
	}
	return r.(*archive.PolicySuccessorRecord), nil
}

func (c vecCase) verifier(t testing.TB, d vecDoc) (*Verifier, vecArchive) {
	var xs []policy.Extractor
	for typ, id := range c.Config.Extractors {
		xs = append(xs, factsExtractor{id: id, typ: typ})
	}
	reg, err := policy.NewExtractors(xs...)
	require.NoError(t, err)
	files := map[string][]byte{}
	for _, p := range c.Archive {
		files[p] = unhex(t, d.Records[p])
	}
	for p, b := range c.Corrupt {
		files[p] = unhex(t, b)
	}
	arch := vecArchive{files: files}
	cfg := Config{
		GateKeys:      []ed25519.PublicKey{unhex(t, d.Gate.Key)},
		RequirePolicy: c.Config.RequirePolicy, PolicyFull: c.Config.PolicyFull,
	}
	if c.Config.MaxWalkSteps != nil {
		n, err := strconv.Atoi(*c.Config.MaxWalkSteps)
		require.NoError(t, err)
		cfg.MaxWalkSteps = n
	}
	for _, k := range c.Config.Principals {
		cfg.PrincipalKeys = append(cfg.PrincipalKeys, unhex(t, k))
	}
	for _, e := range c.Config.Evidence {
		cfg.Evidence = append(cfg.Evidence, unhex(t, e))
	}
	return &Verifier{cfg: cfg, archive: arch, extractors: reg}, arch
}

func (c vecCase) input(t testing.TB, d vecDoc) policyInput {
	var h commitment.Hash
	copy(h[:], unhex(t, c.Decision.CommitmentHash))
	vu, err := strconv.ParseUint(c.Decision.ValidUntil, 10, 64)
	require.NoError(t, err)
	in := policyInput{
		Hash: h, AgentPub: unhex(t, c.Decision.Agent), ActionType: c.Decision.ActionType,
		Action: unhex(t, c.Decision.Action), ActionHash: unhex(t, c.Decision.ActionHash),
		ValidUntil: vu, GateID: c.Decision.GateID, GateKeys: []ed25519.PublicKey{unhex(t, d.Gate.Key)},
	}
	if c.TH != nil {
		in.TH, err = strconv.ParseUint(*c.TH, 10, 64)
		require.NoError(t, err)
		in.THVerified = true
	}
	return in
}

// verdictOf runs the real verdict rule over a report that passed every core
// check and carries the policy outcome.
func verdictOf(v *Verifier, out policyOutcome) Report {
	r := &run{v: v}
	r.rep.State = archive.StateAuthorized
	for _, n := range []CheckName{CheckDecision, CheckEnvelope, CheckAction, CheckAuthorization, CheckPayload, CheckAnchor, CheckAnchorTime, CheckHeaderTrust} {
		r.pass(n)
	}
	if out.Ran {
		r.rep.Checks = append(r.rep.Checks, out.Check)
		r.rep.GateIntegrity = out.Integrity
	}
	r.finish()
	return r.rep
}

func exitFor(rep Report) string {
	switch {
	case rep.Verdict == VerdictInvalid:
		return "1"
	case rep.Verdict == VerdictUnchecked && rep.GateIntegrity.Status == IntegrityViolated:
		return "5"
	case rep.Verdict == VerdictUnchecked:
		return "2"
	case rep.Verdict == VerdictNotAuthorized:
		return "3"
	}
	return "0"
}

func TestPolicyVerifyVectors(t *testing.T) {
	d := loadVec(t)
	require.Len(t, d.Cases, 47)
	for _, c := range d.Cases {
		t.Run(c.ID, func(t *testing.T) {
			v, _ := c.verifier(t, d)
			out, err := v.checkPolicy(t.Context(), c.input(t, d))
			require.NoError(t, err)
			require.True(t, out.Ran)
			assert.Equal(t, Status(c.Expect.Policy.Status), out.Check.Status, "%v", out.Check.Err)
			switch out.Check.Status {
			case StatusFail:
				var pf *PolicyFailure
				require.ErrorAs(t, out.Check.Err, &pf)
				require.ErrorIs(t, out.Check.Err, ErrPolicyViolation)
				assert.Equal(t, c.Expect.Policy.Rule, pf.Rule)
			case StatusUnchecked:
				assert.Equal(t, Reason(c.Expect.Policy.Reason), out.Check.Reason)
			}
			ig := out.Integrity
			assert.Equal(t, IntegrityStatus(c.Expect.Integrity.Status), ig.Status)
			want := ""
			if c.Expect.Integrity.Reason != nil {
				want = *c.Expect.Integrity.Reason
			}
			assert.Equal(t, want, string(ig.Reason))
			var got []string
			for _, h := range ig.EvidenceHashes {
				got = append(got, hex.EncodeToString(h[:]))
			}
			assert.Equal(t, len(c.Expect.Integrity.Evidence), len(got))
			if len(got) > 0 {
				assert.Equal(t, c.Expect.Integrity.Evidence, got)
			}
			assert.Len(t, ig.Evidence, len(ig.EvidenceHashes))
			if w := c.Expect.Integrity.Walk; w != nil {
				require.NotNil(t, ig.Walk)
				u := func(s string) uint64 {
					n, err := strconv.ParseUint(s, 10, 64)
					require.NoError(t, err)
					return n
				}
				assert.Equal(t, WalkInfo{
					MaxSteps: u(w.MaxSteps), Steps: u(w.Steps), FromSeq: u(w.FromSeq),
					ToSeq: u(w.ToSeq), Total: u(w.Total), End: WalkEnd(w.End),
				}, *ig.Walk)
			}

			rep := verdictOf(v, out)
			assert.Equal(t, Verdict(c.Expect.Verdict), rep.Verdict)
			assert.Equal(t, c.Expect.Exit, exitFor(rep))
		})
	}
}

func TestPolicyCheckSkippedWithoutRecords(t *testing.T) {
	d := loadVec(t)
	c := d.Cases[0]
	c.Archive = nil
	v, _ := c.verifier(t, d)
	out, err := v.checkPolicy(t.Context(), c.input(t, d))
	require.NoError(t, err)
	assert.False(t, out.Ran, "no allow record and no RequirePolicy: no check")
	rep := verdictOf(v, out)
	assert.Equal(t, VerdictValid, rep.Verdict)
	assert.Equal(t, IntegrityNotChecked, rep.GateIntegrity.Status)

	v.cfg.RequirePolicy = true
	out, err = v.checkPolicy(t.Context(), c.input(t, d))
	require.NoError(t, err)
	assert.Equal(t, ReasonPolicyVerdictUnavailable, out.Check.Reason)
}

type faultArchive struct{ vecArchive }

func (faultArchive) PolicyAllow(context.Context, commitment.Hash) (*archive.PolicyAllowRecord, error) {
	return nil, errors.New("disk on fire")
}

func TestPolicyArchiveFaultIsOperational(t *testing.T) {
	d := loadVec(t)
	c := d.Cases[0]
	v, arch := c.verifier(t, d)
	v.archive = faultArchive{arch}
	_, err := v.checkPolicy(t.Context(), c.input(t, d))
	require.Error(t, err)
}

func TestPolicyReasonsAreInTheTable(t *testing.T) {
	for _, r := range []Reason{
		ReasonPolicyVerdictUnavailable, ReasonPolicyMandateUnavailable, ReasonPolicyPrincipalUntrusted,
		ReasonPolicyNoExtractor, ReasonStateHistoryUnavailable, ReasonGateEquivocation,
	} {
		_, ok := r.Info()
		assert.True(t, ok, r)
	}
}
