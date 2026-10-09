package gate_test

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/gate"
	"github.com/vgonkivs/edicta/gate/registry"
	"github.com/vgonkivs/edicta/policy"
	"github.com/vgonkivs/edicta/test/gatefix"
)

// lastByteExtractor reads the amount from the last action byte.
type lastByteExtractor struct{ typ string }

func (lastByteExtractor) ID() string           { return "test/last-byte/v1" }
func (x lastByteExtractor) ActionType() string { return x.typ }
func (lastByteExtractor) Extract(a []byte) (policy.Facts, error) {
	if len(a) == 0 || a[len(a)-1] == 255 {
		return policy.Facts{}, errors.New("unreadable action")
	}
	return policy.Facts{Kind: "transfer", Asset: "x:a", Amount: policy.AmountFromUint64(uint64(a[len(a)-1])), Scale: 0, Recipient: "bob"}, nil
}

var principalKey = func() ed25519.PrivateKey {
	s := sha256.Sum256([]byte("gate policy test principal"))
	return ed25519.NewKeyFromSeed(s[:])
}()

func baseMandate(t *testing.T) *policy.Mandate {
	return &policy.Mandate{
		Format: 1, Principal: principalKey.Public().(ed25519.PublicKey), GateID: gatefix.GateID,
		Agents:    [][]byte{gatefix.Pub(t, "agent2"), gatefix.Pub(t, "agent1")},
		NotBefore: 1, NotAfter: 1 << 35, MandateID: make([]byte, 16), Version: 1,
		Assets: []policy.AssetRule{{Asset: "x:a", Scale: 0, PerActionMax: []byte{60},
			Periods: []policy.PeriodLimit{{Hours: 1, Max: []byte{100}}}}},
	}
}

func signedMandate(t *testing.T, m *policy.Mandate) []byte {
	b, _, err := policy.SignMandate(principalKey, m)
	require.NoError(t, err)
	return b
}

func policyOpts(t *testing.T, m *policy.Mandate, extra ...gatefix.Option) []gatefix.Option {
	x, err := policy.NewExtractors(lastByteExtractor{typ: gatefix.ActionType})
	require.NoError(t, err)
	return append([]gatefix.Option{
		gatefix.WithConfig(func(c *gate.Config) { c.Mandate = signedMandate(t, m) }),
		gatefix.WithDeps(func(d *gate.Deps) { d.Extractors = x }),
	}, extra...)
}

type pEnv struct {
	*gatefix.Env
	t    *testing.T
	base *commitment.Commitment
	m    *policy.Mandate
}

func newPolicyEnv(t *testing.T, m *policy.Mandate, extra ...gatefix.Option) *pEnv {
	e := gatefix.New(t, policyOpts(t, m, extra...)...)
	c := gatefix.Template(t)
	e.StageDA(c, gatefix.Blob(t))
	c.Version = commitment.Version
	p := &pEnv{Env: e, t: t, base: c, m: m}
	p.rebase()
	return p
}

// rebase points later requests at the mandate configured now: a gate with a
// mandate admits only v1 commitments that name it.
func (p *pEnv) rebase() {
	_, mh, err := policy.VerifyMandate(p.Cfg.Mandate)
	require.NoError(p.t, err)
	p.base.MandateRef = mh[:]
}

// request signs a fresh decision whose action ends in amount.
func (p *pEnv) request(tag byte, agent string, amount byte) (*commitment.Commitment, []byte, []byte) {
	action := gatefix.OtherAction(p.t, int(amount))
	c := gatefix.WithAction(p.t, gatefix.Fresh(p.base, tag), gatefix.ActionType, action)
	c = gatefix.WithKey(p.t, c, agent)
	if agent == "agent2" {
		c.AgentID = "dca-agent-2"
	}
	b, _ := gatefix.Sign(p.t, agent, c)
	return c, b, action
}

func (p *pEnv) counter() *policy.Counter {
	sr, ok := p.Reg.(registry.StateRegistry)
	require.True(p.t, ok)
	ck := p.m.CounterKey()
	cell, err := sr.State(context.Background(), registry.StateKey(ck))
	require.NoError(p.t, err)
	c, err := policy.DecodeCounter(cell.Value)
	require.NoError(p.t, err)
	return c
}

func (p *pEnv) verdict(b []byte) (*policy.SignedVerdict, commitment.Hash) {
	sv, h, err := policy.VerifyVerdict(b, p.Signer.PublicKey())
	require.NoError(p.t, err)
	return sv, h
}

func TestPolicyAllowsChainAndShareTheCounter(t *testing.T) {
	p := newPolicyEnv(t, baseMandate(t))
	c1, b1, a1 := p.request(1, "agent1", 40)
	r1, err := p.AuthorizeWith(b1, a1)
	require.NoError(t, err)
	v1, h1 := p.verdict(r1.PolicyVerdict)
	require.Equal(t, uint64(policy.OutcomeAllow), v1.Verdict.Outcome)
	require.EqualValues(t, 0, v1.Verdict.PrevState.Seq)

	c2, b2, a2 := p.request(2, "agent2", 50)
	r2, err := p.AuthorizeWith(b2, a2)
	require.NoError(t, err)
	v2, _ := p.verdict(r2.PolicyVerdict)
	prevHash, ok := v2.Verdict.PrevStateHash()
	require.True(t, ok)
	assert.Equal(t, v1.Verdict.NewStateHash, prevHash[:])
	assert.Equal(t, h1[:], v2.Verdict.PrevVerdictHash)
	h1c, _ := commitment.HashOf(c1)
	assert.Equal(t, h1c[:], v2.Verdict.PrevCommitmentHash)

	// 40 + 50 used; another 20 passes the per-action rule but not the window.
	c3, b3, a3 := p.request(3, "agent1", 20)
	r3, err := p.AuthorizeWith(b3, a3)
	require.ErrorIs(t, err, policy.ErrPeriodLimit)
	require.ErrorIs(t, err, policy.ErrDenied)
	v3, _ := p.verdict(r3.PolicyVerdict)
	assert.Equal(t, "ErrPeriodLimit", v3.Verdict.Reason)
	assert.EqualValues(t, 2, v3.Verdict.PrevState.Seq)
	assert.Empty(t, r3.Authorization)
	p.RequireUntouched(c3)
	assert.EqualValues(t, 2, p.counter().Ledger.State.Seq, "a deny changes no state")

	// The stored retry returns the authorization and the verdict.
	r2b, err := p.AuthorizeWith(b2, a2)
	require.ErrorIs(t, err, gate.ErrNonceUsed)
	assert.Equal(t, r2.Authorization, r2b.Authorization)
	assert.Equal(t, r2.PolicyVerdict, r2b.PolicyVerdict)
	ent, err := p.Entry(c2)
	require.NoError(t, err)
	assert.Equal(t, r2.PolicyVerdict, ent.Verdict)
	assert.EqualValues(t, 2, p.counter().Ledger.State.Seq, "a retry counts nothing twice")
}

type recordingArchiver struct {
	mu   sync.Mutex
	n    int
	fail error
}

func (a *recordingArchiver) Put(context.Context, gate.DecisionRecord) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.n++
	return a.fail
}

func TestPolicyAdmissionDenyArchivesTheDecision(t *testing.T) {
	arch := &recordingArchiver{}
	p := newPolicyEnv(t, baseMandate(t), gatefix.WithDeps(func(d *gate.Deps) { d.Archiver = arch }))
	c, b, a := p.request(1, "agent1", 70) // above the per-action maximum of 60
	res, err := p.AuthorizeWith(b, a)
	require.ErrorIs(t, err, policy.ErrAmountAboveMax)
	require.True(t, res.DecisionArchived)
	assert.Equal(t, 1, arch.n)
	sv, _ := p.verdict(res.PolicyVerdict)
	assert.Equal(t, "ErrAmountAboveMax", sv.Verdict.Reason)
	assert.Nil(t, sv.Verdict.PrevState, "a 4p deny reads no state")
	p.RequireUntouched(c)

	arch.fail = errors.New("disk full")
	_, b, a = p.request(2, "agent1", 70)
	res, err = p.AuthorizeWith(b, a)
	require.ErrorIs(t, err, policy.ErrAmountAboveMax, "an archive failure does not change the deny")
	assert.False(t, res.DecisionArchived)
	assert.NotEmpty(t, res.PolicyVerdict)
}

func TestPolicyDecisionAgeIsGateAttested(t *testing.T) {
	m := baseMandate(t)
	m.MaxDecisionAge = 1
	p := newPolicyEnv(t, m)
	c, b, a := p.request(1, "agent1", 10)
	res, err := p.AuthorizeWith(b, a)
	require.ErrorIs(t, err, policy.ErrDecisionAge)
	sv, _ := p.verdict(res.PolicyVerdict)
	assert.EqualValues(t, 1, sv.Verdict.GateClock)
	assert.EqualValues(t, 0, sv.Verdict.EvalTime)
	p.RequireUntouched(c)
}

func TestPolicyAgentAndExtractorFailClosed(t *testing.T) {
	m := baseMandate(t)
	m.Agents = [][]byte{gatefix.Pub(t, "agent2")}
	p := newPolicyEnv(t, m)
	_, b, a := p.request(1, "agent1", 10)
	res, err := p.AuthorizeWith(b, a)
	require.ErrorIs(t, err, policy.ErrAgentNotCovered)
	assert.NotEmpty(t, res.PolicyVerdict)

	// An action the extractor cannot read is a deny, not an allow.
	p2 := newPolicyEnv(t, baseMandate(t))
	c, b2, a2 := p2.request(2, "agent1", 255)
	res, err = p2.AuthorizeWith(b2, a2)
	require.ErrorIs(t, err, policy.ErrFactsInvalid)
	sv, _ := p2.verdict(res.PolicyVerdict)
	assert.Equal(t, "ErrFactsInvalid", sv.Verdict.Reason)
	assert.Nil(t, sv.Verdict.Facts)
	p2.RequireUntouched(c)
}

func TestPolicyConfigurationErrors(t *testing.T) {
	m := baseMandate(t)
	x, err := policy.NewExtractors(lastByteExtractor{typ: "application/other"})
	require.NoError(t, err)
	_, err = gatefix.TryNew(t,
		gatefix.WithConfig(func(c *gate.Config) { c.Mandate = signedMandate(t, m) }),
		gatefix.WithDeps(func(d *gate.Deps) { d.Extractors = x }))
	require.ErrorIs(t, err, gate.ErrInvalidConfig, "an action type without an extractor")

	_, err = gatefix.TryNew(t, gatefix.WithConfig(func(c *gate.Config) { c.Mandate = signedMandate(t, m) }))
	require.ErrorIs(t, err, gate.ErrInvalidConfig, "no extractor registry")

	other := baseMandate(t)
	other.GateID = "another-gate"
	_, err = gatefix.TryNew(t, policyOpts(t, other)...)
	require.ErrorIs(t, err, gate.ErrInvalidConfig, "mandate bound to another gate")

	bad := signedMandate(t, m)
	bad[len(bad)-1] ^= 1
	_, err = gatefix.TryNew(t,
		gatefix.WithConfig(func(c *gate.Config) { c.Mandate = bad }),
		gatefix.WithDeps(func(d *gate.Deps) { d.Extractors = x }))
	require.ErrorIs(t, err, gate.ErrInvalidConfig, "bad principal signature")

	keyed := baseMandate(t)
	keyed.Principal = gatefix.Pub(t, "gate1")
	_, err = policy.EncodeMandate(keyed)
	require.NoError(t, err)
	kb, _, err := policy.SignMandate(gatefix.Key(t, "gate1"), keyed)
	require.NoError(t, err)
	xx, err := policy.NewExtractors(lastByteExtractor{typ: gatefix.ActionType})
	require.NoError(t, err)
	_, err = gatefix.TryNew(t,
		gatefix.WithConfig(func(c *gate.Config) { c.Mandate = kb }),
		gatefix.WithDeps(func(d *gate.Deps) { d.Extractors = xx }))
	require.ErrorIs(t, err, commitment.ErrKeyRole, "principal is the gate key")
}

func TestPolicyAdoption(t *testing.T) {
	m := baseMandate(t)
	p := newPolicyEnv(t, m)
	_, b, a := p.request(1, "agent1", 40)
	_, err := p.AuthorizeWith(b, a)
	require.NoError(t, err)

	restart := func(mm *policy.Mandate) error {
		p.Cfg.Mandate = signedMandate(t, mm)
		return p.Restart()
	}
	// Same version and hash: the state continues.
	require.NoError(t, restart(m))
	assert.EqualValues(t, 1, p.counter().Ledger.State.Seq)

	// Same version, other rules.
	loose := baseMandate(t)
	loose.Assets[0].Periods[0].Max = []byte{200}
	require.ErrorIs(t, restart(loose), gate.ErrInvalidConfig)

	// A higher version continues the counters under the new rules.
	v2 := baseMandate(t)
	v2.Version = 2
	v2.Assets[0].Periods[0].Max = []byte{60}
	require.NoError(t, restart(v2))
	p.rebase()
	c := p.counter()
	assert.EqualValues(t, 2, c.Version)
	assert.EqualValues(t, 1, c.Ledger.State.Seq)
	p.m = v2
	_, b, a = p.request(2, "agent2", 30) // 40 used + 30 > 60
	_, err = p.AuthorizeWith(b, a)
	require.ErrorIs(t, err, policy.ErrPeriodLimit)

	// A lower version is refused.
	require.ErrorIs(t, restart(m), gate.ErrInvalidConfig)

	// A scale change of a retained asset is refused.
	v3 := baseMandate(t)
	v3.Version = 3
	v3.Assets[0].Scale = 2
	require.ErrorIs(t, restart(v3), gate.ErrInvalidConfig)
}

func TestPolicyFailedCommitLeavesStateUnchanged(t *testing.T) {
	p := newPolicyEnv(t, baseMandate(t), gatefix.WithFaultyRegistry())
	c, b, a := p.request(1, "agent1", 40)
	p.Faulty.FailNext("ConsumeState", errors.New("disk"))
	_, err := p.AuthorizeWith(b, a)
	require.ErrorIs(t, err, gate.ErrRegistryUnavailable)
	p.RequireUntouched(c)
	assert.EqualValues(t, 0, p.counter().Ledger.State.Seq)

	// A concurrent change of the cell is a retryable conflict with nothing written.
	p.Faulty.Before("ConsumeState", func() {
		cur := p.counter()
		cur.Version = 9
		enc, err := policy.EncodeCounter(cur)
		require.NoError(t, err)
		sr := p.Reg.(registry.StateRegistry)
		cell, err := sr.State(context.Background(), registry.StateKey(p.m.CounterKey()))
		require.NoError(t, err)
		require.NoError(t, sr.UpdateState(context.Background(), registry.StateTx{
			Key: registry.StateKey(p.m.CounterKey()), Expect: cell.Version, Next: registry.NewStateCell(enc)}))
	})
	_, err = p.AuthorizeWith(b, a)
	require.ErrorIs(t, err, gate.ErrPolicyStateConflict)
	p.RequireUntouched(c)
}

func TestPolicyConcurrentRequestsShareOneBudget(t *testing.T) {
	m := baseMandate(t)
	m.Assets[0].PerActionMax = nil
	m.Assets[0].Periods[0].Max = []byte{50}
	p := newPolicyEnv(t, m)
	var allowed, denied atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		agent := "agent1"
		if i%2 == 1 {
			agent = "agent2"
		}
		_, b, a := p.request(byte(i+1), agent, 10)
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := p.AuthorizeWith(b, a)
			switch {
			case err == nil:
				allowed.Add(1)
			case errors.Is(err, policy.ErrPeriodLimit):
				denied.Add(1)
			default:
				t.Errorf("unexpected error: %v", err)
			}
		}()
	}
	wg.Wait()
	assert.EqualValues(t, 5, allowed.Load())
	assert.EqualValues(t, 15, denied.Load())
	assert.EqualValues(t, 5, p.counter().Ledger.State.Seq)
}

func TestPolicyRolloverReturnsClosedBucket(t *testing.T) {
	m := baseMandate(t)
	m.Assets[0].Periods[0].Max = []byte{250}
	p := newPolicyEnv(t, m)
	_, b, a := p.request(1, "agent1", 10)
	r1, err := p.AuthorizeWith(b, a)
	require.NoError(t, err)
	assert.Empty(t, r1.ClosedBucket)

	// A decision anchored two hours later closes the first allow's hour.
	c2 := gatefix.Times(p.base, p.base.IssuedAt+7200, p.base.ValidUntil+7200)
	c2.PayloadRef.Height++
	c2 = gatefix.WithAction(t, gatefix.Fresh(c2, 2), gatefix.ActionType, gatefix.OtherAction(t, 20))
	p.StageDA(c2, gatefix.Blob(t))
	p.Clock.Set(gatefix.Now + 7200)
	b2, _ := gatefix.Sign(t, "agent1", c2)
	r2, err := p.AuthorizeWith(b2, gatefix.OtherAction(t, 20))
	require.NoError(t, err)
	require.NotEmpty(t, r2.ClosedBucket)
	require.NotEmpty(t, r2.ClosedSet)
	bk, err := policy.DecodeBucket(r2.ClosedBucket)
	require.NoError(t, err)
	assert.EqualValues(t, 1, bk.Count)
	set, err := policy.DecodeClosedSet(r2.ClosedSet)
	require.NoError(t, err)
	require.Len(t, set.Buckets, 1)
}
