package gate_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/gate"
	"github.com/vgonkivs/edicta/gate/registry"
	"github.com/vgonkivs/edicta/policy"
	"github.com/vgonkivs/edicta/test/gatefix"
)

// requestAt signs a decision anchored at header time th. Every call stages its
// own height so that each decision has its own anchor time.
func (p *pEnv) requestAt(tag byte, agent string, amount byte, th uint64) (*commitment.Commitment, []byte, []byte) {
	p.t.Helper()
	action := gatefix.OtherAction(p.t, int(amount))
	c := gatefix.Times(p.base, th, gatefix.Now+600)
	c.PayloadRef.Height = p.base.PayloadRef.Height + 1 + uint64(tag)
	c = gatefix.WithAction(p.t, gatefix.Fresh(c, tag), gatefix.ActionType, action)
	c = gatefix.WithKey(p.t, c, agent)
	if agent == "agent2" {
		c.AgentID = "dca-agent-2"
	}
	p.StageChain(c, th, th)
	p.DA.Put(c.PayloadRef, gatefix.Blob(p.t))
	b, _ := gatefix.Sign(p.t, agent, c)
	return c, b, action
}

func TestPolicyBackwardsAnchorWithMinSpacing(t *testing.T) {
	now := gatefix.Now // 60 s into an hour
	m := baseMandate(t)
	m.Assets[0].PerActionMax = nil
	m.Assets[0].Periods[0].Max = []byte{250}
	m.MinSpacing = 1000
	m.MaxDecisionAge = 4000
	p := newPolicyEnv(t, m)

	_, b, a := p.requestAt(1, "agent1", 10, now-3000)
	r1, err := p.AuthorizeWith(b, a)
	require.NoError(t, err)
	assert.Empty(t, r1.ClosedBucket)

	c2, b, a := p.requestAt(2, "agent1", 10, now-2500)
	r2, err := p.AuthorizeWith(b, a)
	require.ErrorIs(t, err, policy.ErrMinSpacing)
	p.RequireUntouched(c2)
	sv2, _ := p.verdict(r2.PolicyVerdict)
	assert.EqualValues(t, now-3000, sv2.Verdict.PrevState.LastTH)
	assert.EqualValues(t, now-2500, sv2.Verdict.AnchorTime)

	_, b, a = p.requestAt(3, "agent2", 10, now-2000)
	_, err = p.AuthorizeWith(b, a)
	require.NoError(t, err, "exactly the spacing after the last allowed anchor")

	_, b, a = p.requestAt(4, "agent1", 10, now-10) // the hour that began 50 s ago
	r4, err := p.AuthorizeWith(b, a)
	require.NoError(t, err)
	require.NotEmpty(t, r4.ClosedBucket, "the previous hour closes")
	bk, err := policy.DecodeBucket(r4.ClosedBucket)
	require.NoError(t, err)
	assert.EqualValues(t, 2, bk.Count)

	// An anchor from the closed hour is not let in under the spacing rule.
	c5, b, a := p.requestAt(5, "agent1", 10, now-1500)
	_, err = p.AuthorizeWith(b, a)
	require.ErrorIs(t, err, policy.ErrMinSpacing)
	p.RequireUntouched(c5)
	assert.EqualValues(t, 3, p.counter().Ledger.State.Seq)
}

func TestPolicyBackwardsAnchorIsAttributedToTheLatestTime(t *testing.T) {
	now := gatefix.Now
	m := baseMandate(t)
	m.Assets[0].PerActionMax = nil
	m.Assets[0].Periods[0].Max = []byte{100}
	m.MaxDecisionAge = 4000
	p := newPolicyEnv(t, m)

	_, b, a := p.requestAt(1, "agent1", 10, now-10)
	_, err := p.AuthorizeWith(b, a)
	require.NoError(t, err)
	open := p.counter().Ledger.State.Open.Index

	_, b, a = p.requestAt(2, "agent2", 10, now-2000) // the hour before
	r2, err := p.AuthorizeWith(b, a)
	require.NoError(t, err)
	assert.Empty(t, r2.ClosedBucket, "an older anchor closes no hour")
	sv, _ := p.verdict(r2.PolicyVerdict)
	assert.EqualValues(t, now-2000, sv.Verdict.AnchorTime)
	assert.EqualValues(t, now-10, sv.Verdict.EvalTime)
	ctr := p.counter()
	assert.Equal(t, open, ctr.Ledger.State.Open.Index)
	assert.EqualValues(t, 2, ctr.Ledger.State.Open.Count)
	assert.Empty(t, ctr.Ledger.Closed)

	c3, b, a := p.requestAt(3, "agent1", 85, now-3000)
	_, err = p.AuthorizeWith(b, a)
	require.ErrorIs(t, err, policy.ErrPeriodLimit, "20 used, 85 more does not fit")
	p.RequireUntouched(c3)
}

// Many agents and anchors in two hours race for a count budget: the allows
// form one chain, nothing is lost or counted twice.
func TestPolicyConcurrentAllowsFormOneChainAcrossAnHourRollover(t *testing.T) {
	now := gatefix.Now
	m := baseMandate(t)
	m.Assets[0].PerActionMax = nil
	m.Assets[0].Periods[0].Max = []byte{250}
	m.CountLimits = []policy.CountLimit{{Hours: 24, MaxCount: 7}}
	m.MaxDecisionAge = 4000
	p := newPolicyEnv(t, m)

	const n = 24
	type req struct {
		b, a []byte
	}
	reqs := make([]req, n)
	for i := range reqs {
		agent, th := "agent1", now-2000
		if i%2 == 1 {
			agent = "agent2"
		}
		if i%3 == 0 {
			th = now - 10
		}
		_, b, a := p.requestAt(byte(i+1), agent, 10, th)
		reqs[i] = req{b, a}
	}
	var mu sync.Mutex
	var verdicts [][]byte
	var wg sync.WaitGroup
	for _, r := range reqs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res, err := p.AuthorizeWith(r.b, r.a)
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				verdicts = append(verdicts, res.PolicyVerdict)
			case errors.Is(err, policy.ErrCountLimit):
			default:
				t.Errorf("unexpected: %v", err)
			}
		}()
	}
	wg.Wait()
	require.Len(t, verdicts, 7)

	next := map[string]*policy.Verdict{}
	for _, vb := range verdicts {
		sv, _ := p.verdict(vb)
		h, ok := sv.Verdict.PrevStateHash()
		require.True(t, ok)
		_, dup := next[string(h[:])]
		require.False(t, dup, "two allows from one state: a fork")
		next[string(h[:])] = &sv.Verdict
	}
	g := policy.GenesisLedger()
	cur, err := policy.HashState(&g.State)
	require.NoError(t, err)
	for i := 0; i < 7; i++ {
		v, ok := next[string(cur[:])]
		require.True(t, ok, "the chain breaks at step %d", i)
		assert.EqualValues(t, i, v.PrevState.Seq)
		copy(cur[:], v.NewStateHash)
	}
	ctr := p.counter()
	assert.EqualValues(t, 7, ctr.Ledger.State.Seq)
	total := ctr.Ledger.State.Open.Count
	for _, b := range ctr.Ledger.Closed {
		total += b.Count
	}
	assert.EqualValues(t, 7, total)
	h, err := policy.HashState(&ctr.Ledger.State)
	require.NoError(t, err)
	assert.Equal(t, cur, h, "the cell holds the last state of the chain")
}

func TestPolicySameCommitmentRacedIsOneAllow(t *testing.T) {
	p := newPolicyEnv(t, baseMandate(t))
	c, b, a := p.request(1, "agent1", 40)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var ok, used int
	var auths [][]byte
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res, err := p.AuthorizeWith(b, a)
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				ok++
			case errors.Is(err, gate.ErrNonceUsed):
				used++
			default:
				t.Errorf("unexpected: %v", err)
				return
			}
			auths = append(auths, res.Authorization)
		}()
	}
	wg.Wait()
	assert.Equal(t, 1, ok)
	assert.Equal(t, 11, used)
	for _, x := range auths {
		assert.Equal(t, auths[0], x, "every caller sees the one Authorization")
	}
	assert.EqualValues(t, 1, p.counter().Ledger.State.Seq)
	ent, err := p.Entry(c)
	require.NoError(t, err)
	assert.NotEmpty(t, ent.Verdict)
}

// The mandate only removes allows: whatever the plain gate refuses, the
// gate with a mandate refuses with the same reason, and nothing the mandate
// refuses leaves a trace.
func TestPolicyNeverTurnsARefusalIntoAnAllow(t *testing.T) {
	_, stranger, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	type scenario struct {
		name string
		// build returns the envelope and action for env e; stage is false
		// for a payload that is not made available.
		build func(e *pEnv) (env, action []byte, c *commitment.Commitment)
	}
	valid := func(e *pEnv, tag byte, mod func(c *commitment.Commitment)) (*commitment.Commitment, []byte, []byte) {
		action := gatefix.OtherAction(t, 20)
		c := gatefix.WithAction(t, gatefix.Fresh(e.base, tag), gatefix.ActionType, action)
		c = gatefix.WithKey(t, c, "agent1")
		if mod != nil {
			mod(c)
		}
		b, _ := gatefix.Sign(t, "agent1", c)
		return c, b, action
	}
	scenarios := []scenario{
		{"valid", func(e *pEnv) ([]byte, []byte, *commitment.Commitment) {
			c, b, a := valid(e, 1, nil)
			return b, a, c
		}},
		{"expired", func(e *pEnv) ([]byte, []byte, *commitment.Commitment) {
			c, b, a := valid(e, 2, func(c *commitment.Commitment) { c.ValidUntil = gatefix.Now - 1 })
			return b, a, c
		}},
		{"issued in the future", func(e *pEnv) ([]byte, []byte, *commitment.Commitment) {
			c, b, a := valid(e, 3, func(c *commitment.Commitment) { c.IssuedAt = gatefix.Now + 5000; c.ValidUntil = gatefix.Now + 5600 })
			return b, a, c
		}},
		{"altered signature", func(e *pEnv) ([]byte, []byte, *commitment.Commitment) {
			c, b, a := valid(e, 4, nil)
			b = append([]byte(nil), b...)
			b[len(b)-1] ^= 1
			return b, a, c
		}},
		{"altered action bytes", func(e *pEnv) ([]byte, []byte, *commitment.Commitment) {
			c, b, a := valid(e, 5, nil)
			a = append([]byte(nil), a...)
			a[0] ^= 1
			return b, a, c
		}},
		{"other gate", func(e *pEnv) ([]byte, []byte, *commitment.Commitment) {
			c, b, a := valid(e, 6, func(c *commitment.Commitment) { c.Scope.GateID = "another-gate" })
			return b, a, c
		}},
		{"action type outside the gate", func(e *pEnv) ([]byte, []byte, *commitment.Commitment) {
			action := gatefix.OtherAction(t, 20)
			c := gatefix.WithAction(t, gatefix.Fresh(e.base, 7), "application/other", action)
			c = gatefix.WithKey(t, c, "agent1")
			b, _ := gatefix.Sign(t, "agent1", c)
			return b, action, c
		}},
		{"unlisted agent key", func(e *pEnv) ([]byte, []byte, *commitment.Commitment) {
			action := gatefix.OtherAction(t, 20)
			c := gatefix.WithAction(t, gatefix.Fresh(e.base, 8), gatefix.ActionType, action)
			c.AgentPubKey = stranger.Public().(ed25519.PublicKey)
			b, _ := gatefix.SignWith(t, stranger, c)
			return b, action, c
		}},
		{"payload not available", func(e *pEnv) ([]byte, []byte, *commitment.Commitment) {
			action := gatefix.OtherAction(t, 20)
			c := gatefix.WithAction(t, gatefix.Fresh(e.base, 9), gatefix.ActionType, action)
			c = gatefix.WithKey(t, c, "agent1")
			c.PayloadRef.Height += 77
			e.Headers.Set(c.PayloadRef.Height, gatefix.BlockTime(c))
			b, _ := gatefix.Sign(t, "agent1", c)
			return b, action, c
		}},
		{"agent allowlisted but not in the mandate", func(e *pEnv) ([]byte, []byte, *commitment.Commitment) {
			action := gatefix.OtherAction(t, 20)
			c := gatefix.WithAction(t, gatefix.Fresh(e.base, 10), gatefix.ActionType, action)
			c = gatefix.WithKey(t, c, "agent2")
			c.AgentID = "dca-agent-2"
			b, _ := gatefix.Sign(t, "agent2", c)
			return b, action, c
		}},
		{"amount above the mandate maximum", func(e *pEnv) ([]byte, []byte, *commitment.Commitment) {
			action := gatefix.OtherAction(t, 90)
			c := gatefix.WithAction(t, gatefix.Fresh(e.base, 11), gatefix.ActionType, action)
			c = gatefix.WithKey(t, c, "agent1")
			b, _ := gatefix.Sign(t, "agent1", c)
			return b, action, c
		}},
		{"action the extractor cannot read", func(e *pEnv) ([]byte, []byte, *commitment.Commitment) {
			action := gatefix.OtherAction(t, 255)
			c := gatefix.WithAction(t, gatefix.Fresh(e.base, 12), gatefix.ActionType, action)
			c = gatefix.WithKey(t, c, "agent1")
			b, _ := gatefix.Sign(t, "agent1", c)
			return b, action, c
		}},
	}

	for _, sc := range scenarios {
		t.Run(sc.name, func(t *testing.T) {
			m := baseMandate(t)
			m.Agents = [][]byte{gatefix.Pub(t, "agent1")}
			m.Assets[0].PerActionMax = []byte{60}
			with := newPolicyEnv(t, m)
			plainEnv := gatefix.New(t,
				gatefix.WithConfig(func(c *gate.Config) {}),
			)
			plainEnv.StageDA(gatefix.Template(t), gatefix.Blob(t))
			plain := &pEnv{Env: plainEnv, t: t, base: gatefix.Template(t)}

			bw, aw, cw := sc.build(with)
			bp, ap, cp := sc.build(plain)
			if sc.name != "payload not available" {
				with.StageDA(cw, gatefix.Blob(t))
				plain.StageDA(cp, gatefix.Blob(t))
			}
			_, errWith := with.AuthorizeWith(bw, aw)
			_, errPlain := plain.AuthorizeWith(bp, ap)

			if errWith == nil {
				assert.NoError(t, errPlain, "the mandate allowed what the plain gate refused")
			}
			for _, s := range gatefix.KnownSentinels() {
				if errors.Is(errPlain, s) {
					assert.ErrorIs(t, errWith, s, "the plain gate's refusal is kept")
				}
			}
			if errWith != nil {
				with.RequireUntouched(cw)
				assert.EqualValues(t, 0, with.counter().Ledger.State.Seq, "a refusal changes no policy state")
			}
			switch sc.name {
			case "valid":
				require.NoError(t, errWith)
				require.NoError(t, errPlain)
			case "agent allowlisted but not in the mandate", "amount above the mandate maximum", "action the extractor cannot read":
				require.NoError(t, errPlain, "the plain gate would have allowed it")
				require.ErrorIs(t, errWith, policy.ErrDenied)
			default:
				require.Error(t, errPlain)
				require.Error(t, errWith)
			}
		})
	}
}

func TestPolicyRefusedAdoptionLeavesTheCellUntouched(t *testing.T) {
	m1 := baseMandate(t)
	p := newPolicyEnv(t, m1)
	_, b, a := p.request(1, "agent1", 40)
	_, err := p.AuthorizeWith(b, a)
	require.NoError(t, err)

	rawCell := func(m *policy.Mandate) registry.StateCell {
		sr := p.Reg.(registry.StateRegistry)
		cell, err := sr.State(context.Background(), registry.StateKey(m.CounterKey()))
		require.NoError(t, err)
		return cell
	}
	restart := func(m *policy.Mandate) error {
		p.Cfg.Mandate = signedMandate(t, m)
		return p.Restart()
	}

	v2 := baseMandate(t)
	v2.Version = 2
	require.NoError(t, restart(v2))
	cell := rawCell(m1)
	assert.EqualValues(t, 2, p.counter().Version)

	require.ErrorIs(t, restart(m1), gate.ErrInvalidConfig, "a lower version")
	assert.Equal(t, cell, rawCell(m1))

	other := baseMandate(t)
	other.Version = 2
	other.Assets[0].Periods[0].Max = []byte{99}
	require.ErrorIs(t, restart(other), gate.ErrInvalidConfig, "the same version with other rules")
	assert.Equal(t, cell, rawCell(m1))

	v3 := baseMandate(t)
	v3.Version = 3
	v3.Assets[0].Scale = 6
	require.ErrorIs(t, restart(v3), gate.ErrInvalidConfig, "a scale change")
	assert.Equal(t, cell, rawCell(m1))

	require.NoError(t, restart(v2), "the stored version still starts")
	assert.EqualValues(t, 1, p.counter().Ledger.State.Seq)

	v4 := baseMandate(t)
	v4.Version = 4
	require.NoError(t, restart(v4))
	assert.EqualValues(t, 4, p.counter().Version)
	assert.EqualValues(t, 1, p.counter().Ledger.State.Seq, "a higher version continues the counter")

	fresh := baseMandate(t)
	fresh.MandateID = []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	require.NoError(t, restart(fresh))
	p.m = fresh
	assert.EqualValues(t, 0, p.counter().Ledger.State.Seq, "a new mandate_id starts from zero")
	assert.EqualValues(t, 4, func() uint64 {
		var c *policy.Counter
		sr := p.Reg.(registry.StateRegistry)
		cell, err := sr.State(context.Background(), registry.StateKey(m1.CounterKey()))
		require.NoError(t, err)
		c, err = policy.DecodeCounter(cell.Value)
		require.NoError(t, err)
		return c.Version
	}(), "the old counter is left as it was")
}
