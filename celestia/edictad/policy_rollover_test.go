package edictad_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/celestia/edictad"
	"github.com/vgonkivs/edicta/celestia/node"
	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/examples/tia-transfer/bankaction"
	"github.com/vgonkivs/edicta/examples/tia-transfer/bankmsg"
	"github.com/vgonkivs/edicta/gate"
	"github.com/vgonkivs/edicta/policy"
	"github.com/vgonkivs/edicta/test/gatefix"
)

type mutClock struct{ unix atomic.Int64 }

func (c *mutClock) Now() time.Time      { return time.Unix(c.unix.Load(), 0).UTC() }
func (c *mutClock) set(t time.Time)     { c.unix.Store(t.Unix()) }
func newMutClock(t time.Time) *mutClock { c := &mutClock{}; c.set(t); return c }

// rollEnv is a policy env with a clock the test moves and decisions anchored
// at chosen header times.
type rollEnv struct {
	*policyEnv
	clk     *mutClock
	nextH   uint64
	agentID string
}

func newRollEnv(t *testing.T, mod func(m *policy.Mandate)) *rollEnv {
	t.Helper()
	p := newPolicyEnv(t)
	r := &rollEnv{policyEnv: p, clk: newMutClock(t0), nextH: p.base.PayloadRef.Height + 10}
	p.deps.Clock = r.clk
	p.mandate.Assets[0].Periods = []policy.PeriodLimit{{Hours: 24, Max: policy.AmountFromUint64(8_000_000)}}
	if mod != nil {
		mod(p.mandate)
	}
	p.file = p.sign(p.principal, p.mandate)
	return r
}

// sendAt is a bank send of amount utia whose payload was anchored at th.
// The first decision of a test may reuse the staged height (th = t0-1000).
func (r *rollEnv) sendAt(tag byte, amount uint64, th time.Time) decision {
	r.t.Helper()
	h := r.nextH
	r.nextH += 10
	hd := blockAt(h, 8)
	hd.Time = th
	r.chain.AddHeader(hd)
	ref := r.base.PayloadRef
	r.chain.AddBlob(h, node.Blob{Namespace: bytes.Clone(ref.Namespace), Data: gatefix.Blob(r.t), ShareVersion: 1,
		Signer: bytes.Clone(ref.Signer), Commitment: bytes.Clone(ref.Commitment)}, rootProof{root: hd.DataRoot})
	head := blockAt(h+1, 8)
	head.Time = r.clk.Now()
	r.chain.AddHeader(head)
	return r.bankDecision(tag, amount, func(c *commitment.Commitment) { c.PayloadRef.Height = h })
}

func (r *rollEnv) bankDecision(tag byte, amount uint64, mod func(*commitment.Commitment)) decision {
	r.t.Helper()
	to, err := bankmsg.EncodeAddress("celestia", bytes.Repeat([]byte{2}, 20))
	require.NoError(r.t, err)
	from, err := bankmsg.EncodeAddress("celestia", bytes.Repeat([]byte{1}, 20))
	require.NoError(r.t, err)
	msg, err := bankmsg.Encode(bankmsg.MsgSend{From: from, To: to, Denom: "utia", Amount: amount}, "celestia")
	require.NoError(r.t, err)
	action, err := bankaction.Encode(bankaction.Action{ChainID: policyChainID, Msg: msg})
	require.NoError(r.t, err)
	now := uint64(r.clk.Now().Unix())
	return r.decisionAct(r.base, tag, action, func(c *commitment.Commitment) {
		h, err := commitment.ActionHash(bankaction.ActionType, action)
		require.NoError(r.t, err)
		c.Action.Type, c.Action.Hash = bankaction.ActionType, h[:]
		c.IssuedAt, c.ValidUntil = now-5, now+600
		if r.agentID != "" {
			c.AgentID = r.agentID
		}
		if mod != nil {
			mod(c)
		}
	})
}

func (r *rollEnv) verdictOf(h commitment.Hash) *policy.Verdict {
	r.t.Helper()
	rec, err := r.real.PolicyAllow(bg, h)
	require.NoError(r.t, err)
	sv, _, err := policy.VerifyVerdict(rec.SignedVerdict, r.gatePub)
	require.NoError(r.t, err)
	return &sv.Verdict
}

func (r *rollEnv) denyOf(h commitment.Hash, reason string) *policy.Verdict {
	r.t.Helper()
	rec, err := r.real.PolicyDeny(bg, h, reason)
	require.NoError(r.t, err)
	sv, _, err := policy.VerifyVerdict(rec.SignedVerdict, r.gatePub)
	require.NoError(r.t, err)
	return &sv.Verdict
}

// requireHistoryReadable checks what a verifier needs to evaluate an allow:
// the closed set of its signed state and every bucket the set names.
func (r *rollEnv) requireHistoryReadable(v *policy.Verdict) {
	r.t.Helper()
	root := commitment.Hash(v.PrevState.ClosedRoot)
	empty := policy.EmptyClosedSet()
	if eh, _ := policy.HashClosedSet(&empty); eh == root {
		return
	}
	rec, err := r.real.PolicyClosed(bg, root)
	require.NoError(r.t, err, "closed set %x", root[:4])
	set, err := policy.DecodeClosedSet(rec.ClosedSet)
	require.NoError(r.t, err)
	require.Equal(r.t, root, policy.HashClosedSetBytes(rec.ClosedSet))
	for _, ref := range set.Buckets {
		b, err := r.real.PolicyBucket(bg, commitment.Hash(ref.Hash))
		require.NoError(r.t, err, "bucket %d", ref.Index)
		require.Equal(r.t, commitment.Hash(ref.Hash), policy.HashBucketBytes(b.Bucket))
	}
}

var rollKinds = []archive.Kind{archive.KindDecision, archive.KindPolicyBucket, archive.KindPolicyClosed,
	archive.KindPolicyAllow, archive.KindPolicySuccessor, archive.KindAuthorization}

func TestPolicyRolloverWritesBucketThenClosedSetThenTheAllow(t *testing.T) {
	r := newRollEnv(t, nil)
	r.startPolicy()
	n := len(r.fs.puts)

	d1 := r.sendAt(1, 2_000_000, t0.Add(-1000*time.Second)) // 11:43
	st, _, _ := r.authorizeRaw(d1)
	require.Equal(t, 200, st)
	assert.Equal(t, []archive.Kind{archive.KindDecision, archive.KindPolicyAllow, archive.KindPolicySuccessor, archive.KindAuthorization},
		kindsOf(r.fs.puts, n), "no hour closed yet")

	r.clk.set(t0.Add(1200 * time.Second))
	n = len(r.fs.puts)
	d2 := r.sendAt(2, 2_000_000, t0.Add(600*time.Second)) // 12:10, the next hour
	st, _, body := r.authorizeRaw(d2)
	require.Equal(t, 200, st, string(body))
	assert.Equal(t, rollKinds, kindsOf(r.fs.puts, n), "bucket, closed set, allow, successor, Authorization")

	v2 := r.verdictOf(d2.hash)
	assert.EqualValues(t, 1, v2.PrevState.Seq)
	r.requireHistoryReadable(v2)

	// The third allow starts from the state that names the new closed set.
	n = len(r.fs.puts)
	d3 := r.sendAt(3, 1_000_000, t0.Add(700*time.Second))
	st, _, _ = r.authorizeRaw(d3)
	require.Equal(t, 200, st)
	assert.Equal(t, []archive.Kind{archive.KindDecision, archive.KindPolicyAllow, archive.KindPolicySuccessor, archive.KindAuthorization},
		kindsOf(r.fs.puts, n))
	v3 := r.verdictOf(d3.hash)
	assert.NotEqual(t, v2.PrevState.ClosedRoot, v3.PrevState.ClosedRoot, "the root moved at the rollover")
	r.requireHistoryReadable(v3)
	set, err := r.real.PolicyClosed(bg, commitment.Hash(v3.PrevState.ClosedRoot))
	require.NoError(t, err)
	cs, err := policy.DecodeClosedSet(set.ClosedSet)
	require.NoError(t, err)
	require.Len(t, cs.Buckets, 1)
	b, err := r.real.PolicyBucket(bg, commitment.Hash(cs.Buckets[0].Hash))
	require.NoError(t, err)
	bk, err := policy.DecodeBucket(b.Bucket)
	require.NoError(t, err)
	assert.EqualValues(t, 1, bk.Count)
	assert.Equal(t, policy.AmountFromUint64(2_000_000), bk.Sums[0].Sum)

	// The retry of an answered decision writes nothing and counts nothing.
	n = len(r.fs.puts)
	st, _, _ = r.authorizeRaw(d3)
	assert.Equal(t, 409, st, "the same decision again is a used nonce")
	for _, k := range kindsOf(r.fs.puts, n) {
		assert.Equal(t, archive.KindDecision, k, "a retry writes no policy or Authorization record")
	}

	// 4p and 10p denies: the first reads no state, the second signs the one it read.
	n = len(r.fs.puts)
	d4 := r.sendAt(4, 1_000_000, t0.Add(800*time.Second)) // 6M used of 8M
	st, _, _ = r.authorizeRaw(d4)
	require.Equal(t, 200, st)
	n = len(r.fs.puts)
	d5 := r.sendAt(5, 3_000_000, t0.Add(900*time.Second)) // 9M > 8M
	st, _, body = r.authorizeRaw(d5)
	require.Equal(t, 403, st, string(body))
	assert.True(t, hasCode(body, "policy.ErrPeriodLimit"), string(body))
	assert.Equal(t, []archive.Kind{archive.KindDecision, archive.KindPolicyDeny, archive.KindRejection}, kindsOf(r.fs.puts, n))
	dv := r.denyOf(d5.hash, "ErrPeriodLimit")
	require.NotNil(t, dv.PrevState, "a 10p deny signs the state it read")
	assert.EqualValues(t, 4, dv.PrevState.Seq)
	_, err = r.real.PolicyAllow(bg, d5.hash)
	require.ErrorIs(t, err, archive.ErrNotFound)

	n = len(r.fs.puts)
	d6 := r.sendAt(6, 6_000_000, t0.Add(950*time.Second)) // above the 5M per-action maximum
	st, _, body = r.authorizeRaw(d6)
	require.Equal(t, 403, st, string(body))
	assert.True(t, hasCode(body, "policy.ErrAmountAboveMax"), string(body))
	assert.Equal(t, []archive.Kind{archive.KindDecision, archive.KindPolicyDeny, archive.KindRejection}, kindsOf(r.fs.puts, n))
	assert.Nil(t, r.denyOf(d6.hash, "ErrAmountAboveMax").PrevState, "a 4p deny reads no state")

	// Neither deny moved the counter.
	d7 := r.sendAt(7, 1_000_000, t0.Add(990*time.Second))
	st, _, _ = r.authorizeRaw(d7)
	require.Equal(t, 200, st)
	assert.EqualValues(t, 4, r.verdictOf(d7.hash).PrevState.Seq)
}

func TestPolicyDecisionAgeDenyIsGateAttestedOverHTTP(t *testing.T) {
	r := newRollEnv(t, func(m *policy.Mandate) { m.MaxDecisionAge = 60 })
	r.startPolicy()
	n := len(r.fs.puts)
	d := r.sendAt(1, 1_000_000, t0.Add(-1000*time.Second))
	st, _, body := r.authorizeRaw(d)
	require.Equal(t, 410, st, string(body))
	assert.True(t, hasCode(body, "policy.ErrDecisionAge"), string(body))
	assert.Equal(t, []archive.Kind{archive.KindDecision, archive.KindPolicyDeny, archive.KindRejection}, kindsOf(r.fs.puts, n))
	assert.EqualValues(t, 1, r.denyOf(d.hash, "ErrDecisionAge").GateClock)
}

// A failed closed-set write holds back everything behind it, and the sweep
// finishes the chain in order.
func TestPolicyRolloverFailedClosedSetHoldsBackTheAllow(t *testing.T) {
	r := newRollEnv(t, nil)
	tick := make(chan time.Time)
	r.deps.SweepTick = tick
	r.startPolicy()
	d1 := r.sendAt(1, 3_000_000, t0.Add(-1000*time.Second))
	st, _, _ := r.authorizeRaw(d1)
	require.Equal(t, 200, st)

	r.clk.set(t0.Add(1200 * time.Second))
	r.fs.failKind(archive.KindPolicyClosed, errArchiveDown)
	n := len(r.fs.puts)
	d2 := r.sendAt(2, 3_000_000, t0.Add(600*time.Second))
	st, _, _ = r.authorizeRaw(d2)
	require.Equal(t, 200, st, "a failed archive write does not change the answer")
	assert.Equal(t, []archive.Kind{archive.KindDecision, archive.KindPolicyBucket, archive.KindPolicyClosed}, kindsOf(r.fs.puts, n))
	_, err := r.real.PolicyAllow(bg, d2.hash)
	require.ErrorIs(t, err, archive.ErrNotFound)
	_, err = r.real.Authorization(bg, d2.hash)
	require.ErrorIs(t, err, archive.ErrNotFound)

	r.fs.failKind(archive.KindPolicyClosed, nil)
	tick <- t0
	eventually(t, func() bool { _, err := r.real.Authorization(bg, d2.hash); return err == nil }, "the chain is finished")
	v := r.verdictOf(d2.hash)
	r.requireHistoryReadable(v)
	got := kindsOf(r.fs.puts, n)
	idx := func(k archive.Kind) int { return slices.Index(got[3:], k) }
	assert.True(t, idx(archive.KindPolicyAllow) < idx(archive.KindAuthorization), "the verdict goes first: %v", got)
	assert.True(t, idx(archive.KindPolicySuccessor) < idx(archive.KindAuthorization), "%v", got)
}

// The process dies after the registry commit and before any policy record
// reaches the archive: the next start repairs the verdict, the successor, the
// closed buckets, and writes the Authorization record last.
func TestPolicyCrashAfterTheRolloverCommitIsRepairedOnRestart(t *testing.T) {
	r := newRollEnv(t, nil)
	r.startPolicy()
	d1 := r.sendAt(1, 3_000_000, t0.Add(-1000*time.Second))
	st, _, _ := r.authorizeRaw(d1)
	require.Equal(t, 200, st)

	r.clk.set(t0.Add(1200 * time.Second))
	lost := []archive.Kind{archive.KindPolicyBucket, archive.KindPolicyClosed, archive.KindPolicyAllow, archive.KindPolicySuccessor, archive.KindAuthorization}
	for _, k := range lost {
		r.fs.failKind(k, errArchiveDown)
	}
	d2 := r.sendAt(2, 3_000_000, t0.Add(600*time.Second))
	st, _, _ = r.authorizeRaw(d2)
	require.Equal(t, 200, st)
	_, err := r.real.Authorization(bg, d2.hash)
	require.ErrorIs(t, err, archive.ErrNotFound)
	_ = r.srv.Shutdown(bg) // the retry queue dies with the process

	for _, k := range lost {
		r.fs.failKind(k, nil)
	}
	n := len(r.fs.puts)
	fresh := blockAt(r.nextH, 8)
	fresh.Time = r.clk.Now()
	r.nextH += 10
	r.chain.AddHeader(fresh)
	r.startPolicy()
	eventually(t, func() bool { _, err := r.real.Authorization(bg, d2.hash); return err == nil }, "the Authorization is repaired")

	got := kindsOf(r.fs.puts, n)
	pos := func(k archive.Kind) int { return slices.Index(got, k) }
	for _, k := range []archive.Kind{archive.KindPolicyAllow, archive.KindPolicySuccessor, archive.KindPolicyBucket, archive.KindPolicyClosed} {
		require.GreaterOrEqual(t, pos(k), 0, "%s repaired: %v", k, got)
	}
	assert.Less(t, pos(archive.KindPolicyAllow), pos(archive.KindAuthorization), "%v", got)
	assert.Less(t, pos(archive.KindPolicySuccessor), pos(archive.KindAuthorization), "%v", got)

	r.requireHistoryReadable(r.verdictOf(d2.hash))
	d3 := r.sendAt(3, 1_000_000, t0.Add(700*time.Second))
	st, _, _ = r.authorizeRaw(d3)
	require.Equal(t, 200, st)
	v3 := r.verdictOf(d3.hash)
	assert.EqualValues(t, 2, v3.PrevState.Seq)
	r.requireHistoryReadable(v3)
}

// Two rollovers whose policy records never reached the archive, and a retry
// queue lost with the process: the registry entries still hold the closed
// bucket and set of each, so the older set is rebuilt too.
func TestPolicyOlderClosedSetIsRebuiltFromItsEntry(t *testing.T) {
	r := newRollEnv(t, nil)
	r.startPolicy()
	d1 := r.sendAt(1, 3_000_000, t0.Add(-1000*time.Second))
	st, _, _ := r.authorizeRaw(d1)
	require.Equal(t, 200, st)

	lost := []archive.Kind{archive.KindPolicyBucket, archive.KindPolicyClosed, archive.KindPolicyAllow, archive.KindPolicySuccessor, archive.KindAuthorization}
	for _, k := range lost {
		r.fs.failKind(k, errArchiveDown)
	}
	r.clk.set(t0.Add(1200 * time.Second))
	d2 := r.sendAt(2, 3_000_000, t0.Add(600*time.Second))
	st, _, _ = r.authorizeRaw(d2)
	require.Equal(t, 200, st)
	r.clk.set(t0.Add(1200*time.Second + 2*time.Hour))
	d3 := r.sendAt(3, 1_000_000, t0.Add(600*time.Second+2*time.Hour))
	st, _, _ = r.authorizeRaw(d3)
	require.Equal(t, 200, st)
	_ = r.srv.Shutdown(bg)

	for _, k := range lost {
		r.fs.failKind(k, nil)
	}
	fresh := blockAt(r.nextH, 8)
	fresh.Time = r.clk.Now()
	r.nextH += 10
	r.chain.AddHeader(fresh)
	r.startPolicy()
	eventually(t, func() bool { _, err := r.real.Authorization(bg, d3.hash); return err == nil }, "the Authorization is repaired")

	v3 := r.verdictOf(d3.hash)
	require.NotEqual(t, r.verdictOf(d2.hash).PrevState.ClosedRoot, v3.PrevState.ClosedRoot, "the second allow starts on an older set")
	r.requireHistoryReadable(r.verdictOf(d2.hash))
	r.requireHistoryReadable(v3)
}

func TestPolicyRestartAdoptionRules(t *testing.T) {
	r := newRollEnv(t, func(m *policy.Mandate) { m.Version = 2 })
	r.startPolicy()
	d1 := r.sendAt(1, 1_000_000, t0.Add(-1000*time.Second))
	st, _, _ := r.authorizeRaw(d1)
	require.Equal(t, 200, st)
	require.NoError(t, r.srv.Shutdown(bg))
	n, listens := len(r.fs.puts), r.listens

	refuse := func(name string, mod func(m *policy.Mandate)) {
		m := *r.mandate
		m.Assets = slices.Clone(r.mandate.Assets)
		mod(&m)
		r.file = r.sign(r.principal, &m)
		_, err := edictad.Start(bg, r.cfg(r.edits()...), r.deps)
		require.ErrorIs(t, err, gate.ErrInvalidConfig, name)
		assert.Equal(t, listens, r.listens, "%s: no listener", name)
		assert.Equal(t, n, len(r.fs.puts), "%s: nothing archived", name)
	}
	refuse("lower version", func(m *policy.Mandate) { m.Version = 1 })
	refuse("same version, other rules", func(m *policy.Mandate) {
		m.Assets[0].PerActionMax = policy.AmountFromUint64(4_000_000)
	})
	refuse("scale of a retained asset", func(m *policy.Mandate) { m.Version = 3; m.Assets[0].Scale = 2 })

	// The same mandate starts again and the counter carries on.
	r.file = r.sign(r.principal, r.mandate)
	r.startPolicy()
	d2 := r.sendAt(2, 1_000_000, t0.Add(-900*time.Second))
	st, _, _ = r.authorizeRaw(d2)
	require.Equal(t, 200, st)
	assert.EqualValues(t, 1, r.verdictOf(d2.hash).PrevState.Seq)
	require.NoError(t, r.srv.Shutdown(bg))

	// A higher version carries the counter over, with its new rules.
	m3 := *r.mandate
	m3.Version = 3
	m3.Assets = slices.Clone(r.mandate.Assets)
	m3.Assets[0].PerActionMax = policy.AmountFromUint64(500_000)
	r.file = r.sign(r.principal, &m3)
	r.startPolicy()
	d3 := r.sendAt(3, 1_000_000, t0.Add(-800*time.Second))
	st, _, body := r.authorizeRaw(d3)
	require.Equal(t, 403, st, string(body))
	assert.True(t, hasCode(body, "policy.ErrAmountAboveMax"))
	d4 := r.sendAt(4, 400_000, t0.Add(-700*time.Second))
	st, _, _ = r.authorizeRaw(d4)
	require.Equal(t, 200, st)
	v4 := r.verdictOf(d4.hash)
	assert.EqualValues(t, 2, v4.PrevState.Seq)
	mh := commitment.Hash(v4.MandateHash)
	_, err := r.real.Mandate(bg, mh)
	require.NoError(t, err, "the version in force is archived")
}

// Two agent keys draw on one budget while requests race; every allow is on
// one chain and each has exactly its records.
func TestPolicySharedCounterAcrossAgentKeysUnderConcurrency(t *testing.T) {
	r := newRollEnv(t, nil)
	pub2, prv2, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	writeFile(t, r.path("agents.toml"), []byte(fmt.Sprintf("[[agents]]\nagent_id = \"agent-1\"\npubkey = %q\n\n[[agents]]\nagent_id = \"agent-2\"\npubkey = %q\n",
		hex.EncodeToString(r.agentPub), hex.EncodeToString(pub2))), 0o600)
	keys := [][]byte{bytes.Clone(r.agentPub), bytes.Clone(pub2)}
	slices.SortFunc(keys, bytes.Compare)
	r.mandate.Agents = keys
	r.file = r.sign(r.principal, r.mandate)
	r.startPolicy()

	const n = 20
	decs := make([]decision, n)
	own, ownPub := r.agentPrv, r.agentPub
	for i := range decs {
		if i%2 == 1 {
			r.agentPrv, r.agentPub, r.agentID = prv2, pub2, "agent-2"
		} else {
			r.agentPrv, r.agentPub, r.agentID = own, ownPub, "agent-1"
		}
		tag := byte(i + 1)
		th := t0.Add(-1000 * time.Second)
		if i%4 >= 2 {
			th = t0.Add(-100 * time.Second) // a second anchor time, hour 11
		}
		decs[i] = r.sendAt(tag, 1_000_000, th)
	}
	r.agentPrv, r.agentPub = own, ownPub

	var wg sync.WaitGroup
	var mu sync.Mutex
	var allowed []decision
	var denied int
	for _, d := range decs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			st, err := r.authorizeStatus(d)
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err != nil:
				t.Errorf("request: %v", err)
			case st == 200:
				allowed = append(allowed, d)
			case st == 403:
				denied++
			default:
				t.Errorf("status %d", st)
			}
		}()
	}
	wg.Wait()
	assert.Len(t, allowed, 8, "8M budget, 1M each")
	assert.Equal(t, n-8, denied)
	for _, k := range []archive.Kind{archive.KindPolicyAllow, archive.KindPolicySuccessor, archive.KindAuthorization} {
		assert.Equal(t, 8, r.fs.putCount(k), k.String())
	}
	assert.Equal(t, n-8, r.fs.putCount(archive.KindPolicyDeny))
	assert.NotContains(t, r.logs.String(), "possible fork")

	next := map[string]*policy.Verdict{}
	agents := map[string]bool{}
	for _, d := range allowed {
		v := r.verdictOf(d.hash)
		h, ok := v.PrevStateHash()
		require.True(t, ok)
		_, dup := next[string(h[:])]
		require.False(t, dup, "a fork in the archive")
		next[string(h[:])] = v
		agents[string(v.AgentPubKey)] = true
		r.requireHistoryReadable(v)
	}
	assert.Len(t, agents, 2, "both keys were served")
	g := policy.GenesisLedger()
	cur, err := policy.HashState(&g.State)
	require.NoError(t, err)
	for i := 0; i < 8; i++ {
		v, ok := next[string(cur[:])]
		require.True(t, ok, "chain broken at %d", i)
		copy(cur[:], v.NewStateHash)
	}
}
