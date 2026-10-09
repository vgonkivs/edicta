package gate_test

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/sha256"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/gate"
	"github.com/vgonkivs/edicta/policy"
	"github.com/vgonkivs/edicta/policy/privatebox"
	"github.com/vgonkivs/edicta/test/gatefix"
)

var auditorKey = func() *ecdh.PrivateKey {
	s := sha256.Sum256([]byte("gate private test auditor"))
	k, err := ecdh.X25519().NewPrivateKey(s[:])
	if err != nil {
		return nil
	}
	return k
}()

func privateMandate(t *testing.T) *policy.Mandate {
	require.NotNil(t, auditorKey)
	m := baseMandate(t)
	pub := auditorKey.PublicKey().Bytes()
	m.Auditors = []policy.Auditor{{Kid: policy.AuditorKid(pub), Pubkey: pub, Label: "Alice"}}
	m.StateSalt = bytes.Repeat([]byte{0x5a}, 32)
	return m
}

func opener(t *testing.T) *privatebox.Opener {
	o, err := privatebox.NewOpener(auditorKey)
	require.NoError(t, err)
	return o
}

// sealingArchiver keeps the decision records and reveals it was given.
type sealingArchiver struct {
	mu      sync.Mutex
	recs    []gate.DecisionRecord
	reveals []gate.RevealRecord
}

func (a *sealingArchiver) Put(_ context.Context, r gate.DecisionRecord) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.recs = append(a.recs, r)
	return nil
}

func (a *sealingArchiver) PutReveal(_ context.Context, r gate.RevealRecord) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.reveals = append(a.reveals, r)
	return nil
}

func (p *pEnv) open(priv *policy.Verdict, part []byte) *policy.Verdict {
	pp, err := policy.DecodePrivatePart(part)
	require.NoError(p.t, err)
	m, err := policy.MergeVerdict(priv, pp)
	require.NoError(p.t, err)
	return m
}

func TestPrivateAllowsSignThePrivateForm(t *testing.T) {
	m := privateMandate(t)
	p := newPolicyEnv(t, m)
	h := policy.NewStateHasher(m)

	_, b1, a1 := p.request(1, "agent1", 40)
	r1, err := p.AuthorizeWith(b1, a1)
	require.NoError(t, err)
	v1, vh1 := p.verdict(r1.PolicyVerdict)
	require.True(t, v1.Verdict.Private())
	assert.Nil(t, v1.Verdict.PrevState, "no key 13 in private form")
	assert.Zero(t, v1.Verdict.DecidedAt)
	g := policy.GenesisStateHash()
	assert.Equal(t, g[:], v1.Verdict.BlindPrevStateHash, "genesis keeps the public hash")
	require.NotEmpty(t, r1.PrivatePart)
	m1 := p.open(&v1.Verdict, r1.PrivatePart)
	assert.EqualValues(t, 0, m1.PrevState.Seq)

	c2, b2, a2 := p.request(2, "agent2", 50)
	r2, err := p.AuthorizeWith(b2, a2)
	require.NoError(t, err)
	v2, _ := p.verdict(r2.PolicyVerdict)
	m2 := p.open(&v2.Verdict, r2.PrivatePart)
	blind, err := h.StateHash(m2.PrevState)
	require.NoError(t, err)
	public, err := policy.HashState(m2.PrevState)
	require.NoError(t, err)
	assert.Equal(t, blind[:], v2.Verdict.BlindPrevStateHash, "key 20 is the blinded hash of the state read")
	assert.NotEqual(t, public[:], v2.Verdict.BlindPrevStateHash)
	assert.Equal(t, v1.Verdict.NewStateHash, v2.Verdict.BlindPrevStateHash, "the chain links by blinded hashes")
	assert.Equal(t, vh1[:], v2.Verdict.PrevVerdictHash)

	ent, err := p.Entry(c2)
	require.NoError(t, err)
	assert.Equal(t, r2.PrivatePart, ent.PrivatePart, "the registry keeps the clear PrivatePart")
	assert.Equal(t, r2.PolicyVerdict, ent.Verdict)

	// A stored retry answers with the stored private-form verdict.
	again, err := p.AuthorizeWith(b2, a2)
	require.ErrorIs(t, err, gate.ErrNonceUsed)
	assert.Equal(t, r2.PolicyVerdict, again.PolicyVerdict)
}

func TestPrivateDeniesShowNoReason(t *testing.T) {
	p := newPolicyEnv(t, privateMandate(t))
	c, b, a := p.request(1, "agent1", 70) // above the per-action maximum
	res, err := p.AuthorizeWith(b, a)
	require.ErrorIs(t, err, policy.ErrAmountAboveMax, "the caller still learns the reason")
	sv, _ := p.verdict(res.PolicyVerdict)
	v := &sv.Verdict
	require.True(t, v.Private())
	assert.Empty(t, v.Reason)
	assert.Nil(t, v.Facts)
	assert.Nil(t, v.NewStateHash)
	assert.Nil(t, v.BlindPrevStateHash)
	merged := p.open(v, res.PrivatePart)
	assert.Equal(t, "ErrAmountAboveMax", merged.Reason)
	p.RequireUntouched(c)

	// The same deny again has the same content and a fresh salt.
	res2, err := p.AuthorizeWith(b, a)
	require.ErrorIs(t, err, policy.ErrAmountAboveMax)
	sv2, _ := p.verdict(res2.PolicyVerdict)
	assert.NotEqual(t, v.PrivateHash, sv2.Verdict.PrivateHash)

	// A stateful deny keeps its state read in the PrivatePart only.
	_, b1, a1 := p.request(2, "agent1", 60)
	_, err = p.AuthorizeWith(b1, a1)
	require.NoError(t, err)
	_, b3, a3 := p.request(3, "agent1", 50)
	res3, err := p.AuthorizeWith(b3, a3)
	require.ErrorIs(t, err, policy.ErrPeriodLimit)
	sv3, _ := p.verdict(res3.PolicyVerdict)
	assert.Nil(t, sv3.Verdict.BlindPrevStateHash)
	m3 := p.open(&sv3.Verdict, res3.PrivatePart)
	require.NotNil(t, m3.PrevState)
	assert.EqualValues(t, 1, m3.PrevState.Seq)
}

func TestPrivateDecisionRecordIsSealed(t *testing.T) {
	arch := &sealingArchiver{}
	p := newPolicyEnv(t, privateMandate(t), gatefix.WithDeps(func(d *gate.Deps) { d.Archiver = arch }))
	c, b, a := p.request(1, "agent1", 70)
	_, err := p.AuthorizeWith(b, a)
	require.ErrorIs(t, err, policy.ErrAmountAboveMax)
	_, b2, a2 := p.request(2, "agent1", 10)
	_, err = p.AuthorizeWith(b2, a2)
	require.NoError(t, err)

	require.Len(t, arch.recs, 2, "a denied decision is archived too")
	for i, r := range arch.recs {
		require.True(t, r.Private())
		assert.Nil(t, r.Action, "never the action in clear")
		assert.Nil(t, r.ActionSalt, "never the salt in clear")
		pt, _, err := opener(t).Open(policy.PrivateAction, r.PrivateAction)
		require.NoError(t, err)
		assert.Equal(t, append(bytes.Clone(gatefix.Salt(t)), [][]byte{a, a2}[i]...), pt, "salt || action bytes")
		ah, err := policy.PlaintextHash(policy.PrivateAction, pt, c.Action.Type)
		require.NoError(t, err)
		assert.Equal(t, r.ActionHash, ah, "record %d is keyed by the salted action hash", i)
	}
}

func TestPrivateActionSealFailureSignsNothing(t *testing.T) {
	p := newPolicyEnv(t, privateMandate(t), gatefix.WithDeps(func(d *gate.Deps) {
		d.Archiver = &sealingArchiver{}
		d.Sealer = failingSealer{}
	}))
	c, b, a := p.request(1, "agent1", 10)
	res, err := p.AuthorizeWith(b, a)
	require.ErrorIs(t, err, gate.ErrArchiveUnavailable)
	assert.Empty(t, res.Authorization)
	assert.Empty(t, res.PolicyVerdict)
	p.RequireUntouched(c)
}

type failingSealer struct{}

func (failingSealer) Seal(policy.PrivateKind, []byte, []policy.Auditor) ([]byte, error) {
	return nil, assert.AnError
}

func TestPrivateMandateAdoptionKeepsTheSalt(t *testing.T) {
	m := privateMandate(t)
	p := newPolicyEnv(t, m)
	assert.Equal(t, m.StateSalt, p.counter().StateSalt)

	next := privateMandate(t)
	next.Version = 2
	next.StateSalt = bytes.Repeat([]byte{0x6b}, 32)
	p.Cfg.Mandate = signedMandate(t, next)
	require.ErrorIs(t, p.Restart(), gate.ErrInvalidConfig)
	require.ErrorIs(t, p.Restart(), policy.ErrStateSaltChanged)

	public := baseMandate(t)
	public.Version = 2
	p.Cfg.Mandate = signedMandate(t, public)
	require.ErrorIs(t, p.Restart(), policy.ErrStateSaltChanged, "a counter never switches mode")

	next.StateSalt = m.StateSalt
	p.Cfg.Mandate = signedMandate(t, next)
	require.NoError(t, p.Restart())
	assert.EqualValues(t, 2, p.counter().Version)
}

func TestRevealOnExecution(t *testing.T) {
	for _, tc := range []struct {
		name    string
		private bool
		reveal  bool
		want    int
	}{
		{"private and configured", true, true, 1},
		{"private, not configured", true, false, 0},
		{"public, configured", false, true, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			arch := &sealingArchiver{}
			m := baseMandate(t)
			if tc.private {
				m = privateMandate(t)
			}
			p := newPolicyEnv(t, m, gatefix.WithDeps(func(d *gate.Deps) {
				d.Archiver = arch
				d.Profiles = gate.ProfileSet{gatefix.ActionType: true}
			}), gatefix.WithConfig(func(c *gate.Config) {
				if tc.reveal {
					c.RevealOnExecution = []string{gatefix.ActionType}
				}
			}))
			_, b, a := p.request(1, "agent1", 10)
			_, err := p.AuthorizeWith(b, a)
			require.NoError(t, err)
			r, err := p.Record(b, "tx-1")
			require.NoError(t, err)
			require.Len(t, arch.reveals, tc.want)
			if tc.want == 1 {
				assert.Equal(t, r, arch.reveals[0].Receipt)
				assert.Len(t, arch.reveals[0].ActionSalt, commitment.ActionSaltSize)
			}
			// A second receipt request repairs a lost reveal.
			_, err = p.Record(b, "tx-1")
			require.ErrorIs(t, err, gate.ErrReceiptExists)
			assert.Len(t, arch.reveals, 2*tc.want)
		})
	}
}
