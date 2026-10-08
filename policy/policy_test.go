package policy_test

import (
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/policy"
)

type fakeX struct {
	id, typ string
	fn      func([]byte) (policy.Facts, error)
}

func (x fakeX) ID() string                             { return x.id }
func (x fakeX) ActionType() string                     { return x.typ }
func (x fakeX) Extract(a []byte) (policy.Facts, error) { return x.fn(a) }

func testMandate(t *testing.T) (*policy.Mandate, ed25519.PrivateKey) {
	pseed := sha256.Sum256([]byte("p"))
	aseed := sha256.Sum256([]byte("a"))
	p := ed25519.NewKeyFromSeed(pseed[:])
	a := ed25519.NewKeyFromSeed(aseed[:])
	return &policy.Mandate{
		Format: 1, Principal: p.Public().(ed25519.PublicKey), GateID: "g", Agents: [][]byte{a.Public().(ed25519.PublicKey)},
		NotBefore: 1, NotAfter: 1 << 35, MandateID: make([]byte, 16), Version: 1,
		Assets: []policy.AssetRule{{Asset: "x:a", Scale: 0, PerActionMax: []byte{10}, Periods: []policy.PeriodLimit{{Hours: 1, Max: []byte{15}}}}},
	}, a
}

func TestExtractorRegistry(t *testing.T) {
	ok := fakeX{id: "t/ok/v1", typ: "a", fn: func([]byte) (policy.Facts, error) {
		return policy.Facts{Kind: "transfer", Asset: "x:a", Amount: []byte{1}}, nil
	}}
	_, err := policy.NewExtractors(ok, ok)
	require.Error(t, err)
	boom := fakeX{id: "t/boom/v1", typ: "b", fn: func([]byte) (policy.Facts, error) { panic("x") }}
	fail := fakeX{id: "t/fail/v1", typ: "c", fn: func([]byte) (policy.Facts, error) { return policy.Facts{}, errors.New("no") }}
	invalid := fakeX{id: "t/inv/v1", typ: "d", fn: func([]byte) (policy.Facts, error) { return policy.Facts{}, nil }}
	r, err := policy.NewExtractors(ok, boom, fail, invalid)
	require.NoError(t, err)
	_, _, err = r.Extract("zz", nil)
	require.ErrorIs(t, err, policy.ErrNoExtractor)
	for _, typ := range []string{"b", "c", "d"} {
		id, _, err := r.Extract(typ, nil)
		require.ErrorIs(t, err, policy.ErrFactsInvalid)
		require.NotEmpty(t, id)
	}
	_, f, err := r.Extract("a", nil)
	require.NoError(t, err)
	require.Equal(t, "x:a", f.Asset)
}

func TestAdmitDenies(t *testing.T) {
	m, agent := testMandate(t)
	amount := byte(5)
	rec := ""
	x, err := policy.NewExtractors(fakeX{id: "t/ok/v1", typ: "a", fn: func([]byte) (policy.Facts, error) {
		return policy.Facts{Kind: "transfer", Asset: "x:a", Amount: []byte{amount}, Recipient: rec}, nil
	}})
	require.NoError(t, err)
	d := policy.Decision{AgentPubKey: agent.Public().(ed25519.PublicKey), ActionType: "a", ValidUntil: 100}
	_, err = policy.Admit(m, x, d)
	require.NoError(t, err)

	other := d
	other.AgentPubKey = make([]byte, 32)
	_, err = policy.Admit(m, x, other)
	require.ErrorIs(t, err, policy.ErrAgentNotCovered)
	other = d
	other.ActionType = "zz"
	_, err = policy.Admit(m, x, other)
	require.ErrorIs(t, err, policy.ErrNoExtractor)
	other = d
	other.ValidUntil = m.NotAfter + 1
	_, err = policy.Admit(m, x, other)
	require.ErrorIs(t, err, policy.ErrOutsideMandate)
	amount = 11
	_, err = policy.Admit(m, x, d)
	require.ErrorIs(t, err, policy.ErrAmountAboveMax)
	require.ErrorIs(t, err, policy.ErrDenied)
	amount = 5
	m.Kinds = []string{"swap"}
	_, err = policy.Admit(m, x, d)
	require.ErrorIs(t, err, policy.ErrKindNotAllowed)
	m.Kinds = nil
	m.Assets[0].Recipients = []string{"bob"}
	_, err = policy.Admit(m, x, d)
	require.ErrorIs(t, err, policy.ErrRecipientNotAllowed)
	rec = "bob"
	_, err = policy.Admit(m, x, d)
	require.NoError(t, err)
	m.Assets[0].Scale = 2
	_, err = policy.Admit(m, x, d)
	require.ErrorIs(t, err, policy.ErrAssetNotAllowed)
}

func TestSharedCounterAndCounterCell(t *testing.T) {
	m, _ := testMandate(t)
	f := policy.Facts{Kind: "transfer", Asset: "x:a", Amount: []byte{10}}
	l := policy.GenesisLedger()
	a := policy.Admission{Facts: f, Asset: 0}
	s1, err := policy.Evaluate(m, l, a, 7200)
	require.NoError(t, err)
	f.Amount = []byte{6}
	_, err = policy.Evaluate(m, s1.Next, policy.Admission{Facts: f}, 7201)
	require.ErrorIs(t, err, policy.ErrPeriodLimit)
	f.Amount = []byte{5}
	s2, err := policy.Evaluate(m, s1.Next, policy.Admission{Facts: f}, 7201)
	require.NoError(t, err)

	canon, err := policy.EncodeMandate(m)
	require.NoError(t, err)
	c := policy.NewCounter(m, policy.HashMandate(canon))
	c.Ledger = s2.Next
	c.HeadCommitment, c.HeadVerdict = make([]byte, 32), make([]byte, 32)
	enc, err := policy.EncodeCounter(c)
	require.NoError(t, err)
	back, err := policy.DecodeCounter(enc)
	require.NoError(t, err)
	require.Equal(t, c.Ledger.State, back.Ledger.State)
	require.NoError(t, policy.CheckScales(m, back.Ledger))
	m.Assets[0].Scale = 3
	require.ErrorIs(t, policy.CheckScales(m, back.Ledger), policy.ErrScaleChanged)
}
