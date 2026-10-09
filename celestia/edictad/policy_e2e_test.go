package edictad_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/archive/fsarchive"
	"github.com/vgonkivs/edicta/celestia/edictad"
	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/examples/tia-transfer/bankaction"
	"github.com/vgonkivs/edicta/examples/tia-transfer/bankmsg"
	"github.com/vgonkivs/edicta/policy"
)

const (
	policyChainID = "test-1"
	policyAsset   = "cosmos:test-1/utia"
)

// policyEnv is archiveEnv with a signed mandate for the agent of the env and a
// config that serves bank sends.
type policyEnv struct {
	*env
	fs        *faultStore
	real      *fsarchive.Store
	base      *commitment.Commitment
	principal ed25519.PrivateKey
	mandate   *policy.Mandate
	file      string
}

func newPolicyEnv(t *testing.T) *policyEnv {
	t.Helper()
	e, fs, real, base := archiveEnv(t)
	_, prv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	p := &policyEnv{env: e, fs: fs, real: real, base: base, principal: prv}
	p.mandate = &policy.Mandate{
		Format: 1, Principal: prv.Public().(ed25519.PublicKey), GateID: "gate-test-1",
		Agents:    [][]byte{bytes.Clone(e.agentPub)},
		NotBefore: uint64(t0.Unix()) - 86400, NotAfter: uint64(t0.Unix()) + 86400,
		MandateID: bytes.Repeat([]byte{3}, 16), Version: 1,
		Assets: []policy.AssetRule{{Asset: policyAsset, Scale: 6, PerActionMax: policy.AmountFromUint64(5_000_000)}},
	}
	p.file = p.sign(prv, p.mandate)
	return p
}

// sign writes the signed mandate to a file of the env and returns its path.
func (p *policyEnv) sign(prv ed25519.PrivateKey, m *policy.Mandate) string {
	p.t.Helper()
	b, mh, err := policy.SignMandate(prv, m)
	require.NoError(p.t, err)
	// Later decisions name the mandate last signed: a gate with a mandate
	// admits only v1 commitments that name the one in force.
	base := *p.base
	base.Version, base.MandateRef = commitment.VersionV1, bytes.Clone(mh[:])
	p.base = &base
	path := p.path("mandate.cbor")
	writeFile(p.t, path, b, 0o600)
	return path
}

func (p *policyEnv) edits(extra ...[2]string) [][2]string {
	return append([][2]string{
		rep(`action_types = ["application/vnd.edicta.test.v0+cbor"]`, `action_types = ["`+bankaction.ActionType+`"]`),
		rep("[http]", "[policy]\nmandate_file = \""+p.file+"\"\n\n[http]"),
	}, extra...)
}

func (p *policyEnv) startPolicy(extra ...[2]string) {
	p.t.Helper()
	p.start(p.edits(extra...)...)
}

// send is a signed decision committing to a bank send of amount utia.
func (p *policyEnv) send(tag byte, amount uint64) decision {
	p.t.Helper()
	to, err := bankmsg.EncodeAddress("celestia", bytes.Repeat([]byte{2}, 20))
	require.NoError(p.t, err)
	from, err := bankmsg.EncodeAddress("celestia", bytes.Repeat([]byte{1}, 20))
	require.NoError(p.t, err)
	msg, err := bankmsg.Encode(bankmsg.MsgSend{From: from, To: to, Denom: "utia", Amount: amount}, "celestia")
	require.NoError(p.t, err)
	action, err := bankaction.Encode(bankaction.Action{ChainID: policyChainID, Msg: msg})
	require.NoError(p.t, err)
	return p.decisionAct(p.base, tag, action, func(c *commitment.Commitment) {
		h, err := commitment.ActionHash(bankaction.ActionType, action)
		require.NoError(p.t, err)
		c.Action.Type, c.Action.Hash = bankaction.ActionType, h[:]
	})
}

func kindsOf(puts []archive.Kind, from int) []archive.Kind { return puts[from:] }

func TestPolicyAllowWritesTheRecordsInOrder(t *testing.T) {
	p := newPolicyEnv(t)
	p.startPolicy()
	assert.Equal(t, []archive.Kind{archive.KindMandate, archive.KindPolicyClosed}, p.fs.puts,
		"the mandate and the genesis closed set precede the listener")
	n := len(p.fs.puts)

	d := p.send(1, 1_000_000)
	st, _, _ := p.authorizeRaw(d)
	require.Equal(t, 200, st)
	assert.Equal(t, []archive.Kind{archive.KindDecision, archive.KindPolicyAllow, archive.KindPolicySuccessor, archive.KindAuthorization},
		kindsOf(p.fs.puts, n), "policy records come before the Authorization record")

	allow, err := p.real.PolicyAllow(bg, d.hash)
	require.NoError(t, err)
	sv, _, err := policy.VerifyVerdict(allow.SignedVerdict, p.gatePub)
	require.NoError(t, err)
	assert.Equal(t, uint64(policy.OutcomeAllow), sv.Verdict.Outcome)
	assert.Equal(t, "celestia/tia-transfer/v1", sv.Verdict.Extractor)
	_, err = p.real.Authorization(bg, d.hash)
	require.NoError(t, err)
	_, err = p.real.Mandate(bg, commitment.Hash(sv.Verdict.MandateHash))
	require.NoError(t, err)
}

func TestPolicyDenyWritesTheVerdictThenTheMarker(t *testing.T) {
	p := newPolicyEnv(t)
	p.startPolicy()
	n := len(p.fs.puts)

	d := p.send(1, 6_000_000)
	st, _, body := p.authorizeRaw(d)
	require.GreaterOrEqual(t, st, 400)
	assert.True(t, hasCode(body, "policy.ErrAmountAboveMax"), "body %q", body)
	assert.Equal(t, []archive.Kind{archive.KindDecision, archive.KindPolicyDeny, archive.KindRejection}, kindsOf(p.fs.puts, n))

	deny, err := p.real.PolicyDeny(bg, d.hash, "ErrAmountAboveMax")
	require.NoError(t, err)
	sv, _, err := policy.VerifyVerdict(deny.SignedVerdict, p.gatePub)
	require.NoError(t, err)
	assert.Equal(t, uint64(policy.OutcomeDeny), sv.Verdict.Outcome)
	_, err = p.real.Rejection(bg, d.hash, "ErrAmountAboveMax")
	require.NoError(t, err)
	_, err = p.real.Authorization(bg, d.hash)
	require.ErrorIs(t, err, archive.ErrNotFound)
}

func TestPolicyRestartReadoptsTheMandate(t *testing.T) {
	p := newPolicyEnv(t)
	p.startPolicy()
	d1 := p.send(1, 1_000_000)
	st, _, _ := p.authorizeRaw(d1)
	require.Equal(t, 200, st)
	require.NoError(t, p.srv.Shutdown(bg))

	p.startPolicy()
	d2 := p.send(2, 1_000_000)
	st, _, _ = p.authorizeRaw(d2)
	require.Equal(t, 200, st)

	a2, err := p.real.PolicyAllow(bg, d2.hash)
	require.NoError(t, err)
	sv, _, err := policy.VerifyVerdict(a2.SignedVerdict, p.gatePub)
	require.NoError(t, err)
	assert.EqualValues(t, 1, sv.Verdict.PrevState.Seq, "the counter continues across the restart")
	assert.Contains(t, p.logs.String(), "mandate in force")
}

func TestPolicyKeyOverlapIsRefused(t *testing.T) {
	cases := map[string]func(p *policyEnv) ed25519.PrivateKey{
		"principal is the gate key": func(p *policyEnv) ed25519.PrivateKey { return ed25519.NewKeyFromSeed(p.seed) },
		"principal is an allowlisted agent key": func(p *policyEnv) ed25519.PrivateKey {
			return p.agentPrv
		},
	}
	for name, key := range cases {
		t.Run(name, func(t *testing.T) {
			p := newPolicyEnv(t)
			prv := key(p)
			_, other, err := ed25519.GenerateKey(rand.Reader)
			require.NoError(t, err)
			p.mandate.Principal = prv.Public().(ed25519.PublicKey)
			p.mandate.Agents = [][]byte{other.Public().(ed25519.PublicKey)}
			p.file = p.sign(prv, p.mandate)

			_, err = edictad.Start(bg, p.cfg(p.edits()...), p.deps)
			require.ErrorIs(t, err, commitment.ErrKeyRole)
			assert.Zero(t, p.listens, "no listener is bound")
			assert.Empty(t, p.fs.puts, "nothing is archived")
		})
	}
}

func TestPolicyMandateNeedsAnArchive(t *testing.T) {
	p := newPolicyEnv(t)
	toml := p.tomlOf(p.edits(rep(`dir = "`+p.path("archive")+`"`, `dir = ""`))...)
	_, err := edictad.ParseConfig([]byte(toml))
	require.ErrorIs(t, err, edictad.ErrConfig)
	assert.Contains(t, err.Error(), "policy.mandate_file")
}

func TestPolicyMandateForAnotherGateIsRefused(t *testing.T) {
	p := newPolicyEnv(t)
	p.mandate.GateID = "other-gate"
	p.file = p.sign(p.principal, p.mandate)
	_, err := edictad.Start(bg, p.cfg(p.edits()...), p.deps)
	require.Error(t, err)
	assert.Zero(t, p.listens)
}

func TestPolicyActionTypeWithoutExtractorIsRefused(t *testing.T) {
	p := newPolicyEnv(t)
	_, err := edictad.Start(bg, p.cfg(rep("[http]", "[policy]\nmandate_file = \""+p.file+"\"\n\n[http]")), p.deps)
	require.ErrorIs(t, err, edictad.ErrConfig)
	assert.Zero(t, p.listens)
}

func TestPolicyUnreadableOrUnsignedMandateIsRefused(t *testing.T) {
	p := newPolicyEnv(t)
	b, err := os.ReadFile(p.file)
	require.NoError(t, err)
	b[len(b)-1] ^= 1
	writeFile(t, p.file, b, 0o600)
	_, err = edictad.Start(bg, p.cfg(p.edits()...), p.deps)
	require.Error(t, err)
	assert.Zero(t, p.listens)
}

func TestPolicyMandateWriteFailureRefusesTheStart(t *testing.T) {
	p := newPolicyEnv(t)
	p.fs.failKind(archive.KindMandate, errArchiveDown)
	_, err := edictad.Start(bg, p.cfg(p.edits()...), p.deps)
	require.ErrorIs(t, err, errArchiveDown)
	assert.Zero(t, p.listens, "the listener is bound after the mandate is durable")

	p.fs.failKind(archive.KindMandate, nil)
	p.fs.failKind(archive.KindPolicyClosed, errArchiveDown)
	_, err = edictad.Start(bg, p.cfg(p.edits()...), p.deps)
	require.ErrorIs(t, err, errArchiveDown)
	assert.Zero(t, p.listens)
}

// A policy record that fails is retried before anything behind it is written.
func TestPolicyFailedRecordHoldsBackTheAuthorizationUntilRepaired(t *testing.T) {
	p := newPolicyEnv(t)
	tick := make(chan time.Time)
	p.deps.SweepTick = tick
	p.startPolicy()
	n := len(p.fs.puts)

	p.fs.failKind(archive.KindPolicyAllow, errArchiveDown)
	d := p.send(1, 1_000_000)
	st, _, _ := p.authorizeRaw(d)
	require.Equal(t, 200, st, "a failed archive write does not change the answer")
	assert.Equal(t, []archive.Kind{archive.KindDecision, archive.KindPolicyAllow}, kindsOf(p.fs.puts, n),
		"nothing is written behind the failed record")

	tick <- t0
	tick <- t0
	_, err := p.real.Authorization(bg, d.hash)
	require.ErrorIs(t, err, archive.ErrNotFound)

	p.fs.failKind(archive.KindPolicyAllow, nil)
	tick <- t0
	eventually(t, func() bool { _, err := p.real.Authorization(bg, d.hash); return err == nil }, "the chain is repaired")
	_, err = p.real.PolicyAllow(bg, d.hash)
	require.NoError(t, err)

	kinds := kindsOf(p.fs.puts, n)
	last := kinds[len(kinds)-3:]
	assert.Equal(t, []archive.Kind{archive.KindPolicyAllow, archive.KindPolicySuccessor, archive.KindAuthorization}, last)
}
