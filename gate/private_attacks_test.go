package gate_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"slices"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/gate"
	"github.com/vgonkivs/edicta/policy"
	"github.com/vgonkivs/edicta/test/gatefix"
)

// verdictKeys returns the sorted top-level keys of the verdict inside a
// SignedPolicyVerdict, read from the bytes as signed.
func verdictKeys(t *testing.T, signed []byte) []uint64 {
	t.Helper()
	var outer map[uint64]cbor.RawMessage
	require.NoError(t, cbor.Unmarshal(signed, &outer))
	var v map[uint64]cbor.RawMessage
	require.NoError(t, cbor.Unmarshal(outer[1], &v))
	var keys []uint64
	for k := range v {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

func keyRange(from, to uint64, extra ...uint64) []uint64 {
	var out []uint64
	for k := from; k <= to; k++ {
		out = append(out, k)
	}
	out = append(out, extra...)
	slices.Sort(out)
	return out
}

// TestPrivateVerdictPublishesOnlyTheAllowedKeys reads the signed bytes of
// every outcome a private gate can sign: an allow publishes hashes and links
// only, and every deny, whatever its reason or stage, has the same key set
// and the same size, so a reader without the key learns the bit and nothing
// else.
func TestPrivateVerdictPublishesOnlyTheAllowedKeys(t *testing.T) {
	m := privateMandate(t)
	m.MinSpacing = 1000
	m.Agents = [][]byte{gatefix.Pub(t, "agent1")}
	p := newPolicyEnv(t, m)

	_, b, a := p.request(1, "agent1", 40)
	r1, err := p.AuthorizeWith(b, a)
	require.NoError(t, err)
	assert.Equal(t, keyRange(1, 7, 14, 19, 20), verdictKeys(t, r1.PolicyVerdict), "genesis allow: no links")

	denies := map[string]struct {
		agent  string
		amount byte
		want   error
	}{
		"amount above the per-action max": {"agent1", 70, policy.ErrAmountAboveMax},
		"min spacing (stateful)":          {"agent1", 10, policy.ErrMinSpacing},
		"agent not covered":               {"agent2", 10, policy.ErrAgentNotCovered},
		"extractor refuses the bytes":     {"agent1", 255, nil},
	}
	sizes := map[int][]string{}
	tag := byte(10)
	for name, d := range denies {
		tag++
		_, b, a := p.request(tag, d.agent, d.amount)
		res, err := p.AuthorizeWith(b, a)
		require.Error(t, err, name)
		if d.want != nil {
			require.ErrorIs(t, err, d.want, name)
		}
		require.NotEmpty(t, res.PolicyVerdict, name)
		assert.Equal(t, keyRange(1, 7, 19), verdictKeys(t, res.PolicyVerdict), "%s: keys 1 to 7 and 19 only", name)
		sizes[len(res.PolicyVerdict)] = append(sizes[len(res.PolicyVerdict)], name)
		sv, _ := p.verdict(res.PolicyVerdict)
		merged := p.open(&sv.Verdict, res.PrivatePart)
		assert.NotEmpty(t, merged.Reason, "%s: the reason is in the PrivatePart", name)
	}
	assert.Len(t, sizes, 1, "every private deny has one public size: %v", sizes)

	// A later allow carries the chain links, still no state, facts or times.
	p2 := newPolicyEnv(t, privateMandate(t))
	_, b, a = p2.request(1, "agent1", 10)
	_, err = p2.AuthorizeWith(b, a)
	require.NoError(t, err)
	_, b, a = p2.request(2, "agent1", 10)
	r2, err := p2.AuthorizeWith(b, a)
	require.NoError(t, err)
	assert.Equal(t, keyRange(1, 7, 14, 15, 16, 19, 20), verdictKeys(t, r2.PolicyVerdict))
}

// TestPrivateStateSaltNeverLeavesTheGate looks for the counter's state_salt
// in everything a private gate hands out or archives.
func TestPrivateStateSaltNeverLeavesTheGate(t *testing.T) {
	m := privateMandate(t)
	arch := &sealingArchiver{}
	p := newPolicyEnv(t, m, gatefix.WithDeps(func(d *gate.Deps) {
		d.Archiver = arch
		d.Profiles = gate.ProfileSet{gatefix.ActionType: true}
	}), gatefix.WithConfig(func(c *gate.Config) { c.RevealOnExecution = []string{gatefix.ActionType} }))

	var out [][]byte
	keep := func(res gate.Result) {
		out = append(out, res.Authorization, res.PolicyVerdict, res.PrivatePart, res.ClosedBucket, res.ClosedSet)
	}
	_, b, a := p.request(1, "agent1", 40)
	res, err := p.AuthorizeWith(b, a)
	require.NoError(t, err)
	keep(res)
	rcpt, err := p.Record(b, "tx-1")
	require.NoError(t, err)
	out = append(out, rcpt)
	_, b, a = p.request(2, "agent1", 70)
	res, err = p.AuthorizeWith(b, a)
	require.ErrorIs(t, err, policy.ErrAmountAboveMax)
	keep(res)
	for _, r := range arch.recs {
		out = append(out, r.Envelope, r.Action, r.ActionSalt, r.PrivateAction)
	}
	require.Len(t, arch.reveals, 1)
	out = append(out, arch.reveals[0].Receipt, arch.reveals[0].ActionSalt)

	for i, b := range out {
		assert.False(t, bytes.Contains(b, m.StateSalt), "output %d carries the state_salt", i)
	}
	assert.Equal(t, m.StateSalt, p.counter().StateSalt, "only the gate-local cell holds it")
}

// TestPrivateAdoptionRefusesASwitchToPrivate is the other direction of a
// mode switch on one counter: a public counter never becomes private.
func TestPrivateAdoptionRefusesASwitchToPrivate(t *testing.T) {
	p := newPolicyEnv(t, baseMandate(t))
	_, b, a := p.request(1, "agent1", 10)
	_, err := p.AuthorizeWith(b, a)
	require.NoError(t, err)

	next := privateMandate(t)
	next.Version = 2
	p.Cfg.Mandate = signedMandate(t, next)
	err = p.Restart()
	require.ErrorIs(t, err, gate.ErrInvalidConfig)
	require.ErrorIs(t, err, policy.ErrStateSaltChanged)
	assert.Empty(t, p.counter().StateSalt)
}

// TestPrivateMandateWithAForeignKidIsRefused feeds the gate a signed
// mandate whose auditor kid is not derived from the auditor's key.
func TestPrivateMandateWithAForeignKidIsRefused(t *testing.T) {
	raw, err := os.ReadFile("../spec/vectors/policy/mandate.json")
	require.NoError(t, err)
	var f struct {
		Reject []struct {
			ID     string `json:"id"`
			Signed string `json:"signed_mandate_hex"`
		} `json:"reject"`
	}
	require.NoError(t, json.Unmarshal(raw, &f))
	var signed []byte
	for _, r := range f.Reject {
		if r.ID == "auditor_kid_mismatch" {
			signed, err = hex.DecodeString(r.Signed)
			require.NoError(t, err)
		}
	}
	require.NotEmpty(t, signed)
	opts := policyOpts(t, baseMandate(t), gatefix.WithConfig(func(c *gate.Config) { c.Mandate = signed }))
	_, err = gatefix.TryNew(t, opts...)
	require.ErrorIs(t, err, gate.ErrInvalidConfig)
	// The config check formats the mandate error with %v, so only its text
	// survives.
	require.ErrorContains(t, err, policy.ErrAuditorKidMismatch.Error())

	// A producer cannot sign one either.
	m := privateMandate(t)
	m.Auditors[0].Kid = bytes.Repeat([]byte{1}, len(m.Auditors[0].Kid))
	_, _, err = policy.SignMandate(principalKey, m)
	require.ErrorIs(t, err, policy.ErrAuditorKidMismatch)
}

// TestRevealOnlyForAnExecutedAllow: no kind 18 for a denied decision, for an
// allowed one without a receipt, or for a type without a public-execution
// profile.
func TestRevealOnlyForAnExecutedAllow(t *testing.T) {
	arch := &sealingArchiver{}
	p := newPolicyEnv(t, privateMandate(t), gatefix.WithDeps(func(d *gate.Deps) {
		d.Archiver = arch
		d.Profiles = gate.ProfileSet{gatefix.ActionType: true}
	}), gatefix.WithConfig(func(c *gate.Config) { c.RevealOnExecution = []string{gatefix.ActionType} }))

	_, denied, a := p.request(1, "agent1", 70)
	_, err := p.AuthorizeWith(denied, a)
	require.ErrorIs(t, err, policy.ErrAmountAboveMax)
	_, err = p.Record(denied, "tx-denied")
	require.ErrorIs(t, err, gate.ErrNotAuthorized)

	_, unexecuted, a := p.request(2, "agent1", 10)
	_, err = p.AuthorizeWith(unexecuted, a)
	require.NoError(t, err)
	assert.Empty(t, arch.reveals, "no reveal before a receipt or after a deny")

	_, err = gatefix.TryNew(t, policyOpts(t, privateMandate(t),
		gatefix.WithDeps(func(d *gate.Deps) { d.Profiles = gate.ProfileSet{gatefix.ActionType: false} }),
		gatefix.WithConfig(func(c *gate.Config) { c.RevealOnExecution = []string{gatefix.ActionType} }))...)
	require.ErrorIs(t, err, gate.ErrInvalidConfig)
	require.ErrorContains(t, err, gate.CauseRevealNotPublicExecution)

	_, err = gatefix.TryNew(t, policyOpts(t, privateMandate(t),
		gatefix.WithConfig(func(c *gate.Config) { c.RevealOnExecution = []string{gatefix.ActionType} }))...)
	require.ErrorIs(t, err, gate.ErrInvalidConfig, "no profile registry at all")
}
