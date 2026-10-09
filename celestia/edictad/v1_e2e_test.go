package edictad_test

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/commitment"
)

func (e *env) authorizeOn(path string, d decision) (int, []byte) {
	e.t.Helper()
	resp := post(e.t, e.srv, path, "", authorizeBody(string(d.env), string(d.action)))
	var b bytes.Buffer
	_, err := b.ReadFrom(resp.Body)
	require.NoError(e.t, err)
	return resp.StatusCode, b.Bytes()
}

// The version comes from the signed envelope: a v1 decision gets an
// Authorization v1 on the base path and on the alias.
func TestV1DecisionOnBothPaths(t *testing.T) {
	p := newPolicyEnv(t)
	p.startPolicy()
	for i, path := range []string{"/v0/authorize", "/v1/authorize"} {
		d := p.send(byte(10+i), 1_000_000)
		require.EqualValues(t, commitment.VersionV1, d.c.Version)
		st, body := p.authorizeOn(path, d)
		require.Equal(t, 200, st, "%s: %q", path, body)
		rec, err := p.real.Authorization(bg, d.hash)
		require.NoError(t, err)
		sa, _, err := commitment.DecodeSignedAuthorization(rec.SignedAuthorization)
		require.NoError(t, err)
		assert.EqualValues(t, commitment.VersionV1, sa.Authorization.Version, path)
		assert.EqualValues(t, commitment.ModeStrict, sa.Authorization.Mode, path)
		assert.True(t, bytes.Contains(body, rec.SignedAuthorization), "the answer is the archived Authorization")
	}
}

func TestMandateMismatchLeavesAMarkerAndNoVerdict(t *testing.T) {
	p := newPolicyEnv(t)
	p.startPolicy()
	n := len(p.fs.puts)
	other := *p.base
	other.MandateRef = bytes.Repeat([]byte{9}, 32)
	d := p.decisionAct(&other, 1, p.send(1, 1_000_000).action, func(c *commitment.Commitment) {
		c.Action = p.send(1, 1_000_000).c.Action
	})
	st, body := p.authorizeOn("/v1/authorize", d)
	require.Equal(t, 403, st)
	assert.True(t, hasCode(body, "ErrMandateMismatch"), "body %q", body)
	assert.Equal(t, []archive.Kind{archive.KindDecision, archive.KindRejection}, kindsOf(p.fs.puts, n))
	_, err := p.real.Rejection(bg, d.hash, "ErrMandateMismatch")
	require.NoError(t, err)
}

func TestV0DecisionAtAMandateGate(t *testing.T) {
	p := newPolicyEnv(t)
	p.startPolicy()
	n := len(p.fs.puts)
	v0 := *p.base
	v0.Version, v0.MandateRef = commitment.VersionV0, nil
	d := p.decisionAct(&v0, 1, p.send(1, 1_000_000).action, func(c *commitment.Commitment) {
		c.Action = p.send(1, 1_000_000).c.Action
	})
	st, body := p.authorizeOn("/v1/authorize", d)
	require.Equal(t, 403, st)
	assert.True(t, hasCode(body, "ErrVersionNotAccepted"), "body %q", body)
	assert.Empty(t, kindsOf(p.fs.puts, n), "a stage 1 refusal writes nothing")
}
