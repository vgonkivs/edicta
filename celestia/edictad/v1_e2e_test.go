package edictad_test

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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

// The decision gets a strict Authorization on the one authorize path.
func TestDecisionOnTheV1Path(t *testing.T) {
	p := newPolicyEnv(t)
	p.startPolicy()
	d := p.send(10, 1_000_000)
	st, body := p.authorizeOn("/v1/authorize", d)
	require.Equal(t, 200, st, "%q", body)
	rec, err := p.real.Authorization(bg, d.hash)
	require.NoError(t, err)
	sa, _, err := commitment.DecodeSignedAuthorization(rec.SignedAuthorization)
	require.NoError(t, err)
	assert.EqualValues(t, commitment.Version, sa.Authorization.Version)
	assert.EqualValues(t, commitment.ModeStrict, sa.Authorization.Mode)
	assert.True(t, bytes.Contains(body, rec.SignedAuthorization), "the answer is the archived Authorization")
	dec, err := p.real.Decision(bg, d.hash)
	require.NoError(t, err)
	assert.Equal(t, testSalt, dec.ActionSalt, "the decision record keeps the salt as presented")
}

// A commitment naming another mandate is refused and leaves nothing in the
// archive: a record in the form of the mandate in force could publish the
// action of a decision committed under a private one.
func TestMandateMismatchWritesNothing(t *testing.T) {
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
	assert.Empty(t, kindsOf(p.fs.puts, n), "no decision record and no marker")
}

func TestVersionZeroIsRefusedAtDecoding(t *testing.T) {
	p := newPolicyEnv(t)
	p.startPolicy()
	n := len(p.fs.puts)
	v0 := *p.base
	v0.Version, v0.MandateRef = 0, nil
	d := p.decisionAct(&v0, 1, p.send(1, 1_000_000).action, func(c *commitment.Commitment) {
		c.Action = p.send(1, 1_000_000).c.Action
	})
	st, body := p.authorizeOn("/v1/authorize", d)
	require.Equal(t, 400, st)
	assert.True(t, hasCode(body, "ErrUnsupportedVersion"), "body %q", body)
	assert.Empty(t, kindsOf(p.fs.puts, n), "a stage 1 refusal writes nothing")
}
