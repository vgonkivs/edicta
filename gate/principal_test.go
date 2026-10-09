package gate_test

import (
	"bytes"
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/gate"
	"github.com/vgonkivs/edicta/policy"
	"github.com/vgonkivs/edicta/principalsig"
	"github.com/vgonkivs/edicta/test/gatefix"
)

func secpMandate(t *testing.T, scheme principalsig.Scheme) []byte {
	t.Helper()
	sk := sha256.Sum256([]byte("gate secp principal"))
	hrp := ""
	if scheme == principalsig.CosmosADR036 {
		hrp = "celestia"
	}
	s, err := principalsig.NewSecp256k1Signer(scheme, sk[:], hrp)
	require.NoError(t, err)
	m := baseMandate(t)
	m.SigType, m.PrincipalHRP, m.Principal = uint64(scheme), hrp, s.Principal()
	b, _, err := policy.SignMandateWith(s, m)
	require.NoError(t, err)
	return b
}

func TestPolicyGateRunsSecp256k1Mandates(t *testing.T) {
	for _, scheme := range []principalsig.Scheme{principalsig.CosmosADR036, principalsig.EIP712} {
		t.Run(scheme.String(), func(t *testing.T) {
			signed := secpMandate(t, scheme)
			p := newPolicyEnv(t, baseMandate(t), gatefix.WithConfig(func(c *gate.Config) { c.Mandate = signed }))
			_, cb, action := p.request(1, "agent1", 10)
			_, err := p.AuthorizeWith(cb, action)
			require.NoError(t, err)
		})
	}
}

func TestPolicyGateRefusesPrivateMandates(t *testing.T) {
	m := baseMandate(t)
	pub := bytes.Repeat([]byte{9}, 32)
	m.Auditors = []policy.Auditor{{Kid: policy.AuditorKid(pub), Pubkey: pub, Label: "a1"}}
	m.StateSalt = bytes.Repeat([]byte{3}, 32)
	_, err := gatefix.TryNew(t, policyOpts(t, m)...)
	require.ErrorIs(t, err, gate.ErrInvalidConfig)
	require.ErrorContains(t, err, "private mandates")
}
