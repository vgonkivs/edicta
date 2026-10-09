package policy_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/policy"
)

func mandateOf(t *testing.T, id string) *policy.Mandate {
	t.Helper()
	var f struct {
		Cases []struct {
			ID     string `json:"id"`
			Signed string `json:"signed_mandate_hex"`
		} `json:"cases"`
	}
	readVec(t, "mandate.json", &f)
	for _, c := range f.Cases {
		if c.ID == id {
			sm, _, err := policy.VerifyMandate(hx(t, c.Signed))
			require.NoError(t, err)
			return &sm.Mandate
		}
	}
	require.Failf(t, "no such case", id)
	return nil
}

func TestPrincipalPinsComparePerScheme(t *testing.T) {
	ed, cosmos, eth := mandateOf(t, "m_full"), mandateOf(t, "m_adr036"), mandateOf(t, "m_eip712")
	pins := map[string]*policy.Mandate{
		"ed25519:" + hex.EncodeToString(ed.Principal):            ed,
		hex.EncodeToString(ed.Principal):                         ed,
		"cosmos:celestia1hjlq8g26hnkwsegd75vwqqlf39a7gch9u7yer7": cosmos,
		"cosmos:CELESTIA1HJLQ8G26HNKWSEGD75VWQQLF39A7GCH9U7YER7": cosmos,
		"eth:0xda9588643fa4376845af5352ffba44f5e4b0e40f":         eth,
		"eth:0xDA9588643FA4376845AF5352FFBA44F5E4B0E40F":         eth,
	}
	for s, want := range pins {
		id, err := policy.ParsePrincipal(s)
		require.NoError(t, err, s)
		for _, m := range []*policy.Mandate{ed, cosmos, eth} {
			assert.Equal(t, m == want, id.Pins(m), "%s against sig_type %d", s, m.SigType)
		}
		again, err := policy.ParsePrincipal(id.String())
		require.NoError(t, err)
		assert.Equal(t, id, again)
	}
	// The same address under another hrp is another identity.
	other := *cosmos
	other.PrincipalHRP = "cosmos"
	id, err := policy.ParsePrincipal("cosmos:celestia1hjlq8g26hnkwsegd75vwqqlf39a7gch9u7yer7")
	require.NoError(t, err)
	assert.False(t, id.Pins(&other))

	for _, s := range []string{
		"", "ed25519:zz", "ed25519:" + hex.EncodeToString(make([]byte, 32)), "cosmos:celestia1xyz",
		"eth:0x1234", "solana:abc", "cosmos:Celestia1hjlq8g26hnkwsegd75vwqqlf39a7gch9u7yer7",
	} {
		_, err := policy.ParsePrincipal(s)
		require.ErrorIs(t, err, policy.ErrPrincipalPin, s)
	}
}

func TestCounterKeyTypedForms(t *testing.T) {
	ed := mandateOf(t, "m_full")
	legacy := sha256.Sum256(append(append([]byte{byte(len(policy.TagCounter))}, policy.TagCounter...), append(bytes.Clone(ed.Principal), ed.MandateID...)...))
	assert.Equal(t, legacy, ed.CounterKey())

	addr := bytes.Repeat([]byte{0xab}, 20)
	k2 := policy.CounterKey(policy.PrincipalID{SigType: uint8(policy.SigTypeADR036), Principal: addr}, ed.MandateID)
	k3 := policy.CounterKey(policy.PrincipalID{SigType: uint8(policy.SigTypeEIP712), Principal: addr}, ed.MandateID)
	k0 := policy.CounterKey(policy.PrincipalID{Principal: addr}, ed.MandateID)
	assert.NotEqual(t, k2, k3)
	assert.NotEqual(t, k0, k3)
	pre := append(append([]byte{byte(len(policy.TagCounter))}, policy.TagCounter...), 3, 20)
	assert.Equal(t, sha256.Sum256(append(append(pre, addr...), ed.MandateID...)), k3)
}

func TestMandateSchemeRules(t *testing.T) {
	eth := mandateOf(t, "m_eip712")
	m := *eth
	m.SigType = 1
	require.ErrorIs(t, m.ValidateBasic(), policy.ErrMandateInvalid)
	m.SigType = 4
	require.ErrorIs(t, m.ValidateBasic(), policy.ErrMandateInvalid)
	m.SigType = policy.SigTypeEIP712
	m.PrincipalHRP = "celestia"
	require.ErrorIs(t, m.ValidateBasic(), policy.ErrMandateInvalid)
	m.PrincipalHRP = ""
	m.FastModeMaxDelay = 1001
	require.ErrorIs(t, m.ValidateBasic(), policy.ErrMandateInvalid)
	m.FastModeMaxDelay = 1000
	require.NoError(t, m.ValidateBasic())
	m.Auditors = []policy.Auditor{}
	require.ErrorIs(t, m.ValidateBasic(), policy.ErrMandateInvalid)
}

// A cosmos pin keeps the canonical lower-case re-encoding, whatever case the
// user typed.
func TestCosmosPinIsCanonical(t *testing.T) {
	id, err := policy.ParsePrincipal("cosmos:CELESTIA1HJLQ8G26HNKWSEGD75VWQQLF39A7GCH9U7YER7")
	require.NoError(t, err)
	assert.Equal(t, "celestia1hjlq8g26hnkwsegd75vwqqlf39a7gch9u7yer7", string(id.Principal))
	assert.Equal(t, "cosmos:celestia1hjlq8g26hnkwsegd75vwqqlf39a7gch9u7yer7", id.String())
}

// Every tool prints an auditor with the unverified label beside the full
// fingerprint, and the kid is the one derived from the key.
func TestAuditorLine(t *testing.T) {
	pub := bytes.Repeat([]byte{9}, 32)
	a := policy.Auditor{Kid: policy.AuditorKid(pub), Pubkey: pub, Label: "Bob"}
	require.Len(t, a.Kid, 16)
	line := policy.AuditorLine(a)
	assert.Contains(t, line, `Auditor "Bob" (label not verified) - key fingerprint: `)
	assert.Len(t, policy.Fingerprint(a.Kid), 39, "8 groups of 4 hex digits")
}
