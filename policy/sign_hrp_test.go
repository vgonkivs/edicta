package policy_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/policy"
	"github.com/vgonkivs/edicta/principalsig"
)

// opaqueSigner hides the concrete signer, as a remote signer would.
type opaqueSigner struct{ principalsig.Signer }

// An ADR-036 signer under another bech32 prefix than the mandate's would
// produce a signature that never verifies; SignMandateWith refuses it.
func TestSignMandateWithWrongHRP(t *testing.T) {
	var f struct {
		Keys map[string]struct {
			SeedHex string `json:"seed_hex"`
		} `json:"keys"`
		Cases []struct {
			ID        string `json:"id"`
			Signer    string `json:"signer"`
			SignedHex string `json:"signed_mandate_hex"`
		} `json:"cases"`
	}
	readVec(t, "mandate.json", &f)
	for _, c := range f.Cases {
		if c.ID != "m_adr036" {
			continue
		}
		sm, _, err := policy.VerifyMandate(hx(t, c.SignedHex))
		require.NoError(t, err)
		m := &sm.Mandate
		require.NotEqual(t, "other", m.PrincipalHRP)
		seed := hx(t, f.Keys[c.Signer].SeedHex)

		good, err := principalsig.NewSecp256k1Signer(principalsig.CosmosADR036, seed, m.PrincipalHRP)
		require.NoError(t, err)
		_, _, err = policy.SignMandateWith(good, m)
		require.NoError(t, err, "control: the mandate's own prefix")

		bad, err := principalsig.NewSecp256k1Signer(principalsig.CosmosADR036, seed, "other")
		require.NoError(t, err)
		_, _, err = policy.SignMandateWith(bad, m)
		require.ErrorIs(t, err, policy.ErrMandateSignature)
		_, _, err = policy.SignMandateWith(opaqueSigner{bad}, m)
		require.ErrorIs(t, err, policy.ErrMandateSignature, "a signer that does not name its prefix is checked by its result")
		return
	}
	require.FailNow(t, "no m_adr036 vector")
}
