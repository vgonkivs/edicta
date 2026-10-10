package verifycli

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/vgonkivs/edicta/verifier"
)

// When no key opens a private mandate, its id, version and principal are
// absent rather than an empty string and a zero.
func TestKeylessPrivateMandateLeavesOutItsIdentity(t *testing.T) {
	pol := policyJSON(t, &verifier.PolicyInfo{Mode: verifier.PolicyModePrivate, ContentPrivate: true})
	for _, k := range []string{"mandate_id", "version", "principal"} {
		assert.NotContains(t, pol, k)
	}
	assert.Contains(t, pol, "mandate_hash")

	pol = policyJSON(t, &verifier.PolicyInfo{Mode: verifier.PolicyModePrivate, ContentPrivate: true, MandateID: []byte{1}, Principal: []byte{2}})
	assert.JSONEq(t, `"01"`, string(pol["mandate_id"]))
	assert.JSONEq(t, "0", string(pol["version"]))
	assert.JSONEq(t, `"02"`, string(pol["principal"]))

	pol = policyJSON(t, &verifier.PolicyInfo{Mode: verifier.PolicyModePublic, MandateID: []byte{3}, Principal: []byte{4}})
	assert.JSONEq(t, "0", string(pol["version"]))
	assert.JSONEq(t, `"03"`, string(pol["mandate_id"]))
	assert.JSONEq(t, `"04"`, string(pol["principal"]))
}
