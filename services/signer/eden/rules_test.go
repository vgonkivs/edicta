// SPDX-License-Identifier: Apache-2.0

package eden_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/vgonkivs/edicta/api/signerapi"
	"github.com/vgonkivs/edicta/plugins/edenescrow"
	"github.com/vgonkivs/edicta/services/signer"
	"github.com/vgonkivs/edicta/services/signer/eden"
)

// The API carries exactly the requirements the profile accepts, so neither
// a request the profile could take is refused by size nor the reverse.
func TestRequestBoundIsTheWireBound(t *testing.T) {
	assert.EqualValues(t, signerapi.MaxRequirementsSize, edenescrow.MaxRequirementsSize)
	assert.EqualValues(t, signerapi.MaxRequirementsSize, (&eden.Handler{}).MaxRequestBytes())
}

func TestErrorRulesOfTheProfile(t *testing.T) {
	assert.Equal(t, []signer.ErrorRule{
		{Err: edenescrow.ErrRequirements, Status: 422, Code: "signer.ErrRequirements"},
		{Err: edenescrow.ErrMalformed, Status: 422, Code: "edenescrow.ErrMalformed"},
		{Err: edenescrow.ErrUnknownDomain, Status: 422, Code: "edenescrow.ErrUnknownDomain"},
	}, (&eden.Handler{}).ErrorRules())
}
