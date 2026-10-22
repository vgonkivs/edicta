// SPDX-License-Identifier: Apache-2.0

package eden_test

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/internal/testkit"
	"github.com/vgonkivs/edicta/plugins/edenescrow"
	"github.com/vgonkivs/edicta/signer"
	"github.com/vgonkivs/edicta/signer/eden"
	"github.com/vgonkivs/edicta/signer/signertest"
)

type paymentVectors struct {
	Requirements struct {
		Accept []rCase `json:"accept"`
		Reject []rCase `json:"reject"`
	} `json:"requirements"`
	PaymentSignature struct {
		RefusedFields []string `json:"refused_fields"`
		Requests      []struct {
			ID                   string  `json:"id"`
			Field                string  `json:"field"`
			CheckServerSignature bool    `json:"check_server_signature"`
			Resource             string  `json:"resource"`
			RequirementsRef      string  `json:"requirements_ref"`
			CBORHex              string  `json:"cbor_hex"`
			RRef                 *string `json:"r_ref"`
			Expect               string  `json:"expect"`
			MessageHex           string  `json:"message_hex"`
			Error                string  `json:"error"`
			S4Rule               string  `json:"s4_rule"`
		} `json:"requests"`
	} `json:"payment_signature"`
}

type rCase struct {
	ID                  string `json:"id"`
	RHex                string `json:"r_hex"`
	RequirementsHashHex string `json:"requirements_hash_hex"`
}

var sentinels = map[string]error{
	"ErrPinMismatch":   signer.ErrPinMismatch,
	"ErrRequirements":  signer.ErrRequirements,
	"ErrNotAuthorized": signer.ErrNotAuthorized,
	"ErrNotExecuted":   signer.ErrNotExecuted,
}

// The stateless steps of a Payment-Signature request, from the shared
// vectors: the field, the https resource, R bound and signed by the
// facilitator, and the message is always the action's paymentId.
func TestPaymentSignatureRequestVectors(t *testing.T) {
	b, err := os.ReadFile(testkit.SpecPath(t, "vectors", "profiles", "eden-escrow", "x402.json"))
	require.NoError(t, err)
	var v paymentVectors
	require.NoError(t, json.Unmarshal(b, &v))
	rs := map[string]rCase{}
	for _, c := range append(v.Requirements.Accept, v.Requirements.Reject...) {
		rs[c.ID] = c
	}
	require.Contains(t, v.PaymentSignature.RefusedFields, "nonce")
	require.NotEmpty(t, v.PaymentSignature.Requests)
	for _, c := range v.PaymentSignature.Requests {
		t.Run(c.ID, func(t *testing.T) {
			action, err := hex.DecodeString(c.CBORHex)
			require.NoError(t, err)
			a, err := edenescrow.DecodeTxAction(action)
			require.NoError(t, err)
			assert.Equal(t, c.Resource, a.Resource)
			committed, ok := rs[c.RequirementsRef]
			require.True(t, ok, c.RequirementsRef)
			assert.Equal(t, committed.RequirementsHashHex, hex.EncodeToString(a.RequirementsHash[:]))
			var r []byte
			if c.RRef != nil {
				rc, ok := rs[*c.RRef]
				require.True(t, ok, *c.RRef)
				r, err = hex.DecodeString(rc.RHex)
				require.NoError(t, err)
			}
			m, err := eden.PaymentSignatureMessage(c.Field, c.CheckServerSignature, action, r)
			if c.Expect == "pass" {
				require.NoError(t, err)
				assert.Equal(t, c.MessageHex, hex.EncodeToString(m[:]))
				assert.Equal(t, a.Deposit.PaymentID, m, "the message is the action's own paymentId")
				return
			}
			want := sentinels[c.Error]
			require.NotNil(t, want, c.Error)
			require.ErrorIs(t, err, want)
			if c.S4Rule != "" {
				assert.ErrorContains(t, err, "(rule "+c.S4Rule+")")
			}
			if c.Expect == "S11c" {
				assert.ErrorContains(t, err, "(rule S11c)")
			}
		})
	}
}

func TestConfigRefusesThePaymentSignatureOverNonce(t *testing.T) {
	k := pins(signertest.NewKeys("config"))
	cfg := eden.Config{Chains: []eden.ChainPins{k}, PaymentSignatureField: "nonce"}
	cfg.ApplyDefaults()
	assert.ErrorContains(t, cfg.ValidateBasic(), "nonce")
	cfg.PaymentSignatureField = "payment_id"
	assert.Error(t, cfg.ValidateBasic())
	off := false
	cfg.PaymentSignatureField, cfg.CheckServerSignature = eden.FieldPaymentID, &off
	require.NoError(t, cfg.ValidateBasic())
	assert.False(t, cfg.PaymentSignatureEnabled(), "the Payment-Signature needs the server-signature check")
}
