// SPDX-License-Identifier: Apache-2.0

package signer_test

import (
	"bytes"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/api/edictaapi"
	"github.com/vgonkivs/edicta/api/signerapi"
	"github.com/vgonkivs/edicta/services/signer"
	"github.com/vgonkivs/edicta/services/signer/signertest"
)

// FuzzDecodeSignRequest: the request decoder never panics, accepts only the
// canonical encoding (re-encoding gives the input back), and the JSON path
// yields only bytes the CBOR decoder then judges.
func FuzzDecodeSignRequest(f *testing.F) {
	k := signertest.NewKeys("fuzz")
	now := time.Unix(1_800_000_000, 0)
	action, err := signertest.NewDeposit(now).Action()
	require.NoError(f, err)
	d, err := signertest.NewDecision(k, action, now, signertest.DecisionOpts{})
	require.NoError(f, err)
	good := signerapi.EncodeSignRequest(request(d))
	f.Add(good)
	f.Add(good[:len(good)-1])
	f.Add([]byte(`{"envelope":"AA==","action":"AA==","action_salt":"AA==","signed_authorization":"AA=="}`))
	f.Add([]byte{0xa0})
	f.Fuzz(func(t *testing.T, b []byte) {
		if req, err := signerapi.DecodeSignRequest(b); err == nil {
			require.True(t, bytes.Equal(b, signerapi.EncodeSignRequest(req)), "only the canonical encoding decodes")
			require.Len(t, req.Salt, 32)
		}
		if w, err := edictaapi.JSONToWrapper(b, signerapi.SignRequestSchema); err == nil {
			if req, err := signerapi.DecodeSignRequest(w); err == nil {
				require.True(t, bytes.Equal(w, signerapi.EncodeSignRequest(req)))
			}
		}
	})
}

// FuzzDecodePaymentRequest: the payment-signature request decoder never
// panics and accepts only the canonical encoding, with or without R.
func FuzzDecodePaymentRequest(f *testing.F) {
	k := signertest.NewKeys("fuzz")
	now := time.Unix(1_800_000_000, 0)
	dep, err := signertest.QuotedDeposit(signertest.NewDeposit(now))
	require.NoError(f, err)
	action, err := dep.Action()
	require.NoError(f, err)
	d, err := signertest.NewDecision(k, action, now, signertest.DecisionOpts{})
	require.NoError(f, err)
	req := signer.PaymentProofRequest{CommitmentHash: d.Hash, Field: "paymentId", Request: request(d)}
	f.Add(signerapi.EncodePaymentRequest(req))
	req.Requirements = dep.Requirements
	good := signerapi.EncodePaymentRequest(req)
	f.Add(good)
	f.Add(good[:len(good)-1])
	f.Add([]byte(`{"commitment_hash":"AA==","field":"paymentId","envelope":"AA==","action":"AA==","action_salt":"AA==","signed_authorization":"AA=="}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		if req, err := signerapi.DecodePaymentRequest(b); err == nil {
			require.True(t, bytes.Equal(b, signerapi.EncodePaymentRequest(req)), "only the canonical encoding decodes")
			require.NotEmpty(t, req.Field)
		}
		if w, err := edictaapi.JSONToWrapper(b, signerapi.PaymentRequestSchema); err == nil {
			if req, err := signerapi.DecodePaymentRequest(w); err == nil {
				require.True(t, bytes.Equal(w, signerapi.EncodePaymentRequest(req)))
			}
		}
	})
}
