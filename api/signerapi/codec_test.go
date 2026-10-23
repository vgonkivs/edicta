// SPDX-License-Identifier: Apache-2.0

package signerapi_test

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/api/signerapi"
	"github.com/vgonkivs/edicta/engine/commitment"
)

func request(requirements []byte) signerapi.Request {
	return signerapi.Request{
		Envelope: []byte{1}, Action: []byte{2}, Salt: bytes.Repeat([]byte{3}, commitment.ActionSaltSize),
		Authorization: []byte{4}, Requirements: requirements,
	}
}

func TestMessagesRoundTrip(t *testing.T) {
	ch := commitment.Hash{9}
	for _, r := range []signerapi.Request{request(nil), request([]byte("R"))} {
		got, err := signerapi.DecodeSignRequest(signerapi.EncodeSignRequest(r))
		require.NoError(t, err)
		assert.Equal(t, r, got)

		p := signerapi.PaymentProofRequest{CommitmentHash: ch, Field: "paymentId", Request: r}
		gp, err := signerapi.DecodePaymentRequest(signerapi.EncodePaymentRequest(p))
		require.NoError(t, err)
		assert.Equal(t, p, gp)
	}

	o := signerapi.Output{CommitmentHash: ch, Signed: []byte{5}, RailRef: "ref", Repeat: true}
	got, err := signerapi.DecodeSignResponse(signerapi.EncodeSignResponse(o))
	require.NoError(t, err)
	assert.Equal(t, o, got)

	p := signerapi.PaymentProof{Message: [32]byte{6}, Signature: []byte("0x01"), Repeat: true}
	gp, err := signerapi.DecodePaymentResponse(signerapi.EncodePaymentResponse(p))
	require.NoError(t, err)
	assert.Equal(t, p, gp, "the commitment hash is not on the wire")

	for _, st := range []signerapi.Status{
		{State: signerapi.StateSigned},
		{State: signerapi.StateRecorded, Sent: true, RailRef: "ref", Signed: []byte{5}, Outcome: "executed",
			Detail: "d", PaymentProofAllowed: true, Receipt: []byte{7}},
	} {
		gs, err := signerapi.DecodeStatusResponse(signerapi.EncodeStatusResponse(ch, st))
		require.NoError(t, err)
		assert.Equal(t, st, gs)
	}
}

func TestRequirementsAboveTheBoundAreRefused(t *testing.T) {
	big := bytes.Repeat([]byte{'x'}, signerapi.MaxRequirementsSize+1)
	_, err := signerapi.DecodeSignRequest(signerapi.EncodeSignRequest(request(big)))
	require.ErrorIs(t, err, commitment.ErrFieldSize)
	_, err = signerapi.DecodePaymentRequest(signerapi.EncodePaymentRequest(
		signerapi.PaymentProofRequest{Field: "paymentId", Request: request(big)}))
	require.ErrorIs(t, err, commitment.ErrFieldSize)

	at := bytes.Repeat([]byte{'x'}, signerapi.MaxRequirementsSize)
	_, err = signerapi.DecodeSignRequest(signerapi.EncodeSignRequest(request(at)))
	require.NoError(t, err)
}

func TestPaymentFieldIsAlphanumeric(t *testing.T) {
	for _, f := range []string{"payment-id", "payment id", ""} {
		_, err := signerapi.DecodePaymentRequest(signerapi.EncodePaymentRequest(
			signerapi.PaymentProofRequest{Field: f, Request: request(nil)}))
		assert.Error(t, err, "%q", f)
	}
}
