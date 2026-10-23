// SPDX-License-Identifier: Apache-2.0

package signerapi

import (
	"github.com/vgonkivs/edicta/api/edictaapi"
	"github.com/vgonkivs/edicta/engine/commitment"
)

// DecodeSignRequest decodes a CBOR sign request with the strict wrapper
// decoder.
func DecodeSignRequest(b []byte) (Request, error) {
	f, err := edictaapi.DecodeWrapper(b, SignRequestSchema)
	if err != nil {
		return Request{}, err
	}
	r := Request{Envelope: f.Bytes(1), Action: f.Bytes(2), Salt: f.Bytes(3), Authorization: f.Bytes(4)}
	if f.Has(5) {
		r.Requirements = f.Bytes(5)
	}
	return r, nil
}

// EncodeSignRequest is the canonical CBOR of a sign request.
func EncodeSignRequest(r Request) []byte {
	items := []edictaapi.Item{
		edictaapi.BytesItem(1, r.Envelope), edictaapi.BytesItem(2, r.Action),
		edictaapi.BytesItem(3, r.Salt), edictaapi.BytesItem(4, r.Authorization),
	}
	if r.Requirements != nil {
		items = append(items, edictaapi.BytesItem(5, r.Requirements))
	}
	return edictaapi.EncodeWrapper(items...)
}

// DecodePaymentRequest decodes a CBOR payment-signature request with the
// strict wrapper decoder.
func DecodePaymentRequest(b []byte) (PaymentProofRequest, error) {
	f, err := edictaapi.DecodeWrapper(b, PaymentRequestSchema)
	if err != nil {
		return PaymentProofRequest{}, err
	}
	r := PaymentProofRequest{Field: f.Text(2), Request: Request{
		Envelope: f.Bytes(3), Action: f.Bytes(4), Salt: f.Bytes(5), Authorization: f.Bytes(6),
	}}
	copy(r.CommitmentHash[:], f.Bytes(1))
	if f.Has(7) {
		r.Requirements = f.Bytes(7)
	}
	return r, nil
}

// EncodePaymentRequest is the canonical CBOR of a payment-signature request.
func EncodePaymentRequest(r PaymentProofRequest) []byte {
	items := []edictaapi.Item{
		edictaapi.BytesItem(1, r.CommitmentHash[:]), edictaapi.TextItem(2, r.Field),
		edictaapi.BytesItem(3, r.Envelope), edictaapi.BytesItem(4, r.Action),
		edictaapi.BytesItem(5, r.Salt), edictaapi.BytesItem(6, r.Authorization),
	}
	if r.Requirements != nil {
		items = append(items, edictaapi.BytesItem(7, r.Requirements))
	}
	return edictaapi.EncodeWrapper(items...)
}

// EncodePaymentResponse is the CBOR 200 answer of POST
// /v1/payment-signature.
func EncodePaymentResponse(p PaymentProof) []byte {
	var rep uint64
	if p.Repeat {
		rep = 1
	}
	return edictaapi.EncodeWrapper(
		edictaapi.TextItem(1, string(p.Signature)), edictaapi.BytesItem(2, p.Message[:]), edictaapi.UintItem(3, rep),
	)
}

// DecodePaymentResponse decodes a CBOR 200 answer of POST
// /v1/payment-signature.
func DecodePaymentResponse(b []byte) (PaymentProof, error) {
	f, err := edictaapi.DecodeWrapper(b, PaymentResponseSchema)
	if err != nil {
		return PaymentProof{}, err
	}
	p := PaymentProof{Signature: []byte(f.Text(1))}
	copy(p.Message[:], f.Bytes(2))
	rep, _ := f.Uint(3)
	p.Repeat = rep == 1
	return p, nil
}

// EncodeSignResponse is the CBOR 200 answer of POST /v1/sign.
func EncodeSignResponse(o Output) []byte {
	var rep uint64
	if o.Repeat {
		rep = 1
	}
	return edictaapi.EncodeWrapper(
		edictaapi.BytesItem(1, o.Signed), edictaapi.TextItem(2, o.RailRef),
		edictaapi.BytesItem(3, o.CommitmentHash[:]), edictaapi.UintItem(4, rep),
	)
}

// DecodeSignResponse decodes a CBOR 200 answer of POST /v1/sign.
func DecodeSignResponse(b []byte) (Output, error) {
	f, err := edictaapi.DecodeWrapper(b, SignResponseSchema)
	if err != nil {
		return Output{}, err
	}
	o := Output{Signed: f.Bytes(1), RailRef: f.Text(2)}
	copy(o.CommitmentHash[:], f.Bytes(3))
	rep, _ := f.Uint(4)
	o.Repeat = rep == 1
	return o, nil
}

// EncodeStatusResponse is the CBOR 200 answer of GET /v1/status/{hash} for
// the decision ch.
func EncodeStatusResponse(ch commitment.Hash, st Status) []byte {
	var sent, allowed uint64
	if st.Sent {
		sent = 1
	}
	if st.PaymentProofAllowed {
		allowed = 1
	}
	items := []edictaapi.Item{
		edictaapi.TextItem(1, string(st.State)), edictaapi.BytesItem(2, ch[:]), edictaapi.UintItem(3, sent),
	}
	if st.RailRef != "" {
		items = append(items, edictaapi.TextItem(4, st.RailRef))
	}
	if len(st.Signed) != 0 {
		items = append(items, edictaapi.BytesItem(5, st.Signed))
	}
	if st.Outcome != "" {
		items = append(items, edictaapi.TextItem(6, st.Outcome))
	}
	if st.Detail != "" {
		items = append(items, edictaapi.TextItem(7, st.Detail))
	}
	items = append(items, edictaapi.UintItem(8, allowed))
	if len(st.Receipt) != 0 {
		items = append(items, edictaapi.BytesItem(9, st.Receipt))
	}
	return edictaapi.EncodeWrapper(items...)
}

// DecodeStatusResponse decodes a CBOR 200 answer of GET /v1/status/{hash}.
func DecodeStatusResponse(b []byte) (Status, error) {
	f, err := edictaapi.DecodeWrapper(b, StatusResponseSchema)
	if err != nil {
		return Status{}, err
	}
	sent, _ := f.Uint(3)
	allowed, _ := f.Uint(8)
	return Status{
		State: State(f.Text(1)), Sent: sent == 1, RailRef: f.Text(4), Signed: f.Bytes(5), Outcome: f.Text(6),
		Detail: f.Text(7), PaymentProofAllowed: allowed == 1, Receipt: f.Bytes(9),
	}, nil
}
