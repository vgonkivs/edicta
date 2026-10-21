// SPDX-License-Identifier: Apache-2.0

package signertest

import (
	"encoding/hex"
	"fmt"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"

	"github.com/vgonkivs/edicta/edenescrow"
)

// quoteFacilitatorKey is the test facilitator that signs the quotes' paymentId.
func quoteFacilitatorKey() *secp256k1.PrivateKey {
	var s secp256k1.ModNScalar
	s.SetByteSlice(seed("quote facilitator"))
	return secp256k1.NewPrivateKey(&s)
}

// QuoteFacilitator is the address of the facilitator Quote signs as.
func QuoteFacilitator() [20]byte { return edenescrow.Address(quoteFacilitatorKey().PubKey()) }

// tiaPriceUSD is the price word every fixture deposit carries.
const tiaPriceUSD = 42

// Quote is a PAYMENT-REQUIRED document R for d: one escrow-upto entry whose
// fields equal the deposit, with serverSignature by signer over paymentId
// (the quote facilitator when signer is nil). The deposit's Facilitator
// should be QuoteFacilitator for the signature to pass.
func Quote(d Deposit, signer *secp256k1.PrivateKey) ([]byte, error) {
	if signer == nil {
		signer = quoteFacilitatorKey()
	}
	sig, err := edenescrow.Sign(signer, edenescrow.PersonalDigest(d.PaymentID))
	if err != nil {
		return nil, err
	}
	ss := append(append(append([]byte{}, sig.R[:]...), sig.S[:]...), sig.YParity)
	row, _ := edenescrow.Lookup(d.ChainID)
	value := "0"
	if d.Value != nil {
		value = d.Value.String()
	}
	r := fmt.Appendf(nil, `{"x402Version":2,"resource":{"url":%q},"accepts":[{"scheme":"escrow-upto","network":"eip155:%d","asset":"native","amount":%q,"payTo":"0x%x","extra":{"paymentId":"0x%x","escrowContract":"0x%x","facilitator":"0x%x","expiresAt":%d,"refundAfter":%d,"tiaPriceUsd":"%d","chainId":%d,"serverSignature":"0x%s"}}]}`,
		d.Resource, d.ChainID, value, d.PayTo, d.PaymentID, row.Escrow, d.Facilitator, d.ExpiresAt, d.RefundAfter,
		tiaPriceUSD, d.ChainID, hex.EncodeToString(ss))
	return r, nil
}

// QuotedDeposit is d paying the quote facilitator, with Requirements set to
// its Quote.
func QuotedDeposit(d Deposit) (Deposit, error) {
	d.Facilitator = QuoteFacilitator()
	r, err := Quote(d, nil)
	if err != nil {
		return Deposit{}, err
	}
	d.Requirements = r
	return d, nil
}
