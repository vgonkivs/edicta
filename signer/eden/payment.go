// SPDX-License-Identifier: Apache-2.0

package eden

import (
	"encoding/hex"
	"fmt"
	"slices"

	"github.com/vgonkivs/edicta/plugins/edenescrow"
	"github.com/vgonkivs/edicta/signer"
)

// PaymentSignatureMessage runs the steps of a Payment-Signature request that
// need no state: the field is offered under this configuration
// (ErrPinMismatch), the committed resource names https:// and R passes every
// requirements check with the facilitator's signature enforced
// (ErrRequirements). The message is the action's paymentId, which the
// pinned facilitator signed; nothing the request names is ever signed.
func PaymentSignatureMessage(field string, checkServerSignature bool, action, r []byte) ([32]byte, error) {
	if field != FieldPaymentID || !checkServerSignature {
		return [32]byte{}, fmt.Errorf("%w: no Payment-Signature over field %q with the server-signature check %v",
			signer.ErrPinMismatch, field, checkServerSignature)
	}
	a, err := edenescrow.DecodeTxAction(action)
	if err != nil {
		return [32]byte{}, err
	}
	m, err := edenescrow.PaymentProofMessage(a, r)
	if err != nil {
		return [32]byte{}, fmt.Errorf("%w: %w", signer.ErrRequirements, err)
	}
	return m, nil
}

// PaymentProofEnabled says whether the Payment-Signature is offered.
func (h *Handler) PaymentProofEnabled() bool { return h.cfg.PaymentSignatureEnabled() }

// CheckPaymentProofField refuses every field but paymentId, and every field
// while the Payment-Signature is off.
func (h *Handler) CheckPaymentProofField(field string) error {
	if !h.PaymentProofEnabled() || field != FieldPaymentID {
		return fmt.Errorf("%w: no Payment-Signature over field %q", signer.ErrPinMismatch, field)
	}
	return nil
}

// ActionDigest is keccak256 of the action's unsigned transaction.
func (h *Handler) ActionDigest(action []byte) ([32]byte, error) {
	a, err := edenescrow.DecodeTxAction(action)
	if err != nil {
		return [32]byte{}, err
	}
	return a.SigHash(), nil
}

// PaymentProofDigest is the personal_sign digest of the action's
// paymentId, after the stateless checks. The facilitator must still be
// allowed: one removed since the deposit (a compromised key, say) gets no
// more payment proofs.
func (h *Handler) PaymentProofDigest(action, r []byte) (message, digest [32]byte, err error) {
	m, err := PaymentSignatureMessage(FieldPaymentID, h.cfg.checkServerSignature(), action, r)
	if err != nil {
		return [32]byte{}, [32]byte{}, err
	}
	a, err := edenescrow.DecodeTxAction(action)
	if err != nil {
		return [32]byte{}, [32]byte{}, err
	}
	p, ok := h.pins[a.ChainID]
	if !ok || !slices.Contains(p.Facilitators, a.Deposit.Facilitator) {
		return [32]byte{}, [32]byte{}, fmt.Errorf("%w: facilitator %x is no longer allowed", signer.ErrPinMismatch, a.Deposit.Facilitator)
	}
	return m, edenescrow.PersonalDigest(m), nil
}

// SlotOf is the nonce slot of a stored decision, for a store written before
// slots were kept.
func (h *Handler) SlotOf(e signer.Entry) (string, error) {
	a, err := edenescrow.DecodeTxAction(e.Action)
	if err != nil {
		return "", err
	}
	return nonceSlot(a.ChainID, e.Payer, a.Nonce), nil
}

// FinishPaymentProof writes the payer's signature as personal_sign does:
// "0x" and r || s || v in lower-case hex, v = 27 + y_parity. It must recover
// to payer over the message.
func (h *Handler) FinishPaymentProof(message [32]byte, sig [65]byte, payer [20]byte) ([]byte, error) {
	if sig[64] > 1 {
		return nil, fmt.Errorf("signer/eden: y_parity %d", sig[64])
	}
	sig[64] += 27
	got, err := edenescrow.RecoverPersonal(message, sig)
	if err != nil {
		return nil, err
	}
	if got != payer {
		return nil, fmt.Errorf("signer/eden: the Payment-Signature recovers to %x, not the payer %x", got, payer)
	}
	return []byte("0x" + hex.EncodeToString(sig[:])), nil
}
