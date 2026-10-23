// SPDX-License-Identifier: Apache-2.0

package signer

import "github.com/vgonkivs/edicta/api/signerapi"

// The service takes and answers the API's messages as they are.
type (
	Request             = signerapi.Request
	Output              = signerapi.Output
	PaymentProofRequest = signerapi.PaymentProofRequest
	PaymentProof        = signerapi.PaymentProof
	Status              = signerapi.Status
	State               = signerapi.State
)

// The states a decision passes through; the status route shows them.
const (
	StateReserved    = signerapi.StateReserved
	StateSigned      = signerapi.StateSigned
	StateExecuted    = signerapi.StateExecuted
	StateReverted    = signerapi.StateReverted
	StateRecorded    = signerapi.StateRecorded
	StateNotExecuted = signerapi.StateNotExecuted
	StateWrong       = signerapi.StateWrong
)
