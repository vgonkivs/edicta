// SPDX-License-Identifier: Apache-2.0

package anchor

import (
	"bytes"
	"fmt"

	blobtypes "github.com/celestiaorg/celestia-app/v10/x/blob/types"
	libshare "github.com/celestiaorg/go-square/v4/share"
	squaretx "github.com/celestiaorg/go-square/v4/tx"
	"github.com/cosmos/cosmos-sdk/types/bech32"
	cosmostx "github.com/cosmos/cosmos-sdk/types/tx"

	"github.com/vgonkivs/edicta/engine/commitment"
	"github.com/vgonkivs/edicta/engine/gate"
)

func invalidIntent(format string, a ...any) error {
	return fmt.Errorf("%w: %s", gate.ErrAnchorIntentInvalid, fmt.Sprintf(format, a...))
}

const pfbTypeURL = "/celestia.blob.v1.MsgPayForBlobs"

// CheckPFB requires tx to be a signed Cosmos tx with exactly one message, a
// MsgPayForBlobs that pays for the reference's blob (namespace, share
// commitment, share version 1) with the reference's signer, and a
// timeout_height of 0 or above h0. It returns the timeout_height.
func CheckPFB(tx []byte, ref commitment.PayloadRef) (uint64, error) {
	if _, isBlob, _ := squaretx.UnmarshalBlobTx(tx); isBlob {
		return 0, invalidIntent("the intent holds a BlobTx, not the bare tx")
	}
	var raw cosmostx.TxRaw
	if err := raw.Unmarshal(tx); err != nil {
		return 0, invalidIntent("tx: %v", err)
	}
	var body cosmostx.TxBody
	if err := body.Unmarshal(raw.BodyBytes); err != nil {
		return 0, invalidIntent("tx body: %v", err)
	}
	if len(body.Messages) != 1 || body.Messages[0] == nil || body.Messages[0].TypeUrl != pfbTypeURL {
		return 0, invalidIntent("tx must hold exactly one MsgPayForBlobs")
	}
	var msg blobtypes.MsgPayForBlobs
	if err := msg.Unmarshal(body.Messages[0].Value); err != nil {
		return 0, invalidIntent("MsgPayForBlobs: %v", err)
	}
	found := false
	for i := range msg.Namespaces {
		if i < len(msg.ShareCommitments) && i < len(msg.ShareVersions) &&
			bytes.Equal(msg.Namespaces[i], ref.Namespace) && bytes.Equal(msg.ShareCommitments[i], ref.Commitment) &&
			msg.ShareVersions[i] == uint32(libshare.ShareVersionOne) {
			found = true
			break
		}
	}
	if !found {
		return 0, invalidIntent("MsgPayForBlobs pays for no blob of the reference")
	}
	_, signer, err := bech32.DecodeAndConvert(msg.Signer)
	if err != nil || !bytes.Equal(signer, ref.Signer) {
		return 0, invalidIntent("MsgPayForBlobs signer is not the reference's signer")
	}
	if body.TimeoutHeight != 0 && body.TimeoutHeight <= ref.Height {
		return 0, invalidIntent("timeout_height %d at or below h0 %d", body.TimeoutHeight, ref.Height)
	}
	var auth cosmostx.AuthInfo
	if err := auth.Unmarshal(raw.AuthInfoBytes); err != nil {
		return 0, invalidIntent("auth info: %v", err)
	}
	if len(auth.SignerInfos) == 0 || len(raw.Signatures) == 0 {
		return 0, invalidIntent("tx is not signed")
	}
	return body.TimeoutHeight, nil
}
