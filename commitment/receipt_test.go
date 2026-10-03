package commitment_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/commitment"
)

type receiptInput struct {
	Version        string `json:"version"`
	CommitmentHash string `json:"commitment_hash"`
	GateID         string `json:"gate_id"`
	GatePubKey     string `json:"gate_pubkey"`
	Rail           string `json:"rail"`
	RailRef        string `json:"rail_ref"`
	Path           string `json:"path"`
	ExecutedAt     string `json:"executed_at"`
}

type receiptFile struct {
	Cases []struct {
		ID               string       `json:"id"`
		CommitmentRef    string       `json:"commitment_ref"`
		Signer           string       `json:"signer"`
		Input            receiptInput `json:"input"`
		ReceiptCBORHex   string       `json:"receipt_cbor_hex"`
		ReceiptHashHex   string       `json:"receipt_hash_hex"`
		SignedMessageHex string       `json:"signed_message_hex"`
		SignatureHex     string       `json:"signature_hex"`
		SignedReceiptHex string       `json:"signed_receipt_hex"`
	} `json:"cases"`
	Reject []struct {
		ID               string `json:"id"`
		Stage            string `json:"stage"`
		SignedReceiptHex string `json:"signed_receipt_hex"`
		ExpectError      string `json:"expect_error"`
	} `json:"reject"`
}

func toReceipt(t *testing.T, in receiptInput) *commitment.Receipt {
	return &commitment.Receipt{
		Version:        u64(t, in.Version),
		CommitmentHash: mustHex(t, in.CommitmentHash),
		GateID:         in.GateID,
		GatePubKey:     mustHex(t, in.GatePubKey),
		Rail:           commitment.Rail(u64(t, in.Rail)),
		RailRef:        in.RailRef,
		Path:           commitment.ReceiptPath(u64(t, in.Path)),
		ExecutedAt:     u64(t, in.ExecutedAt),
	}
}

func TestReceiptValidVectors(t *testing.T) {
	var rf receiptFile
	loadJSON(t, "receipt.json", &rf)
	vf := loadValid(t)
	gate1 := loadKey(t, "gate1")
	require.GreaterOrEqualf(t, len(rf.Cases), 6, "%d receipt vectors", len(rf.Cases))
	for _, rc := range rf.Cases {
		t.Run(rc.ID, func(t *testing.T) {
			r := toReceipt(t, rc.Input)
			wantCanon := mustHex(t, rc.ReceiptCBORHex)
			wantHash := mustHex(t, rc.ReceiptHashHex)
			wantMsg := mustHex(t, rc.SignedMessageHex)
			wantSig := mustHex(t, rc.SignatureHex)
			wantSigned := mustHex(t, rc.SignedReceiptHex)

			require.Equalf(t, "gate1", rc.Signer, "signer %q", rc.Signer)
			require.Equal(t, validCaseByID(t, vf, rc.CommitmentRef).CommitmentHashHex, rc.Input.CommitmentHash, "receipt carries another commitment hash than the vector it references")

			canon, err := commitment.EncodeReceipt(r)
			require.NoErrorf(t, err, "EncodeReceipt: %v\n got %x\nwant %x", err, canon, wantCanon)
			require.Equalf(t, hex.EncodeToString(wantCanon), hex.EncodeToString(canon), "EncodeReceipt: %v\n got %x\nwant %x", err, canon, wantCanon)
			h := commitment.HashReceipt(canon)
			require.Equal(t, hex.EncodeToString(wantHash), hex.EncodeToString(h[:]))
			msg := commitment.ReceiptSigningMessage(h)
			require.Equal(t, hex.EncodeToString(wantMsg), hex.EncodeToString(msg))
			require.Len(t, msg, 54)
			require.EqualValues(t, 21, msg[0])
			require.EqualValues(t, "edicta/v0/receipt-sig", string(msg[1:22]))
			sig := ed25519.Sign(gate1, msg)
			require.Equal(t, hex.EncodeToString(wantSig), hex.EncodeToString(sig))
			signed, err := commitment.EncodeSignedReceipt(&commitment.SignedReceipt{Receipt: *r, Signature: wantSig})
			require.NoErrorf(t, err, "EncodeSignedReceipt: %v\n got %x\nwant %x", err, signed, wantSigned)
			require.Equalf(t, hex.EncodeToString(wantSigned), hex.EncodeToString(signed), "EncodeSignedReceipt: %v\n got %x\nwant %x", err, signed, wantSigned)
			require.LessOrEqualf(t, len(signed), 354, "signed receipt of %d bytes", len(signed))
			require.LessOrEqualf(t, len(signed), commitment.MaxReceiptSize, "signed receipt of %d bytes", len(signed))

			sr, dh, err := commitment.DecodeSignedReceipt(wantSigned)
			require.NoError(t, err, "DecodeSignedReceipt")
			require.Equalf(t, r, &sr.Receipt, "decoded %+v", sr)
			require.Equalf(t, hex.EncodeToString(wantSig), hex.EncodeToString(sr.Signature), "decoded %+v", sr)
			require.Equalf(t, hex.EncodeToString(wantHash), hex.EncodeToString(dh[:]), "decoded %+v", sr)
			vr, vh, err := commitment.VerifyReceipt(wantSigned)
			require.NoError(t, err, "VerifyReceipt")
			require.Equal(t, sr, vr, "VerifyReceipt differs from DecodeSignedReceipt")
			require.Equal(t, dh, vh, "VerifyReceipt differs from DecodeSignedReceipt")
		})
	}
}

func TestReceiptRejectVectors(t *testing.T) {
	var rf receiptFile
	loadJSON(t, "receipt.json", &rf)
	require.GreaterOrEqualf(t, len(rf.Reject), 35, "%d reject vectors", len(rf.Reject))
	for _, rc := range rf.Reject {
		t.Run(rc.ID, func(t *testing.T) {
			b := mustHex(t, rc.SignedReceiptHex)
			_, _, err := commitment.VerifyReceipt(b)
			assertSentinel(t, err, rc.ExpectError)
			if rc.Stage == "D" {
				_, _, derr := commitment.DecodeSignedReceipt(b)
				assertSentinel(t, derr, rc.ExpectError)
			}
		})
	}
}

func TestMaxReceiptSize(t *testing.T) {
	require.EqualValuesf(t, 512, commitment.MaxReceiptSize, "MaxReceiptSize = %d", commitment.MaxReceiptSize)
	_, _, err := commitment.VerifyReceipt(make([]byte, commitment.MaxReceiptSize+1))
	assertSentinel(t, err, "ErrTooLarge")
}

// A receipt signature must not verify as a commitment signature and the
// reverse, and a commitment envelope is not a receipt.
func TestReceiptAndCommitmentDomainsAreSeparate(t *testing.T) {
	var rf receiptFile
	loadJSON(t, "receipt.json", &rf)
	rc := rf.Cases[0]
	h := commitment.Hash(mustHex(t, rc.ReceiptHashHex))
	require.False(t, bytes.Equal(commitment.ReceiptSigningMessage(h), commitment.SigningMessage(h)), "receipt and commitment signing messages are equal")
	pub := loadKey(t, "gate1").Public().(ed25519.PublicKey)
	require.False(t, ed25519.Verify(pub, commitment.SigningMessage(h), mustHex(t, rc.SignatureHex)), "receipt signature verifies under the commitment tag")
	vf := loadValid(t)
	_, _, err := commitment.VerifyReceipt(mustHex(t, vf.Cases[0].EnvelopeHex))
	require.Error(t, err, "a commitment envelope was accepted as a receipt")
	_, _, err = commitment.VerifyForGate(mustHex(t, rc.SignedReceiptHex), 1791000060, toGate(t, vf.Gate), toParams(t, vf.Params))
	require.Error(t, err, "a receipt was accepted as a commitment envelope")
}

// Every single-bit change of a signed receipt must be refused.
func TestEveryBitFlipOfAReceiptIsRejected(t *testing.T) {
	var rf receiptFile
	loadJSON(t, "receipt.json", &rf)
	good := mustHex(t, rf.Cases[0].SignedReceiptHex)
	_, _, err := commitment.VerifyReceipt(good)
	require.NoError(t, err)
	for i := range good {
		for bit := 0; bit < 8; bit++ {
			b := append([]byte(nil), good...)
			b[i] ^= 1 << bit
			_, _, err := commitment.VerifyReceipt(b)
			require.Errorf(t, err, "flip of byte %d bit %d accepted", i, bit)
		}
	}
}
