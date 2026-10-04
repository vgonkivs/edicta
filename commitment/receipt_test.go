package commitment_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/commitment"
)

type receiptInput struct {
	Version        string `json:"version"`
	CommitmentHash string `json:"commitment_hash"`
	GateID         string `json:"gate_id"`
	GatePubKey     string `json:"gate_pubkey"`
	RailRef        string `json:"rail_ref"`
	RecordedAt     string `json:"recorded_at"`
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
		RailRef:        in.RailRef,
		RecordedAt:     u64(t, in.RecordedAt),
	}
}

func TestReceiptValidVectors(t *testing.T) {
	var rf receiptFile
	loadJSON(t, "receipt.json", &rf)
	vf := loadValid(t)
	gate1 := loadKey(t, "gate1")
	require.GreaterOrEqualf(t, len(rf.Cases), 5, "%d receipt vectors", len(rf.Cases))
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
			require.LessOrEqualf(t, len(signed), 350, "signed receipt of %d bytes", len(signed))
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
	require.GreaterOrEqualf(t, len(rf.Reject), 36, "%d reject vectors", len(rf.Reject))
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

// rail_ref is opaque: any ID-charset string of 1..128 characters is carried
// as is, whatever shape a rail uses for its references.
func TestReceiptRailRefIsOpaque(t *testing.T) {
	var rf receiptFile
	loadJSON(t, "receipt.json", &rf)
	base := toReceipt(t, rf.Cases[0].Input)
	for name, ref := range map[string]string{
		"ibkr order id":  "1370093239",
		"evm tx hash":    "0x9f2c1d7e5b8a4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d",
		"opaque token":   "ref-0001",
		"longest":        string(bytes.Repeat([]byte("a"), 128)),
		"single char":    "x",
		"not a number":   "pending",
		"looks like cid": "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi",
	} {
		t.Run(name, func(t *testing.T) {
			r := *base
			r.RailRef = ref
			canon, err := commitment.EncodeReceipt(&r)
			require.NoError(t, err)
			h := commitment.HashReceipt(canon)
			sig := ed25519.Sign(loadKey(t, "gate1"), commitment.ReceiptSigningMessage(h))
			b, err := commitment.EncodeSignedReceipt(&commitment.SignedReceipt{Receipt: r, Signature: sig})
			require.NoError(t, err)
			got, _, err := commitment.VerifyReceipt(b)
			require.NoError(t, err)
			assert.Equal(t, ref, got.Receipt.RailRef)
		})
	}
}

// The receipt vectors cover every rail_ref and recorded_at extreme the
// schema allows, and every receipt names an authorized commitment.
func TestReceiptVectorsReferenceValidCommitments(t *testing.T) {
	var rf receiptFile
	loadJSON(t, "receipt.json", &rf)
	vf := loadValid(t)
	for _, rc := range rf.Cases {
		vc := validCaseByID(t, vf, rc.CommitmentRef)
		assert.Equal(t, vc.CommitmentHashHex, rc.Input.CommitmentHash, rc.ID)
		assert.Equal(t, vf.Gate.GateID, rc.Input.GateID, rc.ID)
	}
}
