package commitment_test

import (
	"crypto/ed25519"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/commitment"
)

type recordKeys struct {
	Keys map[string]struct {
		SeedHex string `json:"seed_hex"`
	} `json:"keys"`
}

type recordFile struct {
	recordKeys
	Gate struct {
		GateID string `json:"gate_id"`
	} `json:"gate"`
	Cases []struct {
		ID                string `json:"id"`
		CommitmentHashHex string `json:"commitment_hash_hex"`
		RailRef           string `json:"rail_ref"`
		Signer            string `json:"signer"`
		ExecutorPubKeyHex string `json:"executor_pubkey_hex"`
		RecordMessageHex  string `json:"record_message_hex"`
		SignatureHex      string `json:"signature_hex"`
	} `json:"cases"`
	Reject []struct {
		ID                string `json:"id"`
		Stage             string `json:"stage"`
		CommitmentHashHex string `json:"commitment_hash_hex"`
		RailRef           string `json:"rail_ref"`
		ExecutorPubKeyHex string `json:"executor_pubkey_hex"`
		SignatureHex      string `json:"signature_hex"`
		ExpectError       string `json:"expect_error"`
	} `json:"reject"`
}

func executorKey(t testing.TB, name string) ed25519.PrivateKey {
	t.Helper()
	var f recordKeys
	loadJSON(t, "record_request.json", &f)
	k, ok := f.Keys[name]
	require.Truef(t, ok, "no executor key %q", name)
	return ed25519.NewKeyFromSeed(mustHex(t, k.SeedHex))
}

// signRecord signs the record request as the named executor.
func signRecord(t testing.TB, name, gateID string, h []byte, railRef string) []byte {
	t.Helper()
	msg, err := commitment.RecordRequestMessage(commitment.Hash(h), gateID, railRef)
	require.NoError(t, err)
	return ed25519.Sign(executorKey(t, name), msg)
}

func TestRecordRequestValidVectors(t *testing.T) {
	var f recordFile
	loadJSON(t, "record_request.json", &f)
	require.GreaterOrEqual(t, len(f.Cases), 5)
	for _, c := range f.Cases {
		t.Run(c.ID, func(t *testing.T) {
			h := commitment.Hash(mustHex(t, c.CommitmentHashHex))
			msg, err := commitment.RecordRequestMessage(h, f.Gate.GateID, c.RailRef)
			require.NoError(t, err)
			require.Equal(t, c.RecordMessageHex, hex.EncodeToString(msg))
			require.EqualValues(t, 0x18, msg[0])
			require.Equal(t, "edicta/v0/record-request", string(msg[1:25]))
			require.Equal(t, 25+32+1+len(f.Gate.GateID)+1+len(c.RailRef), len(msg))

			priv := executorKey(t, c.Signer)
			sig := ed25519.Sign(priv, msg)
			require.Equal(t, c.SignatureHex, hex.EncodeToString(sig))
			pub := priv.Public().(ed25519.PublicKey)
			require.Equal(t, c.ExecutorPubKeyHex, hex.EncodeToString(pub))
			require.NoError(t, commitment.VerifyRecordRequest(h, f.Gate.GateID, c.RailRef, pub, sig))
		})
	}
}

func TestRecordRequestRejectVectors(t *testing.T) {
	var f recordFile
	loadJSON(t, "record_request.json", &f)
	require.GreaterOrEqual(t, len(f.Reject), 19)
	for _, c := range f.Reject {
		if c.Stage == "R" {
			continue // allowlist and key roles are gate configuration
		}
		t.Run(c.ID, func(t *testing.T) {
			err := commitment.VerifyRecordRequest(commitment.Hash(mustHex(t, c.CommitmentHashHex)), f.Gate.GateID, c.RailRef,
				mustHex(t, c.ExecutorPubKeyHex), mustHex(t, c.SignatureHex))
			assertSentinel(t, err, c.ExpectError)
		})
	}
}

func TestRecordRequestMessageRules(t *testing.T) {
	h := commitment.Hash{1}
	for name, ref := range map[string]string{"empty": "", "129": strings.Repeat("a", 129), "space": "a b", "unicode": "café"} {
		_, err := commitment.RecordRequestMessage(h, "gate-paper-1", ref)
		assert.Errorf(t, err, name)
	}
	msgA, err := commitment.RecordRequestMessage(h, "gate-paper-1", "ab")
	require.NoError(t, err)
	msgB, err := commitment.RecordRequestMessage(commitment.Hash{2}, "gate-paper-1", "ab")
	require.NoError(t, err)
	assert.NotEqual(t, msgA, msgB)
	assert.Len(t, msgA, 25+32+1+12+1+2)
	msgC, err := commitment.RecordRequestMessage(h, "gate-paper-2", "ab")
	require.NoError(t, err)
	assert.NotEqual(t, msgA, msgC, "the gate id is signed")
	_, err = commitment.RecordRequestMessage(h, "", "ab")
	assert.Error(t, err, "an empty gate id")
	assert.EqualValues(t, 24, len(commitment.TagRecordRequest))
}

func TestRecordRequestSignatureIsNotAnotherKind(t *testing.T) {
	var rf receiptFile
	loadJSON(t, "receipt.json", &rf)
	rc := rf.Cases[0]
	h := commitment.Hash(mustHex(t, rc.Input.CommitmentHash))
	pub := executorKey(t, "executor1").Public().(ed25519.PublicKey)
	sig := signRecord(t, "executor1", rc.Input.GateID, h[:], rc.Input.RailRef)
	other := commitment.Hash{9}
	for name, msg := range map[string][]byte{
		"commitment":    commitment.SigningMessage(h),
		"receipt":       commitment.ReceiptSigningMessage(h),
		"authorization": commitment.AuthorizationSigningMessage(h),
	} {
		assert.Falsef(t, ed25519.Verify(pub, msg, sig), "record signature verifies as %s", name)
	}
	assert.Error(t, commitment.VerifyRecordRequest(other, rc.Input.GateID, rc.Input.RailRef, pub, sig))
	assert.Error(t, commitment.VerifyRecordRequest(h, "gate-paper-2", rc.Input.RailRef, pub, sig), "a claim for another gate")
}
