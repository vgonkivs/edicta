// SPDX-License-Identifier: Apache-2.0

package edenescrow

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/engine/policy"
	"github.com/vgonkivs/edicta/internal/evm/rlp"
	"github.com/vgonkivs/edicta/internal/testkit"
)

type mainnetIndex struct {
	Runs []struct {
		ID                      string `json:"id"`
		Dir                     string `json:"dir"`
		ResourceCalled          string `json:"resource_called"`
		Buyer                   string `json:"buyer"`
		PaymentID               string `json:"payment_id"`
		TxHash                  string `json:"tx_hash"`
		PaymentSignatureMessage string `json:"payment_signature_message"`
		Files                   []struct {
			File          string `json:"file"`
			Provenance    string `json:"provenance"`
			ContentLength string `json:"content_length"`
		} `json:"files"`
	} `json:"runs"`
}

type mainnetVectors struct {
	header
	Runs []struct {
		ID           string `json:"id"`
		Requirements struct {
			RequirementsHashHex string `json:"requirements_hash_hex"`
		} `json:"requirements"`
		Deposit struct {
			RailRef       string `json:"rail_ref"`
			UnsignedTxHex string `json:"unsigned_tx_hex"`
			SighashHex    string `json:"sighash_hex"`
			Payer         string `json:"payer"`
		} `json:"deposit"`
		Action struct {
			CBORHex      string      `json:"cbor_hex"`
			Facts        vectorFacts `json:"facts"`
			FactsCBORHex string      `json:"facts_cbor_hex"`
		} `json:"action"`
		PaymentSignature struct {
			RecoveredOverPaymentID string `json:"recovered_over_payment_id"`
			RecoveredOverNonce     string `json:"recovered_over_nonce"`
		} `json:"payment_signature"`
	} `json:"runs"`
}

type paymentSignatureHeader struct {
	X402Version json.RawMessage `json:"x402Version"`
	Resource    json.RawMessage `json:"resource"`
	Accepted    json.RawMessage `json:"accepted"`
	Payload     struct {
		Signature string `json:"signature"`
		PaymentID string `json:"paymentId"`
		Nonce     string `json:"nonce"`
	} `json:"payload"`
}

func readLive(t *testing.T, dir, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(testkit.SpecPath(t, vectorDir, "live", dir, name))
	require.NoError(t, err)
	return b
}

func unhex0x(t *testing.T, s string) []byte {
	t.Helper()
	require.True(t, strings.HasPrefix(s, "0x"), s)
	b, err := hex.DecodeString(s[2:])
	require.NoError(t, err)
	return b
}

// actionFromSigned rebuilds the unsigned transaction from the first nine
// items of a signed one, so a run without a recorded build answer can still
// be decoded and its signature checked with ParseSigned.
func actionFromSigned(t *testing.T, signed []byte, resource string, req [32]byte) []byte {
	t.Helper()
	require.Equal(t, byte(0x02), signed[0])
	top, rest, err := rlp.Next(signed[1:])
	require.NoError(t, err)
	require.Empty(t, rest)
	b := top.Payload
	var items []byte
	for i := 0; i < 9; i++ {
		it, r, err := rlp.Next(b)
		require.NoError(t, err)
		items = append(items, it.Raw...)
		b = r
	}
	action, err := EncodeTxAction(rlp.AppendList([]byte{0x02}, items), resource, req)
	require.NoError(t, err)
	return action
}

func TestMainnetRuns(t *testing.T) {
	var idx mainnetIndex
	require.NoError(t, json.Unmarshal(readLive(t, "", "mainnet-runs.json"), &idx))
	require.Len(t, idx.Runs, 3)
	var vec mainnetVectors
	vb, err := os.ReadFile(testkit.SpecPath(t, vectorDir, "x402_mainnet.json"))
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(vb, &vec))
	assert.Equal(t, profileRevision(t), vec.Revision)
	require.Len(t, vec.Runs, len(idx.Runs))
	for i, run := range idx.Runs {
		v := vec.Runs[i]
		t.Run(run.ID, func(t *testing.T) {
			require.Equal(t, run.ID, v.ID)
			for _, f := range run.Files {
				b := readLive(t, run.Dir, f.File)
				if f.ContentLength != "" {
					assert.Equal(t, f.ContentLength, big.NewInt(int64(len(b))).String(), f.File)
				}
			}
			buyer := [20]byte(unhex0x(t, run.Buyer))
			pid := [32]byte(unhex0x(t, run.PaymentID))

			r, err := DecodePaymentRequired(string(readLive(t, run.Dir, "header-payment-required.b64")))
			require.NoError(t, err)

			signed := unhex0x(t, string(readLive(t, run.Dir, "deposit-signed.hex")))
			assert.Equal(t, strings.TrimPrefix(run.TxHash, "0x"), RailRef(signed), "keccak256(signed) is the recorded tx hash")

			action := actionFromSigned(t, signed, run.ResourceCalled, RequirementsHash(r))
			a, err := DecodeTxAction(action)
			require.NoError(t, err, "form T on chain 714 with the NativeEscrow deposit call")
			assert.Equal(t, uint64(714), a.ChainID)
			assert.Equal(t, pid, a.Deposit.PaymentID, "calldata w0 is the recorded paymentId")
			_, payer, err := ParseSigned(a, signed)
			require.NoError(t, err)
			assert.Equal(t, buyer, payer, "the deposit is signed by the buyer")

			q, err := CheckRequirements(a, r, true)
			require.NoError(t, err, "S4 a to f with the server signature on the wire R")
			assert.Equal(t, pid, q.PaymentID())
			require.NoError(t, CheckAsksForPayment(r, pid))
			m, err := PaymentProofMessage(a, r)
			require.NoError(t, err)
			assert.Equal(t, pid, m)

			for _, f := range run.Files {
				if f.File != "body-deposit-build.json" {
					continue
				}
				built, ba, err := ActionFromDepositBuild(readLive(t, run.Dir, f.File), run.ResourceCalled, RequirementsHash(r))
				require.NoError(t, err)
				assert.Equal(t, action, built, "the build answer gives exactly the transaction that was signed")
				assert.Equal(t, pid, ba.Deposit.PaymentID)
			}

			hv := string(readLive(t, run.Dir, "header-payment-signature.b64"))
			raw, err := base64.StdEncoding.Strict().DecodeString(hv)
			require.NoError(t, err)
			var ps paymentSignatureHeader
			require.NoError(t, json.Unmarshal(raw, &ps))
			assert.Equal(t, "2", string(ps.X402Version))
			assert.Contains(t, string(r), string(ps.Accepted), "accepted is R's entry verbatim")
			assert.Contains(t, string(r), string(ps.Resource), "resource is R's verbatim")
			assert.Equal(t, run.PaymentID, ps.Payload.PaymentID)
			sig := [65]byte(unhex0x(t, ps.Payload.Signature))
			overPID, err := RecoverPersonal(pid, sig)
			require.NoError(t, err)
			overNonce, err := RecoverPersonal([32]byte(unhex0x(t, ps.Payload.Nonce)), sig)
			require.NoError(t, err)
			switch run.PaymentSignatureMessage {
			case "paymentId":
				assert.Equal(t, buyer, overPID, "EIP-191 over the 32 raw paymentId bytes recovers to the buyer")
				assert.NotEqual(t, buyer, overNonce)
			case "nonce":
				assert.NotEqual(t, buyer, overPID, "the refused signature does not recover to the buyer over paymentId")
				assert.Equal(t, buyer, overNonce, "it was made by the buyer over extra.nonce")
			default:
				require.Failf(t, "unknown message field", "%q", run.PaymentSignatureMessage)
			}
			h := RequirementsHash(r)
			assert.Equal(t, v.Requirements.RequirementsHashHex, hex.EncodeToString(h[:]))
			assert.Equal(t, v.Deposit.RailRef, RailRef(signed))
			assert.Equal(t, v.Deposit.UnsignedTxHex, hex.EncodeToString(a.Unsigned()))
			sh := a.SigHash()
			assert.Equal(t, v.Deposit.SighashHex, hex.EncodeToString(sh[:]))
			assert.Equal(t, v.Deposit.Payer, "0x"+hex.EncodeToString(payer[:]))
			assert.Equal(t, v.Action.CBORHex, hex.EncodeToString(action))
			facts, err := New().Extract(action)
			require.NoError(t, err)
			fc, err := policy.EncodeFacts(&facts)
			require.NoError(t, err)
			assert.Equal(t, v.Action.FactsCBORHex, hex.EncodeToString(fc))
			assert.Equal(t, v.PaymentSignature.RecoveredOverPaymentID, "0x"+hex.EncodeToString(overPID[:]))
			assert.Equal(t, v.PaymentSignature.RecoveredOverNonce, "0x"+hex.EncodeToString(overNonce[:]))
			t.Logf("run %s: rail_ref %s payer %x nonce %d value %x fee %x gas %d action %d bytes", run.ID, RailRef(signed), payer, a.Nonce, a.Value, a.MaxFeePerGas, a.GasLimit, len(action))
		})
	}
}
