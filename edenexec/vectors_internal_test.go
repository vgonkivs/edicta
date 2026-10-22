// SPDX-License-Identifier: Apache-2.0

package edenexec

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/edenescrow"
	"github.com/vgonkivs/edicta/internal/testkit"
)

const vectorDir = "vectors/profiles/eden-escrow"

// profileRevision is the revision the profile document states today; every
// vector file must carry exactly it.
func profileRevision(t testing.TB) string {
	t.Helper()
	b, err := os.ReadFile(testkit.SpecPath(t, "profiles/eden-escrow-v1.md"))
	require.NoError(t, err)
	m := regexp.MustCompile("Status: revision `(eden-escrow-v1-draft\\.[0-9]+)`").FindSubmatch(b)
	require.NotNil(t, m, "profile document has no revision line")
	return string(m[1])
}

func loadVector(t testing.TB, name string, v any) {
	t.Helper()
	b, err := os.ReadFile(testkit.SpecPath(t, vectorDir, name))
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(b, v))
	var hdr struct {
		Revision string `json:"revision"`
	}
	require.NoError(t, json.Unmarshal(b, &hdr))
	if hdr.Revision != "" {
		require.Equal(t, profileRevision(t), hdr.Revision, name)
	}
}

func unhex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
	require.NoError(t, err, s)
	return b
}

func hash32(t testing.TB, s string) [32]byte {
	t.Helper()
	var h [32]byte
	b := unhex(t, s)
	require.Len(t, b, 32)
	copy(h[:], b)
	return h
}

func addr20(t testing.TB, s string) [20]byte {
	t.Helper()
	var a [20]byte
	b := unhex(t, s)
	require.Len(t, b, 20)
	copy(a[:], b)
	return a
}

func devBuild() bool { return edenescrow.RegisteredExtractorID() == edenescrow.DevExtractorID }

type actionFile struct {
	Cases []struct {
		ID      string `json:"id"`
		Build   string `json:"build"`
		CBORHex string `json:"cbor_hex"`
	} `json:"cases"`
}

// actions returns the decoded actions of action.json this build accepts.
func actions(t testing.TB) map[string]edenescrow.TxAction {
	t.Helper()
	var f actionFile
	loadVector(t, "action.json", &f)
	out := map[string]edenescrow.TxAction{}
	for _, c := range f.Cases {
		if c.Build == "edictadev" && !devBuild() {
			continue
		}
		a, err := edenescrow.DecodeTxAction(unhex(t, c.CBORHex))
		require.NoError(t, err, c.ID)
		out[c.ID] = a
	}
	return out
}

type signedFile struct {
	Cases []struct {
		ID        string `json:"id"`
		ActionRef string `json:"action_ref"`
		SignedHex string `json:"signed_hex"`
		RailRef   string `json:"rail_ref"`
		Payer     string `json:"payer"`
	} `json:"cases"`
	RailRef []struct {
		ID      string `json:"id"`
		RailRef string `json:"rail_ref"`
		Expect  string `json:"expect"`
		Status  string `json:"status"`
	} `json:"rail_ref"`
	ExactTx []struct {
		ID        string `json:"id"`
		ActionRef string `json:"action_ref"`
		SignedHex string `json:"signed_hex"`
		RailRef   string `json:"rail_ref"`
		Expect    string `json:"expect"`
		Payer     string `json:"payer"`
	} `json:"exact_tx"`
}

func TestVectorsRailRef(t *testing.T) {
	var f signedFile
	loadVector(t, "signed.json", &f)
	require.NotEmpty(t, f.RailRef)
	a := actions(t)["tx_f14_714"]
	for _, c := range f.RailRef {
		t.Run(c.ID, func(t *testing.T) {
			h, err := ParseRailRef(c.RailRef)
			if c.Expect == "ok" {
				require.NoError(t, err)
				assert.Equal(t, c.RailRef, hex.EncodeToString(h[:]))
				return
			}
			require.ErrorIs(t, err, ErrMalformedRailRef)
			require.Equal(t, string(ReasonMalformedRailRef), c.Expect)

			// The report is unchecked and asks no source.
			src := &FakeSource{SrcName: "a"}
			chk := newTestChecker(t, Config{}, src)
			rep, err := chk.Settlement(context.Background(), Target{Action: a, RailRef: c.RailRef})
			require.NoError(t, err)
			assert.Equal(t, Status(c.Status), rep.Status)
			assert.Equal(t, ReasonMalformedRailRef, rep.Reason)
			require.ErrorIs(t, rep.Err, ErrMalformedRailRef)
			assert.Zero(t, src.TotalCalls())
		})
	}
}

func TestVectorsSignedCases(t *testing.T) {
	var f signedFile
	loadVector(t, "signed.json", &f)
	acts := actions(t)
	for _, c := range f.Cases {
		t.Run(c.ID, func(t *testing.T) {
			a, ok := acts[c.ActionRef]
			if !ok {
				t.Skip("action of another build")
			}
			signed := unhex(t, c.SignedHex)
			assert.Equal(t, c.RailRef, hexOf(keccak256(signed)))
			payer, err := CheckExactTx(signed, a)
			require.NoError(t, err)
			assert.Equal(t, addr20(t, c.Payer), payer)
		})
	}
}

func TestVectorsExactTx(t *testing.T) {
	var f signedFile
	loadVector(t, "signed.json", &f)
	acts := actions(t)
	require.Len(t, f.ExactTx, 29)
	for _, c := range f.ExactTx {
		t.Run(c.ID, func(t *testing.T) {
			a, ok := acts[c.ActionRef]
			if !ok {
				t.Skip("action of another build")
			}
			signed := unhex(t, c.SignedHex)
			assert.Equal(t, c.RailRef, hexOf(keccak256(signed)))
			payer, err := CheckExactTx(signed, a)
			switch c.Expect {
			case "pass":
				require.NoError(t, err)
				assert.Equal(t, addr20(t, c.Payer), payer)
			case string(ReasonWrongTx):
				require.ErrorIs(t, err, ErrWrongTx)
				require.ErrorIs(t, err, ErrViolation)
				require.ErrorIs(t, err, edenescrow.ErrSignedMismatch)
				assert.Equal(t, ReasonWrongTx, ReasonOf(err))
			default:
				t.Fatalf("unknown expectation %q", c.Expect)
			}
		})
	}
}

type vectorLog struct {
	Address          string   `json:"address"`
	Topics           []string `json:"topics"`
	Data             string   `json:"data"`
	BlockHash        string   `json:"blockHash"`
	TransactionHash  string   `json:"transactionHash"`
	TransactionIndex string   `json:"transactionIndex"`
	Removed          bool     `json:"removed"`
}

func quantityOf(t testing.TB, s string) uint64 {
	t.Helper()
	v, err := strconv.ParseUint(strings.TrimPrefix(s, "0x"), 16, 64)
	require.NoError(t, err, s)
	return v
}

func TestVectorsDepositEvent(t *testing.T) {
	var f struct {
		DepositEvent []struct {
			ID        string      `json:"id"`
			ActionRef string      `json:"action_ref"`
			TxHash    string      `json:"tx_hash"`
			BlockHash string      `json:"block_hash"`
			TxIndex   string      `json:"transaction_index"`
			From      string      `json:"from"`
			Escrow    string      `json:"escrow"`
			Status    string      `json:"status"`
			Logs      []vectorLog `json:"logs"`
			Expect    string      `json:"expect"`
		} `json:"deposit_event"`
		Event struct {
			Topic0Hex string `json:"topic0_hex"`
		} `json:"event"`
	}
	loadVector(t, "settlement.json", &f)
	assert.Equal(t, f.Event.Topic0Hex, hex.EncodeToString(DepositTopic[:]))
	assert.Equal(t, DepositTopic, keccak256([]byte("NativeEscrowDeposited(bytes32,address,address,address,uint256,uint256,uint256,uint256)")))
	acts := actions(t)
	require.Len(t, f.DepositEvent, 22)
	for _, c := range f.DepositEvent {
		t.Run(c.ID, func(t *testing.T) {
			a := acts[c.ActionRef]
			status, err := strconv.ParseUint(c.Status, 10, 64)
			require.NoError(t, err)
			rc := ReceiptView{
				Type: TxDynamicFee, Status: status, TxHash: hash32(t, c.TxHash), BlockHash: hash32(t, c.BlockHash),
				Index: quantityOf(t, c.TxIndex),
			}
			for _, l := range c.Logs {
				lv := LogView{
					Address: addr20(t, l.Address), Data: unhex(t, l.Data), BlockHash: hash32(t, l.BlockHash),
					TxHash: hash32(t, l.TransactionHash), Index: quantityOf(t, l.TransactionIndex), Removed: l.Removed,
				}
				for _, tp := range l.Topics {
					lv.Topics = append(lv.Topics, hash32(t, tp))
				}
				rc.Logs = append(rc.Logs, lv)
			}
			out, err := CheckDeposit(rc, a, addr20(t, c.From), addr20(t, c.Escrow))
			switch c.Expect {
			case string(OutcomeExecuted), string(OutcomeReverted):
				require.NoError(t, err)
				assert.Equal(t, Outcome(c.Expect), out)
			case string(ReasonLogMismatch):
				require.ErrorIs(t, err, ErrLogMismatch)
				assert.Equal(t, ReasonLogMismatch, ReasonOf(err))
			default:
				t.Fatalf("unknown expectation %q", c.Expect)
			}
		})
	}
}
