package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protowire"

	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/examples/tia-transfer/bankaction"
	"github.com/vgonkivs/edicta/examples/tia-transfer/bankmsg"
)

func sprint(format string, a ...any) string { return fmt.Sprintf(format, a...) }

func mustKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	return pub, priv
}

const (
	hrp  = "celestia"
	addr = "celestia1qqp0ztywuvn8agqn6znr4k35eda494vv7klwtc"
	dst  = "celestia1mzkhlmxtluk4gmet2kja0yv8kxc2n07ml6lld3"
)

var chash = commitment.Hash{0xab, 0xcd, 3, 4}

func hx(h commitment.Hash) string { return hex.EncodeToString(h[:]) }

func goodEvidence() *Evidence {
	tx := strings.Repeat("ab", 32)
	e := &Evidence{
		ChainID: "test-1", BlobHeight: 100, CommitmentHash: hx(chash),
		Authorization: AuthorizationEvidence{Verified: true, CommitmentHash: hx(chash)},
		Transfer: TransferEvidence{
			TxHash: tx, Height: 101, Memo: hx(chash), TimeoutHeight: 150, Broadcast: true,
		},
		Receipt: ReceiptEvidence{Verified: true, CommitmentHash: hx(chash), RailRef: tx, ExecutorKey: strings.Repeat("cd", 32)},
	}
	return e
}

func TestEvidenceCheckOK(t *testing.T) {
	require.NoError(t, goodEvidence().Check())
}

func TestEvidenceTransferHeightMustExceedBlobHeight(t *testing.T) {
	for _, tc := range []struct {
		name string
		h    uint64
		ok   bool
	}{{"above", 101, true}, {"far above", 5000, true}, {"equal", 100, false}, {"below", 99, false}, {"zero", 0, false}} {
		t.Run(tc.name, func(t *testing.T) {
			e := goodEvidence()
			e.Transfer.Height = tc.h
			err := e.Check()
			if tc.ok {
				require.NoError(t, err)
				return
			}
			require.ErrorIs(t, err, ErrEvidence)
			assert.Contains(t, err.Error(), "not above blob height")
		})
	}
}

func TestEvidenceMemoMustEqualCommitmentHash(t *testing.T) {
	for _, memo := range []string{"", strings.Repeat("0", 64), strings.ToUpper(hx(chash)), hx(chash) + "00", "hello"} {
		e := goodEvidence()
		e.Transfer.Memo = memo
		err := e.Check()
		require.ErrorIs(t, err, ErrEvidence, memo)
		assert.Contains(t, err.Error(), "memo")
	}
}

func TestEvidenceOtherClaims(t *testing.T) {
	mut := map[string]func(*Evidence){
		"authorization not verified": func(e *Evidence) { e.Authorization.Verified = false },
		"authorization other commit": func(e *Evidence) { e.Authorization.CommitmentHash = strings.Repeat("00", 32) },
		"failed on chain":            func(e *Evidence) { e.Transfer.Code = 5 },
		"not broadcast":              func(e *Evidence) { e.Transfer.Broadcast = false },
		"no timeout":                 func(e *Evidence) { e.Transfer.TimeoutHeight = 0 },
		"bad tx hash":                func(e *Evidence) { e.Transfer.TxHash = "xyz" },
		"receipt not verified":       func(e *Evidence) { e.Receipt.Verified = false },
		"receipt other commitment":   func(e *Evidence) { e.Receipt.CommitmentHash = strings.Repeat("00", 32) },
		"receipt other ref":          func(e *Evidence) { e.Receipt.RailRef = strings.Repeat("00", 32) },
		"receipt no executor":        func(e *Evidence) { e.Receipt.ExecutorKey = "" },
		"no blob height":             func(e *Evidence) { e.BlobHeight = 0 },
		"bad commitment hash":        func(e *Evidence) { e.CommitmentHash = "00" },
	}
	for name, f := range mut {
		t.Run(name, func(t *testing.T) {
			e := goodEvidence()
			f(e)
			require.ErrorIs(t, e.Check(), ErrEvidence)
		})
	}
}

func TestEvidenceDryRun(t *testing.T) {
	e := goodEvidence()
	e.DryRun = true
	e.Transfer.Broadcast, e.Transfer.Height = false, 0
	e.Receipt = ReceiptEvidence{}
	require.NoError(t, e.Check(), "a dry run has no tx height and no receipt")
	e.Transfer.Memo = "wrong"
	require.ErrorIs(t, e.Check(), ErrEvidence, "the memo is checked even in a dry run")
	assert.Contains(t, e.Text(), "NOT broadcast")
}

func TestEvidenceReportsEveryFailure(t *testing.T) {
	e := goodEvidence()
	e.Transfer.Height = 1
	e.Transfer.Memo = "x"
	err := e.Check()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not above blob height")
	assert.Contains(t, err.Error(), "memo")
}

func TestEvidenceOutputs(t *testing.T) {
	e := goodEvidence()
	e.Hints = hintsFor(e)
	txt := e.Text()
	for _, want := range []string{"blob height H:", "commitment_hash:", "equals commitment_hash", "above than H", "receipt (gate)"} {
		assert.Contains(t, txt, want)
	}
	assert.NotContains(t, txt, "http", "no hard-coded explorer or other URL")
	j, err := e.JSON()
	require.NoError(t, err)
	var back Evidence
	require.NoError(t, json.Unmarshal(j, &back))
	assert.Equal(t, e.Transfer, back.Transfer)
	require.NoError(t, back.Check(), "the JSON alone is enough to repeat the checks")
}

func realTxRaw(t *testing.T, h commitment.Hash, th uint64) (txRaw []byte, a bankaction.Action) {
	t.Helper()
	msg, err := bankmsg.Encode(bankmsg.MsgSend{From: addr, To: dst, Denom: "utia", Amount: 10}, hrp)
	require.NoError(t, err)
	a = bankaction.Action{ChainID: "test-1", Msg: msg}
	body, err := bankaction.Body(msg, h, th)
	require.NoError(t, err)
	txRaw = protowire.AppendTag(nil, 1, protowire.BytesType)
	txRaw = protowire.AppendBytes(txRaw, body)
	txRaw = protowire.AppendTag(txRaw, 2, protowire.BytesType)
	txRaw = protowire.AppendBytes(txRaw, []byte("auth-info"))
	txRaw = protowire.AppendTag(txRaw, 3, protowire.BytesType)
	txRaw = protowire.AppendBytes(txRaw, []byte("sig"))
	return txRaw, a
}

func TestMemoComesFromTheSignedBody(t *testing.T) {
	raw, a := realTxRaw(t, chash, 150)
	body, err := bodyOfTxRaw(raw)
	require.NoError(t, err)
	memo, err := memoOfBody(body)
	require.NoError(t, err)
	assert.Equal(t, hx(chash), memo)
	th, err := bankaction.CheckBody(a, chash, body)
	require.NoError(t, err)
	assert.EqualValues(t, 150, th)

	// A transaction signed for another decision carries another memo.
	other := commitment.Hash{9}
	raw2, _ := realTxRaw(t, other, 150)
	body2, err := bodyOfTxRaw(raw2)
	require.NoError(t, err)
	memo2, err := memoOfBody(body2)
	require.NoError(t, err)
	assert.NotEqual(t, hx(chash), memo2)
	e := goodEvidence()
	e.Transfer.Memo = memo2
	require.ErrorIs(t, e.Check(), ErrEvidence)
}

func TestBodyAndMemoParsingRefusals(t *testing.T) {
	_, err := bodyOfTxRaw(nil)
	assert.Error(t, err)
	_, err = bodyOfTxRaw([]byte{0x12, 0x00})
	assert.Error(t, err, "field 2 first")
	_, err = bodyOfTxRaw([]byte{0x0a, 0x05, 0x01})
	assert.Error(t, err, "truncated")

	_, err = memoOfBody([]byte{0x18, 0x01})
	assert.Error(t, err, "no memo")
	twice := protowire.AppendString(protowire.AppendTag(nil, 2, protowire.BytesType), "a")
	twice = protowire.AppendString(protowire.AppendTag(twice, 2, protowire.BytesType), "b")
	_, err = memoOfBody(twice)
	assert.Error(t, err, "two memos")
	_, err = memoOfBody([]byte{0x12, 0x09, 0x01})
	assert.Error(t, err, "truncated memo")
}

func TestHintsNameNoExplorer(t *testing.T) {
	e := goodEvidence()
	for _, h := range hintsFor(e) {
		assert.NotContains(t, strings.ToLower(h), "http")
		assert.NotContains(t, strings.ToLower(h), "scan")
	}
}
