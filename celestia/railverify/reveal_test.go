package railverify_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/celestia/railverify"
	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/examples/tia-transfer/bankaction"
	"github.com/vgonkivs/edicta/test/bankvec"
	"github.com/vgonkivs/edicta/verifier"
)

func TestActionFromTxVectors(t *testing.T) {
	raw, err := os.ReadFile("../../spec/vectors/profiles/bank-send/action_from_tx.json")
	require.NoError(t, err)
	var f struct {
		TypeURL string `json:"type_url"`
		Cases   []struct {
			ID        string `json:"id"`
			TxRawHex  string `json:"tx_raw_hex"`
			ChainID   string `json:"chain_id"`
			ActionHex string `json:"action_hex"`
		} `json:"cases"`
		Reject []struct {
			ID       string `json:"id"`
			TxRawHex string `json:"tx_raw_hex"`
			ChainID  string `json:"chain_id"`
			Expect   string `json:"expect"`
		} `json:"reject"`
	}
	require.NoError(t, json.Unmarshal(raw, &f))
	require.Equal(t, "/cosmos.bank.v1beta1.MsgSend", f.TypeURL)
	require.NotEmpty(t, f.Cases)
	require.NotEmpty(t, f.Reject)
	for _, c := range f.Cases {
		t.Run(c.ID, func(t *testing.T) {
			got, err := railverify.ActionFromTx(bankvec.Hex(t, c.TxRawHex), c.ChainID)
			require.NoError(t, err)
			assert.Equal(t, c.ActionHex, hex.EncodeToString(got))
		})
	}
	for _, r := range f.Reject {
		t.Run(r.ID, func(t *testing.T) {
			require.Equal(t, "refused", r.Expect)
			got, err := railverify.ActionFromTx(bankvec.Hex(t, r.TxRawHex), r.ChainID)
			require.Error(t, err)
			assert.Nil(t, got)
			assert.True(t, errors.Is(err, railverify.ErrTxMalformed) || errors.Is(err, railverify.ErrNoBankSend), "%v", err)
		})
	}
}

// The minimal vector's action is what the executor signed; the real checker
// rebuilds it from the transaction, so the revealed salt gives the agent's
// action hash, and anything else does not.
func TestRevealThroughTheBankSendChecker(t *testing.T) {
	v := loadVec(t)
	salt := bytes.Repeat([]byte{0x5a}, commitment.ActionSaltSize)
	committed, err := commitment.ActionHash(bankaction.ActionType, salt, v.action)
	require.NoError(t, err)
	in := verifier.ExecutionInput{CommitmentHash: v.hash, ActionType: bankaction.ActionType, RailRef: v.railRef, AnchorHeight: txH - 10}

	revealer := func(t *testing.T, c railverify.Config, primary railverify.TxSource, opts ...railverify.Option) verifier.ActionRevealer {
		t.Helper()
		chk, err := railverify.NewBankSend(c, primary, &fakeHeaders{}, nil, opts...)
		require.NoError(t, err)
		ar, ok := chk.(verifier.ActionRevealer)
		require.True(t, ok, "the bank-send checker offers the reveal path")
		require.True(t, ar.PublicExecution())
		return ar
	}
	serving := func(name string, tx []byte) *fakeSource {
		s := newSource(name)
		s.txs[ref32(t, v.railRef)] = railverify.RawTx{Bytes: tx, Height: txH}
		return s
	}

	t.Run("the executed transaction gives the committed action", func(t *testing.T) {
		src := serving("rpc-a.example", v.txRaw)
		a, err := revealer(t, cfg(), src).ActionFromTx(bg, in)
		require.NoError(t, err)
		assert.Equal(t, v.action, a)
		got, err := commitment.ActionHash(bankaction.ActionType, salt, a)
		require.NoError(t, err)
		assert.Equal(t, committed, got)
		require.Len(t, src.calls, 1)
		assert.False(t, src.calls[0].prove, "the reveal needs only the bytes")
	})

	t.Run("a checker set for another chain never matches the action hash", func(t *testing.T) {
		c := cfg()
		c.ChainID = "celestia"
		a, err := revealer(t, c, serving("rpc-a.example", v.txRaw)).ActionFromTx(bg, in)
		require.NoError(t, err)
		got, err := commitment.ActionHash(bankaction.ActionType, salt, a)
		require.NoError(t, err)
		assert.NotEqual(t, committed, got)
	})

	t.Run("bytes that do not hash to the rail_ref are skipped for an alternate", func(t *testing.T) {
		other := v.withBody(append(bytes.Clone(v.body), 0x20, 0x01))
		alt := serving("rpc-b.example", v.txRaw)
		a, err := revealer(t, cfg(), serving("rpc-a.example", other), railverify.WithAlternates(alt)).ActionFromTx(bg, in)
		require.NoError(t, err)
		assert.Equal(t, v.action, a)
	})

	t.Run("no source with the transaction gives no bytes", func(t *testing.T) {
		a, err := revealer(t, cfg(), newSource("rpc-a.example")).ActionFromTx(bg, in)
		require.ErrorIs(t, err, railverify.ErrTxNotFound)
		assert.Nil(t, a)

		other := v.withBody(append(bytes.Clone(v.body), 0x20, 0x01))
		a, err = revealer(t, cfg(), serving("rpc-a.example", other)).ActionFromTx(bg, in)
		require.ErrorIs(t, err, railverify.ErrTxHashMismatch)
		assert.Nil(t, a)
	})

	t.Run("a transaction that is not a bank send gives no bytes", func(t *testing.T) {
		body := bytes.Replace(bytes.Clone(v.body), []byte("MsgSend"), []byte("MsgBurn"), 1)
		tx := v.withBody(body)
		src := newSource("rpc-a.example")
		src.txs[ref32(t, refOf(tx))] = railverify.RawTx{Bytes: tx, Height: txH}
		in := in
		in.RailRef = refOf(tx)
		a, err := revealer(t, cfg(), src).ActionFromTx(bg, in)
		require.ErrorIs(t, err, railverify.ErrNoBankSend)
		assert.Nil(t, a)
	})

	t.Run("a malformed rail_ref gives no bytes", func(t *testing.T) {
		in := in
		in.RailRef = "ABC"
		_, err := revealer(t, cfg(), serving("rpc-a.example", v.txRaw)).ActionFromTx(bg, in)
		require.ErrorIs(t, err, railverify.ErrRailRefMalformed)
	})

	t.Run("a cancelled context is returned as such", func(t *testing.T) {
		ctx, cancel := context.WithCancel(bg)
		cancel()
		src := newSource("rpc-a.example")
		src.err = context.Canceled
		_, err := revealer(t, cfg(), src).ActionFromTx(ctx, in)
		require.ErrorIs(t, err, context.Canceled)
	})
}

func TestActionFromTxIsStrict(t *testing.T) {
	v := loadVec(t)
	anyMsg := cat([]byte{0x0a, byte(len("/cosmos.bank.v1beta1.MsgSend"))}, []byte("/cosmos.bank.v1beta1.MsgSend"), field(2, v.msg))
	rest := v.body[len(field(1, anyMsg)):]
	require.Equal(t, field(1, anyMsg), v.body[:len(field(1, anyMsg))], "the vector body starts with the MsgSend Any")

	a, err := railverify.ActionFromTx(v.withBody(cat(field(1, anyMsg), rest)), chainID)
	require.NoError(t, err)
	assert.Equal(t, v.action, a)

	for name, body := range map[string][]byte{
		"another field first":            cat(field(2, []byte("x")), field(1, anyMsg), rest),
		"value before type_url":          cat(field(1, cat(field(2, v.msg), field(1, []byte("/cosmos.bank.v1beta1.MsgSend")))), rest),
		"data after the value":           cat(field(1, cat(anyMsg, field(3, []byte{1}))), rest),
		"no value":                       cat(field(1, field(1, []byte("/cosmos.bank.v1beta1.MsgSend"))), rest),
		"empty value":                    cat(field(1, cat(field(1, []byte("/cosmos.bank.v1beta1.MsgSend")), field(2, nil))), rest),
		"longer message length":          cat([]byte{0x0a, 0x80 | byte(len(anyMsg)&0x7f), 0x80 | byte(len(anyMsg)>>7), 0x00}, anyMsg, rest),
		"a type_url with a trailing '/'": cat(field(1, cat(field(1, []byte("/cosmos.bank.v1beta1.MsgSend/")), field(2, v.msg))), rest),
		"empty body":                     {},
	} {
		t.Run(name, func(t *testing.T) {
			a, err := railverify.ActionFromTx(v.withBody(body), chainID)
			require.ErrorIs(t, err, railverify.ErrNoBankSend)
			assert.Nil(t, a)
		})
	}
}
