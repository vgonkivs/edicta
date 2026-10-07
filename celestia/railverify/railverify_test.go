package railverify_test

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/celestia/railverify"
	"github.com/vgonkivs/edicta/examples/tia-transfer/bankaction"
	"github.com/vgonkivs/edicta/test/bankvec"
	"github.com/vgonkivs/edicta/verifier"
)

// every rejection of the checker, so a test can require that exactly one
// applies.
var sentinels = []error{
	railverify.ErrTxNotFound, railverify.ErrTxSourceUnavailable, railverify.ErrTxHashMismatch, railverify.ErrTxMalformed,
	railverify.ErrRailRefMalformed, railverify.ErrChainConfig, railverify.ErrTxProof, railverify.ErrResultsProof,
	bankaction.ErrBodyMismatch, bankaction.ErrMalformed,
}

// requireOnly requires the error to match want and no other rejection. What a
// source says, or fails to prove, is unchecked; only bytes that hash to the
// signed rail_ref and break a rule, or a malformed signed value, are a
// violation.
func requireOnly(t testing.TB, err, want error) {
	t.Helper()
	require.ErrorIs(t, err, want)
	for _, other := range sentinels {
		if other != want && !errors.Is(want, other) {
			assert.NotErrorIsf(t, err, other, "also matches %v", other)
		}
	}
	violation := errors.Is(want, railverify.ErrTxMalformed) || errors.Is(want, railverify.ErrRailRefMalformed) ||
		errors.Is(want, bankaction.ErrBodyMismatch) || errors.Is(want, bankaction.ErrMalformed)
	if violation {
		assert.ErrorIs(t, err, verifier.ErrExecutionViolation, "bound objects prove it")
		assert.NotErrorIs(t, err, verifier.ErrExecutionUnchecked, "a violation is not a lack of facts")
	} else {
		assert.ErrorIs(t, err, verifier.ErrExecutionUnchecked, "a source's word is never a finding")
		assert.NotErrorIs(t, err, verifier.ErrExecutionViolation)
	}
}

// reasonOf requires the error to carry this reason and returns the sources it
// names.
func reasonOf(t testing.TB, err error, want verifier.Reason) []string {
	t.Helper()
	got, srcs, ok := verifier.ReasonOf(err)
	require.True(t, ok, "the error carries a reason")
	require.Equal(t, want, got)
	return srcs
}

type world struct {
	t       *testing.T
	v       vec
	headers *fakeHeaders
	primary *fakeSource
	alts    []railverify.TxSource
	cross   []railverify.TxSource
	opts    []railverify.Option
	cfg     railverify.Config
	hdrHash []byte
	root    []byte
	proof   json.RawMessage
}

func layoutBig(tx []byte) ([][]byte, int)   { f := fillers(2); return [][]byte{f[0], tx, f[1]}, 1 }
func layoutAlone(tx []byte) ([][]byte, int) { return [][]byte{tx}, 0 }
func layoutMid(tx []byte) ([][]byte, int) {
	return [][]byte{make([]byte, 40), tx, make([]byte, 40)}, 1
}
func layoutSpill(tx []byte) ([][]byte, int) {
	return [][]byte{make([]byte, 300), tx, make([]byte, 300)}, 1
}

func newWorld(t *testing.T) *world { return newWorldIn(t, layoutBig) }

func newWorldIn(t *testing.T, layout func([]byte) ([][]byte, int)) *world {
	t.Helper()
	v := loadVec(t)
	txs, idx := layout(v.txRaw)
	proof, root := proofOf(t, txs, idx)
	raw, hash := headerAt(t, chainID, txH, root)
	w := &world{
		t: t, v: v, cfg: cfg(), hdrHash: hash, root: root, proof: proof,
		headers: &fakeHeaders{byH: map[uint64][]byte{txH: raw}},
		primary: newSource("rpc-a.example"),
	}
	w.put(w.primary, v.txRaw, railverify.RawTx{Bytes: v.txRaw, Height: txH, Code: 0, Proof: proof})
	return w
}

func (w *world) put(s *fakeSource, tx []byte, rt railverify.RawTx) {
	s.txs[ref32(w.t, refOf(tx))] = rt
}

func (w *world) check(tx []byte) (verifier.ExecutionFacts, error) {
	w.t.Helper()
	opts := append([]railverify.Option{railverify.WithAlternates(w.alts...)}, w.opts...)
	c, err := railverify.NewBankSend(w.cfg, w.primary, w.headers, w.cross, opts...)
	require.NoError(w.t, err)
	return c.CheckExecution(bg, w.v.input(tx))
}

func (w *world) ok() (verifier.ExecutionFacts, error) { return w.check(w.v.txRaw) }

func TestConfigValidateBasic(t *testing.T) {
	assert.NoError(t, railverify.Config{ChainID: "mocha-4", HRP: "celestia"}.ValidateBasic())
	for name, c := range map[string]railverify.Config{
		"no chain id":    {HRP: "celestia"},
		"no hrp":         {ChainID: "mocha-4"},
		"empty":          {},
		"chain id space": {ChainID: " ", HRP: "celestia"},
	} {
		assert.Error(t, c.ValidateBasic(), name)
	}
}

func TestNewBankSendChecksItsDependencies(t *testing.T) {
	src := newSource("a.example")
	hs := &fakeHeaders{}
	_, err := railverify.NewBankSend(railverify.Config{}, src, hs, nil)
	assert.Error(t, err, "the config is validated first")
	_, err = railverify.NewBankSend(cfg(), nil, hs, nil)
	assert.Error(t, err)
	_, err = railverify.NewBankSend(cfg(), src, nil, nil)
	assert.Error(t, err)
	_, err = railverify.NewBankSend(cfg(), src, hs, []railverify.TxSource{nil})
	assert.Error(t, err)
	_, err = railverify.NewBankSend(cfg(), src, hs, []railverify.TxSource{newSource("a.example")})
	assert.Error(t, err, "a cross source on the primary's host is not another source")
	_, err = railverify.NewBankSend(cfg(), src, hs, []railverify.TxSource{newSource("b.example"), newSource("b.example")})
	assert.Error(t, err, "two cross sources on one host are one source")
	_, err = railverify.NewBankSend(cfg(), src, hs, []railverify.TxSource{newSource("b.example"), newSource("c.example")})
	assert.NoError(t, err)
}

func TestProvenInclusion(t *testing.T) {
	layouts := map[string]func([]byte) ([][]byte, int){
		"between big transactions":     layoutBig,
		"alone in the block":           layoutAlone,
		"starting inside a share":      layoutMid,
		"spilling into a second share": layoutSpill,
	}
	for name, layout := range layouts {
		t.Run(name, func(t *testing.T) {
			w := newWorldIn(t, layout)
			f, err := w.ok()
			require.NoError(t, err)
			assert.Equal(t, txH, f.Height)
			assert.Equal(t, w.hdrHash, f.HeaderHash, "the hash of the header the checker read the chain id and data root from")
			assert.Equal(t, "proven", f.Inclusion)
			assert.Equal(t, "success", f.Outcome)
			assert.Equal(t, "node-attested", f.Result, "with no results source the code is the node's word")
			assert.Equal(t, "off", f.CrossCheck)
			assert.False(t, f.ChainMismatch)
			assert.Equal(t, []verifier.ExecutionSource{{Name: "rpc-a.example", Role: verifier.RolePrimary, Result: verifier.SourceUsed}}, f.Sources)
			reasonOf(t, f.ResultProblem, verifier.ReasonResultHeaderUnreachable)

			require.Len(t, w.primary.calls, 1)
			assert.Equal(t, ref32(t, w.v.railRef), w.primary.calls[0].hash)
			assert.True(t, w.primary.calls[0].prove, "the primary is asked for the proof")
			assert.Equal(t, []uint64{txH, txH + 1}, w.headers.reads, "the header at the transaction height, then the next one for the result proof")
		})
	}
}

func TestNoProofIsNodeAttested(t *testing.T) {
	for name, p := range map[string]json.RawMessage{"absent": nil, "empty": {}} {
		t.Run(name, func(t *testing.T) {
			w := newWorld(t)
			w.put(w.primary, w.v.txRaw, railverify.RawTx{Bytes: w.v.txRaw, Height: txH, Proof: p})
			f, err := w.ok()
			require.NoError(t, err)
			assert.Equal(t, "node-attested", f.Inclusion)
			assert.Equal(t, "node-attested", f.Result)
			assert.Equal(t, w.hdrHash, f.HeaderHash)
		})
	}
}

func TestAProofThatFailsIsNeverDowngradedToNodeAttested(t *testing.T) {
	w := newWorld(t)
	other, _ := proofOf(t, fillers(3), 1)
	w.put(w.primary, w.v.txRaw, railverify.RawTx{Bytes: w.v.txRaw, Height: txH, Proof: other})
	f, err := w.ok()
	requireOnly(t, err, railverify.ErrTxProof)
	reasonOf(t, err, verifier.ReasonTxProofInvalid)
	assert.Zero(t, f.Height, "no fact is taken from an answer that was set aside")
	assert.Empty(t, f.Inclusion)
}

func TestRailRefMustBeLowerCaseHex(t *testing.T) {
	w := newWorld(t)
	c, err := railverify.NewBankSend(w.cfg, w.primary, w.headers, nil)
	require.NoError(t, err)
	for name, ref := range map[string]string{
		"empty":      "",
		"short":      w.v.railRef[:62],
		"long":       w.v.railRef + "00",
		"upper case": "A9A1550E0BA85FE6F8FACEBF26978B7F7DBFB399987B6D86D78B9B6340245971",
		"0x prefix":  "0x" + w.v.railRef[2:],
		"not hex":    "zz" + w.v.railRef[2:],
		"whitespace": w.v.railRef + "\n",
		"opaque id":  "9876543210",
	} {
		t.Run(name, func(t *testing.T) {
			in := w.v.input(w.v.txRaw)
			in.RailRef = ref
			_, err := c.CheckExecution(bg, in)
			requireOnly(t, err, railverify.ErrRailRefMalformed)
			assert.Empty(t, w.primary.calls, "a reference that cannot be a hash is not looked up")
		})
	}
}

func TestSourceAnswers(t *testing.T) {
	t.Run("not found is unchecked", func(t *testing.T) {
		w := newWorld(t)
		delete(w.primary.txs, ref32(t, w.v.railRef))
		f, err := w.ok()
		requireOnly(t, err, railverify.ErrTxNotFound)
		assert.Equal(t, []string{"rpc-a.example"}, reasonOf(t, err, verifier.ReasonTxNotFound))
		require.Len(t, f.Sources, 1)
		assert.Equal(t, verifier.SourceSetAside, f.Sources[0].Result)
	})
	t.Run("a source that is down is unchecked", func(t *testing.T) {
		w := newWorld(t)
		w.primary.err = railverify.ErrTxSourceUnavailable
		_, err := w.ok()
		requireOnly(t, err, railverify.ErrTxSourceUnavailable)
		reasonOf(t, err, verifier.ReasonTxSourceUnavailable)
	})
	t.Run("an unclassified source error is unchecked too", func(t *testing.T) {
		w := newWorld(t)
		w.primary.err = errors.New("connection reset")
		_, err := w.ok()
		require.Error(t, err)
		assert.ErrorIs(t, err, verifier.ErrExecutionUnchecked, "no fact was established")
		assert.NotErrorIs(t, err, railverify.ErrTxHashMismatch)
	})
}

func TestBytesMustHashToTheReceiptsRef(t *testing.T) {
	t.Run("other bytes under the reference", func(t *testing.T) {
		w := newWorld(t)
		other := append([]byte(nil), w.v.txRaw...)
		other[len(other)-1] ^= 1
		w.put(w.primary, w.v.txRaw, railverify.RawTx{Bytes: other, Height: txH, Proof: w.proof})
		_, err := w.ok()
		requireOnly(t, err, railverify.ErrTxHashMismatch)
		reasonOf(t, err, verifier.ReasonTxHashMismatch)
	})
	t.Run("empty bytes", func(t *testing.T) {
		w := newWorld(t)
		w.put(w.primary, w.v.txRaw, railverify.RawTx{Bytes: nil, Height: txH})
		_, err := w.ok()
		requireOnly(t, err, railverify.ErrTxHashMismatch)
	})
	t.Run("the hash field of the answer is not used", func(t *testing.T) {
		w := newWorld(t)
		raw := w.v.txRaw
		wrong := append([]byte(nil), raw...)
		wrong[0] ^= 1
		w.put(w.primary, raw, railverify.RawTx{Bytes: wrong, Height: txH})
		_, err := w.ok()
		requireOnly(t, err, railverify.ErrTxHashMismatch)
	})
}

func TestTxRawIsDecodedStrictly(t *testing.T) {
	v := loadVec(t)
	tests := []struct {
		name string
		tx   []byte
	}{
		{"no signature", cat(field(1, v.body), field(2, v.auth))},
		{"body twice", cat(field(1, v.body), field(1, v.body), field(2, v.auth), field(3, v.sig))},
		{"another body last", cat(field(1, v.body), field(2, v.auth), field(1, []byte("last wins in the chain's decoder")), field(3, v.sig))},
		{"auth info twice", cat(field(1, v.body), field(2, v.auth), field(2, v.auth), field(3, v.sig))},
		{"auth info first", cat(field(2, v.auth), field(1, v.body), field(3, v.sig))},
		{"signature first", cat(field(3, v.sig), field(1, v.body), field(2, v.auth))},
		{"signature between", cat(field(1, v.body), field(3, v.sig), field(2, v.auth), field(3, v.sig))},
		{"no body", cat(field(2, v.auth), field(3, v.sig))},
		{"no auth info", cat(field(1, v.body), field(3, v.sig))},
		{"unknown field", cat(field(1, v.body), field(2, v.auth), field(3, v.sig), field(4, []byte{1}))},
		{"trailing zero", append(v.txRaw[:len(v.txRaw):len(v.txRaw)], 0)},
		{"trailing tag", append(v.txRaw[:len(v.txRaw):len(v.txRaw)], 0x0a)},
		{"truncated", v.txRaw[:len(v.txRaw)-1]},
		{"body as a varint", cat([]byte{0x08, 0x01}, field(2, v.auth), field(3, v.sig))},
		{"empty", []byte{}},
		{"garbage", []byte("not a transaction at all")},
		{"body length not in shortest form", longLen(v)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w := newWorld(t)
			w.put(w.primary, tc.tx, railverify.RawTx{Bytes: tc.tx, Height: txH})
			in := w.v.input(tc.tx)
			c, err := railverify.NewBankSend(w.cfg, w.primary, w.headers, nil)
			require.NoError(t, err)
			_, err = c.CheckExecution(bg, in)
			requireOnly(t, err, railverify.ErrTxMalformed)
		})
	}
	t.Run("two signatures are fine", func(t *testing.T) {
		tx := cat(field(1, v.body), field(2, v.auth), field(3, v.sig), field(3, v.sig))
		w := newWorld(t)
		w.put(w.primary, tx, railverify.RawTx{Bytes: tx, Height: txH})
		c, err := railverify.NewBankSend(w.cfg, w.primary, w.headers, nil)
		require.NoError(t, err)
		_, err = c.CheckExecution(bg, w.v.input(tx))
		require.NoError(t, err)
	})
}

// longLen is the vector transaction with the body length padded by a
// continuation byte.
func longLen(v vec) []byte {
	n := len(v.body)
	var b []byte
	b = append(b, 0x0a, byte(n&0x7f)|0x80, byte(n>>7)|0x80, 0x00)
	b = append(b, v.body...)
	return cat(b, field(2, v.auth), field(3, v.sig))
}

func TestChainIdOfTheHeader(t *testing.T) {
	for name, chain := range map[string]string{"another chain": "mocha-5", "the chain id differs in case": "Mocha-4"} {
		t.Run("the header's chain id is another one: "+name, func(t *testing.T) {
			w := newWorld(t)
			raw, _ := headerAt(t, chain, txH, w.root)
			w.headers.byH[txH] = raw
			f, err := w.ok()
			require.NoError(t, err, "the checker reports the fact, and the outcome rule judges it")
			assert.True(t, f.ChainMismatch)
			assert.Equal(t, "proven", f.Inclusion)

			j := verifier.JudgeCheck(f, err, txH-10)
			assert.Equal(t, verifier.StatusFail, j.Status, "a proven inclusion in another chain's block")
			assert.ErrorIs(t, j.Err, railverify.ErrChainMismatch)

			f.Inclusion = "node-attested"
			j = verifier.JudgeCheck(f, nil, txH-10)
			assert.Equal(t, verifier.StatusUnchecked, j.Status, "without a proof the block is the source's claim")
			assert.Equal(t, verifier.ReasonChainUnbound, j.Reason)
		})
	}
	t.Run("the configured chain is another one", func(t *testing.T) {
		w := newWorld(t)
		w.cfg.ChainID = "mocha-5"
		_, err := w.ok()
		requireOnly(t, err, railverify.ErrChainConfig)
		reasonOf(t, err, verifier.ReasonChainConfig)
		assert.Empty(t, w.primary.calls, "no source is asked")
	})
	t.Run("the action names another chain", func(t *testing.T) {
		w := newWorld(t)
		a, err := bankaction.Encode(bankaction.Action{ChainID: "mocha-5", Msg: w.v.msg})
		require.NoError(t, err)
		in := w.v.input(w.v.txRaw)
		in.Action = a
		c, err := railverify.NewBankSend(w.cfg, w.primary, w.headers, nil)
		require.NoError(t, err)
		_, err = c.CheckExecution(bg, in)
		requireOnly(t, err, railverify.ErrChainConfig)
		assert.Empty(t, w.primary.calls)
	})
	t.Run("an action that does not decode", func(t *testing.T) {
		w := newWorld(t)
		in := w.v.input(w.v.txRaw)
		in.Action = []byte("garbage")
		c, err := railverify.NewBankSend(w.cfg, w.primary, w.headers, nil)
		require.NoError(t, err)
		_, err = c.CheckExecution(bg, in)
		requireOnly(t, err, bankaction.ErrMalformed)
	})
	t.Run("a header the trusted chain cannot give is unchecked", func(t *testing.T) {
		w := newWorld(t)
		w.headers.err = errors.New("no such header")
		f, err := w.ok()
		require.Error(t, err)
		assert.ErrorIs(t, err, verifier.ErrExecutionUnchecked)
		reasonOf(t, err, verifier.ReasonHeaderNotLinking)
		require.Len(t, f.Sources, 1)
		assert.Equal(t, verifier.SourceSetAside, f.Sources[0].Result, "the candidate is set aside")
	})
	t.Run("a header that does not decode is not a chain mismatch", func(t *testing.T) {
		w := newWorld(t)
		w.headers.byH[txH] = []byte{0xff, 0xff}
		_, err := w.ok()
		require.Error(t, err)
		assert.ErrorIs(t, err, verifier.ErrExecutionUnchecked)
		reasonOf(t, err, verifier.ReasonHeaderNotLinking)
	})
	t.Run("a header of another height", func(t *testing.T) {
		w := newWorld(t)
		raw, _ := headerAt(t, chainID, txH+1, w.root)
		w.headers.byH[txH] = raw
		_, err := w.ok()
		require.Error(t, err)
		reasonOf(t, err, verifier.ReasonHeaderNotLinking)
	})
	t.Run("the reason of the trusted chain is kept", func(t *testing.T) {
		for _, reason := range []verifier.Reason{verifier.ReasonHeaderAboveCheckpoint, verifier.ReasonHeaderNotLinking} {
			w := newWorld(t)
			w.headers.err = verifier.WithReason(reason, []string{"headers.example"}, errors.New("trust"))
			_, err := w.ok()
			assert.Equal(t, []string{"headers.example"}, reasonOf(t, err, reason))
		}
	})
	t.Run("a disagreement about the header ends the check and keeps the answer used", func(t *testing.T) {
		w := newWorld(t)
		alt := newSource("rpc-b.example")
		w.put(alt, w.v.txRaw, railverify.RawTx{Bytes: w.v.txRaw, Height: txH, Proof: w.proof})
		w.alts = []railverify.TxSource{alt}
		w.headers.err = verifier.WithReason(verifier.ReasonHeaderDisagreement, []string{"rpc-x.example"}, errors.New("cross"))
		f, err := w.ok()
		assert.Equal(t, []string{"rpc-x.example"}, reasonOf(t, err, verifier.ReasonHeaderDisagreement))
		assert.Empty(t, alt.calls, "no other tx source can settle a disagreement about headers")
		require.Len(t, f.Sources, 1)
		assert.Equal(t, verifier.SourceUsed, f.Sources[0].Result)
	})
}

func TestBodyEqualsTheAuthorizedMessage(t *testing.T) {
	v := loadVec(t)
	txs := bankvec.Txs(t)
	require.NotEmpty(t, txs.Reject)
	byRef := map[string][]byte{}
	for _, c := range bankvec.Msgs(t).Cases {
		byRef[c.ID] = bankvec.Hex(t, c.MsgHex)
	}
	for _, r := range txs.Reject {
		t.Run(r.ID, func(t *testing.T) {
			require.Contains(t, byRef, r.MsgRef)
			tx := v.withBody(bankvec.Hex(t, r.BodyHex))
			w := newWorld(t)
			w.v.hash = hashOf(t, r.HashHex)
			act, err := bankaction.Encode(bankaction.Action{ChainID: chainID, Msg: byRef[r.MsgRef]})
			require.NoError(t, err)
			w.v.action = act
			w.put(w.primary, tx, railverify.RawTx{Bytes: tx, Height: txH})
			_, err = w.check(tx)
			requireOnly(t, err, bankaction.ErrBodyMismatch)
		})
	}
	t.Run("the vector body of another decision", func(t *testing.T) {
		w := newWorld(t)
		w.v.hash[0] ^= 1
		_, err := w.ok()
		requireOnly(t, err, bankaction.ErrBodyMismatch)
	})
	t.Run("a different message under the same memo", func(t *testing.T) {
		w := newWorld(t)
		typical, _ := bankvec.Msg(t, "msg_typical")
		act, err := bankaction.Encode(bankaction.Action{ChainID: chainID, Msg: typical})
		require.NoError(t, err)
		w.v.action = act
		_, err = w.ok()
		requireOnly(t, err, bankaction.ErrBodyMismatch)
	})
}

func TestProofAndCodeOrdering(t *testing.T) {
	t.Run("a failed code is a fact, and a source's word", func(t *testing.T) {
		w := newWorld(t)
		w.put(w.primary, w.v.txRaw, railverify.RawTx{Bytes: w.v.txRaw, Height: txH, Code: 11, Proof: w.proof})
		f, err := w.ok()
		require.NoError(t, err)
		assert.Equal(t, "failure", f.Outcome)
		assert.Equal(t, "node-attested", f.Result)
		j := verifier.JudgeCheck(f, err, txH-10)
		assert.Equal(t, verifier.StatusUnchecked, j.Status, "no result proof backs the code")
		assert.Equal(t, verifier.ReasonCodeUnproven, j.Reason)
		assert.ErrorIs(t, j.Err, railverify.ErrResultUnconfirmed)
	})
	t.Run("a body mismatch is reported before a failed code", func(t *testing.T) {
		w := newWorld(t)
		w.v.hash[0] ^= 1
		w.put(w.primary, w.v.txRaw, railverify.RawTx{Bytes: w.v.txRaw, Height: txH, Code: 11})
		_, err := w.ok()
		requireOnly(t, err, bankaction.ErrBodyMismatch)
	})
	t.Run("a bad proof is reported before a failed code", func(t *testing.T) {
		w := newWorld(t)
		other, _ := proofOf(t, fillers(3), 1)
		w.put(w.primary, w.v.txRaw, railverify.RawTx{Bytes: w.v.txRaw, Height: txH, Code: 11, Proof: other})
		_, err := w.ok()
		requireOnly(t, err, railverify.ErrTxProof)
	})
	t.Run("a failed code without a proof", func(t *testing.T) {
		w := newWorld(t)
		w.put(w.primary, w.v.txRaw, railverify.RawTx{Bytes: w.v.txRaw, Height: txH, Code: 5})
		f, err := w.ok()
		require.NoError(t, err)
		assert.Equal(t, "failure", f.Outcome)
		assert.Equal(t, "node-attested", f.Inclusion)
		assert.Equal(t, verifier.StatusUnchecked, verifier.JudgeCheck(f, err, txH-10).Status)
	})
	t.Run("a hash mismatch comes before everything", func(t *testing.T) {
		w := newWorld(t)
		bad := append([]byte(nil), w.v.txRaw...)
		bad[3] ^= 1
		w.put(w.primary, w.v.txRaw, railverify.RawTx{Bytes: bad, Height: txH, Code: 11})
		w.v.hash[0] ^= 1
		_, err := w.ok()
		requireOnly(t, err, railverify.ErrTxHashMismatch)
	})
}

func TestProofAgainstTheHeadersDataRoot(t *testing.T) {
	t.Run("the header's data root is another one", func(t *testing.T) {
		w := newWorld(t)
		raw, _ := headerAt(t, chainID, txH, make([]byte, 32))
		w.headers.byH[txH] = raw
		_, err := w.ok()
		requireOnly(t, err, railverify.ErrTxProof)
	})
	t.Run("the proof is for another block", func(t *testing.T) {
		w := newWorld(t)
		_, otherRoot := proofOf(t, fillers(3), 0)
		raw, _ := headerAt(t, chainID, txH, otherRoot)
		w.headers.byH[txH] = raw
		_, err := w.ok()
		requireOnly(t, err, railverify.ErrTxProof)
	})
	t.Run("the proof is of another transaction", func(t *testing.T) {
		w := newWorld(t)
		f := fillers(2)
		other, root := proofOf(t, [][]byte{f[0], w.v.txRaw, f[1]}, 0)
		raw, _ := headerAt(t, chainID, txH, root)
		w.headers.byH[txH] = raw
		w.put(w.primary, w.v.txRaw, railverify.RawTx{Bytes: w.v.txRaw, Height: txH, Proof: other})
		_, err := w.ok()
		requireOnly(t, err, railverify.ErrTxProof)
	})
}

func TestCrossSources(t *testing.T) {
	good := func(w *world, name string) *fakeSource {
		s := newSource(name)
		w.put(s, w.v.txRaw, railverify.RawTx{Bytes: w.v.txRaw, Height: txH, Code: 0, Proof: w.proof})
		return s
	}
	t.Run("agreeing sources are reported but do not prove the result", func(t *testing.T) {
		w := newWorld(t)
		a, b := good(w, "rpc-b.example"), good(w, "rpc-c.example")
		w.cross = []railverify.TxSource{a, b}
		f, err := w.ok()
		require.NoError(t, err)
		assert.Equal(t, "pass", f.CrossCheck)
		assert.Equal(t, "cross-confirmed", f.Result)
		var got []string
		for _, s := range f.Sources {
			got = append(got, s.Name+"/"+s.Role+"/"+s.Result)
		}
		assert.Equal(t, []string{"rpc-a.example/primary/used", "rpc-b.example/cross/agree", "rpc-c.example/cross/agree"}, got)
		j := verifier.JudgeCheck(f, err, txH-10)
		assert.Equal(t, verifier.StatusUnchecked, j.Status, "agreement of sources is not a result proof")
		assert.Equal(t, verifier.ReasonResultHeaderUnreachable, j.Reason, "no header after the block, so no result proof")
		for _, s := range []*fakeSource{a, b} {
			require.Len(t, s.calls, 1)
			assert.Equal(t, ref32(t, w.v.railRef), s.calls[0].hash)
			assert.False(t, s.calls[0].prove, "a cross source is asked without the proof")
		}
	})
	// What a cross source says that contradicts the used answer is a
	// disagreement; bytes that do not hash to rail_ref are a fault of that
	// source and say nothing about the answer.
	cases := map[string]struct {
		mod    func(w *world, s *fakeSource)
		cross  string
		result string
	}{
		"another height": {func(w *world, s *fakeSource) {
			w.put(s, w.v.txRaw, railverify.RawTx{Bytes: w.v.txRaw, Height: txH + 1})
		}, "mismatch", verifier.SourceDisagree},
		"another code": {func(w *world, s *fakeSource) {
			w.put(s, w.v.txRaw, railverify.RawTx{Bytes: w.v.txRaw, Height: txH, Code: 11})
		}, "mismatch", verifier.SourceDisagree},
		"other bytes": {func(w *world, s *fakeSource) {
			b := append([]byte(nil), w.v.txRaw...)
			b[len(b)-1] ^= 1
			w.put(s, w.v.txRaw, railverify.RawTx{Bytes: b, Height: txH})
		}, "unavailable", verifier.SourceFault},
		"empty bytes": {func(w *world, s *fakeSource) {
			w.put(s, w.v.txRaw, railverify.RawTx{Height: txH})
		}, "unavailable", verifier.SourceFault},
	}
	for name, tc := range cases {
		t.Run("a cross source with "+name, func(t *testing.T) {
			w := newWorld(t)
			bad := newSource("rpc-b.example")
			tc.mod(w, bad)
			w.cross = []railverify.TxSource{bad}
			f, err := w.ok()
			require.NoError(t, err, "the checker reports it, and the outcome rule judges it")
			assert.Equal(t, tc.cross, f.CrossCheck)
			assert.Equal(t, "proven", f.Inclusion)
			require.Len(t, f.Sources, 2)
			assert.Equal(t, tc.result, f.Sources[1].Result)
			j := verifier.JudgeCheck(f, err, txH-10)
			assert.Equal(t, verifier.StatusUnchecked, j.Status, "a hostile cross source never causes invalid, and never valid")
			if tc.cross == "mismatch" {
				assert.Equal(t, verifier.ReasonCrossDisagree, j.Reason)
				assert.Equal(t, []string{"rpc-a.example", "rpc-b.example"}, j.Sources)
			}
		})
	}
	mismatch := map[string]func(w *world, s *fakeSource){"another code": cases["another code"].mod}
	t.Run("one mismatch beats agreeing and unavailable sources", func(t *testing.T) {
		w := newWorld(t)
		bad := newSource("rpc-b.example")
		mismatch["another code"](w, bad)
		down := newSource("rpc-d.example")
		down.err = errors.New("down")
		w.cross = []railverify.TxSource{good(w, "rpc-c.example"), down, bad}
		f, err := w.ok()
		require.NoError(t, err)
		assert.Equal(t, "mismatch", f.CrossCheck)
	})
	t.Run("not found is unavailable", func(t *testing.T) {
		w := newWorld(t)
		w.cross = []railverify.TxSource{newSource("rpc-b.example")}
		f, err := w.ok()
		require.NoError(t, err)
		assert.Equal(t, "unavailable", f.CrossCheck)
	})
	t.Run("an error is unavailable", func(t *testing.T) {
		w := newWorld(t)
		down := newSource("rpc-b.example")
		down.err = railverify.ErrTxSourceUnavailable
		w.cross = []railverify.TxSource{down}
		f, err := w.ok()
		require.NoError(t, err)
		assert.Equal(t, "unavailable", f.CrossCheck)
	})
	t.Run("agreeing and unavailable is unavailable, not pass", func(t *testing.T) {
		w := newWorld(t)
		down := newSource("rpc-d.example")
		down.err = errors.New("down")
		w.cross = []railverify.TxSource{good(w, "rpc-c.example"), down}
		f, err := w.ok()
		require.NoError(t, err)
		assert.Equal(t, "unavailable", f.CrossCheck)
	})
	t.Run("sources are asked only after the primary passed everything", func(t *testing.T) {
		w := newWorld(t)
		s := good(w, "rpc-b.example")
		w.cross = []railverify.TxSource{s}
		other, _ := proofOf(t, fillers(3), 1)
		w.put(w.primary, w.v.txRaw, railverify.RawTx{Bytes: w.v.txRaw, Height: txH, Proof: other})
		_, err := w.ok()
		requireOnly(t, err, railverify.ErrTxProof)
		assert.Empty(t, s.calls)
	})
}
