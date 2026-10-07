package railverify_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/celestiaorg/celestia-app/v10/pkg/proof"
	"github.com/celestiaorg/go-square/v4"
	"github.com/celestiaorg/go-square/v4/share"
	blobtx "github.com/celestiaorg/go-square/v4/tx"
	cmtjson "github.com/cometbft/cometbft/libs/json"
	core "github.com/cometbft/cometbft/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/celestia/railverify"
)

func live(t testing.TB) (tx []byte, proofJSON json.RawMessage, dataHash []byte) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "tx_prove_1442606.json"))
	require.NoError(t, err)
	var env struct {
		Result struct {
			Tx    []byte          `json:"tx"`
			Proof json.RawMessage `json:"proof"`
		} `json:"result"`
	}
	require.NoError(t, json.Unmarshal(b, &env))

	hb, err := os.ReadFile(filepath.Join("testdata", "header_1442606.json"))
	require.NoError(t, err)
	var henv struct {
		Result struct {
			Header struct {
				DataHash string `json:"data_hash"`
			} `json:"header"`
		} `json:"result"`
	}
	require.NoError(t, json.Unmarshal(hb, &henv))
	dh, err := hex.DecodeString(henv.Result.Header.DataHash)
	require.NoError(t, err)
	return env.Result.Tx, env.Result.Proof, dh
}

// The live answer is a share proof of one transaction share in the
// transaction namespace, and the node's own validation accepts it.
func TestLiveFixtureIsWhatTheProfileSays(t *testing.T) {
	tx, p, dataHash := live(t)
	sum := sha256.Sum256(tx)
	assert.Equal(t, "a9a1550e0ba85fe6f8facebf26978b7f7dbfb399987b6d86d78b9b6340245971", hex.EncodeToString(sum[:]))

	var sp core.ShareProof
	require.NoError(t, cmtjson.Unmarshal(p, &sp))
	require.NoError(t, sp.Validate(dataHash), "ShareProof.Validate accepts it, so the checks that matter are the ones Validate leaves out")
	assert.Equal(t, uint32(0), sp.NamespaceVersion)
	assert.Equal(t, append(make([]byte, 27), 1), sp.NamespaceID)
	assert.Equal(t, 1, len(sp.Data))
}

func TestVerifyShareProofLive(t *testing.T) {
	tx, p, dataHash := live(t)
	require.NoError(t, railverify.VerifyShareProof(p, tx, dataHash))

	t.Run("one byte of the transaction differs", func(t *testing.T) {
		for _, i := range []int{0, len(tx) / 2, len(tx) - 1} {
			bad := bytes.Clone(tx)
			bad[i] ^= 1
			assert.ErrorIs(t, railverify.VerifyShareProof(p, bad, dataHash), railverify.ErrTxProof, "byte %d", i)
		}
	})
	t.Run("a prefix, an extension, empty", func(t *testing.T) {
		for name, bad := range map[string][]byte{
			"prefix":    tx[:len(tx)-1],
			"extension": append(bytes.Clone(tx), 0),
			"shorter":   tx[1:],
			"empty":     {},
			"nil":       nil,
		} {
			assert.ErrorIs(t, railverify.VerifyShareProof(p, bad, dataHash), railverify.ErrTxProof, name)
		}
	})
	t.Run("another data root", func(t *testing.T) {
		for _, bad := range [][]byte{make([]byte, 32), nil, {1}, append(bytes.Clone(dataHash), 0), dataHash[:31]} {
			assert.ErrorIs(t, railverify.VerifyShareProof(p, tx, bad), railverify.ErrTxProof)
		}
		flipped := bytes.Clone(dataHash)
		flipped[31] ^= 1
		assert.ErrorIs(t, railverify.VerifyShareProof(p, tx, flipped), railverify.ErrTxProof)
	})
}

func TestVerifyShareProofTamperedLive(t *testing.T) {
	tx, p, dataHash := live(t)
	flipB64 := func(s string, at int) string {
		b, err := base64.StdEncoding.DecodeString(s)
		require.NoError(t, err)
		b[at] ^= 1
		return base64.StdEncoding.EncodeToString(b)
	}
	tests := []struct {
		name string
		edit func(m map[string]any)
	}{
		{"a data byte flipped in the namespace", func(m map[string]any) {
			d := m["data"].([]any)
			d[0] = flipB64(d[0].(string), 5)
		}},
		{"a data byte flipped in the transaction", func(m map[string]any) {
			d := m["data"].([]any)
			d[0] = flipB64(d[0].(string), 100)
		}},
		{"the info byte flipped", func(m map[string]any) {
			d := m["data"].([]any)
			d[0] = flipB64(d[0].(string), 29)
		}},
		{"namespace id changed", func(m map[string]any) {
			id, _ := base64.StdEncoding.DecodeString(m["namespace_id"].(string))
			id[27] = 2
			m["namespace_id"] = base64.StdEncoding.EncodeToString(id)
		}},
		{"namespace version one", func(m map[string]any) { m["namespace_version"] = 1 }},
		{"namespace id missing", func(m map[string]any) { delete(m, "namespace_id") }},
		{"namespace id too short", func(m map[string]any) { m["namespace_id"] = base64.StdEncoding.EncodeToString([]byte{1}) }},
		{"data missing", func(m map[string]any) { delete(m, "data") }},
		{"data emptied", func(m map[string]any) { m["data"] = []any{} }},
		{"data doubled", func(m map[string]any) { d := m["data"].([]any); m["data"] = append(d, d...) }},
		{"share proofs missing", func(m map[string]any) { delete(m, "share_proofs") }},
		{"share proofs emptied", func(m map[string]any) { m["share_proofs"] = []any{} }},
		{"share proof end moved", func(m map[string]any) { m["share_proofs"].([]any)[0].(map[string]any)["end"] = 2 }},
		{"share proof start moved", func(m map[string]any) { m["share_proofs"].([]any)[0].(map[string]any)["start"] = 1 }},
		{"share proof node removed", func(m map[string]any) {
			sp := m["share_proofs"].([]any)[0].(map[string]any)
			sp["nodes"] = sp["nodes"].([]any)[1:]
		}},
		{"row proof missing", func(m map[string]any) { delete(m, "row_proof") }},
		{"row root changed", func(m map[string]any) {
			rr := m["row_proof"].(map[string]any)["row_roots"].([]any)
			s := rr[0].(string)
			rr[0] = s[:len(s)-1] + map[bool]string{true: "0", false: "1"}[s[len(s)-1] != '0']
		}},
		{"row roots emptied", func(m map[string]any) { m["row_proof"].(map[string]any)["row_roots"] = []any{} }},
		{"row proofs emptied", func(m map[string]any) { m["row_proof"].(map[string]any)["proofs"] = []any{} }},
		{"row proof aunt removed", func(m map[string]any) {
			rp := m["row_proof"].(map[string]any)["proofs"].([]any)[0].(map[string]any)
			rp["aunts"] = rp["aunts"].([]any)[1:]
		}},
		{"row proof leaf hash changed", func(m map[string]any) {
			rp := m["row_proof"].(map[string]any)["proofs"].([]any)[0].(map[string]any)
			rp["leaf_hash"] = flipB64(rp["leaf_hash"].(string), 0)
		}},
		{"row proof total changed", func(m map[string]any) {
			m["row_proof"].(map[string]any)["proofs"].([]any)[0].(map[string]any)["total"] = "64"
		}},
		{"row proof index changed", func(m map[string]any) {
			m["row_proof"].(map[string]any)["proofs"].([]any)[0].(map[string]any)["index"] = "1"
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			bad := editProof(t, p, tc.edit)
			assert.ErrorIs(t, railverify.VerifyShareProof(bad, tx, dataHash), railverify.ErrTxProof)
		})
	}
	t.Run("not a proof at all", func(t *testing.T) {
		for _, bad := range []string{"", "null", "{}", "[]", "0", `"x"`, "{", `{"data":null}`, string(p[:len(p)/2])} {
			assert.ErrorIs(t, railverify.VerifyShareProof([]byte(bad), tx, dataHash), railverify.ErrTxProof, "%q", bad)
		}
	})
}

// The rows of a share proof are only valid for a block when they are rows of
// the original square, counted from the first row the proof names. Validate
// does not look at StartRow.
func TestVerifyShareProofChecksTheRowPosition(t *testing.T) {
	txs := [][]byte{bytes.Repeat([]byte{1}, 1300), bytes.Repeat([]byte{2}, 3000), bytes.Repeat([]byte{3}, 1300)}
	p, root := proofOf(t, txs, 1)
	require.NoError(t, railverify.VerifyShareProof(p, txs[1], root), "a transaction over several rows")

	var m map[string]any
	require.NoError(t, json.Unmarshal(p, &m))
	rp := m["row_proof"].(map[string]any)
	start := rp["start_row"].(float64)
	end := rp["end_row"].(float64)
	t.Logf("rows %v..%v of %d row roots", start, end, len(rp["row_roots"].([]any)))

	for _, shift := range []float64{1, 2, -1} {
		if start+shift < 0 {
			continue
		}
		bad := editProof(t, p, func(m map[string]any) {
			rp := m["row_proof"].(map[string]any)
			rp["start_row"], rp["end_row"] = start+shift, end+shift
		})
		var sp core.ShareProof
		require.NoError(t, cmtjson.Unmarshal(bad, &sp))
		require.NoError(t, sp.Validate(root), "core's own validation still accepts the shifted position (shift %v)", shift)
		assert.ErrorIs(t, railverify.VerifyShareProof(bad, txs[1], root), railverify.ErrTxProof, "shift %v", shift)
	}
	t.Run("rows swapped", func(t *testing.T) {
		bad := editProof(t, p, func(m map[string]any) {
			rp := m["row_proof"].(map[string]any)
			for _, k := range []string{"row_roots", "proofs"} {
				l := rp[k].([]any)
				l[0], l[len(l)-1] = l[len(l)-1], l[0]
			}
		})
		assert.ErrorIs(t, railverify.VerifyShareProof(bad, txs[1], root), railverify.ErrTxProof)
	})
	t.Run("a row dropped", func(t *testing.T) {
		bad := editProof(t, p, func(m map[string]any) {
			rp := m["row_proof"].(map[string]any)
			rp["row_roots"] = rp["row_roots"].([]any)[1:]
			rp["proofs"] = rp["proofs"].([]any)[1:]
			rp["start_row"] = start + 1
		})
		assert.ErrorIs(t, railverify.VerifyShareProof(bad, txs[1], root), railverify.ErrTxProof)
	})
}

func TestVerifyShareProofOnGeneratedBlocks(t *testing.T) {
	tiny := func(n int) []byte { return bytes.Repeat([]byte{0x77}, n) }
	tests := []struct {
		name string
		txs  [][]byte
		idx  int
	}{
		{"one transaction", [][]byte{tiny(324)}, 0},
		{"first of three", [][]byte{tiny(324), tiny(500), tiny(80)}, 0},
		{"middle of three", [][]byte{tiny(90), tiny(324), tiny(80)}, 1},
		{"last of three", [][]byte{tiny(90), tiny(500), tiny(324)}, 2},
		{"starting mid share", [][]byte{tiny(40), tiny(324)}, 1},
		{"exactly one share of data", [][]byte{tiny(478 - 2)}, 0},
		{"spilling one byte", [][]byte{tiny(478)}, 0},
		{"many shares", [][]byte{tiny(100), tiny(9000), tiny(100)}, 1},
		{"a large block", append(fillers(20), tiny(324)), 20},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p, root := proofOf(t, tc.txs, tc.idx)
			require.NoError(t, railverify.VerifyShareProof(p, tc.txs[tc.idx], root))
		})
	}
}

func TestVerifyShareProofIsForTheProvenTransactionOnly(t *testing.T) {
	f := fillers(3)
	p, root := proofOf(t, f, 1)
	require.NoError(t, railverify.VerifyShareProof(p, f[1], root))
	for _, other := range [][]byte{f[0], f[2]} {
		assert.ErrorIs(t, railverify.VerifyShareProof(p, other, root), railverify.ErrTxProof)
	}
}

// A unit that is only a slice inside a bigger transaction is not a
// transaction of the block: the proof has to start at the unit boundary the
// reserved bytes give.
func TestVerifyShareProofRefusesAUnitNestedInAnotherTransaction(t *testing.T) {
	inner := bytes.Repeat([]byte{0x42}, 100)
	prefix := bytes.Repeat([]byte{0x11}, 10)
	var framed []byte
	framed = append(framed, 100)
	framed = append(framed, inner...)
	outer := append(append(bytes.Clone(prefix), framed...), 0x99, 0x98)
	p, root := proofOf(t, [][]byte{outer}, 0)

	require.NoError(t, railverify.VerifyShareProof(p, outer, root))
	assert.ErrorIs(t, railverify.VerifyShareProof(p, inner, root), railverify.ErrTxProof,
		"the bytes are inside the proven share, but they are not a unit of the sequence")
	assert.ErrorIs(t, railverify.VerifyShareProof(p, append(bytes.Clone(prefix), framed...), root), railverify.ErrTxProof)
	assert.ErrorIs(t, railverify.VerifyShareProof(p, framed, root), railverify.ErrTxProof)
}

// Shares of a blob in a user namespace can be laid out like a transaction
// share, and the proof passes core's validation. Only the namespace tells
// them apart.
func TestVerifyShareProofRefusesABlobInAUserNamespace(t *testing.T) {
	tx := bytes.Repeat([]byte{0x5a}, 100)
	const reservedOffset = 38 // namespace 29, info 1, sequence length 4, reserved 4
	data := []byte{0, 0, 0, reservedOffset, byte(len(tx))}
	data = append(data, tx...)

	ns := share.MustNewV0Namespace(bytes.Repeat([]byte{0xab}, 10))
	blob, err := share.NewBlob(ns, data, 0, nil)
	require.NoError(t, err)
	inner := bytes.Repeat([]byte{0x01}, 150)
	bt, err := blobtx.MarshalBlobTx(inner, blob)
	require.NoError(t, err)

	classified := []square.ClassifiedTx{square.NewClassifiedTx(bt)}
	builder, err := square.NewBuilder(64, 64, classified...)
	require.NoError(t, err)
	sq, err := builder.Export()
	require.NoError(t, err)
	start, err := builder.FindBlobStartingIndex(0, 0)
	require.NoError(t, err)
	length, err := builder.BlobShareLength(0, 0)
	require.NoError(t, err)
	sp, err := proof.NewShareInclusionProof(sq, ns, share.NewRange(start, start+length))
	require.NoError(t, err)
	p, root := shareProofJSON(t, sp)

	var parsed core.ShareProof
	require.NoError(t, cmtjson.Unmarshal(p, &parsed))
	require.NoError(t, parsed.Validate(root), "the proof is valid for core")
	require.Len(t, parsed.Data, 1)
	require.Equal(t, ns.Bytes(), parsed.Data[0][:29], "the share is in the user namespace")

	assert.ErrorIs(t, railverify.VerifyShareProof(p, tx, root), railverify.ErrTxProof)

	t.Run("claiming the transaction namespace breaks the proof", func(t *testing.T) {
		bad := editProof(t, p, func(m map[string]any) {
			m["namespace_id"] = base64.StdEncoding.EncodeToString(append(make([]byte, 27), 1))
		})
		assert.ErrorIs(t, railverify.VerifyShareProof(bad, tx, root), railverify.ErrTxProof)
	})
}

func FuzzVerifyShareProof(f *testing.F) {
	tx, p, dataHash := live(f)
	f.Add([]byte(p), tx, dataHash)
	f.Add([]byte(`{}`), []byte{1}, []byte{2})
	f.Add([]byte(`{"data":[""],"share_proofs":[{"end":1,"nodes":[]}],"namespace_id":"AA==","row_proof":{"row_roots":[],"proofs":[],"start_row":0,"end_row":0}}`), []byte{}, []byte{})
	f.Fuzz(func(t *testing.T, proofJSON, txBytes, root []byte) {
		err := railverify.VerifyShareProof(proofJSON, txBytes, root)
		if err == nil {
			assert.Equal(t, tx, txBytes, "only the proven transaction passes")
			assert.Equal(t, dataHash, root)
		}
	})
}
