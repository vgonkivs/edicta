// SPDX-License-Identifier: Apache-2.0

package edenexec_test

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/internal/evm"
	"github.com/vgonkivs/edicta/internal/testkit"
	"github.com/vgonkivs/edicta/plugins/edenescrow"
	"github.com/vgonkivs/edicta/plugins/edenescrow/edenexec"
	"github.com/vgonkivs/edicta/plugins/edenescrow/edenrpc"
)

const vectorDir = "vectors/profiles/eden-escrow"

// recordedBlock is one full Eden mainnet block with all its receipts, read
// once from the public RPC (source and date in the file).
const recordedBlock = "testdata/eden-714-block-227899844.json"

func readJSON(t testing.TB, path string, v any) {
	t.Helper()
	b, err := os.ReadFile(path)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(b, v))
}

func unhex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
	require.NoError(t, err)
	return b
}

func h32(t testing.TB, s string) [32]byte {
	t.Helper()
	var h [32]byte
	b := unhex(t, s)
	require.Len(t, b, 32)
	copy(h[:], b)
	return h
}

type f14File struct {
	Block struct {
		RPCResult json.RawMessage `json:"rpc_result"`
		TxsRawHex []string        `json:"txs_raw_hex"`
	} `json:"block_227899844"`
	Deposit struct {
		Hash       string          `json:"hash"`
		RawHex     string          `json:"raw_hex"`
		RPCTx      json.RawMessage `json:"rpc_tx"`
		RPCReceipt json.RawMessage `json:"rpc_receipt"`
	} `json:"deposit"`
	Settle struct {
		Hash   string          `json:"hash"`
		RawHex string          `json:"raw_hex"`
		RPCTx  json.RawMessage `json:"rpc_tx"`
	} `json:"settle"`
}

type recordedFile struct {
	Source    string `json:"_source"`
	Retrieved string `json:"_retrieved"`
	Block     struct {
		Result json.RawMessage `json:"result"`
	} `json:"eth_getBlockByNumber"`
	Receipts struct {
		Result []json.RawMessage `json:"result"`
	} `json:"eth_getBlockReceipts"`
}

func loadRecorded(t testing.TB) (edenexec.HeaderView, [][]byte, [][]byte, []edenexec.ReceiptView) {
	t.Helper()
	var f recordedFile
	readJSON(t, recordedBlock, &f)
	require.Equal(t, "https://rpc.eden.gateway.fm/", f.Source)
	require.NotEmpty(t, f.Retrieved)
	h, raws, err := edenrpc.DecodeBlock(f.Block.Result)
	require.NoError(t, err)
	var txs [][]byte
	for _, raw := range raws {
		tx, err := edenrpc.DecodeTransaction(raw)
		require.NoError(t, err)
		b, err := edenexec.RebuildSigned(tx)
		require.NoError(t, err)
		require.Equal(t, tx.Hash, evm.Keccak256(b))
		txs = append(txs, b)
	}
	var rcpts [][]byte
	var views []edenexec.ReceiptView
	for _, raw := range f.Receipts.Result {
		rc, err := edenrpc.DecodeReceipt(raw)
		require.NoError(t, err)
		enc, err := edenexec.ReceiptEncoding(rc)
		require.NoError(t, err)
		rcpts = append(rcpts, enc)
		views = append(views, rc)
	}
	return h, txs, rcpts, views
}

// TestRecordedBlockProof settles the receipt-root and header-hash questions
// on a real block: the header fields Eden serves hash to the block hash, and
// the rebuilt transactions and receipts give the header's roots.
func TestRecordedBlockProof(t *testing.T) {
	h, txs, rcpts, views := loadRecorded(t)
	require.Len(t, txs, 2)
	require.Len(t, rcpts, 2)
	enc, err := edenexec.HeaderRLP(h)
	require.NoError(t, err)
	assert.Equal(t, h.Hash, evm.Keccak256(enc))
	assert.Equal(t, h.TxRoot, edenexec.DeriveSha(txs))
	assert.Equal(t, h.ReceiptRoot, edenexec.DeriveSha(rcpts))

	var f14 f14File
	readJSON(t, testkit.SpecPath(t, vectorDir, "live/f14.json"), &f14)
	for i, raw := range f14.Block.TxsRawHex {
		assert.Equal(t, unhex(t, raw), txs[i], "the rebuilt bytes equal the Celestia copy")
	}
	deposit := unhex(t, f14.Deposit.RawHex)
	require.NoError(t, edenexec.VerifyBlock(h, h.Hash, txs, rcpts, 1, deposit, rcpts[1]))
	assert.Equal(t, h32(t, f14.Deposit.Hash), views[1].TxHash)

	t.Run("tampering", func(t *testing.T) {
		swapped := [][]byte{rcpts[1], rcpts[0]}
		require.ErrorIs(t, edenexec.VerifyBlock(h, h.Hash, txs, swapped, 1, deposit, rcpts[0]), edenexec.ErrBlockProof)
		require.ErrorIs(t, edenexec.VerifyBlock(h, h.Hash, txs, rcpts, 0, deposit, rcpts[1]), edenexec.ErrBlockProof)
		require.ErrorIs(t, edenexec.VerifyBlock(h, h.Hash, txs, rcpts, 1, deposit, rcpts[0]), edenexec.ErrBlockProof)
		require.ErrorIs(t, edenexec.VerifyBlock(h, h.Hash, txs[:1], rcpts[:1], 1, deposit, rcpts[1]), edenexec.ErrBlockProof)
		require.ErrorIs(t, edenexec.VerifyBlock(h, h.Hash, txs, rcpts[:1], 1, deposit, rcpts[1]), edenexec.ErrBlockProof)
		other := h.Hash
		other[31] ^= 1
		require.ErrorIs(t, edenexec.VerifyBlock(h, other, txs, rcpts, 1, deposit, rcpts[1]), edenexec.ErrBlockProof)
		hh := h
		hh.Time++
		require.ErrorIs(t, edenexec.VerifyBlock(hh, h.Hash, txs, rcpts, 1, deposit, rcpts[1]), edenexec.ErrBlockProof)
		hh = h
		hh.Unknown = []string{"slotNumber"}
		require.ErrorIs(t, edenexec.VerifyBlock(hh, h.Hash, txs, rcpts, 1, deposit, rcpts[1]), edenexec.ErrBlockProof)
		hh = h
		hh.BlobGasUsed = nil
		require.ErrorIs(t, edenexec.VerifyBlock(hh, h.Hash, txs, rcpts, 1, deposit, rcpts[1]), edenexec.ErrBlockProof,
			"a later fork's field without an earlier one")
		empty := [][]byte{txs[0], {}}
		require.ErrorIs(t, edenexec.VerifyBlock(h, h.Hash, empty, rcpts, 0, txs[0], rcpts[0]), edenexec.ErrBlockProof)
		require.ErrorIs(t, edenexec.VerifyBlock(h, h.Hash, txs, [][]byte{{}, rcpts[1]}, 1, deposit, rcpts[1]), edenexec.ErrBlockProof)
		hh = h
		hh.RequestsHash = nil
		require.ErrorIs(t, edenexec.VerifyBlock(hh, h.Hash, txs, rcpts, 1, deposit, rcpts[1]), edenexec.ErrBlockProof)
	})
}

// TestSettlementVectors runs the recorded answers of settlement.json through
// the strict decoders and the rebuild.
func TestSettlementVectors(t *testing.T) {
	var f struct {
		Rebuild []struct {
			ID         string          `json:"id"`
			RailRef    string          `json:"rail_ref"`
			RPCTx      json.RawMessage `json:"rpc_tx"`
			RebuiltHex string          `json:"rebuilt_hex"`
			RebuiltHsh string          `json:"rebuilt_hash"`
			Expect     string          `json:"expect"`
		} `json:"rebuild"`
		Receipt struct {
			TxHash       string `json:"tx_hash"`
			ConsensusHex string `json:"consensus_hex"`
		} `json:"receipt"`
		Block struct {
			HeaderRLPHex     string   `json:"header_rlp_hex"`
			HeaderHash       string   `json:"header_hash"`
			TxsRawHex        []string `json:"txs_raw_hex"`
			TransactionsRoot string   `json:"transactions_root"`
		} `json:"block"`
	}
	readJSON(t, testkit.SpecPath(t, vectorDir, "settlement.json"), &f)
	var f14 f14File
	readJSON(t, testkit.SpecPath(t, vectorDir, "live/f14.json"), &f14)

	require.Len(t, f.Rebuild, 3)
	for _, c := range f.Rebuild {
		t.Run(c.ID, func(t *testing.T) {
			tx, err := edenrpc.DecodeTransaction(c.RPCTx)
			require.NoError(t, err)
			b, err := edenexec.RebuildSigned(tx)
			require.NoError(t, err)
			assert.Equal(t, unhex(t, c.RebuiltHex), b)
			got := evm.Keccak256(b)
			assert.Equal(t, h32(t, c.RebuiltHsh), got)
			switch c.Expect {
			case "match":
				assert.Equal(t, h32(t, c.RailRef), got)
			case string(edenexec.ReasonHashMismatch):
				assert.NotEqual(t, h32(t, c.RailRef), got)
			default:
				t.Fatalf("unknown expectation %q", c.Expect)
			}
		})
	}

	rc, err := edenrpc.DecodeReceipt(f14.Deposit.RPCReceipt)
	require.NoError(t, err)
	enc, err := edenexec.ReceiptEncoding(rc)
	require.NoError(t, err)
	assert.Equal(t, unhex(t, f.Receipt.ConsensusHex), enc)

	h, _, err := edenrpc.DecodeBlock(f14.Block.RPCResult)
	require.NoError(t, err)
	hdr, err := edenexec.HeaderRLP(h)
	require.NoError(t, err)
	assert.Equal(t, unhex(t, f.Block.HeaderRLPHex), hdr)
	assert.Equal(t, h32(t, f.Block.HeaderHash), evm.Keccak256(hdr))
	var txs [][]byte
	for _, raw := range f.Block.TxsRawHex {
		txs = append(txs, unhex(t, raw))
	}
	assert.Equal(t, h32(t, f.Block.TransactionsRoot), edenexec.DeriveSha(txs))
}

// TestEscrowCreationRebuilds rebuilds a contract creation (no recipient) from
// its recorded answer.
func TestEscrowCreationRebuilds(t *testing.T) {
	var f struct {
		CreationTx struct {
			RPCTx json.RawMessage `json:"rpc_tx"`
		} `json:"creation_tx"`
		RPCReads []struct {
			Method string          `json:"method"`
			Params []any           `json:"params"`
			URL    string          `json:"url"`
			Result json.RawMessage `json:"result"`
		} `json:"rpc_reads"`
	}
	readJSON(t, testkit.SpecPath(t, vectorDir, "live/escrow-code.json"), &f)
	tx, err := edenrpc.DecodeTransaction(f.CreationTx.RPCTx)
	require.NoError(t, err)
	assert.Nil(t, tx.To)
	b, err := edenexec.RebuildSigned(tx)
	require.NoError(t, err)
	assert.Equal(t, tx.Hash, evm.Keccak256(b))

	row, ok := edenescrow.Lookup(714)
	require.True(t, ok)
	found := false
	for _, r := range f.RPCReads {
		if r.Method != "eth_getCode" || len(r.Params) == 0 || !strings.EqualFold(r.Params[0].(string), "0x65d77c98e73dfbea91ecb72b27c9753e186a94c8") {
			continue
		}
		if !strings.Contains(r.URL, "rpc.eden.gateway.fm") {
			continue
		}
		var code string
		require.NoError(t, json.Unmarshal(r.Result, &code))
		assert.Equal(t, row.CodeHash, evm.Keccak256(unhex(t, code)))
		found = true
	}
	assert.True(t, found, "the recorded eth_getCode of the 714 escrow")
}

// f14Source serves the recorded F14 answers: the real relayed deposit, its
// receipt and block. Against the synthetic form T action with the same
// deposit it is a different transaction, so the claim is wrong_tx.
func f14Source(t testing.TB) (*edenexec.FakeSource, [32]byte) {
	t.Helper()
	var f f14File
	readJSON(t, testkit.SpecPath(t, vectorDir, "live/f14.json"), &f)
	tx, err := edenrpc.DecodeTransaction(f.Deposit.RPCTx)
	require.NoError(t, err)
	rc, err := edenrpc.DecodeReceipt(f.Deposit.RPCReceipt)
	require.NoError(t, err)
	h, _, err := edenrpc.DecodeBlock(f.Block.RPCResult)
	require.NoError(t, err)
	row, ok := edenescrow.Lookup(714)
	require.True(t, ok)
	R := h32(t, f.Deposit.Hash)
	return &edenexec.FakeSource{
		SrcName: "rpc.eden.gateway.fm", Chain: 714, HeadNum: h.Number + 1000, Code: row.CodeHash,
		Txs:      map[[32]byte]edenexec.TxView{R: tx},
		Receipts: map[[32]byte]edenexec.ReceiptView{R: rc},
		Headers:  map[[32]byte]edenexec.HeaderView{h.Hash: h},
	}, R
}

func f14Action(t testing.TB) []byte {
	t.Helper()
	var f struct {
		Cases []struct {
			ID      string `json:"id"`
			CBORHex string `json:"cbor_hex"`
		} `json:"cases"`
	}
	readJSON(t, testkit.SpecPath(t, vectorDir, "action.json"), &f)
	for _, c := range f.Cases {
		if c.ID == "tx_f14_714" {
			return unhex(t, c.CBORHex)
		}
	}
	t.Fatal("no tx_f14_714")
	return nil
}

func TestF14AtL0IsWrongTx(t *testing.T) {
	src, R := f14Source(t)
	cfg := edenexec.Config{}
	cfg.ApplyDefaults()
	chk, err := edenexec.NewChecker(cfg, []edenexec.Source{src}, nil)
	require.NoError(t, err)
	rep, err := chk.SettlementOfAction(context.Background(), f14Action(t), hex.EncodeToString(R[:]), 1792572000, 1792571000)
	require.NoError(t, err)
	assert.Equal(t, edenexec.StatusViolated, rep.Status)
	assert.Equal(t, edenexec.ReasonWrongTx, rep.Reason)
	require.ErrorIs(t, rep.Err, edenexec.ErrWrongTx)
	require.Len(t, rep.Sources, 1)
	assert.Equal(t, 1, src.CallCount("Transaction"))
	assert.Zero(t, src.CallCount("Receipt"), "the claim is decided before any inclusion read")
}

// TestF14RecordedLogsAreNotFormT reads the recorded receipt as if it were a
// form T receipt: its five logs fail the one-log rule.
func TestF14RecordedLogsAreNotFormT(t *testing.T) {
	var f f14File
	readJSON(t, testkit.SpecPath(t, vectorDir, "live/f14.json"), &f)
	rc, err := edenrpc.DecodeReceipt(f.Deposit.RPCReceipt)
	require.NoError(t, err)
	a, err := edenescrow.DecodeTxAction(f14Action(t))
	require.NoError(t, err)
	_, err = edenexec.CheckDeposit(rc, a, [20]byte{}, a.Row.Escrow)
	require.ErrorIs(t, err, edenexec.ErrLogMismatch)
}

// TestDeriveShaAgainstGoEthereum pins the trie root on sizes that reach the
// branch and extension shapes of real blocks (more than 16, 128 and 256
// items), against roots go-ethereum computed offline.
func TestDeriveShaAgainstGoEthereum(t *testing.T) {
	var f struct {
		Tag   string `json:"tag"`
		Cases []struct {
			N       uint64 `json:"n"`
			RootHex string `json:"root_hex"`
		} `json:"cases"`
	}
	readJSON(t, "testdata/derivesha-geth.json", &f)
	require.NotEmpty(t, f.Cases)
	maxN := uint64(0)
	for _, c := range f.Cases {
		items := make([][]byte, 0, c.N)
		for i := uint64(0); i < c.N; i++ {
			var b [16]byte
			binary.BigEndian.PutUint64(b[:8], c.N)
			binary.BigEndian.PutUint64(b[8:], i)
			k := evm.Keccak256(append([]byte(f.Tag), b[:]...))
			l := 1 + (i*37+c.N)%90
			var it []byte
			for uint64(len(it)) < l {
				it = append(it, k[:]...)
			}
			items = append(items, it[:l])
		}
		assert.Equal(t, h32(t, c.RootHex), edenexec.DeriveSha(items), "n = %d", c.N)
		maxN = max(maxN, c.N)
	}
	assert.GreaterOrEqual(t, maxN, uint64(130))
}
