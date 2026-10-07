package railverify_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"testing"

	"github.com/celestiaorg/celestia-app/v10/pkg/proof"
	"github.com/cometbft/cometbft/crypto/merkle"
	tmbytes "github.com/cometbft/cometbft/libs/bytes"
	cmtjson "github.com/cometbft/cometbft/libs/json"
	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	core "github.com/cometbft/cometbft/types"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protowire"

	"github.com/vgonkivs/edicta/celestia/railverify"
	"github.com/vgonkivs/edicta/celestia/test/cometfake"
	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/examples/tia-transfer/bankaction"
	"github.com/vgonkivs/edicta/test/bankvec"
	"github.com/vgonkivs/edicta/verifier"
)

var bg = context.Background()

const (
	chainID = "mocha-4"
	hrp     = "celestia"
	txH     = uint64(6543290)
)

func cfg() railverify.Config { return railverify.Config{ChainID: chainID, HRP: hrp} }

// vec is the minimal action of the vectors with its body and signed
// transaction.
type vec struct {
	action  []byte
	msg     []byte
	hash    commitment.Hash
	body    []byte
	auth    []byte
	sig     []byte
	txRaw   []byte
	railRef string
}

func hashOf(t testing.TB, h string) commitment.Hash {
	t.Helper()
	var out commitment.Hash
	b := bankvec.Hex(t, h)
	require.Len(t, b, len(out))
	copy(out[:], b)
	return out
}

func loadVec(t testing.TB) vec {
	t.Helper()
	var action bankvec.ActionCase
	for _, c := range bankvec.Actions(t).Cases {
		if c.ID == "action_minimal_mocha" {
			action = c
		}
	}
	require.NotEmpty(t, action.ID)
	require.Equal(t, chainID, action.Input.ChainID)

	txs := bankvec.Txs(t)
	var body bankvec.Body
	for _, b := range txs.Body {
		if b.ID == "body_minimal" {
			body = b
		}
	}
	var signed bankvec.Signed
	for _, s := range txs.Signed {
		if s.ID == "signed_minimal_mocha" {
			signed = s
		}
	}
	require.NotEmpty(t, body.ID)
	require.NotEmpty(t, signed.ID)
	require.Equal(t, "body_minimal", signed.BodyRef)

	raw := bankvec.Hex(t, signed.TxRawHex)
	b, a, sigs := splitTxRaw(t, raw)
	require.Len(t, sigs, 1)
	require.Equal(t, bankvec.Hex(t, body.BodyHex), b)
	sum := sha256.Sum256(raw)
	require.Equal(t, signed.RailRef, hex.EncodeToString(sum[:]))
	return vec{
		action: bankvec.Hex(t, action.CBORHex), msg: bankvec.Hex(t, action.Input.MsgHex), hash: hashOf(t, body.HashHex),
		body: b, auth: a, sig: sigs[0], txRaw: raw, railRef: signed.RailRef,
	}
}

func splitTxRaw(t testing.TB, raw []byte) (body, auth []byte, sigs [][]byte) {
	t.Helper()
	for len(raw) > 0 {
		num, typ, n := protowire.ConsumeTag(raw)
		require.GreaterOrEqual(t, n, 0)
		raw = raw[n:]
		require.Equal(t, protowire.BytesType, typ)
		v, n := protowire.ConsumeBytes(raw)
		require.GreaterOrEqual(t, n, 0)
		raw = raw[n:]
		switch num {
		case 1:
			body = v
		case 2:
			auth = v
		case 3:
			sigs = append(sigs, v)
		default:
			require.Failf(t, "unexpected field", "%d", num)
		}
	}
	return body, auth, sigs
}

func field(num protowire.Number, v []byte) []byte {
	b := protowire.AppendTag(nil, num, protowire.BytesType)
	return protowire.AppendBytes(b, v)
}

func cat(parts ...[]byte) []byte { return bytes.Join(parts, nil) }

func (v vec) withBody(body []byte) []byte {
	return cat(field(1, body), field(2, v.auth), field(3, v.sig))
}

func refOf(tx []byte) string {
	s := sha256.Sum256(tx)
	return hex.EncodeToString(s[:])
}

func ref32(t testing.TB, ref string) [32]byte {
	t.Helper()
	var h [32]byte
	b, err := hex.DecodeString(ref)
	require.NoError(t, err)
	copy(h[:], b)
	return h
}

func (v vec) input(tx []byte) verifier.ExecutionInput {
	return verifier.ExecutionInput{CommitmentHash: v.hash, ActionType: bankaction.ActionType, Action: v.action, RailRef: refOf(tx)}
}

// proofOf builds a real inclusion proof of txs[idx] in a square made of txs,
// and returns it in the RPC's JSON form with the data root it verifies against.
func proofOf(t testing.TB, txs [][]byte, idx int) (json.RawMessage, []byte) {
	t.Helper()
	sp, err := proof.NewTxInclusionProof(txs, uint64(idx), 0)
	require.NoError(t, err)
	return shareProofJSON(t, sp)
}

func shareProofJSON(t testing.TB, sp proof.ShareProof) (json.RawMessage, []byte) {
	t.Helper()
	out := core.ShareProof{
		Data:             sp.Data,
		NamespaceID:      sp.NamespaceId,
		NamespaceVersion: sp.NamespaceVersion,
		RowProof:         core.RowProof{StartRow: sp.RowProof.StartRow, EndRow: sp.RowProof.EndRow},
	}
	for _, p := range sp.ShareProofs {
		out.ShareProofs = append(out.ShareProofs, &cmtproto.NMTProof{Start: p.Start, End: p.End, Nodes: p.Nodes})
	}
	for i, r := range sp.RowProof.RowRoots {
		out.RowProof.RowRoots = append(out.RowProof.RowRoots, tmbytes.HexBytes(r))
		p := sp.RowProof.Proofs[i]
		out.RowProof.Proofs = append(out.RowProof.Proofs, &merkle.Proof{Total: p.Total, Index: p.Index, LeafHash: p.LeafHash, Aunts: p.Aunts})
	}
	root := out.RowProof.Proofs[0].ComputeRootHash()
	require.NoError(t, out.Validate(root), "the generated proof is valid for core's own validation")
	b, err := cmtjson.Marshal(out)
	require.NoError(t, err)
	return b, root
}

// filler transactions are big enough to own their shares.
func fillers(n int) [][]byte {
	out := make([][]byte, n)
	for i := range out {
		out[i] = bytes.Repeat([]byte{byte(0x30 + i)}, 1300)
	}
	return out
}

// editProof applies f to the decoded JSON proof and re-encodes it.
func editProof(t testing.TB, in json.RawMessage, f func(m map[string]any)) json.RawMessage {
	t.Helper()
	var m map[string]any
	require.NoError(t, json.Unmarshal(in, &m))
	f(m)
	out, err := json.Marshal(m)
	require.NoError(t, err)
	return out
}

// header builds the protobuf header of the block that holds the transaction.
func headerAt(t testing.TB, chain string, height uint64, dataHash []byte) (raw []byte, hash []byte) {
	t.Helper()
	h := cometfake.MkHeader(chain, height, bytes.Repeat([]byte{7}, 32), "app")
	if dataHash != nil {
		h.DataHash = dataHash
	}
	return cometfake.Encode(t, h), h.Hash()
}

// fakeHeaders serves headers by height and records the reads.
type fakeHeaders struct {
	mu    sync.Mutex
	byH   map[uint64][]byte
	err   error
	reads []uint64
}

func (f *fakeHeaders) Header(_ context.Context, h uint64) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reads = append(f.reads, h)
	if f.err != nil {
		return nil, f.err
	}
	b, ok := f.byH[h]
	if !ok {
		return nil, fmt.Errorf("no header at %d", h)
	}
	return bytes.Clone(b), nil
}

type call struct {
	hash  [32]byte
	prove bool
}

// fakeSource is a tx source with one answer per hash.
type fakeSource struct {
	mu    sync.Mutex
	name  string
	txs   map[[32]byte]railverify.RawTx
	err   error
	calls []call
}

func newSource(name string) *fakeSource {
	return &fakeSource{name: name, txs: map[[32]byte]railverify.RawTx{}}
}

func (f *fakeSource) Name() string { return f.name }

func (f *fakeSource) Tx(_ context.Context, hash [32]byte, prove bool) (railverify.RawTx, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, call{hash, prove})
	if f.err != nil {
		return railverify.RawTx{}, f.err
	}
	tx, ok := f.txs[hash]
	if !ok {
		return railverify.RawTx{}, railverify.ErrTxNotFound
	}
	if !prove {
		tx.Proof = nil
	}
	return tx, nil
}
