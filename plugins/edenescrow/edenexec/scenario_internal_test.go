// SPDX-License-Identifier: Apache-2.0

package edenexec

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/plugins/edenescrow"
)

// rlpItemsOf splits a list encoding into its items' payloads; it is enough
// for the short and long forms of the vectors.
func rlpItemsOf(t testing.TB, b []byte) (payloads [][]byte, lists []bool) {
	t.Helper()
	read := func(b []byte) (payload []byte, list bool, rest []byte) {
		c := b[0]
		switch {
		case c < 0x80:
			return b[:1], false, b[1:]
		case c <= 0xb7:
			n := int(c - 0x80)
			return b[1 : 1+n], false, b[1+n:]
		case c <= 0xbf:
			ll := int(c - 0xb7)
			n := 0
			for _, x := range b[1 : 1+ll] {
				n = n<<8 | int(x)
			}
			return b[1+ll : 1+ll+n], false, b[1+ll+n:]
		case c <= 0xf7:
			n := int(c - 0xc0)
			return b[1 : 1+n], true, b[1+n:]
		default:
			ll := int(c - 0xf7)
			n := 0
			for _, x := range b[1 : 1+ll] {
				n = n<<8 | int(x)
			}
			return b[1+ll : 1+ll+n], true, b[1+ll+n:]
		}
	}
	payload, list, rest := read(b)
	require.True(t, list)
	require.Empty(t, rest)
	for len(payload) > 0 {
		p, l, r := read(payload)
		payloads, lists = append(payloads, p), append(lists, l)
		payload = r
	}
	return payloads, lists
}

// txViewOf is what a source would serve for signed type 2 bytes with an
// empty access list.
func txViewOf(t testing.TB, signed []byte) TxView {
	t.Helper()
	require.Equal(t, TxDynamicFee, signed[0])
	it, lists := rlpItemsOf(t, signed[1:])
	require.Len(t, it, 12)
	require.True(t, lists[8])
	require.Empty(t, it[8])
	var to [20]byte
	copy(to[:], it[5])
	return TxView{
		Type: TxDynamicFee, Hash: keccak256(signed), ChainID: it[0], Nonce: it[1], MaxPriorityFee: it[2], MaxFee: it[3],
		Gas: it[4], To: &to, Value: it[6], Input: it[7], V: it[9], R: it[10], S: it[11],
	}
}

// scenario is a consistent block of two transactions whose second is the
// authorized deposit, executed, with one source's worth of answers.
type scenario struct {
	action    edenescrow.TxAction
	signed    []byte
	railRef   string
	R         [32]byte
	payer     [20]byte
	tx        TxView
	receipt   ReceiptView
	header    HeaderView
	blockHash [32]byte
	blockTxs  [][]byte
	blockRcpt [][]byte
	target    Target
}

const (
	scnNumber = 227_900_000
	scnTime   = 1_792_572_000
)

func newScenario(t testing.TB) *scenario {
	t.Helper()
	var f signedFile
	loadVector(t, "signed.json", &f)
	acts := actions(t)
	byID := map[string]int{}
	for i, c := range f.Cases {
		byID[c.ID] = i
	}
	ours := f.Cases[byID["signed_f14_714"]]
	other := f.Cases[byID["signed_min_714"]]

	s := &scenario{action: acts[ours.ActionRef], signed: unhex(t, ours.SignedHex), railRef: ours.RailRef}
	s.R = hash32(t, ours.RailRef)
	s.payer = addr20(t, ours.Payer)
	otherSigned := unhex(t, other.SignedHex)
	s.blockTxs = [][]byte{otherSigned, s.signed}

	otherRcpt := ReceiptView{Type: TxDynamicFee, Status: 1, CumulativeGasUsed: []byte{0x52, 0x08}, TxHash: keccak256(otherSigned)}
	s.receipt = ReceiptView{
		Type: TxDynamicFee, Status: 1, CumulativeGasUsed: []byte{0x01, 0x00, 0x00}, TxHash: s.R, Index: 1,
		Logs: []LogView{s.depositLog()},
	}
	s.header = HeaderView{
		Number: scnNumber, GasLimit: 50_000_000, GasUsed: 0x10000, Time: scnTime, Difficulty: []byte{},
		HasBaseFee: true, BaseFee: []byte{0x05, 0xfd},
	}
	empty := DeriveSha(nil)
	zero, zero64 := [32]byte{}, uint64(0)
	s.header.WithdrawalsHash, s.header.BlobGasUsed, s.header.ExcessBlobGas = &empty, &zero64, &zero64
	s.header.ParentBeaconRoot, s.header.RequestsHash = &zero, &empty
	s.header.TxRoot = DeriveSha(s.blockTxs)
	s.seal(t, otherRcpt)
	s.target = Target{Action: s.action, RailRef: s.railRef, Expires: scnTime + 100, TRef: scnTime - 100}
	return s
}

// seal fixes the receipts root and the block hash after any change.
func (s *scenario) seal(t testing.TB, otherRcpt ReceiptView) {
	t.Helper()
	enc0, err := ReceiptEncoding(otherRcpt)
	require.NoError(t, err)
	enc1, err := ReceiptEncoding(s.receipt)
	require.NoError(t, err)
	s.blockRcpt = [][]byte{enc0, enc1}
	s.header.ReceiptRoot = DeriveSha(s.blockRcpt)
	enc, err := HeaderRLP(s.header)
	require.NoError(t, err)
	s.blockHash = keccak256(enc)
	s.header.Hash = s.blockHash
	// The receipts name the block, which their root does not cover.
	s.receipt.BlockHash, s.receipt.BlockNumber = s.blockHash, scnNumber
	for i := range s.receipt.Logs {
		s.receipt.Logs[i].BlockHash = s.blockHash
	}
	s.tx = txViewOf(t, s.signed)
	s.tx.Included, s.tx.BlockHash, s.tx.BlockNumber, s.tx.Index = true, s.blockHash, scnNumber, 1
}

func (s *scenario) depositLog() LogView {
	a := s.action
	return LogView{
		Address: a.Row.Escrow,
		Topics:  [][32]byte{DepositTopic, a.Deposit.PaymentID, addressWord(s.payer), addressWord(a.Deposit.PayTo)},
		Data:    depositData(a), TxHash: s.R, Index: 1,
	}
}

// source is one honest source of the scenario, at the confirmation depth.
func (s *scenario) source(name string) *FakeSource {
	return &FakeSource{
		SrcName: name, Chain: s.action.ChainID, HeadNum: scnNumber + DefaultConfirmDepth, Code: s.action.Row.CodeHash,
		Txs:       map[[32]byte]TxView{s.R: s.tx},
		Receipts:  map[[32]byte]ReceiptView{s.R: s.receipt},
		Headers:   map[[32]byte]HeaderView{s.blockHash: s.header},
		BlockTxs:  map[[32]byte][][]byte{s.blockHash: s.blockTxs},
		BlockRcpt: map[[32]byte][][]byte{s.blockHash: s.blockRcpt},
	}
}

func newTestChecker(t testing.TB, cfg Config, srcs ...Source) *Checker {
	t.Helper()
	cfg.ApplyDefaults()
	c, err := NewChecker(cfg, srcs, nil)
	require.NoError(t, err)
	return c
}
