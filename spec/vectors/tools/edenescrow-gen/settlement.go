// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"
)

const (
	depositedEvent = "NativeEscrowDeposited(bytes32,address,address,address,uint256,uint256,uint256,uint256)"
	settledEvent   = "NativeEscrowSettled(bytes32,address,address,uint256,uint256)"
)

var (
	topicDeposited = crypto.Keccak256([]byte(depositedEvent))
	topicSettled   = crypto.Keccak256([]byte(settledEvent))
)

type rpcLog struct {
	Address          string   `json:"address"`
	Topics           []string `json:"topics"`
	Data             string   `json:"data"`
	BlockHash        string   `json:"blockHash"`
	TransactionHash  string   `json:"transactionHash"`
	TransactionIndex string   `json:"transactionIndex"`
	Removed          bool     `json:"removed"`
}

func (l rpcLog) json() obj {
	return obj{
		{"address", l.Address}, {"topics", l.Topics}, {"data", l.Data}, {"blockHash", l.BlockHash},
		{"transactionHash", l.TransactionHash}, {"transactionIndex", l.TransactionIndex}, {"removed", l.Removed},
	}
}

func rebuild(rpcTx json.RawMessage) []byte {
	var tx types.Transaction
	if err := json.Unmarshal(rpcTx, &tx); err != nil {
		panic(err)
	}
	b, err := tx.MarshalBinary()
	if err != nil {
		panic(err)
	}
	return b
}

func withField(raw json.RawMessage, key, val string) json.RawMessage {
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		panic(err)
	}
	m[key] = val
	b, err := json.Marshal(m)
	if err != nil {
		panic(err)
	}
	return b
}

// checkDeposit is the generator's own reading of the deposit-event rule,
// used only to fill in the expectation of each constructed case.
func checkDeposit(status uint64, logs []rpcLog, t txIn, from, escrow common.Address, txHash, blockHash, index string) string {
	if status == 0 {
		if len(logs) == 0 {
			return "reverted"
		}
		return "settlement_log_mismatch"
	}
	if len(logs) != 1 {
		return "settlement_log_mismatch"
	}
	l := logs[0]
	d := t.data
	w := func(i int) []byte { return d[4+32*i : 4+32*(i+1)] }
	wantTopics := [][]byte{topicDeposited, w(0), word(from[:]), w(1)}
	wantData := cat(w(2), word(t.value.Bytes()), w(3), w(4), w(5))
	if !bytes.Equal(unhex(l.Address), escrow[:]) || l.Removed || len(l.Topics) != 4 ||
		l.TransactionHash != txHash || l.BlockHash != blockHash || l.TransactionIndex != index {
		return "settlement_log_mismatch"
	}
	for i, tp := range l.Topics {
		if !bytes.Equal(unhex(tp), wantTopics[i]) {
			return "settlement_log_mismatch"
		}
	}
	if !bytes.Equal(unhex(l.Data), wantData) {
		return "settlement_log_mismatch"
	}
	return "executed"
}

func flipHexByte(s string, fromEnd int) string {
	b := unhex(s)
	b[len(b)-1-fromEnd] ^= 1
	return "0x" + hx(b)
}

func buildSettlementFile(lv *live) obj {
	// Rebuild of the served transactions (the bytes source of the check).
	type rb struct {
		id, desc string
		rpc      json.RawMessage
		want     string
		raw      string
	}
	rbs := []rb{
		{"rebuild_f14_deposit", "eth_getTransactionByHash answer for the F14 deposit", lv.Deposit.RPCTx, lv.Deposit.Hash, lv.Deposit.RawHex},
		{"rebuild_f14_settle", "eth_getTransactionByHash answer for the F14 settle", lv.Settle.RPCTx, lv.Settle.Hash, lv.Settle.RawHex},
		{"rebuild_f14_deposit_nonce_lie", "the deposit answer with nonce + 1: the rebuilt bytes no longer hash to the asked hash", withField(lv.Deposit.RPCTx, "nonce", "0xbb959"), lv.Deposit.Hash, ""},
	}
	var rbj []any
	for _, r := range rbs {
		b := rebuild(r.rpc)
		got := "0x" + hx(crypto.Keccak256(b))
		expect := "match"
		if got != r.want {
			expect = "settlement_hash_mismatch"
		}
		if r.raw != "" && (expect != "match" || hx(b) != r.raw) {
			panic("rebuilt bytes differ from the bytes recorded on Celestia: " + r.id)
		}
		var m any
		if err := json.Unmarshal(r.rpc, &m); err != nil {
			panic(err)
		}
		rbj = append(rbj, obj{{"id", r.id}, {"description", r.desc}, {"rail_ref", strings.TrimPrefix(r.want, "0x")},
			{"rpc_tx", m}, {"rebuilt_hex", hx(b)}, {"rebuilt_hash", strings.TrimPrefix(got, "0x")}, {"expect", expect}})
	}

	// Receipt consensus encoding (the bytes sources must agree on at L1).
	var rcpt types.Receipt
	if err := json.Unmarshal(lv.Deposit.RPCReceipt, &rcpt); err != nil {
		panic(err)
	}
	rcptBin, err := rcpt.MarshalBinary()
	if err != nil {
		panic(err)
	}
	bloomOK := types.CreateBloom(&rcpt) == rcpt.Bloom

	// Deposit event cases.
	var served struct {
		Status string   `json:"status"`
		Logs   []rpcLog `json:"logs"`
	}
	if err := json.Unmarshal(lv.Deposit.RPCReceipt, &served); err != nil {
		panic(err)
	}
	escrowLog := served.Logs[0]
	acts := actionCases(lv)
	a := acts[0]
	buyer := common.HexToAddress(lv.Deposit.InnerCall.Buyer)
	relayer := common.HexToAddress(rpcFrom(lv.Deposit.RPCTx))
	txHash := escrowLog.TransactionHash
	blockHash := escrowLog.BlockHash
	index := escrowLog.TransactionIndex
	mutLog := func(f func(*rpcLog)) []rpcLog {
		l := escrowLog
		l.Topics = append([]string{}, l.Topics...)
		f(&l)
		return []rpcLog{l}
	}
	setDataWord := func(l *rpcLog, i int) {
		b := unhex(l.Data)
		b[32*i+31] ^= 1
		l.Data = "0x" + hx(b)
	}
	type ev struct {
		id, cause string
		status    uint64
		logs      []rpcLog
		from      common.Address
	}
	evs := []ev{
		{"event_f14_log", "the recorded escrow log, read as if the buyer account had sent the form T deposit itself", 1, []rpcLog{escrowLog}, buyer},
		{"event_f14_all_logs", "all five logs of the recorded receipt (form A adds the account and forwarder logs)", 1, served.Logs, buyer},
		{"event_no_logs", "status 1 and no log", 1, nil, buyer},
		{"event_two_deposit_logs", "the escrow log twice", 1, []rpcLog{escrowLog, escrowLog}, buyer},
		{"event_topic_settled", "topic0 of NativeEscrowSettled", 1, mutLog(func(l *rpcLog) { l.Topics[0] = "0x" + hx(topicSettled) }), buyer},
		{"event_other_address", "emitted by the HoustonForwarder address", 1, mutLog(func(l *rpcLog) { l.Address = strings.ToLower(forwarder.Hex()) }), buyer},
		{"event_buyer_not_from", "from is the relayer, the log names the account", 1, []rpcLog{escrowLog}, relayer},
		{"event_payment_id", "paymentId topic changed", 1, mutLog(func(l *rpcLog) { l.Topics[1] = flipHexByte(l.Topics[1], 0) }), buyer},
		{"event_pay_to", "payTo topic changed", 1, mutLog(func(l *rpcLog) { l.Topics[3] = flipHexByte(l.Topics[3], 0) }), buyer},
		{"event_three_topics", "payTo topic missing", 1, mutLog(func(l *rpcLog) { l.Topics = l.Topics[:3] }), buyer},
		{"event_facilitator", "facilitator word changed", 1, mutLog(func(l *rpcLog) { setDataWord(l, 0) }), buyer},
		{"event_amount", "amount word changed", 1, mutLog(func(l *rpcLog) { setDataWord(l, 1) }), buyer},
		{"event_expires_at", "expiresAt word changed", 1, mutLog(func(l *rpcLog) { setDataWord(l, 2) }), buyer},
		{"event_refund_after", "refundAfter word changed", 1, mutLog(func(l *rpcLog) { setDataWord(l, 3) }), buyer},
		{"event_price", "tiaPriceUsd word changed", 1, mutLog(func(l *rpcLog) { setDataWord(l, 4) }), buyer},
		{"event_data_short", "data of 128 bytes", 1, mutLog(func(l *rpcLog) { l.Data = l.Data[:2+256] }), buyer},
		{"event_removed", "removed = true", 1, mutLog(func(l *rpcLog) { l.Removed = true }), buyer},
		{"event_other_tx_hash", "the log names another transaction", 1, mutLog(func(l *rpcLog) { l.TransactionHash = flipHexByte(l.TransactionHash, 0) }), buyer},
		{"event_other_block", "the log names another block", 1, mutLog(func(l *rpcLog) { l.BlockHash = flipHexByte(l.BlockHash, 0) }), buyer},
		{"event_other_index", "the log names another transactionIndex", 1, mutLog(func(l *rpcLog) { l.TransactionIndex = "0x0" }), buyer},
		{"event_reverted", "status 0 and no log: outcome reverted, the event rule does not apply", 0, nil, buyer},
		{"event_reverted_with_log", "status 0 with a log", 0, []rpcLog{escrowLog}, buyer},
	}
	var evj []any
	for _, e := range evs {
		var lj []any
		for _, l := range e.logs {
			lj = append(lj, l.json())
		}
		if lj == nil {
			lj = []any{}
		}
		evj = append(evj, obj{
			{"id", e.id}, {"cause", e.cause}, {"action_ref", a.id},
			{"tx_hash", txHash}, {"block_hash", blockHash}, {"transaction_index", index},
			{"from", strings.ToLower(e.from.Hex())}, {"escrow", strings.ToLower(escrow714.Hex())},
			{"status", dec(e.status)}, {"logs", lj},
			{"expect", checkDeposit(e.status, e.logs, a.tx, e.from, escrow714, txHash, blockHash, index)},
		})
	}

	// Block 227899844: header hash and transactions root from served fields.
	var hdr types.Header
	if err := json.Unmarshal(lv.Block.RPCResult, &hdr); err != nil {
		panic(err)
	}
	var blk struct {
		Hash string `json:"hash"`
	}
	if err := json.Unmarshal(lv.Block.RPCResult, &blk); err != nil {
		panic(err)
	}
	hdrRLP, err := rlp.EncodeToBytes(&hdr)
	if err != nil {
		panic(err)
	}
	var txs types.Transactions
	var txHex []string
	for _, h := range lv.Block.TxsRawHex {
		var tx types.Transaction
		if err := tx.UnmarshalBinary(unhex(h)); err != nil {
			panic(err)
		}
		txs = append(txs, &tx)
		txHex = append(txHex, h)
	}
	txRoot := types.DeriveSha(txs, trie.NewStackTrie(nil))
	var m any
	if err := json.Unmarshal(lv.Block.RPCResult, &m); err != nil {
		panic(err)
	}

	return obj{
		{"format", format}, {"profile", profile}, {"revision", revision}, {"generator", generator},
		{"upstream", upstream},
		{"live_input", "spec/vectors/profiles/eden-escrow/live/f14.json"},
		{"event", obj{{"signature", depositedEvent}, {"topic0_hex", hx(topicDeposited)},
			{"settled_signature", settledEvent}, {"settled_topic0_hex", hx(topicSettled)},
			{"f14_receipt_topic0_equal", hx(topicDeposited) == strings.TrimPrefix(escrowLog.Topics[0], "0x")}}},
		{"rebuild", rbj},
		{"receipt", obj{{"tx_hash", strings.TrimPrefix(txHash, "0x")}, {"consensus_hex", hx(rcptBin)},
			{"bloom_recomputed_equal", bloomOK}}},
		{"deposit_event", evj},
		{"block", obj{
			{"number", hdr.Number.String()},
			{"served_hash", strings.TrimPrefix(blk.Hash, "0x")},
			{"header_rlp_hex", hx(hdrRLP)},
			{"header_hash", hx(hdr.Hash().Bytes())},
			{"header_hash_equal", hdr.Hash().Hex() == blk.Hash},
			{"txs_raw_hex", txHex},
			{"served_transactions_root", strings.TrimPrefix(hdr.TxHash.Hex(), "0x")},
			{"transactions_root", strings.TrimPrefix(txRoot.Hex(), "0x")},
			{"transactions_root_equal", txRoot == hdr.TxHash},
			{"receipts_root", "not checked: the receipt of tx 0 is not recorded"},
		}},
	}
}

func rpcFrom(raw json.RawMessage) string {
	var v struct {
		From string `json:"from"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		panic(err)
	}
	return v.From
}
