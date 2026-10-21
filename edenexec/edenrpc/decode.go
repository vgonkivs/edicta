// SPDX-License-Identifier: Apache-2.0

package edenrpc

import (
	"encoding/json"

	"github.com/vgonkivs/edicta/edenexec"
)

// maxQuantityBytes bounds a 256-bit integer.
const maxQuantityBytes = 32

type rpcAccess struct {
	Address     *string   `json:"address"`
	StorageKeys *[]string `json:"storageKeys"`
}

type rpcAuth struct {
	ChainID *string `json:"chainId"`
	Address *string `json:"address"`
	Nonce   *string `json:"nonce"`
	YParity *string `json:"yParity"`
	R       *string `json:"r"`
	S       *string `json:"s"`
}

type rpcTx struct {
	Type                 *string      `json:"type"`
	Hash                 *string      `json:"hash"`
	ChainID              *string      `json:"chainId"`
	Nonce                *string      `json:"nonce"`
	GasPrice             *string      `json:"gasPrice"`
	MaxPriorityFeePerGas *string      `json:"maxPriorityFeePerGas"`
	MaxFeePerGas         *string      `json:"maxFeePerGas"`
	Gas                  *string      `json:"gas"`
	To                   *string      `json:"to"`
	Value                *string      `json:"value"`
	Input                *string      `json:"input"`
	AccessList           *[]rpcAccess `json:"accessList"`
	MaxFeePerBlobGas     *string      `json:"maxFeePerBlobGas"`
	BlobVersionedHashes  *[]string    `json:"blobVersionedHashes"`
	AuthorizationList    *[]rpcAuth   `json:"authorizationList"`
	V                    *string      `json:"v"`
	YParity              *string      `json:"yParity"`
	R                    *string      `json:"r"`
	S                    *string      `json:"s"`
	BlockHash            *string      `json:"blockHash"`
	BlockNumber          *string      `json:"blockNumber"`
	TransactionIndex     *string      `json:"transactionIndex"`
}

// reader collects the first error of a sequence of field reads.
type reader struct{ err error }

func (r *reader) need(p *string, name string) string {
	if p == nil {
		if r.err == nil {
			r.err = malformed("field %s missing", name)
		}
		return ""
	}
	return *p
}

func (r *reader) qty(p *string, name string) []byte {
	s := r.need(p, name)
	if r.err != nil {
		return nil
	}
	b, err := quantity(s, maxQuantityBytes)
	if err != nil {
		r.err = err
	}
	return b
}

func (r *reader) u64(p *string, name string) uint64 {
	s := r.need(p, name)
	if r.err != nil {
		return 0
	}
	v, err := quantity64(s)
	if err != nil {
		r.err = err
	}
	return v
}

func (r *reader) data(p *string, name string) []byte {
	s := r.need(p, name)
	if r.err != nil {
		return nil
	}
	b, err := data(s)
	if err != nil {
		r.err = err
	}
	return b
}

func (r *reader) fixed(p *string, name string, dst []byte) {
	s := r.need(p, name)
	if r.err != nil {
		return
	}
	if err := fixed(s, dst); err != nil {
		r.err = malformed("%s: %v", name, err)
	}
}

// DecodeTransaction reads one transaction object strictly. A type the
// rebuild does not know keeps only its type, hash and block fields.
func DecodeTransaction(raw []byte) (edenexec.TxView, error) {
	if err := checkStrict(raw); err != nil {
		return edenexec.TxView{}, err
	}
	var t rpcTx
	if err := json.Unmarshal(raw, &t); err != nil {
		return edenexec.TxView{}, malformed("transaction: %v", err)
	}
	return txFromRPC(t)
}

func txFromRPC(t rpcTx) (edenexec.TxView, error) {
	var (
		v edenexec.TxView
		r reader
	)
	typ := r.u64(t.Type, "type")
	r.fixed(t.Hash, "hash", v.Hash[:])
	if r.err != nil {
		return v, r.err
	}
	if typ > 0xff {
		return v, malformed("type %d", typ)
	}
	v.Type = uint8(typ)
	if t.BlockHash != nil {
		v.Included = true
		r.fixed(t.BlockHash, "blockHash", v.BlockHash[:])
		v.BlockNumber = r.u64(t.BlockNumber, "blockNumber")
		v.Index = r.u64(t.TransactionIndex, "transactionIndex")
	}
	if v.Type > edenexec.TxSetCode {
		return v, r.err
	}

	v.Nonce = r.qty(t.Nonce, "nonce")
	v.Gas = r.qty(t.Gas, "gas")
	v.Value = r.qty(t.Value, "value")
	v.Input = r.data(t.Input, "input")
	v.R = r.qty(t.R, "r")
	v.S = r.qty(t.S, "s")
	if t.To != nil {
		var to [20]byte
		r.fixed(t.To, "to", to[:])
		v.To = &to
	}
	if v.Type == edenexec.TxLegacy {
		v.GasPrice = r.qty(t.GasPrice, "gasPrice")
		v.V = r.qty(t.V, "v")
		return v, r.err
	}
	v.ChainID = r.qty(t.ChainID, "chainId")
	v.AccessList = r.accessList(t.AccessList)
	switch {
	case t.YParity != nil:
		v.V = r.qty(t.YParity, "yParity")
		if t.V != nil && r.err == nil {
			if other := r.qty(t.V, "v"); r.err == nil && string(other) != string(v.V) {
				r.err = malformed("v %s and yParity %s differ", *t.V, *t.YParity)
			}
		}
	default:
		v.V = r.qty(t.V, "v")
	}
	if v.Type == edenexec.TxAccessList {
		v.GasPrice = r.qty(t.GasPrice, "gasPrice")
		return v, r.err
	}
	v.MaxPriorityFee = r.qty(t.MaxPriorityFeePerGas, "maxPriorityFeePerGas")
	v.MaxFee = r.qty(t.MaxFeePerGas, "maxFeePerGas")
	switch v.Type {
	case edenexec.TxBlob:
		v.MaxFeePerBlobGas = r.qty(t.MaxFeePerBlobGas, "maxFeePerBlobGas")
		if t.BlobVersionedHashes == nil {
			r.need(nil, "blobVersionedHashes")
		} else {
			for _, h := range *t.BlobVersionedHashes {
				var b [32]byte
				r.fixed(&h, "blobVersionedHashes", b[:])
				v.BlobHashes = append(v.BlobHashes, b)
			}
		}
	case edenexec.TxSetCode:
		if t.AuthorizationList == nil {
			r.need(nil, "authorizationList")
		} else {
			for _, a := range *t.AuthorizationList {
				var at edenexec.AuthTuple
				at.ChainID = r.qty(a.ChainID, "authorization chainId")
				r.fixed(a.Address, "authorization address", at.Address[:])
				at.Nonce = r.qty(a.Nonce, "authorization nonce")
				at.YParity = r.qty(a.YParity, "authorization yParity")
				at.R = r.qty(a.R, "authorization r")
				at.S = r.qty(a.S, "authorization s")
				v.AuthList = append(v.AuthList, at)
			}
		}
	}
	return v, r.err
}

func (r *reader) accessList(al *[]rpcAccess) []edenexec.AccessTuple {
	if al == nil {
		r.need(nil, "accessList")
		return nil
	}
	out := make([]edenexec.AccessTuple, 0, len(*al))
	for _, e := range *al {
		var t edenexec.AccessTuple
		r.fixed(e.Address, "accessList address", t.Address[:])
		if e.StorageKeys == nil {
			r.need(nil, "accessList storageKeys")
		} else {
			for _, k := range *e.StorageKeys {
				var b [32]byte
				r.fixed(&k, "accessList storage key", b[:])
				t.StorageKeys = append(t.StorageKeys, b)
			}
		}
		out = append(out, t)
	}
	return out
}

type rpcLog struct {
	Address          *string   `json:"address"`
	Topics           *[]string `json:"topics"`
	Data             *string   `json:"data"`
	BlockHash        *string   `json:"blockHash"`
	TransactionHash  *string   `json:"transactionHash"`
	TransactionIndex *string   `json:"transactionIndex"`
	Removed          *bool     `json:"removed"`
}

type rpcReceipt struct {
	Type              *string   `json:"type"`
	Status            *string   `json:"status"`
	CumulativeGasUsed *string   `json:"cumulativeGasUsed"`
	LogsBloom         *string   `json:"logsBloom"`
	Logs              *[]rpcLog `json:"logs"`
	TransactionHash   *string   `json:"transactionHash"`
	BlockHash         *string   `json:"blockHash"`
	BlockNumber       *string   `json:"blockNumber"`
	TransactionIndex  *string   `json:"transactionIndex"`
}

// maxTopics is the most topics a log can carry (LOG4).
const maxTopics = 4

// DecodeReceipt reads one receipt object strictly.
func DecodeReceipt(raw []byte) (edenexec.ReceiptView, error) {
	if err := checkStrict(raw); err != nil {
		return edenexec.ReceiptView{}, err
	}
	var rc rpcReceipt
	if err := json.Unmarshal(raw, &rc); err != nil {
		return edenexec.ReceiptView{}, malformed("receipt: %v", err)
	}
	return receiptFromRPC(rc)
}

func receiptFromRPC(rc rpcReceipt) (edenexec.ReceiptView, error) {
	var (
		v edenexec.ReceiptView
		r reader
	)
	typ := r.u64(rc.Type, "type")
	v.Status = r.u64(rc.Status, "status")
	v.CumulativeGasUsed = r.qty(rc.CumulativeGasUsed, "cumulativeGasUsed")
	r.fixed(rc.LogsBloom, "logsBloom", v.Bloom[:])
	r.fixed(rc.TransactionHash, "transactionHash", v.TxHash[:])
	r.fixed(rc.BlockHash, "blockHash", v.BlockHash[:])
	v.BlockNumber = r.u64(rc.BlockNumber, "blockNumber")
	v.Index = r.u64(rc.TransactionIndex, "transactionIndex")
	if r.err != nil {
		return v, r.err
	}
	if typ > 0x7f {
		return v, malformed("receipt type %d", typ)
	}
	if v.Status > 1 {
		return v, malformed("receipt status %d", v.Status)
	}
	v.Type = uint8(typ)
	if rc.Logs == nil {
		return v, malformed("field logs missing")
	}
	for _, l := range *rc.Logs {
		var lv edenexec.LogView
		r.fixed(l.Address, "log address", lv.Address[:])
		lv.Data = r.data(l.Data, "log data")
		r.fixed(l.BlockHash, "log blockHash", lv.BlockHash[:])
		r.fixed(l.TransactionHash, "log transactionHash", lv.TxHash[:])
		lv.Index = r.u64(l.TransactionIndex, "log transactionIndex")
		switch {
		case l.Removed == nil:
			r.need(nil, "log removed")
		default:
			lv.Removed = *l.Removed
		}
		switch {
		case l.Topics == nil:
			r.need(nil, "log topics")
		case len(*l.Topics) > maxTopics:
			if r.err == nil {
				r.err = malformed("log with %d topics", len(*l.Topics))
			}
		default:
			for _, tp := range *l.Topics {
				var b [32]byte
				r.fixed(&tp, "log topic", b[:])
				lv.Topics = append(lv.Topics, b)
			}
		}
		v.Logs = append(v.Logs, lv)
	}
	return v, r.err
}

// headerKeys are the header fields a block object serves; blockKeys the
// other members of a block object the header ignores.
var (
	headerKeys = map[string]bool{
		"parentHash": true, "sha3Uncles": true, "miner": true, "stateRoot": true, "transactionsRoot": true,
		"receiptsRoot": true, "logsBloom": true, "difficulty": true, "number": true, "gasLimit": true,
		"gasUsed": true, "timestamp": true, "extraData": true, "mixHash": true, "nonce": true,
		"baseFeePerGas": true, "withdrawalsRoot": true, "blobGasUsed": true, "excessBlobGas": true,
		"parentBeaconBlockRoot": true, "requestsHash": true,
	}
	blockKeys = map[string]bool{
		"hash": true, "size": true, "uncles": true, "transactions": true, "withdrawals": true, "totalDifficulty": true,
	}
)

type rpcBlock struct {
	Hash                  *string           `json:"hash"`
	ParentHash            *string           `json:"parentHash"`
	Sha3Uncles            *string           `json:"sha3Uncles"`
	Miner                 *string           `json:"miner"`
	StateRoot             *string           `json:"stateRoot"`
	TransactionsRoot      *string           `json:"transactionsRoot"`
	ReceiptsRoot          *string           `json:"receiptsRoot"`
	LogsBloom             *string           `json:"logsBloom"`
	Difficulty            *string           `json:"difficulty"`
	Number                *string           `json:"number"`
	GasLimit              *string           `json:"gasLimit"`
	GasUsed               *string           `json:"gasUsed"`
	Timestamp             *string           `json:"timestamp"`
	ExtraData             *string           `json:"extraData"`
	MixHash               *string           `json:"mixHash"`
	Nonce                 *string           `json:"nonce"`
	BaseFeePerGas         *string           `json:"baseFeePerGas"`
	WithdrawalsRoot       *string           `json:"withdrawalsRoot"`
	BlobGasUsed           *string           `json:"blobGasUsed"`
	ExcessBlobGas         *string           `json:"excessBlobGas"`
	ParentBeaconBlockRoot *string           `json:"parentBeaconBlockRoot"`
	RequestsHash          *string           `json:"requestsHash"`
	Transactions          []json.RawMessage `json:"transactions"`
}

// DecodeBlock reads a block object strictly: its header, and its
// transactions as served (hashes or objects).
func DecodeBlock(raw []byte) (edenexec.HeaderView, []json.RawMessage, error) {
	if err := checkStrict(raw); err != nil {
		return edenexec.HeaderView{}, nil, err
	}
	var keys map[string]json.RawMessage
	if err := json.Unmarshal(raw, &keys); err != nil {
		return edenexec.HeaderView{}, nil, malformed("block: %v", err)
	}
	var b rpcBlock
	if err := json.Unmarshal(raw, &b); err != nil {
		return edenexec.HeaderView{}, nil, malformed("block: %v", err)
	}
	var (
		h edenexec.HeaderView
		r reader
	)
	for k := range keys {
		if !headerKeys[k] && !blockKeys[k] {
			h.Unknown = append(h.Unknown, k)
		}
	}
	r.fixed(b.Hash, "hash", h.Hash[:])
	r.fixed(b.ParentHash, "parentHash", h.ParentHash[:])
	r.fixed(b.Sha3Uncles, "sha3Uncles", h.UncleHash[:])
	r.fixed(b.Miner, "miner", h.Coinbase[:])
	r.fixed(b.StateRoot, "stateRoot", h.Root[:])
	r.fixed(b.TransactionsRoot, "transactionsRoot", h.TxRoot[:])
	r.fixed(b.ReceiptsRoot, "receiptsRoot", h.ReceiptRoot[:])
	r.fixed(b.LogsBloom, "logsBloom", h.Bloom[:])
	h.Difficulty = r.qty(b.Difficulty, "difficulty")
	h.Number = r.u64(b.Number, "number")
	h.GasLimit = r.u64(b.GasLimit, "gasLimit")
	h.GasUsed = r.u64(b.GasUsed, "gasUsed")
	h.Time = r.u64(b.Timestamp, "timestamp")
	h.Extra = r.data(b.ExtraData, "extraData")
	r.fixed(b.MixHash, "mixHash", h.MixDigest[:])
	r.fixed(b.Nonce, "nonce", h.Nonce[:])
	if b.BaseFeePerGas != nil {
		h.BaseFee, h.HasBaseFee = r.qty(b.BaseFeePerGas, "baseFeePerGas"), true
	}
	h.WithdrawalsHash = r.optHash(b.WithdrawalsRoot, "withdrawalsRoot")
	h.BlobGasUsed = r.optU64(b.BlobGasUsed, "blobGasUsed")
	h.ExcessBlobGas = r.optU64(b.ExcessBlobGas, "excessBlobGas")
	h.ParentBeaconRoot = r.optHash(b.ParentBeaconBlockRoot, "parentBeaconBlockRoot")
	h.RequestsHash = r.optHash(b.RequestsHash, "requestsHash")
	if r.err != nil {
		return edenexec.HeaderView{}, nil, r.err
	}
	return h, b.Transactions, nil
}

func (r *reader) optHash(p *string, name string) *[32]byte {
	if p == nil {
		return nil
	}
	var h [32]byte
	r.fixed(p, name, h[:])
	return &h
}

func (r *reader) optU64(p *string, name string) *uint64 {
	if p == nil {
		return nil
	}
	v := r.u64(p, name)
	return &v
}
