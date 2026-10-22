// SPDX-License-Identifier: Apache-2.0

package edenexec

import "fmt"

// EIP-2718 transaction types the rebuild knows.
const (
	TxLegacy     uint8 = 0
	TxAccessList uint8 = 1
	TxDynamicFee uint8 = 2
	TxBlob       uint8 = 3
	TxSetCode    uint8 = 4
)

// quantities encodes integer items, refusing any with a leading zero byte.
type quantities struct {
	what string
	err  error
}

func (q *quantities) enc(name string, b []byte) []byte {
	out, ok := rlpQuantity(b)
	if !ok && q.err == nil {
		q.err = fmt.Errorf("%s %s has a leading zero byte", q.what, name)
	}
	return out
}

// RebuildSigned rebuilds the EIP-2718 bytes of a served transaction, as
// go-ethereum's Transaction.MarshalBinary does, so that keccak256 of the
// result can be compared with the hash asked for. Eden serves no raw
// transaction bytes. A type the rebuild does not know is ErrTxType.
func RebuildSigned(tx TxView) ([]byte, error) {
	q := &quantities{what: "transaction"}
	to := func() []byte {
		if tx.To == nil {
			return rlpBytes(nil)
		}
		return rlpBytes(tx.To[:])
	}
	sig := func() [][]byte { return [][]byte{q.enc("v", tx.V), q.enc("r", tx.R), q.enc("s", tx.S)} }
	var (
		items  [][]byte
		prefix bool
	)
	switch tx.Type {
	case TxLegacy:
		items = [][]byte{q.enc("nonce", tx.Nonce), q.enc("gasPrice", tx.GasPrice), q.enc("gas", tx.Gas), to(),
			q.enc("value", tx.Value), rlpBytes(tx.Input)}
	case TxAccessList:
		items = [][]byte{q.enc("chainId", tx.ChainID), q.enc("nonce", tx.Nonce), q.enc("gasPrice", tx.GasPrice),
			q.enc("gas", tx.Gas), to(), q.enc("value", tx.Value), rlpBytes(tx.Input), accessList(tx.AccessList)}
		prefix = true
	case TxDynamicFee, TxBlob, TxSetCode:
		if tx.Type != TxDynamicFee && tx.To == nil {
			return nil, wrapf(ErrTxType, "type %d transaction without a recipient", tx.Type)
		}
		items = [][]byte{q.enc("chainId", tx.ChainID), q.enc("nonce", tx.Nonce), q.enc("maxPriorityFeePerGas", tx.MaxPriorityFee),
			q.enc("maxFeePerGas", tx.MaxFee), q.enc("gas", tx.Gas), to(), q.enc("value", tx.Value), rlpBytes(tx.Input),
			accessList(tx.AccessList)}
		switch tx.Type {
		case TxBlob:
			hashes := make([][]byte, len(tx.BlobHashes))
			for i := range tx.BlobHashes {
				hashes[i] = rlpBytes(tx.BlobHashes[i][:])
			}
			items = append(items, q.enc("maxFeePerBlobGas", tx.MaxFeePerBlobGas), rlpList(hashes...))
		case TxSetCode:
			auths := make([][]byte, len(tx.AuthList))
			for i, a := range tx.AuthList {
				auths[i] = rlpList(q.enc("auth chainId", a.ChainID), rlpBytes(a.Address[:]), q.enc("auth nonce", a.Nonce),
					q.enc("auth yParity", a.YParity), q.enc("auth r", a.R), q.enc("auth s", a.S))
			}
			items = append(items, rlpList(auths...))
		}
		prefix = true
	default:
		return nil, wrapf(ErrTxType, "type %d", tx.Type)
	}
	items = append(items, sig()...)
	if q.err != nil {
		return nil, wrapf(ErrSourceUnavailable, "%v", q.err)
	}
	body := rlpList(items...)
	if !prefix {
		return body, nil
	}
	return append([]byte{tx.Type}, body...), nil
}

func accessList(al []AccessTuple) []byte {
	entries := make([][]byte, len(al))
	for i, e := range al {
		keys := make([][]byte, len(e.StorageKeys))
		for j := range e.StorageKeys {
			keys[j] = rlpBytes(e.StorageKeys[j][:])
		}
		entries[i] = rlpList(rlpBytes(e.Address[:]), rlpList(keys...))
	}
	return rlpList(entries...)
}

// ReceiptEncoding is the consensus encoding of a served receipt, the leaf of
// the receipts trie: type || rlp([status, cumulativeGasUsed, logsBloom,
// logs]), without the type byte for a legacy receipt.
func ReceiptEncoding(r ReceiptView) ([]byte, error) {
	q := &quantities{what: "receipt"}
	if r.Status > 1 {
		return nil, fmt.Errorf("receipt status %d", r.Status)
	}
	if r.Type > 0x7f {
		return nil, fmt.Errorf("receipt type %d", r.Type)
	}
	logs := make([][]byte, len(r.Logs))
	for i, l := range r.Logs {
		topics := make([][]byte, len(l.Topics))
		for j := range l.Topics {
			topics[j] = rlpBytes(l.Topics[j][:])
		}
		logs[i] = rlpList(rlpBytes(l.Address[:]), rlpList(topics...), rlpBytes(l.Data))
	}
	body := rlpList(rlpUint64(r.Status), q.enc("cumulativeGasUsed", r.CumulativeGasUsed), rlpBytes(r.Bloom[:]), rlpList(logs...))
	if q.err != nil {
		return nil, q.err
	}
	if r.Type == TxLegacy {
		return body, nil
	}
	return append([]byte{r.Type}, body...), nil
}

// HeaderRLP is the RLP encoding whose keccak256 is the block hash. Fields of
// later forks are appended in fork order; one served without every earlier
// one is a shape no fork defines, and is refused.
func HeaderRLP(h HeaderView) ([]byte, error) {
	if len(h.Unknown) > 0 {
		return nil, fmt.Errorf("header has fields the verifier does not know: %v", h.Unknown)
	}
	q := &quantities{what: "header"}
	items := [][]byte{
		rlpBytes(h.ParentHash[:]), rlpBytes(h.UncleHash[:]), rlpBytes(h.Coinbase[:]), rlpBytes(h.Root[:]),
		rlpBytes(h.TxRoot[:]), rlpBytes(h.ReceiptRoot[:]), rlpBytes(h.Bloom[:]), q.enc("difficulty", h.Difficulty),
		rlpUint64(h.Number), rlpUint64(h.GasLimit), rlpUint64(h.GasUsed), rlpUint64(h.Time), rlpBytes(h.Extra),
		rlpBytes(h.MixDigest[:]), rlpBytes(h.Nonce[:]),
	}
	optional := []struct {
		set bool
		enc func() []byte
	}{
		{h.HasBaseFee, func() []byte { return q.enc("baseFeePerGas", h.BaseFee) }},
		{h.WithdrawalsHash != nil, func() []byte { return rlpBytes(h.WithdrawalsHash[:]) }},
		{h.BlobGasUsed != nil, func() []byte { return rlpUint64(*h.BlobGasUsed) }},
		{h.ExcessBlobGas != nil, func() []byte { return rlpUint64(*h.ExcessBlobGas) }},
		{h.ParentBeaconRoot != nil, func() []byte { return rlpBytes(h.ParentBeaconRoot[:]) }},
		{h.RequestsHash != nil, func() []byte { return rlpBytes(h.RequestsHash[:]) }},
	}
	ended := false
	for i, f := range optional {
		switch {
		case !f.set:
			ended = true
		case ended:
			return nil, fmt.Errorf("header serves optional field %d without an earlier one", i)
		default:
			items = append(items, f.enc())
		}
	}
	if q.err != nil {
		return nil, q.err
	}
	return rlpList(items...), nil
}
