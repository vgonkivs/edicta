// SPDX-License-Identifier: Apache-2.0

package edenescrow

import (
	"bytes"
	"math/big"
	"slices"
)

// MaxBuildBodySize bounds a /deposit/build answer. A producer reads at most
// one byte more and refuses a longer answer before parsing it.
const MaxBuildBodySize = 16384

// txData members of a /deposit/build answer; type and accessList are
// optional.
var (
	buildRequired = []string{"to", "data", "value", "nonce", "gasLimit", "maxFeePerGas", "maxPriorityFeePerGas", "chainId"}
	buildOptional = []string{"type", "accessList"}
)

// ActionFromDepositBuild converts the payment server's /deposit/build answer
// to the form T action for resource and requirementsHash, and decodes it
// with this build's table. The answer is untrusted: it is read strictly,
// every txData member is required to have one form, and the result must
// pass the action decoder. A refusal is ErrMalformed, or ErrUnknownDomain
// from the decoder. The transaction is taken as the server built it;
// nothing is filled in or defaulted, so two producers build the same bytes.
func ActionFromDepositBuild(body []byte, resource string, requirementsHash [32]byte) ([]byte, TxAction, error) {
	if len(body) < 1 || len(body) > MaxBuildBodySize {
		return nil, TxAction{}, malformed("BJ0", "answer of %d bytes", len(body))
	}
	doc, err := parseJSON(body)
	if err != nil {
		return nil, TxAction{}, malformed("BJ1", "%v", err)
	}
	if doc.kind != jsonObject {
		return nil, TxAction{}, malformed("BJ1", "the answer is not an object")
	}
	txData := doc.member("txData")
	if txData == nil || txData.kind != jsonObject {
		return nil, TxAction{}, malformed("BJ1", "txData is not an object")
	}
	paymentID := doc.member("paymentId")
	if !paymentID.isString() {
		return nil, TxAction{}, malformed("BJ1", "paymentId is not a string")
	}

	for _, m := range txData.members {
		if !slices.Contains(buildRequired, m.name) && !slices.Contains(buildOptional, m.name) {
			return nil, TxAction{}, malformed("BJ2", "txData member %q", m.name)
		}
	}
	for _, name := range buildRequired {
		if txData.member(name) == nil {
			return nil, TxAction{}, malformed("BJ2", "txData has no %s", name)
		}
	}

	var big4 [4]*big.Int
	for i, name := range []string{"value", "gasLimit", "maxFeePerGas", "maxPriorityFeePerGas"} {
		n, ok := decimalString(txData.member(name))
		if !ok {
			return nil, TxAction{}, malformed("BJ3", "%s is not a decimal string", name)
		}
		big4[i] = n
	}
	value, gasLimit, maxFee, tip := big4[0], big4[1], big4[2], big4[3]
	nonce, ok := jsonUint(txData.member("nonce"))
	if !ok {
		return nil, TxAction{}, malformed("BJ3", "nonce is not an integer up to 2^53-1")
	}
	chainID, ok := jsonUint(txData.member("chainId"))
	if !ok {
		return nil, TxAction{}, malformed("BJ3", "chainId is not an integer up to 2^53-1")
	}

	to, ok := hexString(txData.member("to"), 20)
	if !ok {
		return nil, TxAction{}, malformed("BJ4", "to is not 0x and 40 hex digits")
	}
	data, ok := hexString(txData.member("data"), -1)
	if !ok {
		return nil, TxAction{}, malformed("BJ4", "data is not 0x and an even number of hex digits")
	}
	pid, ok := hexString(paymentID, 32)
	if !ok {
		return nil, TxAction{}, malformed("BJ4", "paymentId is not 0x and 64 hex digits")
	}

	if t := txData.member("type"); t != nil && (t.kind != jsonNumber || t.text != "2") {
		return nil, TxAction{}, malformed("BJ5", "type is not the number 2")
	}
	if l := txData.member("accessList"); l != nil && (l.kind != jsonArray || len(l.elems) != 0) {
		return nil, TxAction{}, malformed("BJ5", "accessList is not empty")
	}

	var p []byte
	for _, it := range [][]byte{
		new(big.Int).SetUint64(chainID).Bytes(), new(big.Int).SetUint64(nonce).Bytes(),
		tip.Bytes(), maxFee.Bytes(), gasLimit.Bytes(), to, value.Bytes(), data,
	} {
		p = append(p, rlpString(it)...)
	}
	p = append(p, 0xc0)
	tx := append(append([]byte{txType}, rlpListHeader(len(p))...), p...)
	action, err := EncodeTxAction(tx, resource, requirementsHash)
	if err != nil {
		return nil, TxAction{}, err
	}
	a, err := DecodeTxAction(action)
	if err != nil {
		return nil, TxAction{}, err
	}
	if !bytes.Equal(pid, a.Deposit.PaymentID[:]) {
		return nil, TxAction{}, malformed("BJ7", "paymentId differs from the calldata's")
	}
	return action, a, nil
}
