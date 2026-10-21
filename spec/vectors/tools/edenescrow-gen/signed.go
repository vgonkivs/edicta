// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"crypto/ecdsa"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
)

const payerLabel = "eden-escrow-v1 vector key payer1"

var secpN = crypto.S256().Params().N

func payerKey() *ecdsa.PrivateKey {
	k, err := crypto.ToECDSA(label(payerLabel))
	if err != nil {
		panic(err)
	}
	return k
}

type sig struct {
	y    uint64
	r, s *big.Int
}

// splice builds the signed transaction the way the profile's signer does:
// the nine item encodings of the action are copied verbatim and the three
// signature items are appended.
func splice(items [][]byte, sg sig) []byte {
	all := append(append([][]byte{}, items...), rlpUint(sg.y), rlpBig(sg.r), rlpBig(sg.s))
	return txOf(all)
}

func signGeth(t txIn, key *ecdsa.PrivateKey) ([]byte, sig) {
	signed, err := types.SignTx(t.geth(), t.gethSigner(), key)
	if err != nil {
		panic(err)
	}
	bin, err := signed.MarshalBinary()
	if err != nil {
		panic(err)
	}
	v, r, s := signed.RawSignatureValues()
	sg := sig{v.Uint64(), r, s}
	if !bytes.Equal(splice(t.items(), sg), bin) {
		panic("splice rule differs from go-ethereum's signed encoding")
	}
	return bin, sg
}

func railRef(signed []byte) string { return hx(crypto.Keccak256(signed)) }

func buildSignedFile(lv *live) obj {
	key := payerKey()
	payer := crypto.PubkeyToAddress(key.PublicKey)
	acts := actionCases(lv)
	byID := map[string]actionCase{}
	var cases []any
	for _, a := range acts {
		byID[a.id] = a
		bin, sg := signGeth(a.tx, key)
		cases = append(cases, obj{
			{"id", "signed_" + strings.TrimPrefix(a.id, "tx_")}, {"action_ref", a.id}, {"key", "payer1"},
			{"sighash_hex", hx(a.tx.sighash())},
			{"y_parity", dec(sg.y)}, {"r_hex", hx(sg.r.Bytes())}, {"s_hex", hx(sg.s.Bytes())},
			{"signed_hex", hx(bin)}, {"rail_ref", railRef(bin)},
			{"payer", strings.ToLower(payer.Hex())},
		})
	}

	base := byID["tx_f14_714"]
	goodBin, goodSig := signGeth(base.tx, key)
	mut := func(f func(*txIn)) []byte {
		t := base.tx
		t.data = bytes.Clone(t.data)
		f(&t)
		b, _ := signGeth(t, key)
		return b
	}
	gethOther := func(inner types.TxData) []byte {
		chain := big.NewInt(714)
		signed, err := types.SignNewTx(key, types.LatestSignerForChainID(chain), inner)
		if err != nil {
			panic(err)
		}
		b, err := signed.MarshalBinary()
		if err != nil {
			panic(err)
		}
		return b
	}
	to := base.tx.to
	highS := sig{1 - goodSig.y, goodSig.r, new(big.Int).Sub(secpN, goodSig.s)}
	sLeadingZero := cat(rlpStr(append([]byte{0}, goodSig.s.Bytes()...)))
	items := base.tx.items()
	extra := append(append([][]byte{}, items...), rlpUint(goodSig.y), rlpBig(goodSig.r), rlpBig(goodSig.s), []byte{0x80})
	type ee3 struct {
		id, ref, expect, cause string
		signed                 []byte
	}
	var e3 []ee3
	for _, a := range acts {
		b, _ := signGeth(a.tx, key)
		e3 = append(e3, ee3{"exact_" + strings.TrimPrefix(a.id, "tx_"), a.id, "pass", "the signer's output for this action", b})
	}
	e3 = append(e3,
		ee3{"other_nonce", base.id, "wrong_tx", "nonce + 1, signed by the same key", mut(func(t *txIn) { t.nonce++ })},
		ee3{"other_value", base.id, "wrong_tx", "value + 1 wei", mut(func(t *txIn) { t.value = new(big.Int).Add(t.value, big.NewInt(1)) })},
		ee3{"other_payment_id", base.id, "wrong_tx", "paymentId with its last byte changed", mut(func(t *txIn) { t.data[35] ^= 1 })},
		ee3{"other_chain", base.id, "wrong_tx", "the same fields signed for chain 1", mut(func(t *txIn) { t.chainID = 1 })},
		ee3{"other_to", base.id, "wrong_tx", "sent to the HoustonForwarder", mut(func(t *txIn) { t.to = forwarder })},
		ee3{"other_gas", base.id, "wrong_tx", "gas_limit + 1", mut(func(t *txIn) { t.gas++ })},
		ee3{"access_list_entry", base.id, "wrong_tx", "same fields with one access list entry",
			gethOther(&types.DynamicFeeTx{ChainID: big.NewInt(714), Nonce: base.tx.nonce, GasTipCap: base.tx.tip, GasFeeCap: base.tx.fee,
				Gas: base.tx.gas, To: &to, Value: base.tx.value, Data: base.tx.data, AccessList: types.AccessList{{Address: escrow714}}})},
		ee3{"legacy_type", base.id, "wrong_tx", "same fields as an EIP-155 legacy tx (gas price = max fee)",
			gethOther(&types.LegacyTx{Nonce: base.tx.nonce, GasPrice: base.tx.fee, Gas: base.tx.gas, To: &to, Value: base.tx.value, Data: base.tx.data})},
		ee3{"access_list_type", base.id, "wrong_tx", "same fields as an EIP-2930 tx (type 1)",
			gethOther(&types.AccessListTx{ChainID: big.NewInt(714), Nonce: base.tx.nonce, GasPrice: base.tx.fee, Gas: base.tx.gas, To: &to, Value: base.tx.value, Data: base.tx.data})},
		ee3{"high_s", base.id, "wrong_tx", "s replaced by n - s and y_parity flipped (recovers the same key)", splice(items, highS)},
		ee3{"y_parity_2", base.id, "wrong_tx", "y_parity 2", splice(items, sig{2, goodSig.r, goodSig.s})},
		ee3{"r_zero", base.id, "wrong_tx", "r = 0", splice(items, sig{goodSig.y, big.NewInt(0), goodSig.s})},
		ee3{"r_equals_n", base.id, "wrong_tx", "r = n", splice(items, sig{goodSig.y, secpN, goodSig.s})},
		ee3{"s_zero", base.id, "wrong_tx", "s = 0", splice(items, sig{goodSig.y, goodSig.r, big.NewInt(0)})},
		ee3{"r_not_on_curve", base.id, "wrong_tx", "r is no x-coordinate of the curve, so no key recovers", splice(items, sig{goodSig.y, notOnCurve(), goodSig.s})},
		ee3{"y_parity_zero_byte", base.id, "wrong_tx", "y_parity 0 encoded as the single byte 0x00",
			txOf(append(append([][]byte{}, items...), []byte{0x00}, rlpBig(goodSig.r), rlpBig(goodSig.s)))},
		ee3{"s_as_list", base.id, "wrong_tx", "s encoded as a list holding the s string",
			txOf(append(append([][]byte{}, items...), rlpUint(goodSig.y), rlpBig(goodSig.r), rlpList(rlpBig(goodSig.s))))},
		ee3{"s_leading_zero", base.id, "wrong_tx", "s with a leading zero byte",
			txOf(append(append([][]byte{}, items...), rlpUint(goodSig.y), rlpBig(goodSig.r), sLeadingZero))},
		ee3{"thirteen_items", base.id, "wrong_tx", "a thirteenth item after s", txOf(extra)},
		ee3{"trailing_byte", base.id, "wrong_tx", "one byte after the list", append(bytes.Clone(goodBin), 0x80)},
		ee3{"f14_relayed_deposit", base.id, "wrong_tx", "the recorded F14 tx: the same deposit call, relayed through HoustonForwarder.executeBatch (form A)", unhex(lv.Deposit.RawHex)},
	)
	var e3j []any
	for _, c := range e3 {
		e := obj{{"id", c.id}, {"action_ref", c.ref}, {"signed_hex", hx(c.signed)}, {"rail_ref", railRef(c.signed)},
			{"expect", c.expect}, {"cause", c.cause}}
		if c.expect == "pass" {
			e = append(e, kv{"payer", strings.ToLower(payer.Hex())})
		}
		e3j = append(e3j, e)
	}
	if hx(crypto.Keccak256(unhex(lv.Deposit.RawHex))) != strings.TrimPrefix(lv.Deposit.Hash, "0x") {
		panic("f14 deposit hash")
	}

	good := railRef(goodBin)
	railRefs := []obj{
		{{"id", "rail_ref_ok"}, {"rail_ref", good}, {"expect", "ok"}},
		{{"id", "rail_ref_upper"}, {"rail_ref", upperFirstLetter(good)}, {"expect", "malformed_rail_ref"}, {"status", "unchecked"}},
		{{"id", "rail_ref_0x"}, {"rail_ref", "0x" + good}, {"expect", "malformed_rail_ref"}, {"status", "unchecked"}},
		{{"id", "rail_ref_63"}, {"rail_ref", good[:63]}, {"expect", "malformed_rail_ref"}, {"status", "unchecked"}},
		{{"id", "rail_ref_65"}, {"rail_ref", good + "0"}, {"expect", "malformed_rail_ref"}, {"status", "unchecked"}},
		{{"id", "rail_ref_non_hex"}, {"rail_ref", "g" + good[1:]}, {"expect", "malformed_rail_ref"}, {"status", "unchecked"}},
		{{"id", "rail_ref_one_char"}, {"rail_ref", "a"}, {"expect", "malformed_rail_ref"}, {"status", "unchecked"}},
		{{"id", "rail_ref_f14"}, {"rail_ref", strings.TrimPrefix(lv.Deposit.Hash, "0x")}, {"expect", "ok"}},
	}
	return obj{
		{"format", format}, {"profile", profile}, {"revision", revision}, {"generator", generator},
		{"upstream", upstream},
		{"keys", obj{{"payer1", obj{
			{"label", payerLabel}, {"private_key_hex", hx(label(payerLabel))},
			{"public_key_hex", hx(crypto.FromECDSAPub(&key.PublicKey))},
			{"address", strings.ToLower(payer.Hex())},
		}}}},
		{"secp256k1_n_hex", hx(secpN.Bytes())},
		{"cases", cases},
		{"rail_ref", railRefs},
		{"exact_tx", e3j},
	}
}

func upperFirstLetter(s string) string {
	i := strings.IndexAny(s, "abcdef")
	return s[:i] + strings.ToUpper(s[i:i+1]) + s[i+1:]
}

// notOnCurve returns the smallest r for which x^3 + 7 has no square root
// modulo p, so no point has x = r.
func notOnCurve() *big.Int {
	p := crypto.S256().Params().P
	for x := int64(1); ; x++ {
		r := big.NewInt(x)
		y2 := new(big.Int).Exp(r, big.NewInt(3), p)
		y2.Add(y2, big.NewInt(7)).Mod(y2, p)
		if new(big.Int).ModSqrt(y2, p) == nil {
			return r
		}
	}
}
