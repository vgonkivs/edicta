// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
)

const (
	actionType      = "application/vnd.edicta.eden.escrow-deposit-tx.v1+cbor"
	extractorID     = "eden/escrow-deposit-tx/v1"
	extractorDevID  = "eden/escrow-deposit-tx-dev/v1"
	requirementsTag = "edicta/eden-escrow/v1/requirements"
	depositSig      = "deposit(bytes32,address,address,uint256,uint256,uint256)"
	settleSig       = "settle(bytes32,uint256)"
	errMalformed    = "edenescrow.ErrMalformed"
	errDomain       = "edenescrow.ErrUnknownDomain"
	errFacts        = "ErrFactsInvalid"
	maxInt63        = uint64(1<<63 - 1)
)

var (
	escrow714   = common.HexToAddress("0x65d77c98E73DFbEA91eCb72B27c9753e186a94c8")
	forwarder   = common.HexToAddress("0xEb35f99ED9B10CB724698076b5Be63DE0ed14c3a")
	selDeposit  = crypto.Keccak256([]byte(depositSig))[:4]
	selSettle   = crypto.Keccak256([]byte(settleSig))[:4]
	two256Minus = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))
)

// tableRow is one row of the extractor table; builds is "all" or
// "edictadev". The rows are filled by loadEscrowCode from recorded data.
type tableRow struct {
	chainID uint64
	escrow  common.Address
	builds  string
}

var table []tableRow

// --- deposit calldata ---

type deposit struct {
	paymentID   [32]byte
	payTo       common.Address
	facilitator common.Address
	expiresAt   uint64
	refundAfter uint64
	price       [32]byte
}

func word(b []byte) []byte {
	w := make([]byte, 32)
	copy(w[32-len(b):], b)
	return w
}

func uintWord(u uint64) []byte { return word(new(big.Int).SetUint64(u).Bytes()) }

func (d deposit) calldata() []byte {
	return cat(selDeposit, d.paymentID[:], word(d.payTo[:]), word(d.facilitator[:]),
		uintWord(d.expiresAt), uintWord(d.refundAfter), d.price[:])
}

func decodeCalldataUnchecked(b []byte) deposit {
	var d deposit
	w := func(i int) []byte { return b[4+32*i : 4+32*(i+1)] }
	copy(d.paymentID[:], w(0))
	d.payTo = common.BytesToAddress(w(1)[12:])
	d.facilitator = common.BytesToAddress(w(2)[12:])
	d.expiresAt = new(big.Int).SetBytes(w(3)).Uint64()
	d.refundAfter = new(big.Int).SetBytes(w(4)).Uint64()
	copy(d.price[:], w(5))
	return d
}

func depositFields(d deposit) obj {
	return obj{
		{"payment_id_hex", hx(d.paymentID[:])},
		{"pay_to", strings.ToLower(d.payTo.Hex())},
		{"facilitator", strings.ToLower(d.facilitator.Hex())},
		{"expires_at", dec(d.expiresAt)},
		{"refund_after", dec(d.refundAfter)},
		{"tia_price_usd_hex", hx(d.price[:])},
	}
}

func fill(b byte) (a [32]byte) {
	for i := range a {
		a[i] = b
	}
	return a
}

type callCase struct {
	id, desc, source string
	data             []byte
}

func depositCalls(lv *live) (cases []callCase, byID map[string][]byte) {
	f14 := unhex(lv.Deposit.InnerCall.DataHex)
	var one, maxPrice [32]byte
	one[31] = 1
	copy(maxPrice[:], word(two256Minus.Bytes()))
	min := deposit{
		payTo: common.BytesToAddress([]byte{1}), facilitator: common.BytesToAddress([]byte{2}),
		expiresAt: 1, refundAfter: 2, price: one,
	}
	max := deposit{
		paymentID: fill(0xff), payTo: common.BytesToAddress(bytes.Repeat([]byte{0xff}, 20)),
		facilitator: common.BytesToAddress(bytes.Repeat([]byte{0xfe}, 20)),
		expiresAt:   maxInt63 - 1, refundAfter: maxInt63, price: maxPrice,
	}
	cases = []callCase{
		{"call_f14", "The inner deposit call of the recorded mainnet flow (F14), verbatim.", "f14", f14},
		{"call_min", "Smallest accepted values: zero paymentId, addresses 0x..01 and 0x..02, expiresAt 1, refundAfter 2, tiaPriceUsd 1.", "synthetic", min.calldata()},
		{"call_max", "Largest accepted values: expiresAt 2^63-2, refundAfter 2^63-1, tiaPriceUsd 2^256-1.", "synthetic", max.calldata()},
	}
	byID = map[string][]byte{}
	for _, c := range cases {
		byID[c.id] = c.data
	}
	return cases, byID
}

type rejectCase struct {
	id, rule, cause string
	data            []byte
}

func setWord(b []byte, i int, w []byte) []byte {
	out := bytes.Clone(b)
	copy(out[4+32*i:4+32*(i+1)], w)
	return out
}

func calldataRejects(f14 []byte) []rejectCase {
	dirty := word(escrow714[:])
	dirty[0] = 1
	settle := cat(selSettle, f14[4:36], uintWord(0))
	return []rejectCase{
		{"call_empty", "DC1", "no bytes", nil},
		{"call_195", "DC1", "one byte short", f14[:195]},
		{"call_197", "DC1", "one trailing byte", append(bytes.Clone(f14), 0)},
		{"call_settle", "DC1", "a settle call (68 bytes), not a deposit", settle},
		{"call_settle_selector_196", "DC2", "196 bytes under the settle selector", cat(selSettle, f14[4:])},
		{"call_selector_off_by_one", "DC2", "selector b707d861", cat([]byte{0xb7, 0x07, 0xd8, 0x61}, f14[4:])},
		{"call_pay_to_dirty", "DC3", "payTo word with a nonzero high byte", setWord(f14, 1, dirty)},
		{"call_facilitator_dirty", "DC3", "facilitator word with a nonzero high byte", setWord(f14, 2, dirty)},
		{"call_pay_to_zero", "DC3", "payTo is the zero address", setWord(f14, 1, make([]byte, 32))},
		{"call_facilitator_zero", "DC3", "facilitator is the zero address", setWord(f14, 2, make([]byte, 32))},
		{"call_expires_2_64", "DC4", "expiresAt 2^64 (a nonzero byte above the low 8)", setWord(f14, 3, word([]byte{1, 0, 0, 0, 0, 0, 0, 0, 0}))},
		{"call_expires_2_63", "DC4", "expiresAt 2^63, above 2^63-1", setWord(setWord(f14, 3, uintWord(1<<63)), 4, word([]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}))},
		{"call_expires_zero", "DC4", "expiresAt 0", setWord(f14, 3, uintWord(0))},
		{"call_refund_equal", "DC4", "refundAfter equal to expiresAt", setWord(f14, 4, f14[4+96:4+128])},
		{"call_refund_before", "DC4", "refundAfter one second before expiresAt", setWord(f14, 4, uintWord(decodeCalldataUnchecked(f14).expiresAt-1))},
		{"call_price_zero", "DC5", "tiaPriceUsd 0", setWord(f14, 5, make([]byte, 32))},
	}
}

func buildDepositCallFile(lv *live) obj {
	cases, _ := depositCalls(lv)
	var cs []any
	for _, c := range cases {
		cs = append(cs, obj{
			{"id", c.id}, {"description", c.desc}, {"source", c.source},
			{"data_hex", hx(c.data)}, {"fields", depositFields(decodeCalldataUnchecked(c.data))},
		})
	}
	var rs []any
	for _, r := range calldataRejects(unhex(lv.Deposit.InnerCall.DataHex)) {
		rs = append(rs, obj{
			{"id", r.id}, {"data_hex", hx(r.data)}, {"expect_error", errMalformed},
			{"rule", r.rule}, {"cause", r.cause},
		})
	}
	return obj{
		{"format", format}, {"profile", profile}, {"revision", revision}, {"generator", generator},
		{"upstream", upstream},
		{"signature", depositSig},
		{"selector_hex", hx(selDeposit)},
		{"length", "196"},
		{"cases", cs},
		{"reject", rs},
	}
}

// --- form T transaction and action ---

type txIn struct {
	chainID  uint64
	nonce    uint64
	tip, fee *big.Int
	gas      uint64
	to       common.Address
	value    *big.Int
	data     []byte
}

func (t txIn) items() [][]byte {
	return [][]byte{
		rlpUint(t.chainID), rlpUint(t.nonce), rlpBig(t.tip), rlpBig(t.fee), rlpUint(t.gas),
		rlpStr(t.to[:]), rlpBig(t.value), rlpStr(t.data), rlpList(),
	}
}

func (t txIn) unsigned() []byte { return append([]byte{2}, rlpList(t.items()...)...) }

func (t txIn) geth() *types.Transaction {
	to := t.to
	return types.NewTx(&types.DynamicFeeTx{
		ChainID: new(big.Int).SetUint64(t.chainID), Nonce: t.nonce, GasTipCap: t.tip, GasFeeCap: t.fee,
		Gas: t.gas, To: &to, Value: t.value, Data: t.data,
	})
}

func (t txIn) gethSigner() types.Signer {
	return types.LatestSignerForChainID(new(big.Int).SetUint64(t.chainID))
}

// sighash checks the profile's rule (keccak256 of the action's tx field)
// against go-ethereum's EIP-1559 signing hash before any vector uses it.
func (t txIn) sighash() []byte {
	u := t.unsigned()
	h := crypto.Keccak256(u)
	if g := t.gethSigner().Hash(t.geth()); !bytes.Equal(g[:], h) {
		panic(fmt.Sprintf("sighash differs from go-ethereum for chain %d", t.chainID))
	}
	enc, err := rlp.EncodeToBytes([]any{
		new(big.Int).SetUint64(t.chainID), t.nonce, t.tip, t.fee, t.gas, t.to, t.value, t.data, types.AccessList{},
	})
	if err != nil || !bytes.Equal(append([]byte{2}, enc...), u) {
		panic("hand-built RLP differs from go-ethereum's encoder")
	}
	return h
}

func requirementsHash(raw []byte) []byte {
	h := sha256.Sum256(cat([]byte{byte(len(requirementsTag))}, []byte(requirementsTag), raw))
	return h[:]
}

func actionCBOR(tx []byte, resource string, req []byte) []byte {
	return cborMap(cborUint(1), cborUint(1), cborUint(2), cborBytes(tx), cborUint(3), cborText(resource),
		cborUint(4), cborBytes(req))
}

func actionHash(salt, action []byte) []byte {
	tag := "edicta/v1/action"
	h := sha256.Sum256(cat([]byte{byte(len(tag))}, []byte(tag), []byte{byte(len(actionType))}, []byte(actionType), salt, action))
	return h[:]
}

type facts struct {
	kind, asset, recipient string
	amount                 []byte
	scale                  uint64
}

func factsOf(t txIn) facts {
	d := decodeCalldataUnchecked(t.data)
	return facts{
		kind:      "x402-payment",
		asset:     fmt.Sprintf("eip155:%d/native", t.chainID),
		amount:    t.value.Bytes(),
		scale:     18,
		recipient: fmt.Sprintf("eip155:%d:%s", t.chainID, strings.ToLower(d.payTo.Hex())),
	}
}

func (f facts) cbor() []byte {
	return cborMap(cborUint(1), cborText(f.kind), cborUint(2), cborText(f.asset), cborUint(3), cborBytes(f.amount),
		cborUint(4), cborUint(f.scale), cborUint(5), cborText(f.recipient))
}

func (f facts) json() obj {
	return obj{{"kind", f.kind}, {"asset", f.asset}, {"amount", hx(f.amount)}, {"scale", dec(f.scale)}, {"recipient", f.recipient}}
}

type actionCase struct {
	id, desc, build, callRef string
	tx                       txIn
	resource                 string
	requirements             []byte
}

func (a actionCase) cbor() []byte {
	return actionCBOR(a.tx.unsigned(), a.resource, requirementsHash(a.requirements))
}

// mockRequirements stands in for the exact PaymentRequirements bytes until
// the escrow-upto wire format is known; only its hash enters the action.
func mockRequirements(chainID uint64, value string) []byte {
	return []byte(fmt.Sprintf(`{"scheme":"escrow-upto","network":"eip155:%d","maxAmountRequired":"%s","mock":true}`, chainID, value))
}

func actionCases(lv *live) []actionCase {
	_, calls := depositCalls(lv)
	f14Value, ok := new(big.Int).SetString(lv.Deposit.InnerCall.ValueWei, 10)
	if !ok {
		panic("f14 value")
	}
	base := txIn{
		chainID: 714, nonce: 7, tip: big.NewInt(0), fee: big.NewInt(0x8fb), gas: 200000,
		to: escrow714, value: f14Value, data: calls["call_f14"],
	}
	dev := base
	dev.chainID, dev.to = 31337, escrowCopy
	testnet := base
	testnet.chainID, testnet.to = 3735928814, escrowCopy
	printable := make([]byte, 0, 2048)
	for len(printable) < 2048 {
		printable = append(printable, byte(0x21+len(printable)%94))
	}
	return []actionCase{
		{"tx_f14_714", "Form T deposit on chain 714 with the recorded F14 calldata and value (the F14 flow itself is form A).", "production", "call_f14",
			base, "https://api.example.com/v1/quote?symbol=TIA", mockRequirements(714, f14Value.String())},
		{"tx_min_714", "Smallest integers: nonce 0, tip 0, fee 1, value 1; one-character resource.", "production", "call_min",
			txIn{714, 0, big.NewInt(0), big.NewInt(1), 21000, escrow714, big.NewInt(1), calls["call_min"]}, "a", mockRequirements(714, "1")},
		{"tx_single_byte_714", "Integers at the RLP single-byte boundary: nonce, tip and value 127 (one byte), fee 128 (0x81 0x80).", "production", "call_f14",
			txIn{714, 127, big.NewInt(127), big.NewInt(128), 100000, escrow714, big.NewInt(127), calls["call_f14"]}, "https://x.example/p", mockRequirements(714, "127")},
		{"tx_max_714", "Largest values: nonce and gas 2^63-1, fees and value 2^256-1, a 2048-byte resource of every printable character.", "production", "call_max",
			txIn{714, maxInt63, two256Minus, two256Minus, maxInt63, escrow714, two256Minus, calls["call_max"]}, string(printable), mockRequirements(714, two256Minus.String())},
		{"tx_f14_testnet", "The tx_f14_714 deposit on the testnet 3735928814, to the CREATE2 copy of the escrow.", "production", "call_f14",
			testnet, "https://api.example.com/v1/quote?symbol=TIA", mockRequirements(3735928814, f14Value.String())},
		{"tx_f14_dev_31337", "The tx_f14_714 deposit on the dev chain 31337, to the CREATE2 address; accepted only by an edictadev build.", "edictadev", "call_f14",
			dev, "https://api.example.com/v1/quote?symbol=TIA", mockRequirements(31337, f14Value.String())},
	}
}

type gethTx9 struct {
	ChainID    *big.Int
	Nonce      uint64
	GasTipCap  *big.Int
	GasFeeCap  *big.Int
	Gas        uint64
	To         []byte
	Value      *big.Int
	Data       []byte
	AccessList types.AccessList
}

// gethDecodes reports whether go-ethereum's RLP decoder reads the tx body as
// a nine-field EIP-1559 payload. Informative only: it shows which rejects
// rest on rules of this profile rather than on RLP itself.
func gethDecodes(tx []byte) any {
	if len(tx) == 0 || tx[0] != 2 {
		return nil
	}
	var v gethTx9
	return rlp.DecodeBytes(tx[1:], &v) == nil
}

type actionReject struct {
	id, rule, cause, err, build string
	cbor                        []byte
	tx                          []byte
}

func withItem(items [][]byte, i int, b []byte) [][]byte {
	out := make([][]byte, len(items))
	copy(out, items)
	out[i] = b
	return out
}

func txOf(items [][]byte) []byte { return append([]byte{2}, rlpList(items...)...) }

func actionRejects(a actionCase) []actionReject {
	res, req := a.resource, requirementsHash(a.requirements)
	good := a.tx.unsigned()
	it := a.tx.items()
	wrap := func(tx []byte) []byte { return actionCBOR(tx, res, req) }
	var out []actionReject
	addC := func(id, rule, cause string, b []byte) {
		out = append(out, actionReject{id: id, rule: rule, cause: cause, err: errMalformed, cbor: b})
	}
	addT := func(id, rule, cause, err string, tx []byte) {
		out = append(out, actionReject{id: id, rule: rule, cause: cause, err: err, cbor: wrap(tx), tx: tx})
	}
	k := func(n uint64) []byte { return cborUint(n) }
	txp, rsp, rqp := cborBytes(good), cborText(res), cborBytes(req)
	one := cborUint(1)

	// Action CBOR (EA1 to EA3).
	addC("action_empty", "EA1", "no bytes", nil)
	addC("action_4097", "EA1", "4097 bytes, over the 4096 cap, refused before parsing", cborMap(k(2), cborBytes(make([]byte, 4092))))
	addC("action_indefinite_map", "EA2", "indefinite-length map", cat([]byte{0xbf}, k(1), one, k(2), txp, k(3), rsp, k(4), rqp, []byte{0xff}))
	addC("action_version_two_byte_head", "EA2", "version 1 encoded as 0x18 0x01", cborMap(k(1), []byte{0x18, 0x01}, k(2), txp, k(3), rsp, k(4), rqp))
	addC("action_keys_descending", "EA2", "key 2 before key 1", cborMap(k(2), txp, k(1), one, k(3), rsp, k(4), rqp))
	addC("action_duplicate_key", "EA2", "key 3 twice", cborMap(k(1), one, k(2), txp, k(3), rsp, k(3), rsp, k(4), rqp))
	addC("action_tagged", "EA2", "tag 24 around the map", append([]byte{0xd8, 0x18}, wrap(good)...))
	addC("action_float_version", "EA2", "version as a half float", cborMap(k(1), []byte{0xf9, 0x3c, 0x00}, k(2), txp, k(3), rsp, k(4), rqp))
	addC("action_trailing_byte", "EA2", "one byte after the map", append(wrap(good), 0x00))
	addC("action_array", "EA3", "an array of the four values, not a map", cat([]byte{0x84}, one, txp, rsp, rqp))
	addC("action_unknown_key", "EA3", "extra key 5", cborMap(k(1), one, k(2), txp, k(3), rsp, k(4), rqp, k(5), one))
	addC("action_version_2", "EA3", "version 2", cborMap(k(1), cborUint(2), k(2), txp, k(3), rsp, k(4), rqp))
	addC("action_missing_version", "EA3", "key 1 absent", cborMap(k(2), txp, k(3), rsp, k(4), rqp))
	addC("action_missing_requirements", "EA3", "key 4 absent", cborMap(k(1), one, k(2), txp, k(3), rsp))
	addC("action_tx_as_text", "EA3", "key 2 as a (valid UTF-8) text string", cborMap(k(1), one, k(2), cborText(strings.Repeat("a", 64)), k(3), rsp, k(4), rqp))
	addC("action_tx_empty", "EA3", "key 2 empty", cborMap(k(1), one, k(2), cborBytes(nil), k(3), rsp, k(4), rqp))
	addC("action_tx_513", "EA3", "key 2 of 513 bytes", cborMap(k(1), one, k(2), cborBytes(append(bytes.Clone(good), make([]byte, 513-len(good))...)), k(3), rsp, k(4), rqp))
	addC("action_resource_empty", "EA3", "resource empty", cborMap(k(1), one, k(2), txp, k(3), cborText(""), k(4), rqp))
	addC("action_resource_space", "EA3", "resource with a space (0x20)", cborMap(k(1), one, k(2), txp, k(3), cborText("https://a.example/x y"), k(4), rqp))
	addC("action_resource_del", "EA3", "resource with 0x7f", cborMap(k(1), one, k(2), txp, k(3), cborText("https://a.example/\x7f"), k(4), rqp))
	addC("action_resource_non_ascii", "EA3", "resource with U+00E9", cborMap(k(1), one, k(2), txp, k(3), cborText("https://caf\xc3\xa9.example/"), k(4), rqp))
	addC("action_resource_2049", "EA3", "resource of 2049 bytes", cborMap(k(1), one, k(2), txp, k(3), cborText(strings.Repeat("a", 2049)), k(4), rqp))
	addC("action_requirements_31", "EA3", "requirements_hash of 31 bytes", cborMap(k(1), one, k(2), txp, k(3), rsp, k(4), cborBytes(req[:31])))
	addC("action_requirements_text", "EA3", "requirements_hash as a text string", cborMap(k(1), one, k(2), txp, k(3), rsp, k(4), cborText(strings.Repeat("a", 32))))

	// Transaction (ET1 to ET8, then ED1).
	addT("tx_type_1", "ET1", "type byte 0x01 (EIP-2930)", errMalformed, append([]byte{1}, good[1:]...))
	addT("tx_untyped", "ET1", "the RLP list without the type byte", errMalformed, good[1:])
	addT("tx_trailing_byte", "ET2", "one byte after the list", errMalformed, append(bytes.Clone(good), 0x80))
	list := good[1:]
	short := bytes.Clone(good[:len(good)-1])
	addT("tx_list_truncated", "ET2", "the list header claims one byte more than follows", errMalformed, short)
	addT("tx_8_items", "ET2", "access_list missing", errMalformed, txOf(it[:8]))
	addT("tx_10_items", "ET2", "a tenth item (0x80)", errMalformed, txOf(append(append([][]byte{}, it...), []byte{0x80})))
	addT("tx_list_length_leading_zero", "ET2", "list length with a leading zero byte", errMalformed,
		cat([]byte{2, list[0] + 1, 0x00}, list[1:]))
	addT("tx_nonce_wrapped_single_byte", "ET2", "nonce 7 encoded as 0x81 0x07", errMalformed, txOf(withItem(it, 1, []byte{0x81, 0x07})))
	gas := new(big.Int).SetUint64(a.tx.gas).Bytes()
	addT("tx_gas_long_form", "ET2", "a 3-byte gas_limit in long form (0xb8 0x03 ...)", errMalformed, txOf(withItem(it, 4, cat([]byte{0xb8, byte(len(gas))}, gas))))
	straddle := cat(rlpList(append(append([][]byte{}, it[:8]...), []byte{0xc1})...), []byte{0x80})
	addT("tx_item_straddles_list_end", "ET2", "access_list header 0xc1 claims a byte past the list end; that byte follows the list", errMalformed, append([]byte{2}, straddle...))
	addT("tx_access_list_long_form", "ET2", "the empty access list as 0xf8 0x00 (long form for a short payload)", errMalformed, txOf(withItem(it, 8, []byte{0xf8, 0x00})))
	addT("tx_access_list_as_string", "ET2", "access_list encoded as the empty string 0x80", errMalformed, txOf(withItem(it, 8, []byte{0x80})))
	addT("tx_chain_id_as_list", "ET2", "chain_id encoded as a list", errMalformed, txOf(withItem(it, 0, rlpList(rlpUint(714)))))
	val := a.tx.value.Bytes()
	addT("tx_value_leading_zero", "ET3", "value with a leading zero byte", errMalformed, txOf(withItem(it, 6, rlpStr(append([]byte{0}, val...)))))
	addT("tx_chain_id_leading_zero", "ET3", "chain_id 714 as 00 02 ca", errMalformed, txOf(withItem(it, 0, rlpStr([]byte{0, 2, 0xca}))))
	addT("tx_fee_leading_zero", "ET3", "max_fee_per_gas with a leading zero byte", errMalformed, txOf(withItem(it, 3, rlpStr(append([]byte{0}, a.tx.fee.Bytes()...)))))
	addT("tx_tip_zero_byte", "ET3", "tip 0 encoded as the single byte 0x00 (canonical RLP, not a canonical integer)", errMalformed, txOf(withItem(it, 2, []byte{0x00})))
	addT("tx_nonce_9_bytes", "ET3", "nonce of 9 bytes", errMalformed, txOf(withItem(it, 1, rlpStr([]byte{1, 0, 0, 0, 0, 0, 0, 0, 7}))))
	addT("tx_gas_9_bytes", "ET3", "gas_limit of 9 bytes", errMalformed, txOf(withItem(it, 4, rlpStr(cat([]byte{1}, make([]byte, 5), gas)))))
	addT("tx_tip_33_bytes", "ET3", "max_priority_fee_per_gas of 33 bytes", errMalformed, txOf(withItem(it, 2, rlpStr(cat([]byte{1}, make([]byte, 32))))))
	addT("tx_chain_id_2_63", "ET3", "chain_id 2^63", errMalformed, txOf(withItem(it, 0, rlpUint(1<<63))))
	addT("tx_chain_id_9_bytes", "ET3", "chain_id of 9 bytes", errMalformed, txOf(withItem(it, 0, rlpStr([]byte{1, 0, 0, 0, 0, 0, 0, 2, 0xca}))))
	addT("tx_nonce_2_63", "ET3", "nonce 2^63", errMalformed, txOf(withItem(it, 1, rlpUint(1<<63))))
	addT("tx_gas_2_63", "ET3", "gas_limit 2^63", errMalformed, txOf(withItem(it, 4, rlpUint(1<<63))))
	addT("tx_value_33_bytes", "ET3", "value of 33 bytes", errMalformed, txOf(withItem(it, 6, rlpStr(cat([]byte{1}, make([]byte, 32))))))
	addT("tx_fee_33_bytes", "ET3", "max_fee_per_gas of 33 bytes", errMalformed, txOf(withItem(it, 3, rlpStr(cat([]byte{1}, make([]byte, 32))))))
	addT("tx_tip_above_fee", "ET4", "max_priority_fee_per_gas above max_fee_per_gas", errMalformed, txOf(withItem(it, 2, rlpBig(new(big.Int).Add(a.tx.fee, big.NewInt(1))))))
	addT("tx_to_19_bytes", "ET5", "to of 19 bytes", errMalformed, txOf(withItem(it, 5, rlpStr(escrow714[1:]))))
	addT("tx_to_empty", "ET5", "to empty (contract creation)", errMalformed, txOf(withItem(it, 5, []byte{0x80})))
	addT("tx_value_zero", "ET6", "value 0", errMalformed, txOf(withItem(it, 6, []byte{0x80})))
	al := rlpList(rlpList(rlpStr(escrow714[:]), rlpList()))
	addT("tx_access_list_entry", "ET7", "access_list with one entry", errMalformed, txOf(withItem(it, 8, al)))
	f14 := a.tx.data
	addT("tx_data_settle", "ET8", "calldata of a settle call (DC1)", errMalformed, txOf(withItem(it, 7, rlpStr(cat(selSettle, f14[4:36], uintWord(0))))))
	dirty := word(escrow714[:])
	dirty[0] = 1
	addT("tx_data_pay_to_dirty", "ET8", "payTo word with a nonzero high byte (DC3)", errMalformed, txOf(withItem(it, 7, rlpStr(setWord(f14, 1, dirty)))))
	addT("tx_data_refund_equal", "ET8", "refundAfter equal to expiresAt (DC4)", errMalformed, txOf(withItem(it, 7, rlpStr(setWord(f14, 4, f14[4+96:4+128])))))
	addT("tx_chain_1_and_dirty_data", "ET8", "chain 1 and a dirty payTo: the format rule comes first", errMalformed,
		txOf(withItem(withItem(it, 0, rlpUint(1)), 7, rlpStr(setWord(f14, 1, dirty)))))
	addT("tx_chain_1", "ED1", "chain 1 is not a row", errDomain, txOf(withItem(it, 0, rlpUint(1))))
	addT("tx_testnet_mainnet_address", "ED1", "chain 3735928814 with to = the 714 escrow address (no code there on testnet)", errDomain, txOf(withItem(it, 0, rlpUint(3735928814))))
	addT("tx_714_copy_address", "ED1", "chain 714 with to = the CREATE2 copy address", errDomain, txOf(withItem(it, 5, rlpStr(escrowCopy[:]))))
	addT("tx_chain_0", "ED1", "chain 0", errDomain, txOf(withItem(it, 0, []byte{0x80})))
	addT("tx_other_contract", "ED1", "chain 714 with to = the HoustonForwarder", errDomain, txOf(withItem(it, 5, rlpStr(forwarder[:]))))
	devTx := txOf(withItem(withItem(it, 0, rlpUint(31337)), 5, rlpStr(escrowCopy[:])))
	out = append(out, actionReject{id: "tx_dev_row_in_production", rule: "ED1", cause: "the dev row (31337, CREATE2 address) in a production build",
		err: errDomain, build: "production", cbor: wrap(devTx), tx: devTx})
	devOld := txOf(withItem(it, 0, rlpUint(31337)))
	out = append(out, actionReject{id: "tx_dev_mainnet_address", rule: "ED1", cause: "chain 31337 with to = the 714 escrow address, in an edictadev build",
		err: errDomain, build: "edictadev", cbor: wrap(devOld), tx: devOld})
	return out
}

func buildActionFile(lv *live, code obj) obj {
	var cs []any
	for _, a := range actionCases(lv) {
		u := a.tx.unsigned()
		action := a.cbor()
		salt := label("eden-escrow-v1 vector salt " + a.id)
		f := factsOf(a.tx)
		cs = append(cs, obj{
			{"id", a.id}, {"description", a.desc}, {"build", a.build}, {"extractor_ids", idsFor(a.build)},
			{"input", obj{
				{"chain_id", dec(a.tx.chainID)}, {"nonce", dec(a.tx.nonce)},
				{"max_priority_fee_per_gas", a.tx.tip.String()}, {"max_fee_per_gas", a.tx.fee.String()},
				{"gas_limit", dec(a.tx.gas)}, {"to", strings.ToLower(a.tx.to.Hex())}, {"value", a.tx.value.String()},
				{"data_ref", a.callRef}, {"resource", a.resource},
				{"requirements_hex", hx(a.requirements)},
			}},
			{"requirements_hash_hex", hx(requirementsHash(a.requirements))},
			{"tx_hex", hx(u)},
			{"sighash_hex", hx(a.tx.sighash())},
			{"cbor_hex", hx(action)},
			{"action_salt_hex", hx(salt)},
			{"action_hash_hex", hx(actionHash(salt, action))},
			{"facts", f.json()},
			{"facts_cbor_hex", hx(f.cbor())},
		})
	}
	var rs []any
	for _, r := range actionRejects(actionCases(lv)[0]) {
		build := r.build
		if build == "" {
			build = "production"
		}
		id := extractorID
		if build == "edictadev" {
			id = extractorDevID
		}
		e := obj{{"id", r.id}, {"build", build}, {"extractor_id", id}, {"cbor_hex", hx(r.cbor)}, {"expect_error", r.err},
			{"extractor_expect_error", errFacts}, {"rule", r.rule}, {"cause", r.cause}}
		if r.tx != nil {
			e = append(e, kv{"geth_rlp_decodes", gethDecodes(r.tx)})
		}
		rs = append(rs, e)
	}
	rowsFor := func(dev bool) []any {
		var rows []any
		for _, r := range table {
			if r.builds == "edictadev" && !dev {
				continue
			}
			rows = append(rows, obj{{"chain_id", dec(r.chainID)}, {"escrow", strings.ToLower(r.escrow.Hex())},
				{"code_hash", hx(codeHash)}})
		}
		return rows
	}
	return obj{
		{"format", format}, {"profile", profile}, {"revision", revision}, {"generator", generator},
		{"upstream", upstream},
		{"action_type", actionType},
		{"extractors", []any{
			obj{{"id", extractorID}, {"build", "production"}, {"kind", "x402-payment"}, {"scale", "18"}, {"rows", rowsFor(false)}},
			obj{{"id", extractorDevID}, {"build", "edictadev"}, {"kind", "x402-payment"}, {"scale", "18"}, {"rows", rowsFor(true)}},
		}},
		{"escrow_code", code},
		{"requirements_tag", requirementsTag},
		{"limits", obj{{"action_max", "4096"}, {"tx_max", "512"}, {"resource_max", "2048"}}},
		{"cases", cs},
		{"reject", rs},
	}
}

// idsFor lists the extractors that accept a case: a dev build registers only
// the dev ID for this type, which also holds the production rows.
func idsFor(build string) []string {
	if build == "edictadev" {
		return []string{extractorDevID}
	}
	return []string{extractorID, extractorDevID}
}
