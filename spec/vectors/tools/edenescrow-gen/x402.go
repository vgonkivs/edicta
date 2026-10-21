// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

const (
	buildFile       = "live/houston-deposit-build.json"
	requiredFile    = "live/houston-payment-required.json"
	otherKeyLabel   = "eden-escrow-v1 vector key facilitator-other"
	maxRequirements = 16384
	bom             = "\xef\xbb\xbf"
)

type houston struct {
	build, required []byte
}

func loadHouston(dir string) houston {
	b, err := os.ReadFile(filepath.Join(dir, buildFile))
	if err != nil {
		panic(err)
	}
	r, err := os.ReadFile(filepath.Join(dir, requiredFile))
	if err != nil {
		panic(err)
	}
	return houston{build: b, required: r}
}

type buildBody struct {
	TxData struct {
		To                   string      `json:"to"`
		Data                 string      `json:"data"`
		Value                string      `json:"value"`
		Nonce                json.Number `json:"nonce"`
		GasLimit             string      `json:"gasLimit"`
		MaxFeePerGas         string      `json:"maxFeePerGas"`
		MaxPriorityFeePerGas string      `json:"maxPriorityFeePerGas"`
		ChainID              json.Number `json:"chainId"`
	} `json:"txData"`
	PaymentID string `json:"paymentId"`
}

type escrowEntry struct {
	Scheme  string `json:"scheme"`
	Network string `json:"network"`
	Asset   string `json:"asset"`
	Amount  string `json:"amount"`
	PayTo   string `json:"payTo"`
	Extra   struct {
		PaymentID       string      `json:"paymentId"`
		EscrowContract  string      `json:"escrowContract"`
		Facilitator     string      `json:"facilitator"`
		RefundAfter     json.Number `json:"refundAfter"`
		ExpiresAt       json.Number `json:"expiresAt"`
		Nonce           string      `json:"nonce"`
		ChainID         json.Number `json:"chainId"`
		TiaPriceUsd     string      `json:"tiaPriceUsd"`
		ServerSignature string      `json:"serverSignature"`
	} `json:"extra"`
}

type paymentRequired struct {
	X402Version int `json:"x402Version"`
	Resource    struct {
		URL string `json:"url"`
	} `json:"resource"`
	Accepts []escrowEntry `json:"accepts"`
}

func mustBig(s string) *big.Int {
	v, ok := new(big.Int).SetString(s, 10)
	if !ok {
		panic("decimal " + s)
	}
	return v
}

func mustU64(n json.Number) uint64 {
	v, ok := new(big.Int).SetString(n.String(), 10)
	if !ok || !v.IsUint64() {
		panic("uint " + n.String())
	}
	return v.Uint64()
}

// txFromBuild is the producer conversion of section 2.2a for a body the
// fixture shows to be well formed; the reject vectors are labelled by hand
// and re-derived by the Python checker.
func txFromBuild(raw []byte) (txIn, [32]byte) {
	var b buildBody
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&b); err != nil {
		panic(err)
	}
	t := b.TxData
	tx := txIn{
		chainID: mustU64(t.ChainID), nonce: mustU64(t.Nonce),
		tip: mustBig(t.MaxPriorityFeePerGas), fee: mustBig(t.MaxFeePerGas), gas: mustBig(t.GasLimit).Uint64(),
		to: common.HexToAddress(t.To), value: mustBig(t.Value), data: unhex(t.Data),
	}
	var pid [32]byte
	copy(pid[:], unhex(b.PaymentID))
	return tx, pid
}

func parseRequired(raw []byte) paymentRequired {
	var pr paymentRequired
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&pr); err != nil {
		panic(err)
	}
	return pr
}

// eip191 is personal_sign's digest of a 32-byte message.
func eip191(m []byte) []byte { return accounts.TextHash(m) }

// signEIP191 returns r || s || v with v = 27 + y_parity, as ethers'
// signMessage does.
func signEIP191(key []byte, m []byte) []byte {
	k, err := crypto.ToECDSA(key)
	if err != nil {
		panic(err)
	}
	sg, err := crypto.Sign(eip191(m), k)
	if err != nil {
		panic(err)
	}
	sg[64] += 27
	return sg
}

func recoverEIP191(m, sg []byte) (common.Address, bool) {
	if len(sg) != 65 {
		return common.Address{}, false
	}
	c := bytes.Clone(sg)
	switch c[64] {
	case 0, 1:
	case 27, 28:
		c[64] -= 27
	default:
		return common.Address{}, false
	}
	pub, err := crypto.SigToPub(eip191(m), c)
	if err != nil {
		return common.Address{}, false
	}
	return crypto.PubkeyToAddress(*pub), true
}

// checkEntry is S4e on the good path: every quoted field equals the tx.
func checkEntry(e escrowEntry, t txIn) {
	d := decodeCalldataUnchecked(t.data)
	eq := func(what string, ok bool) {
		if !ok {
			panic("S4e on the fixture: " + what)
		}
	}
	eq("network", e.Network == fmt.Sprintf("eip155:%d", t.chainID))
	eq("asset", e.Asset == "native")
	eq("amount", mustBig(e.Amount).Cmp(t.value) == 0)
	eq("payTo", common.HexToAddress(e.PayTo) == d.payTo)
	eq("escrow", common.HexToAddress(e.Extra.EscrowContract) == t.to)
	eq("facilitator", common.HexToAddress(e.Extra.Facilitator) == d.facilitator)
	eq("expiresAt", mustU64(e.Extra.ExpiresAt) == d.expiresAt)
	eq("refundAfter", mustU64(e.Extra.RefundAfter) == d.refundAfter)
	eq("tiaPriceUsd", bytes.Equal(word(mustBig(e.Extra.TiaPriceUsd).Bytes()), d.price[:]))
	eq("chainId", mustU64(e.Extra.ChainID) == t.chainID)
	eq("paymentId", bytes.Equal(unhex(e.Extra.PaymentID), d.paymentID[:]))
}

// replaceOnce makes one targeted defect; it panics when the anchor text is
// not in the fixture exactly once, so a changed fixture cannot silently
// produce a vector without its defect.
func replaceOnce(s, old, new string) string {
	if strings.Count(s, old) != 1 {
		panic(fmt.Sprintf("anchor %q found %d times", old, strings.Count(s, old)))
	}
	return strings.Replace(s, old, new, 1)
}

type jsonCase struct {
	id, rule, cause string
	body            string
}

func buildRejects(body string) []jsonCase {
	r := func(old, new string) string { return replaceOnce(body, old, new) }
	const v2256 = "115792089237316195423570985008687907853269984665640564039457584007913129639936"
	return []jsonCase{
		{"build_not_object", "BJ1", "an array at the top level", "[" + body + "]"},
		{"build_trailing", "BJ1", "a character after the object", body + "x"},
		{"build_bom", "BJ1", "a UTF-8 byte order mark first", bom + body},
		{"build_duplicate_member", "BJ1", "value twice inside txData", r(`{"txData":{`, `{"txData":{"value":"1",`)},
		{"build_duplicate_top", "BJ1", "paymentId twice at the top level", r(`,"paymentId":`, `,"paymentId":"0x00","paymentId":`)},
		{"build_txdata_missing", "BJ1", "txData absent (renamed)", r(`"txData"`, `"tx"`)},
		{"build_payment_id_missing", "BJ1", "paymentId absent (renamed)", r(`,"paymentId":`, `,"paymentID":`)},
		{"build_txdata_string", "BJ1", "txData is a string", `{"txData":"0x02","paymentId":"0x64b7e0cf7a15035882485d6a704853c17d7ed8d2b3278c88dc2971236113fed7"}`},
		{"build_from_member", "BJ2", "an extra txData member from", r(`"chainId":714}`, `"chainId":714,"from":"0x0000000000000000000000000000000000000001"}`)},
		{"build_gas_price_member", "BJ2", "an extra txData member gasPrice", r(`"chainId":714}`, `"chainId":714,"gasPrice":"1533"}`)},
		{"build_authorization_list", "BJ2", "an extra txData member authorizationList (a type 4 field)", r(`"chainId":714}`, `"chainId":714,"authorizationList":[]}`)},
		{"build_gas_limit_missing", "BJ2", "gasLimit absent", r(`"gasLimit":"224145",`, ``)},
		{"build_value_number", "BJ3", "value as a JSON number", r(`"value":"7208392580248"`, `"value":7208392580248`)},
		{"build_value_leading_zero", "BJ3", "value with a leading zero", r(`"value":"7208392580248"`, `"value":"07208392580248"`)},
		{"build_value_hex", "BJ3", "value as 0x hex", r(`"value":"7208392580248"`, `"value":"0x68e5bb7a998"`)},
		{"build_value_negative", "BJ3", "value with a minus sign", r(`"value":"7208392580248"`, `"value":"-7208392580248"`)},
		{"build_value_plus", "BJ3", "value with a plus sign", r(`"value":"7208392580248"`, `"value":"+7208392580248"`)},
		{"build_value_empty", "BJ3", "value empty", r(`"value":"7208392580248"`, `"value":""`)},
		{"build_value_79_digits", "BJ3", "value of 79 digits", r(`"value":"7208392580248"`, `"value":"1`+strings.Repeat("0", 78)+`"`)},
		{"build_fee_space", "BJ3", "maxFeePerGas with a trailing space", r(`"maxFeePerGas":"1533"`, `"maxFeePerGas":"1533 "`)},
		{"build_nonce_string", "BJ3", "nonce as a string", r(`"nonce":508260`, `"nonce":"508260"`)},
		{"build_nonce_fraction", "BJ3", "nonce 508260.0", r(`"nonce":508260`, `"nonce":508260.0`)},
		{"build_nonce_exponent", "BJ3", "nonce 5.0826e5", r(`"nonce":508260`, `"nonce":5.0826e5`)},
		{"build_nonce_2_53", "BJ3", "nonce 2^53, above 2^53-1", r(`"nonce":508260`, `"nonce":9007199254740992`)},
		{"build_nonce_negative", "BJ3", "nonce -1", r(`"nonce":508260`, `"nonce":-1`)},
		{"build_chain_id_string", "BJ3", "chainId as a string", r(`"chainId":714`, `"chainId":"714"`)},
		{"build_to_19_bytes", "BJ4", "to of 19 bytes", r(`"to":"0x65d77c98E73DFbEA91eCb72B27c9753e186a94c8"`, `"to":"0x65d77c98E73DFbEA91eCb72B27c9753e186a94"`)},
		{"build_to_no_prefix", "BJ4", "to without 0x", r(`"to":"0x65d77c98E73DFbEA91eCb72B27c9753e186a94c8"`, `"to":"65d77c98E73DFbEA91eCb72B27c9753e186a94c8"`)},
		{"build_to_upper_prefix", "BJ4", "to with 0X", r(`"to":"0x65d77c98E73DFbEA91eCb72B27c9753e186a94c8"`, `"to":"0X65d77c98E73DFbEA91eCb72B27c9753e186a94c8"`)},
		{"build_data_odd", "BJ4", "data with an odd number of hex digits", r(`b3c000","value"`, `b3c00","value"`)},
		{"build_data_non_hex", "BJ4", "data with a g", r(`b3c000","value"`, `b3c00g","value"`)},
		{"build_payment_id_short", "BJ4", "paymentId of 31 bytes", r(`6113fed7"}`, `6113fe"}`)},
		{"build_type_1", "BJ5", "type 1", r(`"chainId":714}`, `"chainId":714,"type":1}`)},
		{"build_type_string", "BJ5", "type as the string 0x2", r(`"chainId":714}`, `"chainId":714,"type":"0x2"}`)},
		{"build_access_list_entry", "BJ5", "a non-empty accessList", r(`"chainId":714}`, `"chainId":714,"accessList":[{"address":"0x65d77c98E73DFbEA91eCb72B27c9753e186a94c8","storageKeys":[]}]}`)},
		{"build_access_list_null", "BJ5", "accessList null", r(`"chainId":714}`, `"chainId":714,"accessList":null}`)},
		{"build_value_zero", "ET6", "value 0: the decoder refuses it", r(`"value":"7208392580248"`, `"value":"0"`)},
		{"build_value_2_256", "ET3", "value 2^256 (78 digits, 33 bytes)", r(`"value":"7208392580248"`, `"value":"`+v2256+`"`)},
		{"build_gas_2_63", "ET3", "gasLimit 2^63", r(`"gasLimit":"224145"`, `"gasLimit":"9223372036854775808"`)},
		{"build_tip_above_fee", "ET4", "maxPriorityFeePerGas above maxFeePerGas", r(`"maxPriorityFeePerGas":"0"`, `"maxPriorityFeePerGas":"1534"`)},
		{"build_selector_other", "ET8", "deposit selector b707d861 (DC2)", r(`"data":"0xb707d860`, `"data":"0xb707d861`)},
		{"build_chain_1", "ED1", "chainId 1", r(`"chainId":714`, `"chainId":1`)},
		{"build_escrow_other", "ED1", "to = the HoustonForwarder", r(`"to":"0x65d77c98E73DFbEA91eCb72B27c9753e186a94c8"`, `"to":"0xeb35f99ed9b10cb724698076b5be63de0ed14c3a"`)},
		{"build_payment_id_other", "BJ7", "top-level paymentId differs from the calldata's", r(`6113fed7"}`, `6113fed8"}`)},
	}
}

func buildVariants(body string) []jsonCase {
	r := func(old, new string) string { return replaceOnce(body, old, new) }
	return []jsonCase{
		{"build_fixture", "pass", "the fixture as received", body},
		{"build_type_2", "pass", "type 2 present", r(`"chainId":714}`, `"chainId":714,"type":2}`)},
		{"build_access_list_empty", "pass", "accessList [] present", r(`"chainId":714}`, `"chainId":714,"accessList":[]}`)},
		{"build_unknown_top_member", "pass", "an unknown top-level member is ignored", r(`{"txData":`, `{"status":"ok","txData":`)},
		{"build_upper_hex", "pass", "to in upper-case hex digits (no checksum check)", r(`"to":"0x65d77c98E73DFbEA91eCb72B27c9753e186a94c8"`, `"to":"0x65D77C98E73DFBEA91ECB72B27C9753E186A94C8"`)},
		{"build_escaped_name", "pass", `member name "to" written as "to" (compared after unescaping)`, r(`"to":`, `"to":`)},
		{"build_whitespace", "pass", "spaces, tabs and CR LF between tokens", r(`{"txData":{`, "{ \"txData\" :\t{\r\n")},
	}
}

func requirementsCases(raw []byte, t txIn) (pass, rej []obj) {
	s := string(raw)
	r := func(old, new string) string { return replaceOnce(s, old, new) }
	sigHex := parseRequired(raw).Accepts[0].Extra.ServerSignature
	sig := unhex(sigHex)
	withV := func(v byte) string {
		c := bytes.Clone(sig)
		c[64] = v
		return r(sigHex, "0x"+hx(c))
	}
	sZero := bytes.Clone(sig)
	copy(sZero[32:64], make([]byte, 32))
	d := decodeCalldataUnchecked(t.data)
	other := signEIP191(label(otherKeyLabel), d.paymentID[:])
	var compact bytes.Buffer
	if err := json.Compact(&compact, raw); err != nil {
		panic(err)
	}
	entry := s[strings.Index(s, `    {`) : strings.LastIndex(s, `    }`)+5]
	exact := replaceOnce(entry, `"scheme": "escrow-upto"`, `"scheme": "exact"`)
	add := func(list *[]obj, id, rule, cause, body string, binding []byte) {
		h := requirementsHash([]byte(body))
		if binding != nil {
			h = binding
		}
		*list = append(*list, obj{{"id", id}, {"expect", rule}, {"cause", cause},
			{"r_hex", hx([]byte(body))}, {"requirements_hash_hex", hx(h)}})
	}
	add(&pass, "r_fixture", "pass", "the fixture bytes (a re-serialization, not wire bytes)", s, nil)
	add(&pass, "r_compact", "pass", "the same document without whitespace (other bytes, other hash)", compact.String(), nil)
	add(&pass, "r_server_sig_v27", "pass", "serverSignature with v = 27 instead of 0", withV(27), nil)
	add(&pass, "r_extra_entry", "pass", "a second accepts entry of scheme exact is ignored", r(entry, entry+",\n"+exact), nil)
	add(&pass, "r_nonce_absent", "pass", "extra.nonce absent: S4 passes, S11 with field nonce refuses", r(`        "nonce": "0x6c10d990d3315965b652bc89080cc3d4998a84be859f461eeeb582cd5d34b0a1",`+"\n", ``), nil)

	add(&rej, "r_too_large", "S4a", "16385 bytes (whitespace padding after the object)", s+strings.Repeat(" ", maxRequirements+1-len(s)), nil)
	add(&rej, "r_binding", "S4b", "one whitespace byte added; the action's requirements_hash is over the fixture", s+"\n", requirementsHash(raw))
	add(&rej, "r_trailing", "S4c", "a character after the object", s+"x", nil)
	add(&rej, "r_bom", "S4c", "a UTF-8 byte order mark first", bom+s, nil)
	add(&rej, "r_duplicate_member", "S4c", "amount twice in the entry", r(`"amount": "7208392580248",`, `"amount": "1", "amount": "7208392580248",`), nil)
	add(&rej, "r_version_1", "S4c", "x402Version 1", r(`"x402Version": 2`, `"x402Version": 1`), nil)
	add(&rej, "r_version_string", "S4c", "x402Version as a string", r(`"x402Version": 2`, `"x402Version": "2"`), nil)
	add(&rej, "r_accepts_object", "S4c", "accepts is an object", replaceOnce(r(`"accepts": [`, `"accepts": {"a": [`), "  ]\n}", "  ]}\n}"), nil)
	add(&rej, "r_no_entry", "S4d", "the only entry has scheme exact", r(`"scheme": "escrow-upto"`, `"scheme": "exact"`), nil)
	add(&rej, "r_two_entries", "S4d", "the escrow-upto entry twice", r(entry, entry+",\n"+entry), nil)
	add(&rej, "r_payment_id_other", "S4d", "the entry's paymentId differs from w0", r(`"paymentId": "0x64b7e0cf`, `"paymentId": "0x64b7e0ce`), nil)
	add(&rej, "r_amount_other", "S4e", "amount one wei more than value", r(`"amount": "7208392580248"`, `"amount": "7208392580249"`), nil)
	add(&rej, "r_amount_leading_zero", "S4e", "amount with a leading zero", r(`"amount": "7208392580248"`, `"amount": "07208392580248"`), nil)
	add(&rej, "r_amount_number", "S4e", "amount as a JSON number", r(`"amount": "7208392580248"`, `"amount": 7208392580248`), nil)
	add(&rej, "r_network_other", "S4e", "network eip155:1", r(`"network": "eip155:714"`, `"network": "eip155:1"`), nil)
	add(&rej, "r_asset_token", "S4e", "asset is a token address", r(`"asset": "native"`, `"asset": "0x65d77c98E73DFbEA91eCb72B27c9753e186a94c8"`), nil)
	add(&rej, "r_pay_to_other", "S4e", "payTo differs from w1", r(`"payTo": "0xC5AaA301`, `"payTo": "0xC5AaA302`), nil)
	add(&rej, "r_escrow_other", "S4e", "escrowContract differs from to", r(`"escrowContract": "0x65d77c98`, `"escrowContract": "0x65d77c99`), nil)
	add(&rej, "r_facilitator_other", "S4e", "facilitator differs from w2", r(`"facilitator": "0xEC7557EA`, `"facilitator": "0xEC7557EB`), nil)
	add(&rej, "r_expires_other", "S4e", "expiresAt differs from w3", r(`"expiresAt": 1792466814`, `"expiresAt": 1792466815`), nil)
	add(&rej, "r_expires_string", "S4e", "expiresAt as a string", r(`"expiresAt": 1792466814`, `"expiresAt": "1792466814"`), nil)
	add(&rej, "r_refund_other", "S4e", "refundAfter differs from w4", r(`"refundAfter": 1793071314`, `"refundAfter": 1793071315`), nil)
	add(&rej, "r_price_other", "S4e", "tiaPriceUsd differs from w5", r(`"tiaPriceUsd": "621692000000000000"`, `"tiaPriceUsd": "621692000000000001"`), nil)
	add(&rej, "r_chain_id_other", "S4e", "extra.chainId 1", r(`"chainId": 714`, `"chainId": 1`), nil)
	add(&rej, "r_nonce_short", "S4e", "extra.nonce of 31 bytes", r(`5d34b0a1"`, `5d34b0"`), nil)
	add(&rej, "r_server_sig_other_key", "S4f", "serverSignature over the same paymentId by another key", r(sigHex, "0x"+hx(other)), nil)
	add(&rej, "r_server_sig_v2", "S4f", "serverSignature with v = 2", withV(2), nil)
	add(&rej, "r_server_sig_s_zero", "S4f", "serverSignature with s = 0", r(sigHex, "0x"+hx(sZero)), nil)
	add(&rej, "r_server_sig_short", "S4f", "serverSignature of 64 bytes", r(sigHex, sigHex[:len(sigHex)-2]), nil)
	add(&rej, "r_server_sig_absent", "S4f", "serverSignature absent", dropServerSig(s, sigHex), nil)
	return pass, rej
}

func dropServerSig(s, sigHex string) string {
	return replaceOnce(s, `,
        "serverSignature": "`+sigHex+`"`, ``)
}

func buildX402File(h houston) obj {
	key := payerKey()
	payer := crypto.PubkeyToAddress(key.PublicKey)
	tx, pid := txFromBuild(h.build)
	pr := parseRequired(h.required)
	if len(pr.Accepts) != 1 || pr.X402Version != 2 {
		panic("fixture shape")
	}
	entry := pr.Accepts[0]
	checkEntry(entry, tx)
	d := decodeCalldataUnchecked(tx.data)
	if pid != d.paymentID {
		panic("build paymentId differs from calldata")
	}
	u := tx.unsigned()
	sh := tx.sighash()
	if hx(sh) != "2b459989ad782892ebe827e4a050ba1b2d1ac9eafe7d261f410cf0979d4ad8dc" || len(u) != 245 {
		panic("fixture tx differs from the research record")
	}
	resource := pr.Resource.URL
	reqHash := requirementsHash(h.required)
	action := actionCBOR(u, resource, reqHash)
	salt := label("eden-escrow-v1 vector salt houston_build")
	f, ok := factsOf(tx)
	if !ok {
		panic("fixture facts")
	}

	srvSig := unhex(entry.Extra.ServerSignature)
	srvAddr, ok := recoverEIP191(d.paymentID[:], srvSig)
	if !ok || srvAddr != d.facilitator {
		panic("serverSignature does not recover to the facilitator")
	}

	var builds []any
	for _, c := range buildVariants(string(h.build)) {
		builds = append(builds, obj{{"id", c.id}, {"expect", c.rule}, {"cause", c.cause}, {"json", c.body}})
	}
	var bRej []any
	for _, c := range buildRejects(string(h.build)) {
		bRej = append(bRej, obj{{"id", c.id}, {"expect", c.rule}, {"cause", c.cause}, {"json", c.body}})
	}
	rPass, rRej := requirementsCases(h.required, tx)

	nonce := unhex(entry.Extra.Nonce)
	psig := func(field string, m []byte) obj {
		sg := signEIP191(label(payerLabel), m)
		got, ok := recoverEIP191(m, sg)
		if !ok || got != payer {
			panic("payment signature does not recover to payer1")
		}
		return obj{
			{"field", field}, {"message_hex", hx(m)},
			{"preimage_hex", hx(cat([]byte("\x19Ethereum Signed Message:\n32"), m))},
			{"digest_hex", hx(eip191(m))},
			{"signature_hex", hx(sg)}, {"signer", strings.ToLower(payer.Hex())},
		}
	}
	srvDigest := eip191(d.paymentID[:])

	sum := sha256.Sum256(h.build)
	sumR := sha256.Sum256(h.required)
	return obj{
		{"format", format}, {"profile", profile}, {"revision", revision}, {"generator", generator},
		{"upstream", upstream},
		{"inputs", obj{
			{"deposit_build", obj{{"file", buildFile}, {"sha256", hx(sum[:])},
				{"note", "The /deposit/build answer of the Houston server, copied byte for byte from the requester's client fixtures; never signed or sent."}}},
			{"payment_required", obj{{"file", requiredFile}, {"sha256", hx(sumR[:])}, {"wire_bytes", false},
				{"note", "The base64-decoded payment-required header of a live 402 as the client's author saved it (pretty-printed). Not known to be the wire bytes, so it is a mock R: every value is real, the hash is not that of the live header."}}},
		}},
		{"build", obj{
			{"from_file", buildFile},
			{"input", obj{
				{"chain_id", dec(tx.chainID)}, {"nonce", dec(tx.nonce)},
				{"max_priority_fee_per_gas", tx.tip.String()}, {"max_fee_per_gas", tx.fee.String()},
				{"gas_limit", dec(tx.gas)}, {"to", strings.ToLower(tx.to.Hex())}, {"value", tx.value.String()},
				{"data_hex", hx(tx.data)}, {"payment_id_hex", hx(pid[:])},
			}},
			{"tx_hex", hx(u)},
			{"tx_length", dec(uint64(len(u)))},
			{"sighash_hex", hx(sh)},
			{"resource", resource},
			{"requirements_from_file", requiredFile},
			{"requirements_hash_hex", hx(reqHash)},
			{"cbor_hex", hx(action)},
			{"action_length", dec(uint64(len(action)))},
			{"action_salt_hex", hx(salt)},
			{"action_hash_hex", hx(actionHash(salt, action))},
			{"extractor_ids", idsFor("production")},
			{"facts", f.json()},
			{"facts_cbor_hex", hx(f.cbor())},
			{"profile_fields", profileFields(tx)},
		}},
		{"build_accept", builds},
		{"build_reject", bRej},
		{"requirements", obj{
			{"tx_ref", "build"},
			{"max_length", dec(maxRequirements)},
			{"check_server_signature", true},
			{"server_signature", obj{
				{"message_hex", hx(d.paymentID[:])}, {"digest_hex", hx(srvDigest)},
				{"signature_hex", hx(srvSig)}, {"v", dec(uint64(srvSig[64]))},
				{"recovered", strings.ToLower(srvAddr.Hex())}, {"facilitator_w2", strings.ToLower(d.facilitator.Hex())},
			}},
			{"accept", rPass},
			{"reject", rRej},
		}},
		{"payment_signature", obj{
			{"key", "payer1 (signed.json keys)"},
			{"scheme", "EIP-191 personal_sign over 32 raw bytes; signature r || s || v, v = 27 + y_parity, RFC 6979, low s"},
			{"cases", []any{psig("paymentId", d.paymentID[:]), psig("nonce", nonce)}},
			{"payment_id_digest_equals_server_signature_digest", bytes.Equal(eip191(d.paymentID[:]), srvDigest)},
		}},
	}
}
