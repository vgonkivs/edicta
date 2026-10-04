// Command banksend-gen writes the protobuf vectors of the bank-send profile
// (msg_send.json and tx.json) with the real cosmos-sdk types of the
// celestia fork that celestia-app runs. It lives in its own module so the
// main module never depends on cosmos-sdk, and so no Edicta code can leak
// into the expected bytes: every encoding here is gogoproto's.
//
// Usage (from this directory):
//
//	go run .           regenerate ../../profiles/bank-send/{msg_send,tx}.json
//	go run . -check    exit 1 if either file differs from a fresh generation
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	sdkmath "cosmossdk.io/math"
	"github.com/cosmos/cosmos-sdk/codec/types"
	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/bech32"
	txtypes "github.com/cosmos/cosmos-sdk/types/tx"
	"github.com/cosmos/cosmos-sdk/types/tx/signing"
	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"
)

const (
	format          = "edicta-vectors/v0"
	profile         = "bank-send"
	profileRevision = "bank-send-v0-draft.1"
	msgSendTypeURL  = "/cosmos.bank.v1beta1.MsgSend"
	pubKeyTypeURL   = "/cosmos.crypto.secp256k1.PubKey"
	hrpCelestia     = "celestia"
	maxInt63        = uint64(1<<63 - 1)
	errMalformed    = "bankmsg.ErrMalformed"
	errBodyMismatch = "bankaction.ErrBodyMismatch"
)

var upstream = map[string]string{
	"cosmos-sdk":   "github.com/celestiaorg/cosmos-sdk v0.52.12 (replace of github.com/cosmos/cosmos-sdk, as in celestia-app v10.4.0-mocha go.mod)",
	"celestia-app": "v10.4.0-mocha (5187d2fb5eb8bc4b534c74724882943c54253ae9), source of the replace block",
}

func label(s string) []byte {
	h := sha256.Sum256([]byte(s))
	return h[:]
}

func addr(hrp string, b []byte) string {
	s, err := bech32.ConvertAndEncode(hrp, b)
	if err != nil {
		panic(err)
	}
	return s
}

type coinJSON struct {
	Denom  string `json:"denom"`
	Amount string `json:"amount"`
}

type msgInput struct {
	FromAddress string   `json:"from_address"`
	ToAddress   string   `json:"to_address"`
	Amount      coinJSON `json:"amount"`
}

type msgCase struct {
	ID          string   `json:"id"`
	Description string   `json:"description"`
	HRP         string   `json:"hrp"`
	Input       msgInput `json:"input"`
	FromHex     string   `json:"from_hex"`
	ToHex       string   `json:"to_hex"`
	MsgHex      string   `json:"msg_hex"`
}

type msgReject struct {
	ID          string `json:"id"`
	Description string `json:"description"`
	HRP         string `json:"hrp"`
	MsgHex      string `json:"msg_hex"`
	ExpectError string `json:"expect_error"`
	// SDKUnmarshalOK records whether gogoproto's MsgSend.Unmarshal accepts
	// the bytes, which shows where the profile decoder is stricter.
	SDKUnmarshalOK bool `json:"sdk_unmarshal_ok"`
}

type msgFile struct {
	Format    string            `json:"format"`
	Profile   string            `json:"profile"`
	Revision  string            `json:"revision"`
	Generator string            `json:"generator"`
	Upstream  map[string]string `json:"upstream"`
	TypeURL   string            `json:"type_url"`
	Cases     []msgCase         `json:"cases"`
	Reject    []msgReject       `json:"reject"`
}

type bodyCase struct {
	ID                string `json:"id"`
	Description       string `json:"description"`
	MsgRef            string `json:"msg_ref"`
	CommitmentHashHex string `json:"commitment_hash_hex"`
	TimeoutHeight     string `json:"timeout_height"`
	Memo              string `json:"memo"`
	BodyHex           string `json:"body_hex"`
}

type bodyReject struct {
	ID                string `json:"id"`
	Description       string `json:"description"`
	MsgRef            string `json:"msg_ref"`
	CommitmentHashHex string `json:"commitment_hash_hex"`
	BodyHex           string `json:"body_hex"`
	ExpectError       string `json:"expect_error"`
}

type keyJSON struct {
	Label      string `json:"label"`
	PrivHex    string `json:"priv_hex"`
	PubKeyHex  string `json:"pubkey_hex"`
	AddressHex string `json:"address_hex"`
	Address    string `json:"address"`
}

type signedCase struct {
	ID            string   `json:"id"`
	Description   string   `json:"description"`
	BodyRef       string   `json:"body_ref"`
	ChainID       string   `json:"chain_id"`
	AccountNumber string   `json:"account_number"`
	Sequence      string   `json:"sequence"`
	Fee           coinJSON `json:"fee"`
	GasLimit      string   `json:"gas_limit"`
	Key           keyJSON  `json:"key"`
	AuthInfoHex   string   `json:"auth_info_hex"`
	SignDocHex    string   `json:"sign_doc_hex"`
	SignatureHex  string   `json:"signature_hex"`
	TxRawHex      string   `json:"tx_raw_hex"`
	TxHashHex     string   `json:"tx_hash_hex"`
	RailRef       string   `json:"rail_ref"`
}

type txFile struct {
	Format     string            `json:"format"`
	Profile    string            `json:"profile"`
	Revision   string            `json:"revision"`
	Generator  string            `json:"generator"`
	Upstream   map[string]string `json:"upstream"`
	Body       []bodyCase        `json:"body"`
	BodyReject []bodyReject      `json:"body_reject"`
	Signed     []signedCase      `json:"signed"`
}

func senderKey(n int) *secp256k1.PrivKey {
	return &secp256k1.PrivKey{Key: label("edicta/v0 test bank sender|" + strconv.Itoa(n))}
}

func receiver(n int) []byte {
	return label("edicta/v0 test bank receiver|" + strconv.Itoa(n))[:20]
}

func marshalMsg(from, to, denom, amount string) []byte {
	amt, ok := sdkmath.NewIntFromString(amount)
	if !ok {
		panic("bad amount " + amount)
	}
	m := banktypes.MsgSend{
		FromAddress: from,
		ToAddress:   to,
		Amount:      sdk.Coins{sdk.Coin{Denom: denom, Amount: amt}},
	}
	b, err := m.Marshal()
	if err != nil {
		panic(err)
	}
	return b
}

func sdkAccepts(b []byte) bool {
	var m banktypes.MsgSend
	return m.Unmarshal(b) == nil
}

// Hand-built wire pieces for the reject vectors only; every accepted byte
// string above comes from gogoproto.
func varint(v uint64) []byte {
	var out []byte
	for v >= 0x80 {
		out = append(out, byte(v)|0x80)
		v >>= 7
	}
	return append(out, byte(v))
}

func field(num int, b []byte) []byte {
	out := varint(uint64(num<<3 | 2))
	out = append(out, varint(uint64(len(b)))...)
	return append(out, b...)
}

func coin(denom, amount string) []byte {
	return append(field(1, []byte(denom)), field(2, []byte(amount))...)
}

func cat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func bech32mEncode(hrp string, data []byte) string {
	var conv []byte
	acc, bits := uint32(0), uint(0)
	for _, b := range data {
		acc = acc<<8 | uint32(b)
		bits += 8
		for bits >= 5 {
			bits -= 5
			conv = append(conv, byte(acc>>bits)&31)
		}
	}
	if bits > 0 {
		conv = append(conv, byte(acc<<(5-bits))&31)
	}
	// bech32 (BIP-173) and bech32m (BIP-350) differ only in the checksum
	// constant; the cosmos library has no bech32m encoder, so compute it.
	const charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
	values := append(hrpExpand(hrp), conv...)
	values = append(values, 0, 0, 0, 0, 0, 0)
	mod := polymod(values) ^ 0x2bc830a3
	var sb strings.Builder
	sb.WriteString(hrp)
	sb.WriteByte('1')
	for _, v := range conv {
		sb.WriteByte(charset[v])
	}
	for i := 0; i < 6; i++ {
		sb.WriteByte(charset[(mod>>uint(5*(5-i)))&31])
	}
	return sb.String()
}

func hrpExpand(hrp string) []byte {
	var out []byte
	for i := 0; i < len(hrp); i++ {
		out = append(out, hrp[i]>>5)
	}
	out = append(out, 0)
	for i := 0; i < len(hrp); i++ {
		out = append(out, hrp[i]&31)
	}
	return out
}

func polymod(values []byte) uint32 {
	gen := []uint32{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}
	chk := uint32(1)
	for _, v := range values {
		top := chk >> 25
		chk = (chk&0x1ffffff)<<5 ^ uint32(v)
		for i := 0; i < 5; i++ {
			if (top>>uint(i))&1 == 1 {
				chk ^= gen[i]
			}
		}
	}
	return chk
}

func flipLastChar(s string) string {
	b := []byte(s)
	if b[len(b)-1] == 'q' {
		b[len(b)-1] = 'p'
	} else {
		b[len(b)-1] = 'q'
	}
	return string(b)
}

func msgVectors() msgFile {
	from := sdk.AccAddress(senderKey(1).PubKey().Address())
	to1, to2 := receiver(1), receiver(2)
	fromS := addr(hrpCelestia, from)
	to1S, to2S := addr(hrpCelestia, to1), addr(hrpCelestia, to2)

	ibc := "ibc/" + strings.ToUpper(hex.EncodeToString(label("edicta/v0 test ibc denom")))
	denom128 := "u" + strings.Repeat("a", 127)

	f := msgFile{
		Format: format, Profile: profile, Revision: profileRevision,
		Generator: "spec/vectors/tools/banksend-gen", Upstream: upstream, TypeURL: msgSendTypeURL,
	}
	add := func(id, desc, hrp, fromA, toA string, fromB, toB []byte, denom, amount string) {
		f.Cases = append(f.Cases, msgCase{
			ID: id, Description: desc, HRP: hrp,
			Input:   msgInput{FromAddress: fromA, ToAddress: toA, Amount: coinJSON{Denom: denom, Amount: amount}},
			FromHex: hex.EncodeToString(fromB), ToHex: hex.EncodeToString(toB),
			MsgHex: hex.EncodeToString(marshalMsg(fromA, toA, denom, amount)),
		})
	}
	add("msg_minimal", "1 utia from the test sender to receiver 1.", hrpCelestia, fromS, to1S, from, to1, "utia", "1")
	add("msg_typical", "1 TIA (1000000 utia) to receiver 2.", hrpCelestia, fromS, to2S, from, to2, "utia", "1000000")
	add("msg_max_amount", "Amount 2^63-1, the largest the profile accepts.", hrpCelestia, fromS, to1S, from, to1,
		"utia", strconv.FormatUint(maxInt63, 10))
	add("msg_ibc_denom", "An IBC denom (ibc/ + 64 upper-case hex): upper case is legal in the Cosmos denom grammar.",
		hrpCelestia, fromS, to1S, from, to1, ibc, "250")
	add("msg_denom_128", "A 128-character denom; the message is longer than 127 bytes, so its length varints take two bytes.",
		hrpCelestia, fromS, to1S, from, to1, denom128, "7")
	add("msg_other_hrp", "Prefix cosmos: the prefix is the chain's, taken from the node, never assumed.",
		"cosmos", addr("cosmos", from), addr("cosmos", to1), from, to1, "stake", "42")

	good := marshalMsg(fromS, to1S, "utia", "1")
	fF, fT := field(1, []byte(fromS)), field(2, []byte(to1S))
	fA := field(3, coin("utia", "1"))
	rej := func(id, desc string, b []byte) {
		f.Reject = append(f.Reject, msgReject{
			ID: id, Description: desc, HRP: hrpCelestia, MsgHex: hex.EncodeToString(b),
			ExpectError: errMalformed, SDKUnmarshalOK: sdkAccepts(b),
		})
	}
	if !bytes.Equal(good, cat(fF, fT, fA)) {
		panic("hand-built MsgSend differs from gogoproto")
	}
	rej("msg_empty", "Zero bytes.", nil)
	rej("msg_missing_amount", "Fields 1 and 2 only.", cat(fF, fT))
	rej("msg_missing_to", "Fields 1 and 3 only.", cat(fF, fA))
	rej("msg_missing_from", "Fields 2 and 3 only.", cat(fT, fA))
	rej("msg_fields_out_of_order", "to_address before from_address.", cat(fT, fF, fA))
	rej("msg_amount_first", "amount before the addresses.", cat(fA, fF, fT))
	rej("msg_duplicate_from", "from_address twice (protobuf keeps the last; the profile refuses).", cat(fF, fF, fT, fA))
	rej("msg_unknown_field_varint", "Unknown field 4, wire type 0, after amount.", cat(fF, fT, fA, []byte{0x20, 0x01}))
	rej("msg_unknown_field_bytes", "Unknown field 15, wire type 2.", cat(fF, fT, fA, field(15, []byte("x"))))
	rej("msg_trailing_byte", "One zero byte after the message.", cat(good, []byte{0x00}))
	rej("msg_truncated", "Last byte of amount missing.", good[:len(good)-1])
	rej("msg_nonminimal_length", "from_address length as a two-byte varint (0xaf 0x00).",
		cat([]byte{0x0a, 0x80 | byte(len(fromS)), 0x00}, []byte(fromS), fT, fA))
	rej("msg_nonminimal_tag", "Tag of field 1 as a two-byte varint (0x8a 0x00).",
		cat([]byte{0x8a, 0x00, byte(len(fromS))}, []byte(fromS), fT, fA))
	rej("msg_wrong_wire_type", "from_address with wire type 0.", cat([]byte{0x08, 0x01}, fT, fA))
	rej("msg_two_coins", "Two Coin entries.", cat(fF, fT, fA, field(3, coin("utia", "2"))))
	rej("msg_coin_missing_amount", "Coin with denom only.", cat(fF, fT, field(3, field(1, []byte("utia")))))
	rej("msg_coin_missing_denom", "Coin with amount only.", cat(fF, fT, field(3, field(2, []byte("1")))))
	rej("msg_coin_fields_reversed", "Coin amount before denom.", cat(fF, fT, field(3, cat(field(2, []byte("1")), field(1, []byte("utia"))))))
	rej("msg_coin_empty_amount_present", "Coin amount present as an empty string.", cat(fF, fT, field(3, coin("utia", ""))))
	rej("msg_coin_unknown_field", "Coin with an unknown field 3.", cat(fF, fT, field(3, cat(coin("utia", "1"), field(3, []byte("x"))))))
	rej("msg_amount_zero", "Amount 0.", cat(fF, fT, field(3, coin("utia", "0"))))
	rej("msg_amount_leading_zero", "Amount 01.", cat(fF, fT, field(3, coin("utia", "01"))))
	rej("msg_amount_2pow63", "Amount 2^63.", cat(fF, fT, field(3, coin("utia", "9223372036854775808"))))
	rej("msg_amount_negative", "Amount -1.", cat(fF, fT, field(3, coin("utia", "-1"))))
	rej("msg_amount_plus", "Amount +1.", cat(fF, fT, field(3, coin("utia", "+1"))))
	rej("msg_amount_decimal", "Amount 1.5.", cat(fF, fT, field(3, coin("utia", "1.5"))))
	rej("msg_amount_space", "Amount with a leading space.", cat(fF, fT, field(3, coin("utia", " 1"))))
	rej("msg_denom_2_chars", "Denom ut (below 3).", cat(fF, fT, field(3, coin("ut", "1"))))
	rej("msg_denom_129_chars", "Denom of 129 characters.", cat(fF, fT, field(3, coin("u"+strings.Repeat("a", 128), "1"))))
	rej("msg_denom_digit_first", "Denom 1tia.", cat(fF, fT, field(3, coin("1tia", "1"))))
	rej("msg_denom_space", "Denom u tia.", cat(fF, fT, field(3, coin("u tia", "1"))))
	rej("msg_from_uppercase", "from_address in upper-case bech32 (valid bech32, refused: lower case only).",
		cat(field(1, []byte(strings.ToUpper(fromS))), fT, fA))
	rej("msg_from_mixed_case", "from_address with one upper-case letter (invalid bech32).",
		cat(field(1, []byte(strings.Replace(fromS, "celestia1", "Celestia1", 1))), fT, fA))
	rej("msg_from_bad_checksum", "from_address with its last character changed.", cat(field(1, []byte(flipLastChar(fromS))), fT, fA))
	rej("msg_from_bech32m", "from_address with a bech32m checksum.", cat(field(1, []byte(bech32mEncode(hrpCelestia, from))), fT, fA))
	rej("msg_from_other_hrp", "from_address with prefix cosmos while the chain's is celestia.",
		cat(field(1, []byte(addr("cosmos", from))), fT, fA))
	rej("msg_to_32_bytes", "to_address encoding 32 bytes (a module or ICA style address).",
		cat(fF, field(2, []byte(addr(hrpCelestia, label("edicta/v0 test bank receiver|32")))), fA))
	rej("msg_to_19_bytes", "to_address encoding 19 bytes.", cat(fF, field(2, []byte(addr(hrpCelestia, to1[:19]))), fA))
	rej("msg_from_equals_to", "from_address equals to_address.", cat(fF, field(2, []byte(fromS)), fA))
	return f
}

func anyMsg(msg []byte) *types.Any {
	return &types.Any{TypeUrl: msgSendTypeURL, Value: msg}
}

func body(msgs [][]byte, memo string, timeout uint64, ext, nonCrit []*types.Any) []byte {
	b := txtypes.TxBody{Memo: memo, TimeoutHeight: timeout, ExtensionOptions: ext, NonCriticalExtensionOptions: nonCrit}
	for _, m := range msgs {
		b.Messages = append(b.Messages, anyMsg(m))
	}
	out, err := b.Marshal()
	if err != nil {
		panic(err)
	}
	return out
}

func msgBytes(f msgFile, id string) []byte {
	for _, c := range f.Cases {
		if c.ID == id {
			b, _ := hex.DecodeString(c.MsgHex)
			return b
		}
	}
	panic("no msg case " + id)
}

func txVectors(mf msgFile) txFile {
	f := txFile{
		Format: format, Profile: profile, Revision: profileRevision,
		Generator: "spec/vectors/tools/banksend-gen", Upstream: upstream,
	}
	addBody := func(id, desc, msgRef string, h []byte, th uint64) {
		memo := hex.EncodeToString(h)
		f.Body = append(f.Body, bodyCase{
			ID: id, Description: desc, MsgRef: msgRef, CommitmentHashHex: memo,
			TimeoutHeight: strconv.FormatUint(th, 10), Memo: memo,
			BodyHex: hex.EncodeToString(body([][]byte{msgBytes(mf, msgRef)}, memo, th, nil, nil)),
		})
	}
	h1 := label("edicta/v0 test bank commitment|1")
	h2 := label("edicta/v0 test bank commitment|2")
	addBody("body_minimal", "msg_minimal, timeout_height 1 (one-byte varint).", "msg_minimal", h1, 1)
	addBody("body_typical", "msg_typical, a realistic timeout_height.", "msg_typical", h2, 9123456)
	addBody("body_timeout_127", "timeout_height 127, the largest one-byte varint.", "msg_minimal", h1, 127)
	addBody("body_timeout_128", "timeout_height 128, the smallest two-byte varint.", "msg_minimal", h1, 128)
	addBody("body_timeout_max", "timeout_height 2^63-1.", "msg_minimal", h1, maxInt63)
	addBody("body_long_msg", "msg_denom_128: the Any and its value need two-byte length varints.", "msg_denom_128", h2, 500)
	addBody("body_other_hrp", "msg_other_hrp: the body rule does not depend on the chain.", "msg_other_hrp", h1, 77)

	msg := msgBytes(mf, "msg_minimal")
	memo := hex.EncodeToString(h1)
	rej := func(id, desc string, b []byte) {
		f.BodyReject = append(f.BodyReject, bodyReject{
			ID: id, Description: desc, MsgRef: "msg_minimal", CommitmentHashHex: memo,
			BodyHex: hex.EncodeToString(b), ExpectError: errBodyMismatch,
		})
	}
	ext := []*types.Any{{TypeUrl: "/edicta.test.Ext", Value: []byte{0x01}}}
	rej("body_timeout_zero", "timeout_height 0, so field 3 is absent.", body([][]byte{msg}, memo, 0, nil, nil))
	rej("body_memo_upper_hex", "memo in upper-case hex.", body([][]byte{msg}, strings.ToUpper(memo), 100, nil, nil))
	rej("body_memo_0x", "memo with a 0x prefix.", body([][]byte{msg}, "0x"+memo, 100, nil, nil))
	rej("body_memo_other_hash", "memo is the hex of another commitment hash.", body([][]byte{msg}, hex.EncodeToString(h2), 100, nil, nil))
	rej("body_memo_absent", "No memo.", body([][]byte{msg}, "", 100, nil, nil))
	rej("body_two_messages", "The authorized message twice.", body([][]byte{msg, msg}, memo, 100, nil, nil))
	rej("body_other_msg", "Another MsgSend than the authorized one.", body([][]byte{msgBytes(mf, "msg_typical")}, memo, 100, nil, nil))
	rej("body_extension_option", "An extension option.", body([][]byte{msg}, memo, 100, ext, nil))
	rej("body_non_critical_extension", "A non-critical extension option.", body([][]byte{msg}, memo, 100, nil, ext))
	rej("body_fields_reordered", "memo before messages (same fields, other order).",
		cat(field(2, []byte(memo)), field(1, cat(field(1, []byte(msgSendTypeURL)), field(2, msg))), []byte{0x18, 0x64}))
	rej("body_other_type_url", "The message under another type URL.",
		cat(field(1, cat(field(1, []byte("/cosmos.bank.v1beta1.MsgMultiSend")), field(2, msg))), field(2, []byte(memo)), []byte{0x18, 0x64}))
	rej("body_trailing_byte", "A zero byte after timeout_height.", cat(body([][]byte{msg}, memo, 100, nil, nil), []byte{0x00}))

	addSigned := func(id, desc, bodyRef, chainID string, acc, seq uint64, fee coinJSON, gas uint64, n int) {
		var bodyBytes []byte
		for _, b := range f.Body {
			if b.ID == bodyRef {
				bodyBytes, _ = hex.DecodeString(b.BodyHex)
			}
		}
		if bodyBytes == nil {
			panic("no body " + bodyRef)
		}
		priv := senderKey(n)
		pub := priv.PubKey().(*secp256k1.PubKey)
		pkAny, err := types.NewAnyWithValue(pub)
		if err != nil {
			panic(err)
		}
		if pkAny.TypeUrl != pubKeyTypeURL {
			panic("unexpected pubkey type url " + pkAny.TypeUrl)
		}
		amt, _ := sdkmath.NewIntFromString(fee.Amount)
		ai := txtypes.AuthInfo{
			SignerInfos: []*txtypes.SignerInfo{{
				PublicKey: pkAny,
				ModeInfo:  &txtypes.ModeInfo{Sum: &txtypes.ModeInfo_Single_{Single: &txtypes.ModeInfo_Single{Mode: signing.SignMode_SIGN_MODE_DIRECT}}},
				Sequence:  seq,
			}},
			Fee: &txtypes.Fee{Amount: sdk.Coins{sdk.Coin{Denom: fee.Denom, Amount: amt}}, GasLimit: gas},
		}
		aiBytes, err := ai.Marshal()
		if err != nil {
			panic(err)
		}
		sd := txtypes.SignDoc{BodyBytes: bodyBytes, AuthInfoBytes: aiBytes, ChainId: chainID, AccountNumber: acc}
		sdBytes, err := sd.Marshal()
		if err != nil {
			panic(err)
		}
		sig, err := priv.Sign(sdBytes)
		if err != nil {
			panic(err)
		}
		if !pub.VerifySignature(sdBytes, sig) {
			panic("signature does not verify")
		}
		raw := txtypes.TxRaw{BodyBytes: bodyBytes, AuthInfoBytes: aiBytes, Signatures: [][]byte{sig}}
		rawBytes, err := raw.Marshal()
		if err != nil {
			panic(err)
		}
		sum := sha256.Sum256(rawBytes)
		f.Signed = append(f.Signed, signedCase{
			ID: id, Description: desc, BodyRef: bodyRef, ChainID: chainID,
			AccountNumber: strconv.FormatUint(acc, 10), Sequence: strconv.FormatUint(seq, 10),
			Fee: fee, GasLimit: strconv.FormatUint(gas, 10),
			Key: keyJSON{
				Label: "edicta/v0 test bank sender|" + strconv.Itoa(n), PrivHex: hex.EncodeToString(priv.Key),
				PubKeyHex: hex.EncodeToString(pub.Key), AddressHex: hex.EncodeToString(pub.Address()),
				Address: addr(hrpCelestia, pub.Address()),
			},
			AuthInfoHex: hex.EncodeToString(aiBytes), SignDocHex: hex.EncodeToString(sdBytes),
			SignatureHex: hex.EncodeToString(sig), TxRawHex: hex.EncodeToString(rawBytes),
			TxHashHex: hex.EncodeToString(sum[:]), RailRef: hex.EncodeToString(sum[:]),
		})
	}
	addSigned("signed_minimal_mocha", "body_minimal signed in SIGN_MODE_DIRECT for chain id mocha-4. AuthInfo is the executor's own and illustrative.",
		"body_minimal", "mocha-4", 42, 7, coinJSON{Denom: "utia", Amount: "2000"}, 100000, 1)
	addSigned("signed_typical_account_0", "body_typical with account_number 0 and sequence 0 (both fields absent from the encodings).",
		"body_typical", "edicta-devnet-1", 0, 0, coinJSON{Denom: "utia", Amount: "1"}, 80000, 1)
	return f
}

func encodeJSON(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func run(dir string, check bool) error {
	mf := msgVectors()
	tf := txVectors(mf)
	files := map[string]any{"msg_send.json": mf, "tx.json": tf}
	var errs []error
	for _, name := range []string{"msg_send.json", "tx.json"} {
		b, err := encodeJSON(files[name])
		if err != nil {
			return err
		}
		path := filepath.Join(dir, name)
		if check {
			old, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			if !bytes.Equal(old, b) {
				errs = append(errs, fmt.Errorf("%s differs from a fresh generation", path))
			}
			continue
		}
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(path, b, 0o644); err != nil {
			return err
		}
		fmt.Println("wrote", path)
	}
	return errors.Join(errs...)
}

func main() {
	check := flag.Bool("check", false, "compare with the files instead of writing them")
	dir := flag.String("dir", filepath.Join("..", "..", "profiles", "bank-send"), "output directory")
	flag.Parse()
	if err := run(*dir, *check); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if *check {
		fmt.Println("OK: msg_send.json and tx.json match a fresh generation")
	}
}
