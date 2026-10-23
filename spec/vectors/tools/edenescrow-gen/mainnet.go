// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

const mainnetIndexFile = "live/mainnet-runs.json"

// buyerRefusalText is the text the payment server's buyer check answers
// with; a 403 whose body holds it is the recognised refusal RR2.
const buyerRefusalText = "neither the escrow buyer"

type mainnetFile struct {
	File          string `json:"file"`
	Provenance    string `json:"provenance"`
	ContentLength string `json:"content_length"`
}

type mainnetRun struct {
	ID                      string        `json:"id"`
	Dir                     string        `json:"dir"`
	ChainID                 string        `json:"chain_id"`
	ResourceCalled          string        `json:"resource_called"`
	Buyer                   string        `json:"buyer"`
	PaymentID               string        `json:"payment_id"`
	TxHash                  string        `json:"tx_hash"`
	Broadcast               string        `json:"broadcast"`
	PaymentSignatureMessage string        `json:"payment_signature_message"`
	Files                   []mainnetFile `json:"files"`
	Observed                struct {
		Relay *struct {
			Status            string `json:"status"`
			DeprecationHeader string `json:"deprecation_header"`
		} `json:"relay"`
		PaidRetry struct {
			Status         string `json:"status"`
			HoustonCostTIA string `json:"houston_cost_tia"`
		} `json:"paid_retry"`
		Settle struct {
			Amount       string `json:"amount"`
			ActualAmount string `json:"actual_amount"`
			RefundAmount string `json:"refund_amount"`
		} `json:"settle"`
	} `json:"observed"`
}

type mainnetIndex struct {
	Runs []mainnetRun `json:"runs"`
}

func readLive(dir, run, name string) []byte {
	b, err := os.ReadFile(filepath.Join(dir, "live", run, name))
	if err != nil {
		panic(err)
	}
	return b
}

func must(ok bool, what string) {
	if !ok {
		panic("mainnet fixture: " + what)
	}
}

func (r mainnetRun) has(name string) bool {
	for _, f := range r.Files {
		if f.File == name {
			return true
		}
	}
	return false
}

// rawR keeps the members of R that a Payment-Signature copies, verbatim.
type rawR struct {
	Resource json.RawMessage   `json:"resource"`
	Accepts  []json.RawMessage `json:"accepts"`
}

type psPayload struct {
	Signature string `json:"signature"`
	PaymentID string `json:"paymentId"`
	Nonce     string `json:"nonce"`
}

func buildMainnetFile(dir string) obj {
	raw, err := os.ReadFile(filepath.Join(dir, mainnetIndexFile))
	if err != nil {
		panic(err)
	}
	var idx mainnetIndex
	must(json.Unmarshal(raw, &idx) == nil && len(idx.Runs) == 3, "index runs")
	idxSum := sha256.Sum256(raw)

	inputs := []any{obj{{"file", mainnetIndexFile}, {"provenance", "index"}, {"sha256", hx(idxSum[:])}}}
	var runs []any
	for _, run := range idx.Runs {
		for _, f := range run.Files {
			b := readLive(dir, run.Dir, f.File)
			sum := sha256.Sum256(b)
			e := obj{{"file", "live/" + run.Dir + "/" + f.File}, {"provenance", f.Provenance}, {"sha256", hx(sum[:])}, {"length", dec(uint64(len(b)))}}
			if f.ContentLength != "" {
				must(dec(uint64(len(b))) == f.ContentLength, run.ID+" "+f.File+" length differs from the server's content-length")
				e = append(e, kv{"content_length", f.ContentLength})
			}
			inputs = append(inputs, e)
		}
		runs = append(runs, mainnetRunVectors(dir, run))
	}
	return obj{
		{"format", format}, {"profile", profile}, {"revision", revision}, {"generator", generator},
		{"upstream", upstream},
		{"note", "Three funded escrow-upto payments on Eden mainnet, recorded on the client side (index " + mainnetIndexFile + "). Every expectation below is derived from the recorded files; wire files are exact, reconstructed bodies are checked by value only."},
		{"inputs", inputs},
		{"runs", runs},
	}
}

func mainnetRunVectors(dir string, run mainnetRun) obj {
	buyer := common.HexToAddress(run.Buyer)
	must(strings.EqualFold(buyer.Hex(), run.Buyer), run.ID+" buyer")
	pid := unhex(run.PaymentID)

	// R, the wire bytes of the payment-required header.
	hv := string(readLive(dir, run.Dir, "header-payment-required.b64"))
	r, rule := decodeHeader(hv)
	must(rule == "", run.ID+" header RH")
	pr := parseRequired(r)
	must(pr.X402Version == 2 && len(pr.Accepts) == 1, run.ID+" R shape")
	entry := pr.Accepts[0]
	var rr rawR
	must(json.Unmarshal(r, &rr) == nil && len(rr.Accepts) == 1, run.ID+" R raw")
	rSum := sha256.Sum256(r)

	// The signed deposit: go-ethereum decodes it, names its hash and sender.
	signedHex := string(readLive(dir, run.Dir, "deposit-signed.hex"))
	must(strings.HasPrefix(signedHex, "0x") && signedHex == strings.ToLower(signedHex), run.ID+" signed hex form")
	signed := unhex(signedHex)
	var gtx types.Transaction
	must(gtx.UnmarshalBinary(signed) == nil && gtx.Type() == types.DynamicFeeTxType, run.ID+" signed tx decodes as type 2")
	must(gtx.Hash().Hex() == common.HexToHash(run.TxHash).Hex() && "0x"+railRef(signed) == run.TxHash, run.ID+" keccak256(signed) is the recorded hash")
	sender, err := types.Sender(types.LatestSignerForChainID(gtx.ChainId()), &gtx)
	must(err == nil && sender == buyer, run.ID+" sender is the buyer")
	must(len(gtx.AccessList()) == 0 && gtx.To() != nil, run.ID+" access list, to")
	t := txIn{
		chainID: gtx.ChainId().Uint64(), nonce: gtx.Nonce(), tip: gtx.GasTipCap(), fee: gtx.GasFeeCap(),
		gas: gtx.Gas(), to: *gtx.To(), value: gtx.Value(), data: gtx.Data(),
	}
	must(dec(t.chainID) == run.ChainID && t.to == escrow714, run.ID+" chain and escrow")
	v, rs, ss := gtx.RawSignatureValues()
	must(bytes.Equal(splice(t.items(), sig{v.Uint64(), rs, ss}), signed), run.ID+" the signed bytes follow the splice rule")
	u := t.unsigned()
	sh := t.sighash()
	d := decodeCalldataUnchecked(t.data)
	must(bytes.Equal(d.calldata(), t.data) && bytes.Equal(d.paymentID[:], pid), run.ID+" calldata and paymentId")

	// S4 on the wire R.
	checkEntry(entry, t)
	srvSig := unhex(entry.Extra.ServerSignature)
	srv, ok := recoverEIP191(d.paymentID[:], srvSig)
	must(ok && srv == d.facilitator, run.ID+" serverSignature recovers to w2")

	reqHash := requirementsHash(r)
	must(strings.HasPrefix(run.ResourceCalled, "https://"), run.ID+" resource")
	action := actionCBOR(u, run.ResourceCalled, reqHash)
	f, ok := factsOf(t)
	must(ok, run.ID+" facts")

	var build any
	if run.has("body-deposit-build.json") {
		bt, bpid := txFromBuild(readLive(dir, run.Dir, "body-deposit-build.json"))
		must(bytes.Equal(bt.unsigned(), u) && bytes.Equal(bpid[:], pid), run.ID+" the build answer gives the signed transaction")
		build = obj{{"file", "live/" + run.Dir + "/body-deposit-build.json"}, {"payment_id_hex", hx(bpid[:])}, {"cbor_hex", hx(action)}}
	}

	// The Payment-Signature header: base64 of R's resource and entry,
	// verbatim, and the payload.
	psv := string(readLive(dir, run.Dir, "header-payment-signature.b64"))
	ps, err := base64.StdEncoding.Strict().DecodeString(psv)
	must(err == nil && base64.StdEncoding.EncodeToString(ps) == psv, run.ID+" payment-signature is padded standard base64")
	var pj struct {
		Payload psPayload `json:"payload"`
	}
	must(json.Unmarshal(ps, &pj) == nil, run.ID+" payment-signature JSON")
	pl, err := json.Marshal(pj.Payload)
	must(err == nil, "payload")
	want := cat([]byte(`{"x402Version":2,"resource":`), rr.Resource, []byte(`,"accepted":`), rr.Accepts[0], []byte(`,"payload":`), pl, []byte(`}`))
	must(bytes.Equal(ps, want), run.ID+" payment-signature is exactly {x402Version, resource, accepted, payload} with R's members verbatim")
	must(pj.Payload.PaymentID == run.PaymentID && pj.Payload.Nonce == entry.Extra.Nonce, run.ID+" payload paymentId and nonce")
	psig := unhex(pj.Payload.Signature)
	overPID, ok1 := recoverEIP191(pid, psig)
	overNonce, ok2 := recoverEIP191(unhex(pj.Payload.Nonce), psig)
	must(ok1 && ok2, run.ID+" payment signature recovers")
	switch run.PaymentSignatureMessage {
	case "paymentId":
		must(overPID == buyer && overNonce != buyer, run.ID+" signed over paymentId by the buyer")
	case "nonce":
		must(overPID != buyer && overNonce == buyer, run.ID+" signed over nonce by the buyer")
	default:
		panic(run.ID + " message")
	}

	// The paid retry.
	paid := obj{{"status", run.Observed.PaidRetry.Status}}
	switch run.Observed.PaidRetry.Status {
	case "200":
		resp := decodeResponseHeader(readLive(dir, run.Dir, "header-payment-response.b64"))
		must(resp.Success && strings.EqualFold(resp.Payer, run.Buyer) && resp.Network == "eip155:"+run.ChainID, run.ID+" payment-response")
		paid = append(paid, kv{"refusal", nil}, kv{"payment_response", obj{{"file", "live/" + run.Dir + "/header-payment-response.b64"},
			{"success", resp.Success}, {"network", resp.Network}, {"payer", strings.ToLower(resp.Payer)}}})
	case "403":
		body := readLive(dir, run.Dir, "body-paid-retry-403.json")
		must(bytes.Contains(body, []byte(buyerRefusalText)), run.ID+" 403 text")
		resp := decodeResponseHeader(readLive(dir, run.Dir, "header-payment-response-resigned.b64"))
		must(resp.Success && strings.EqualFold(resp.Payer, run.Buyer), run.ID+" re-signed payment-response")
		paid = append(paid, kv{"body_file", "live/" + run.Dir + "/body-paid-retry-403.json"}, kv{"refusal", "RR2"},
			kv{"resigned_payment_response", obj{{"file", "live/" + run.Dir + "/header-payment-response-resigned.b64"},
				{"success", resp.Success}, {"network", resp.Network}, {"payer", strings.ToLower(resp.Payer)}}})
	default:
		panic(run.ID + " paid retry status")
	}

	var relay any
	if run.has("body-deposit-send.json") {
		req := readLive(dir, run.Dir, "body-deposit-send-request.json")
		wantReq := fmt.Sprintf(`{"signedTx":"%s","paymentId":"0x%s"}`+"\n", signedHex, hx(d.paymentID[:]))
		must(string(req) == wantReq, run.ID+" relay request is {signedTx, paymentId=w0}")
		var ans struct {
			TxHash    string `json:"txHash"`
			PaymentID string `json:"paymentId"`
		}
		must(json.Unmarshal(readLive(dir, run.Dir, "body-deposit-send.json"), &ans) == nil &&
			ans.TxHash == run.TxHash && ans.PaymentID == run.PaymentID, run.ID+" relay answer")
		must(run.Observed.Relay != nil && run.Observed.Relay.DeprecationHeader == "true", run.ID+" deprecation header")
		relay = obj{{"request_file", "live/" + run.Dir + "/body-deposit-send-request.json"},
			{"answer_file", "live/" + run.Dir + "/body-deposit-send.json"},
			{"answer_tx_hash", strings.TrimPrefix(ans.TxHash, "0x")}, {"answer_names_rail_ref", true},
			{"deprecation_header", run.Observed.Relay.DeprecationHeader}, {"deprecation_in_body", false}}
	} else {
		must(run.Broadcast == "direct" || run.Observed.Relay != nil, run.ID+" broadcast")
	}

	var status any
	if run.has("body-deposit-status.json") {
		var st struct {
			TxHash string `json:"txHash"`
			Status string `json:"status"`
		}
		must(json.Unmarshal(readLive(dir, run.Dir, "body-deposit-status.json"), &st) == nil && st.TxHash == run.TxHash, run.ID+" status answer")
		status = obj{{"file", "live/" + run.Dir + "/body-deposit-status.json"}, {"status", st.Status}, {"evidence", false}}
	}

	var receipt any
	if run.has("rpc-receipt.json") {
		rb := readLive(dir, run.Dir, "rpc-receipt.json")
		var rc types.Receipt
		must(json.Unmarshal(rb, &rc) == nil, run.ID+" receipt")
		bin, err := rc.MarshalBinary()
		must(err == nil && types.CreateBloom(&rc) == rc.Bloom && rc.Status == 1, run.ID+" receipt bloom and status")
		var served struct {
			Logs []rpcLog `json:"logs"`
			From string   `json:"from"`
		}
		must(json.Unmarshal(rb, &served) == nil && len(served.Logs) == 1, run.ID+" receipt logs")
		lg := served.Logs[0]
		must(common.HexToAddress(served.From) == buyer, run.ID+" receipt from")
		ev := checkDeposit(1, served.Logs, t, buyer, escrow714, run.TxHash, lg.BlockHash, lg.TransactionIndex)
		must(ev == "executed", run.ID+" deposit event")
		receipt = obj{{"file", "live/" + run.Dir + "/rpc-receipt.json"}, {"consensus_hex", hx(bin)},
			{"bloom_matches", true}, {"deposit_event", ev}, {"buyer", strings.ToLower(buyer.Hex())}}
	}

	s := run.Observed.Settle
	var settle any
	if s.Amount != "" {
		a, ac, rf := mustBig(s.Amount), mustBig(s.ActualAmount), mustBig(s.RefundAmount)
		must(a.Cmp(t.value) == 0 && new(big.Int).Add(ac, rf).Cmp(a) == 0 && ac.Cmp(mustBig(run.Observed.PaidRetry.HoustonCostTIA)) == 0,
			run.ID+" settle amounts")
		settle = obj{{"amount", s.Amount}, {"actual_amount", s.ActualAmount}, {"refund_amount", s.RefundAmount},
			{"amount_is_value", true}, {"actual_plus_refund_is_amount", true}, {"actual_is_cost", true}}
	}

	return obj{
		{"id", run.ID},
		{"broadcast", run.Broadcast},
		{"requirements", obj{
			{"header_file", "live/" + run.Dir + "/header-payment-required.b64"},
			{"wire_bytes", true},
			{"r_length", dec(uint64(len(r)))}, {"r_sha256", hx(rSum[:])},
			{"requirements_hash_hex", hx(reqHash)},
			{"resource_url", pr.Resource.URL},
			{"s4", "pass"},
			{"asks_for_payment", true},
			{"refund_delay", dec(d.refundAfter - d.expiresAt)},
			{"server_signature", obj{{"signature_hex", hx(srvSig)}, {"v", dec(uint64(srvSig[64]))},
				{"recovered", strings.ToLower(srv.Hex())}, {"facilitator_w2", strings.ToLower(d.facilitator.Hex())}}},
		}},
		{"deposit", obj{
			{"signed_file", "live/" + run.Dir + "/deposit-signed.hex"},
			{"signed_length", dec(uint64(len(signed)))},
			{"rail_ref", railRef(signed)},
			{"unsigned_tx_hex", hx(u)},
			{"sighash_hex", hx(sh)},
			{"y_parity", dec(v.Uint64())}, {"r_hex", hx(rs.Bytes())}, {"s_hex", hx(ss.Bytes())},
			{"payer", strings.ToLower(sender.Hex())},
			{"input", obj{
				{"chain_id", dec(t.chainID)}, {"nonce", dec(t.nonce)},
				{"max_priority_fee_per_gas", t.tip.String()}, {"max_fee_per_gas", t.fee.String()},
				{"gas_limit", dec(t.gas)}, {"to", strings.ToLower(t.to.Hex())}, {"value", t.value.String()},
				{"data_hex", hx(t.data)},
			}},
			{"profile_fields", profileFields(t)},
		}},
		{"action", obj{
			{"resource", run.ResourceCalled},
			{"cbor_hex", hx(action)},
			{"action_length", dec(uint64(len(action)))},
			{"extractor_ids", idsFor("production")},
			{"facts", f.json()},
			{"facts_cbor_hex", hx(f.cbor())},
		}},
		{"build", build},
		{"payment_signature", obj{
			{"header_file", "live/" + run.Dir + "/header-payment-signature.b64"},
			{"decoded_length", dec(uint64(len(ps)))},
			{"shape", "base64 (standard, padded) of {\"x402Version\":2,\"resource\":<R resource>,\"accepted\":<R accepts entry>,\"payload\":{\"signature\",\"paymentId\",\"nonce\"}}, compact, R's members verbatim"},
			{"message", run.PaymentSignatureMessage},
			{"signature_hex", hx(psig)}, {"v", dec(uint64(psig[64]))},
			{"payment_id_hex", hx(pid)}, {"nonce_hex", strings.TrimPrefix(pj.Payload.Nonce, "0x")},
			{"recovered_over_payment_id", strings.ToLower(overPID.Hex())},
			{"recovered_over_nonce", strings.ToLower(overNonce.Hex())},
			{"signer_is_buyer", run.PaymentSignatureMessage == "paymentId"},
		}},
		{"paid_retry", paid},
		{"relay", relay},
		{"deposit_status", status},
		{"receipt", receipt},
		{"settle", settle},
	}
}

type paymentResponse struct {
	Success bool   `json:"success"`
	Network string `json:"network"`
	Payer   string `json:"payer"`
}

func decodeResponseHeader(v []byte) paymentResponse {
	b, err := base64.StdEncoding.Strict().DecodeString(string(v))
	if err != nil {
		panic(err)
	}
	var p paymentResponse
	if err := json.Unmarshal(b, &p); err != nil {
		panic(err)
	}
	return p
}
