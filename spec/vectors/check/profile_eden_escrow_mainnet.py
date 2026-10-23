# SPDX-License-Identifier: Apache-2.0
"""eden-escrow profile: the recorded mainnet payments (spec/vectors/profiles/eden-escrow/x402_mainnet.json).

Re-derives every expectation from the files under live/ without go-ethereum: the transaction hash,
payer and splice rule of each signed deposit, the action bytes and facts, S4 on the wire R, the
/deposit/build conversion, the Payment-Signature header shape and signer, the relay request and
answer, the 403 refusal RR2, the deposit receipt (EE7, EE8) and the settle arithmetic.
"""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

import profile_eden_escrow as ee
import profile_eden_escrow_x402 as xp
from policy_v1 import encode_facts

BUYER_REFUSAL = b"neither the escrow buyer"


def recognised_refusal(status: int, body: bytes) -> str | None:
    """RR2 only: RR1 needs a 402 for a known paymentId, which no recording holds."""
    if len(body) <= 16384 and status == 403 and BUYER_REFUSAL in body:
        return "RR2"
    return None


def unsigned_from_signed(signed: bytes) -> bytes:
    _, items = ee.rlp_list_items(signed, 1, "EE3")
    if len(items) != 12:
        raise ValueError("not 12 items")
    return b"\x02" + ee.rlp_enc_list([signed[es:ee_] for _, _, _, es, ee_ in items[:9]])


def check(d: dict, base: Path, expect, header) -> None:
    header(d, "x402_mainnet")
    raw_index = (base / "live" / "mainnet-runs.json").read_bytes()
    index = json.loads(raw_index)
    inputs = d["inputs"]
    expect(inputs[0]["file"] == "live/mainnet-runs.json"
           and inputs[0]["sha256"] == hashlib.sha256(raw_index).hexdigest(), "mainnet: index hash")
    listed = []
    for run in index["runs"]:
        for f in run["files"]:
            listed.append((f"live/{run['dir']}/{f['file']}", f))
    expect([i["file"] for i in inputs[1:]] == [p for p, _ in listed], "mainnet: inputs follow the index")
    for i, (p, f) in zip(inputs[1:], listed):
        b = (base / p).read_bytes()
        expect(i["sha256"] == hashlib.sha256(b).hexdigest() and i["length"] == str(len(b))
               and i["provenance"] == f["provenance"] in ("wire", "reconstructed", "rpc"), f"mainnet: input {p}")
        if "content_length" in f:
            expect(str(len(b)) == f["content_length"] == i["content_length"], f"mainnet: {p} content-length")
        if f["provenance"] == "wire":
            expect(not b.endswith(b"\n"), f"mainnet: {p} wire bytes carry no newline")
    expect([r["id"] for r in d["runs"]] == [r["id"] for r in index["runs"]], "mainnet: runs")
    for run, v in zip(index["runs"], d["runs"]):
        check_run(run, v, base / "live" / run["dir"], expect)


def check_run(run: dict, v: dict, rd: Path, expect) -> None:
    rid = run["id"]
    read = lambda n: (rd / n).read_bytes()  # noqa: E731
    buyer = bytes.fromhex(run["buyer"][2:])
    pid = bytes.fromhex(run["payment_id"][2:])

    r = xp.decode_header(read("header-payment-required.b64").decode())
    rq = v["requirements"]
    expect(rq["wire_bytes"] is True and rq["r_length"] == str(len(r))
           and rq["r_sha256"] == hashlib.sha256(r).hexdigest()
           and rq["requirements_hash_hex"] == ee.requirements_hash(r).hex(), f"{rid}: R")

    signed_hex = read("deposit-signed.hex").decode()
    signed = bytes.fromhex(signed_hex[2:])
    dp = v["deposit"]
    expect(signed_hex.startswith("0x") and ee.rail_ref(signed) == dp["rail_ref"] == run["tx_hash"][2:],
           f"{rid}: keccak256(signed) is the recorded tx hash")
    tx = unsigned_from_signed(signed)
    expect(tx.hex() == dp["unsigned_tx_hex"] and ee.sighash(tx).hex() == dp["sighash_hex"], f"{rid}: unsigned tx")
    payer = ee.exact_tx(signed, tx)
    expect(payer == buyer and dp["payer"] == run["buyer"], f"{rid}: the deposit is signed by the buyer")
    y, rr, ss = int(dp["y_parity"]), int(dp["r_hex"], 16), int(dp["s_hex"], 16)
    expect(ee.splice(tx, y, rr, ss) == signed, f"{rid}: splice rule gives the wire bytes")

    resource = run["resource_called"]
    action = xp.encode_action(tx, resource, ee.requirements_hash(r))
    a = ee.decode_action(action)
    ac = v["action"]
    expect(ac["resource"] == resource and ac["cbor_hex"] == action.hex() and ac["action_length"] == str(len(action))
           and ac["extractor_ids"] == [ee.EXTRACTOR_ID, ee.EXTRACTOR_DEV_ID], f"{rid}: action")
    expect(a["chain_id"] == int(run["chain_id"]) and a["call"]["payment_id"] == pid, f"{rid}: chain and w0")
    f = ee.facts(a)
    expect(f["amount"].hex() == ac["facts"]["amount"] and f["recipient"] == ac["facts"]["recipient"]
           and encode_facts(f).hex() == ac["facts_cbor_hex"], f"{rid}: facts")
    expect(ee.profile_fields(a) == dp["profile_fields"], f"{rid}: profile fields")
    expect(dp["input"]["nonce"] == str(a["nonce"]) and dp["input"]["value"] == str(a["value"]), f"{rid}: fields")

    entry = xp.check_requirements(r, a, True)
    expect(rq["s4"] == "pass", f"{rid}: S4")
    c = a["call"]
    expect(rq["refund_delay"] == str(c["refund_after"] - c["expires_at"]), f"{rid}: refund delay")
    ssig = bytes.fromhex(entry["extra"]["serverSignature"][2:])
    expect(xp.recover_eip191(pid, ssig) == c["facilitator"]
           and rq["server_signature"]["signature_hex"] == ssig.hex() and rq["server_signature"]["v"] == str(ssig[64]),
           f"{rid}: serverSignature")
    m, refusal = xp.payment_signature_message("paymentId", True, action, r)
    expect(refusal is None and m == pid, f"{rid}: S11 message is w0")

    if v["build"] is not None:
        built, _ = xp.action_from_build(read("body-deposit-build.json"), resource, ee.requirements_hash(r))
        expect(built == action and v["build"]["cbor_hex"] == action.hex(), f"{rid}: the build answer gives the signed tx")
    else:
        expect("body-deposit-build.json" not in [x["file"] for x in run["files"]], f"{rid}: build")

    psv = read("header-payment-signature.b64").decode()
    ps = base64.b64decode(psv, validate=True)
    expect(base64.b64encode(ps).decode() == psv, f"{rid}: Payment-Signature base64 form")
    doc = json.loads(r)
    pj = json.loads(ps)
    compact = lambda o: json.dumps(o, separators=(",", ":"), ensure_ascii=False).encode()  # noqa: E731
    want = (b'{"x402Version":2,"resource":' + compact(doc["resource"]) + b',"accepted":' + compact(doc["accepts"][0])
            + b',"payload":' + compact(pj["payload"]) + b"}")
    expect(ps == want and compact(doc) == r, f"{rid}: Payment-Signature shape, R's members verbatim")
    expect(list(pj["payload"]) == ["signature", "paymentId", "nonce"] and pj["payload"]["paymentId"] == run["payment_id"]
           and pj["payload"]["nonce"] == entry["extra"]["nonce"], f"{rid}: payload")
    psig = bytes.fromhex(pj["payload"]["signature"][2:])
    over_pid = xp.recover_eip191(pid, psig)
    over_nonce = xp.recover_eip191(bytes.fromhex(pj["payload"]["nonce"][2:]), psig)
    pv = v["payment_signature"]
    expect(pv["recovered_over_payment_id"] == "0x" + over_pid.hex()
           and pv["recovered_over_nonce"] == "0x" + over_nonce.hex() and pv["signature_hex"] == psig.hex(),
           f"{rid}: Payment-Signature recovery")
    if run["payment_signature_message"] == "paymentId":
        expect(over_pid == buyer and pv["signer_is_buyer"] is True, f"{rid}: signed over paymentId by the buyer")
    else:
        expect(over_pid != buyer and over_nonce == buyer and pv["signer_is_buyer"] is False, f"{rid}: signed over nonce")

    paid = v["paid_retry"]
    status = int(run["observed"]["paid_retry"]["status"])
    expect(paid["status"] == str(status), f"{rid}: paid retry status")
    if status == 403:
        body = read("body-paid-retry-403.json")
        expect(recognised_refusal(403, body) == paid["refusal"] == "RR2", f"{rid}: RR2")
        resp_file = "header-payment-response-resigned.b64"
    else:
        expect(paid["refusal"] is None and recognised_refusal(status, b"") is None, f"{rid}: no refusal")
        resp_file = "header-payment-response.b64"
    resp = json.loads(base64.b64decode(read(resp_file), validate=True))
    expect(resp["success"] is True and resp["payer"].lower() == run["buyer"]
           and resp["network"] == "eip155:" + run["chain_id"], f"{rid}: payment-response")

    if v["relay"] is not None:
        want_req = json.dumps({"signedTx": signed_hex, "paymentId": "0x" + pid.hex()}, separators=(",", ":")) + "\n"
        ans = json.loads(read("body-deposit-send.json"))
        expect(read("body-deposit-send-request.json").decode() == want_req, f"{rid}: relay request")
        expect(ans == {"txHash": run["tx_hash"], "paymentId": run["payment_id"]} and "deprecation" not in ans
               and v["relay"]["deprecation_header"] == run["observed"]["relay"]["deprecation_header"] == "true",
               f"{rid}: relay answer and deprecation header")
    else:
        expect(run["broadcast"] in ("direct", "relay"), f"{rid}: broadcast")
    if v["deposit_status"] is not None:
        st = json.loads(read("body-deposit-status.json"))
        expect(st == {"txHash": run["tx_hash"], "status": "confirmed"} and v["deposit_status"]["evidence"] is False,
               f"{rid}: deposit status")
    if v["receipt"] is not None:
        rc = json.loads(read("rpc-receipt.json"))
        lg = rc["logs"][0]
        ev = ee.deposit_event(int(rc["status"], 16), rc["logs"], a, buyer, a["to"], run["tx_hash"],
                              lg["blockHash"], lg["transactionIndex"])
        expect(ev == v["receipt"]["deposit_event"] == "executed" and rc["from"] == run["buyer"], f"{rid}: EE7, EE8")
        expect(ee.receipt_consensus(rc).hex() == v["receipt"]["consensus_hex"]
               and ee.bloom(rc["logs"]).hex() == rc["logsBloom"][2:], f"{rid}: receipt encoding and bloom")
    s = run["observed"].get("settle", {})
    if "amount" in s:
        amt, act, ref = int(s["amount"]), int(s["actual_amount"]), int(s["refund_amount"])
        expect(amt == a["value"] and act + ref == amt
               and act == int(run["observed"]["paid_retry"]["houston_cost_tia"])
               and v["settle"]["actual_amount"] == s["actual_amount"], f"{rid}: settle amounts")
