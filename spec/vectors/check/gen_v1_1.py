#!/usr/bin/env python3
"""Writes the vector files of spec revision v1.1 (minor revision, core section 0).

- archive/execution_result_v1.1.json: archive kind 19 (core 19.2): the records built from the synthetic blocks of
  spec/vectors/tools/execresult-gen (section upstream), their keys and paths, must-reject records, the refusal of
  a v1.0 reader, the XR rules of core 20.2.2 case by case, and the migration from the gate's capture store
  (core 19.7, MG1 to MG7);
- api/errors_v1.1.json: the API codes recorder.ErrAnchorRejected and recorder.ErrClockSkew, additive to
  api/errors.json, with the merged match order of core 18.3;
- v1/verify_v1.1.json: the anchor check of a pending reference when header trust reaches the anchor height H but not
  the deadline D (core 20.6.1), on the records of v1/verify.json.

The frozen files are read, never written. The upstream section comes from the Go tool once
(--exec FILE, from `go run . -out FILE` in spec/vectors/tools/execresult-gen) and is carried over afterwards.

Usage: python3 spec/vectors/check/gen_v1_1.py [--exec FILE] [--check]
"""

from __future__ import annotations

import sys

sys.dont_write_bytecode = True

import base64
import copy
import hashlib
import json
from pathlib import Path

import exec_result as X
import records as RD
from cbor_strict import encode
from check_fibre_cert import fields, header_hash, put_uvarint
from edicta import Reject

VECTORS = Path(__file__).resolve().parent.parent
FORMAT, REVISION = "edicta-vectors/v1", "v1.1"
GENERATOR = "spec/vectors/check/gen_v1_1.py"
EXEC_FILE = "archive/execution_result_v1.1.json"
ERRORS_FILE = "api/errors_v1.1.json"
VERIFY_FILE = "v1/verify_v1.1.json"


def load(rel: str) -> dict:
    return json.loads((VECTORS / rel).read_text())


def dump(d: dict) -> str:
    return json.dumps(d, indent=2, ensure_ascii=True) + "\n"


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


# ---------------------------------------------------------------- kind 19 records

def proof_of(block: dict, key: str) -> bytes | None:
    return next((bytes.fromhex(p["proof_hex"]) for p in block["proofs"] if p["key"] == key), None)


def record_of(block: dict, cap: dict) -> dict:
    i = int(cap["tx_index"])
    rec = {"chain_id": block["chain_id"], "rail_ref": bytes.fromhex(cap["rail_ref"]), "height": int(block["height"]),
           "tx_index": i, "header": bytes.fromhex(block["header_hex"]), "next_header": bytes.fromhex(block["next_header_hex"])}
    for key, name in (("9", "tx_proof"), ("10", "pfb_proof"), ("11", "pff_proof"), ("12", "closing_proof")):
        p = proof_of(block, key)
        if p is not None:
            rec[name] = p
    rec["result"] = bytes.fromhex(block["results"][i]["leaf_hex"])
    rec["results_total"] = int(cap["results_total"])
    rec["result_path"] = bytes.fromhex(cap["result_path_hex"])
    return rec


def trusted_of(block: dict) -> dict:
    return {block["height"]: block["header_hash_hex"], str(int(block["height"]) + 1): block["next_header_hash_hex"]}


def plain(rec: dict) -> dict:
    return {k: (v.hex() if isinstance(v, bytes) else str(v) if isinstance(v, int) else v) for k, v in rec.items()}


def pb_field(num: int, wt: int, v) -> bytes:
    key = put_uvarint(num << 3 | wt)
    if wt == 0:
        return key + put_uvarint(v)
    return key + put_uvarint(len(v)) + v


def with_app_version(header: bytes, app: int) -> bytes:
    out = b""
    for num, wt, v in fields(header):
        if num == 1:
            ver = {n: x for n, _, x in fields(v)}
            v = pb_field(1, 0, ver[1]) + (pb_field(2, 0, app) if app else b"")
        out += pb_field(num, wt, v)
    return out


def flip(b: bytes, at: int) -> bytes:
    return b[:at] + bytes([b[at] ^ 0x01]) + b[at + 1:]


def tamper_row_root(proof: bytes) -> bytes:
    """Flip one byte of the first row root (row_proof field 4, its row_roots field 1)."""
    out = b""
    for num, wt, v in fields(proof):
        if num == 4:
            inner, done = b"", False
            for n2, w2, v2 in fields(v):
                if n2 == 1 and not done:
                    v2, done = flip(v2, len(v2) - 1), True
                inner += pb_field(n2, w2, v2)
            v = inner
        out += pb_field(num, wt, v)
    return out


def xr_expect(rec: dict, query: dict, trusted: dict) -> dict:
    try:
        facts = X.xr(rec, query, {int(h): bytes.fromhex(x) for h, x in trusted.items()})
    except X.SetAside as e:
        return {"result": "set_aside", "rule": e.rule, "reason": e.reason}
    return {"result": "pass", "rule": "none", "reason": "none", "facts": facts}


def exec_file(up: dict) -> dict:
    blocks = {b["id"]: b for b in up["blocks"]}
    recs = {}
    records = []
    for b in up["blocks"]:
        for cap in b["captures"]:
            rid = f"{b['id']}_tx{cap['tx_index']}"
            rec = record_of(b, cap)
            raw = X.encode_record(rec)
            assert X.decode_record(raw) == rec
            recs[rid] = (b, rec)
            records.append({"id": rid, "block": b["id"], "path": X.path_of(X.key_of(rec)),
                            "key": {"chain_id": rec["chain_id"], "rail_ref": rec["rail_ref"].hex()},
                            "input": plain(rec), "record_cbor_hex": raw.hex(), "record_sha256_hex": sha(raw),
                            "v1_0_reader_cause": RD.cause(raw)})

    def case(cid: str, desc: str, rid: str, change=None, query=None, trusted=None, note=None) -> dict:
        b, rec = recs[rid]
        rec = copy.deepcopy(rec)
        if change:
            change(rec)
        q = query or {"chain_id": rec["chain_id"], "rail_ref": rec["rail_ref"].hex()}
        t = trusted if trusted is not None else trusted_of(b)
        qd = {"chain_id": q["chain_id"], "rail_ref": bytes.fromhex(q["rail_ref"])}
        c = {"id": cid, "description": desc, "base_record": rid, "record_cbor_hex": X.encode_record(rec).hex(),
             "query": q, "trusted": t, "expect": xr_expect(rec, qd, t)}
        if note:
            c["note"] = note
        return c

    t3 = recs["three_namespaces_tx0"][0]
    other_ref = hashlib.sha256(b"not in the block").hexdigest()

    def drop(name):
        return lambda r: r.pop(name)

    def setf(name, v):
        return lambda r: r.__setitem__(name, v)

    def app9(r):
        r["header"] = with_app_version(r["header"], 9)

    trusted_app9 = dict(trusted_of(t3))
    trusted_app9[t3["height"]] = header_hash(with_app_version(bytes.fromhex(t3["header_hex"]), 9)).hex()
    pfb_as_closing = proof_of(t3, "10")
    tx1_leaf = recs["three_namespaces_tx1"][1]["result"]
    forged_success = X.results_leaf(0, b"", 100000, 52000)
    cases = [
        case("pass_live_tx", "The live bank-send tx at index 0 of a block with all three transaction namespaces and the "
             "closing share: inclusion and result proven, code 0 (outcome success).", "three_namespaces_tx0"),
        case("pass_failed_tx", "Index 1 of the same block, code 5: the result is proven, outcome failure (the profile's "
             "BX9 then gives fail, bank-send ErrTxFailed).", "three_namespaces_tx1"),
        case("pass_square_end", "A 1 x 1 square: the transaction namespace ends the square, no closing proof, an "
             "empty result path (results_total 1).", "single_share_square_tx0"),
        case("pass_no_fibre_namespace", "TX_NS and PFB_NS, then the closing share; key 11 absent.", "tx_then_blob_tx0"),
        case("xr1_other_key", "The record read for another rail_ref (stored under the wrong key).", "three_namespaces_tx0",
             query={"chain_id": t3["chain_id"], "rail_ref": other_ref}),
        case("xr2_next_header_unreachable", "Header trust reaches the height but not height + 1.", "three_namespaces_tx0",
             trusted={t3["height"]: t3["header_hash_hex"]}),
        case("xr2_header_not_on_chain", "The trusted chain has another header at the height.", "three_namespaces_tx0",
             trusted={t3["height"]: "00" * 32, str(int(t3["height"]) + 1): t3["next_header_hash_hex"]}),
        case("xr3_other_app_version", "The trusted header at the height has app version 9: the ordering rule is pinned "
             "to app version 10.", "three_namespaces_tx0", change=app9, trusted=trusted_app9),
        case("xr4_closing_below_fibre", "The closing proof is the PFB_NS proof: its namespace does not follow PFF_NS.",
             "three_namespaces_tx0", change=setf("closing_proof", pfb_as_closing)),
        case("xr4_row_root_tampered", "One byte of a row root of the TX_NS proof changed: the row proof does not reach "
             "data_hash.", "three_namespaces_tx0", change=lambda r: r.__setitem__("tx_proof", tamper_row_root(r["tx_proof"]))),
        case("xr5_pfb_range_missing", "The PFB_NS proof is missing: the PFF_NS range does not start where TX_NS ends.",
             "three_namespaces_tx0", change=drop("pfb_proof")),
        case("xr5_no_closing_share", "The closing proof is missing and the transaction namespaces do not end the square.",
             "three_namespaces_tx0", change=drop("closing_proof")),
        case("xr6_total_three", "results_total 3 instead of 4. The RFC 6962 path alone still verifies (index 0 of 3 and "
             "of 4 have the same shape), so only the count of the complete transaction namespaces catches it.",
             "three_namespaces_tx0", change=setf("results_total", 3), note="path_verifies_alone"),
        case("xr7_tx_index_differs", "tx_index 1 for the tx at unit 0 of TX_NS.", "three_namespaces_tx0",
             change=setf("tx_index", 1)),
        case("xr7_tx_not_in_block", "A rail_ref that no ordinary tx of the block hashes to, read under that key.",
             "three_namespaces_tx0", change=setf("rail_ref", bytes.fromhex(other_ref))),
        case("xr8_result_with_log", "The result leaf carries field 3 (log), which the results hash does not cover.",
             "three_namespaces_tx0", change=lambda r: r.__setitem__("result", r["result"] + pb_field(3, 2, b"x"))),
        case("xr8_path_tampered", "One byte of the result path changed.", "three_namespaces_tx0",
             change=lambda r: r.__setitem__("result_path", flip(r["result_path"], 0))),
        case("xr8_forged_success", "The failed tx at index 1 presented with code 0: the root does not match.",
             "three_namespaces_tx1", change=setf("result", forged_success)),
    ]
    assert tx1_leaf != forged_success

    base_rec = recs["three_namespaces_tx0"][1]

    def reject(rid: str, desc: str, change) -> dict:
        m = {1: 1, 2: X.KIND_EXEC}
        for name, v in base_rec.items():
            m[X.NAMES[name]] = v
        change(m)
        raw = encode(m)
        try:
            X.decode_record(raw)
            got = None
        except Reject as e:
            got = e.sentinel
        assert got is not None, rid
        return {"id": rid, "description": desc, "record_cbor_hex": raw.hex(), "expect_error": "archive.ErrCorrupt",
                "cause": got}

    def put(k, v):
        return lambda m: m.__setitem__(k, v)

    rejects = [
        reject("unknown_key_16", "Key 16 is not defined for kind 19.", put(16, 0)),
        reject("missing_tx_proof", "Key 9 (tx_proof) is required.", lambda m: m.pop(9)),
        reject("missing_result_path", "Key 15 (result_path) is required, even when empty.", lambda m: m.pop(15)),
        reject("rail_ref_31_bytes", "rail_ref is a 32-byte SHA-256.", put(4, base_rec["rail_ref"][:31])),
        reject("rail_ref_as_text", "rail_ref is a bstr, not the hex text of the receipt.", put(4, base_rec["rail_ref"].hex())),
        reject("path_not_32_byte_aunts", "result_path of 33 bytes.", put(15, base_rec["result_path"] + b"\x00")),
        reject("path_65_aunts", "result_path of 65 aunts (2080 bytes, above 2048).", put(15, bytes(32 * 65))),
        reject("chain_id_slash", "chain_id with a character outside [A-Za-z0-9._-].", put(3, "mocha/5")),
        reject("chain_id_leading_dot", "chain_id starting with a dot (a dot file in the canonical path).", put(3, ".mocha-5")),
        reject("chain_id_51_bytes", "chain_id above CometBFT's 50 bytes.", put(3, "m" * 51)),
        reject("height_zero", "height 0.", put(5, 0)),
        reject("results_total_zero", "results_total 0.", put(14, 0)),
        reject("header_empty", "An empty header.", put(7, b"")),
        reject("tx_index_text", "tx_index as text.", put(6, "0")),
        reject("height_above_int63", "height 2^63.", put(5, 1 << 63)),
        reject("closing_proof_empty", "An optional proof present but empty.", put(12, b"")),
    ]

    def capture_of(block: dict) -> dict:
        b64 = lambda h: base64.b64encode(bytes.fromhex(h)).decode()
        txs = []
        for cap in block["captures"]:
            i = int(cap["tx_index"])
            r = block["results"][i]
            res = {"code": int(r["code"]), "gas_wanted": int(r["gas_wanted"]), "gas_used": int(r["gas_used"])}
            if r["data_hex"]:
                res = {"code": res["code"], "data": b64(r["data_hex"]), "gas_wanted": res["gas_wanted"],
                       "gas_used": res["gas_used"]}
            path = bytes.fromhex(cap["result_path_hex"])
            txs.append({"rail_ref": cap["rail_ref"], "tx_index": i, "result": res,
                        "proof": {"total": int(cap["results_total"]), "index": i,
                                  "leaf_hash": base64.b64encode(hashlib.sha256(b"\x00" + bytes.fromhex(r["leaf_hex"])).digest()).decode(),
                                  "aunts": [base64.b64encode(path[j:j + 32]).decode() for j in range(0, len(path), 32)]}})
        return {"chain_id": block["chain_id"], "height": int(block["height"]), "header": b64(block["header_hex"]),
                "next_header": b64(block["next_header_hex"]),
                "namespace_proofs": [{"namespace": b64(p["namespace_hex"]), "start": int(p["start"]), "end": int(p["end"]),
                                      "proof": b64(p["proof_hex"])} for p in block["proofs"]],
                "txs": txs}

    def mcase(mid: str, desc: str, block: dict, change=None) -> dict:
        cap = capture_of(block)
        if change:
            change(cap)
        return {"id": mid, "description": desc, "capture": cap, "expect": migrate(cap)}

    t2 = blocks["tx_then_blob"]

    def tx0(f):
        return lambda c: f(c["txs"][0])

    def other_next(c):
        c["next_header"] = base64.b64encode(bytes.fromhex(t2["next_header_hex"])).decode()

    migration = [
        mcase("capture_three_namespaces", "A block file with two captured txs: two records, byte-identical to the records "
              "three_namespaces_tx0 and three_namespaces_tx1.", t3),
        mcase("capture_tx_then_blob", "A block file without a PFF_NS entry: key 11 is absent.", t2),
        mcase("capture_proof_index_differs", "The capture's proof index is not its tx_index (MG2).", t2,
              tx0(lambda t: t["proof"].__setitem__("index", 1))),
        mcase("capture_leaf_hash_differs", "The capture's leaf hash is not SHA-256(0x00 || result leaf) (MG2).", t2,
              tx0(lambda t: t["proof"].__setitem__("leaf_hash", base64.b64encode(bytes(32)).decode()))),
        mcase("capture_range_differs", "A namespace entry whose end is not the end of the range its proof covers (MG2).",
              t2, lambda c: c["namespace_proofs"][0].__setitem__("end", c["namespace_proofs"][0]["end"] + 1)),
        mcase("capture_namespace_gap", "The PFB_NS entry is missing: the self-check fails at XR5 (MG3).", t3,
              lambda c: c["namespace_proofs"].pop(1)),
        mcase("capture_next_header_other_block", "next_header of another block: it does not name header in "
              "last_block_id (MG3).", t3, other_next),
    ]
    for m in migration:
        if m["id"] == "capture_three_namespaces":
            assert [x["record_cbor_hex"] for x in m["expect"]] == [
                r["record_cbor_hex"] for r in records if r["block"] == "three_namespaces"]

    return {
        "format": FORMAT, "revision": REVISION, "generator": GENERATOR,
        "description": "Archive kind 19, execution_result (core 19.2, since spec revision v1.1): one record per captured "
                       "ordinary tx, key (chain_id, rail_ref), path exec/<chain_id>/<rail_ref hex>, identity the key. "
                       "records: valid records and their keys, paths and the cause a v1.0 reader gives (it does not know "
                       "kind 19). reject: must-reject records of a v1.1 reader (archive.ErrCorrupt with the cause). cases: "
                       "the XR rules of core 20.2.2 on a record (base_record, then the change the description names) "
                       "with the query (chain_id of the action, rail_ref of the receipt) and the hashes header trust "
                       "reached (trusted, height -> hash); expect gives pass with the facts, or set_aside with the first "
                       "failing rule and the reason of core 20.1.1. migration: a block file of the gate's capture store "
                       "(the v1.0.4 JSON layout, byte strings in base64) and what MG1 to MG7 (core 19.7) make of each "
                       "captured tx. upstream: the synthetic blocks, built and checked with upstream code by "
                       "spec/vectors/tools/execresult-gen.",
        "kind": "19",
        "upstream": up,
        "records": records,
        "reject": rejects,
        "cases": cases,
        "migration": migration,
    }


def migrate(cap: dict) -> list:
    """MG2 and MG3 (core 19.7) on one block file: per captured tx, the record written or the refusal."""
    out = []
    b = lambda s: base64.b64decode(s)
    for t in cap["txs"]:
        def refused(rule: str, why: str):
            out.append({"rail_ref": t["rail_ref"], "result": "refused", "rule": rule, "why": why})
        ref = t["rail_ref"]
        if len(ref) != 64 or any(c not in "0123456789abcdef" for c in ref):
            refused("MG2", "rail_ref is not 64 lower-case hex characters")
            continue
        r = t["result"]
        leaf = X.results_leaf(r["code"], b(r.get("data", "")), r["gas_wanted"], r["gas_used"])
        p = t["proof"]
        aunts = [b(a) for a in p["aunts"]]
        if p["index"] != t["tx_index"]:
            refused("MG2", "proof index differs from tx_index")
            continue
        if b(p["leaf_hash"]) != hashlib.sha256(b"\x00" + leaf).digest():
            refused("MG2", "leaf_hash is not the hash of the result leaf")
            continue
        if any(len(a) != 32 for a in aunts):
            refused("MG2", "an aunt is not 32 bytes")
            continue
        rec = {"chain_id": cap["chain_id"], "rail_ref": bytes.fromhex(ref), "height": cap["height"],
               "tx_index": t["tx_index"], "header": b(cap["header"]), "next_header": b(cap["next_header"])}
        bad = None
        names = {X.TX_NS: "tx_proof", X.PFB_NS: "pfb_proof", X.PFF_NS: "pff_proof"}
        for n, e in enumerate(cap["namespace_proofs"]):
            ns = b(e["namespace"])
            name = names.get(ns, "closing_proof")
            if name in rec or (name == "closing_proof" and n != len(cap["namespace_proofs"]) - 1):
                bad = "a namespace twice, or a closing entry that is not the last"
                break
            sp = X._share_proof(b(e["proof"]))
            se = X._span(sp, X._width(sp))
            if se is None or se != (e["start"], e["end"]):
                bad = f"entry {n}: start and end are not the range its proof covers"
                break
            rec[name] = b(e["proof"])
        if bad:
            refused("MG2", bad)
            continue
        rec["result"], rec["results_total"], rec["result_path"] = leaf, p["total"], b"".join(aunts)
        ordered = {k: rec[k] for k in [f[0] for _, f in sorted(X.SCHEMA.items())] if k in rec}
        raw = X.encode_record(ordered)
        nh, hh = X._header(ordered["next_header"]), X._header(ordered["header"])
        nfs = fields(ordered["next_header"])
        lbid = next((v for num, _, v in nfs if num == 5), b"")
        link = next((v for num, _, v in fields(lbid) if num == 1), b"")
        if link != hh["hash"]:
            refused("MG3", "next_header does not name header in last_block_id")
            continue
        try:
            X.xr(ordered, {"chain_id": cap["chain_id"], "rail_ref": bytes.fromhex(ref)},
                 {hh["height"]: hh["hash"], nh["height"]: nh["hash"]})
        except X.SetAside as e:
            refused("MG3", f"self-check {e.rule}: {e}")
            continue
        out.append({"rail_ref": ref, "result": "written", "path": X.path_of(X.key_of(ordered)),
                    "record_cbor_hex": raw.hex()})
    return out


# ---------------------------------------------------------------- API codes

def errors_file() -> dict:
    base = load("api/errors.json")
    anchor_rejected = {"code": "recorder.ErrAnchorRejected", "status": "502", "retryable": "0", "stored": "none",
                       "endpoints": ["/v1/publish"], "rules": "18.3, 10.6.1",
                       "match": "first",
                       "why": "A pay-for-fibre tx of the blob succeeded on chain but its certificate fails the one "
                              "threshold rule; the fee was paid and the Recorder never submits the blob again. The "
                              "Recorder's error also matches ErrAnchorNotFound (425, retryable), so it is matched before "
                              "every row."}
    clock_skew = {"code": "recorder.ErrClockSkew", "status": "503", "retryable": "1", "stored": "none",
                  "endpoints": ["/v1/publish"], "rules": "18.3", "match": "after ErrAnchorIntentRejected",
                  "why": "The Recorder's clock, which dates the payment promise, is off the chain head time by more "
                         "than the allowed skew; nothing was submitted. The same request succeeds once the operator "
                         "fixes the clock."}
    order = [{"code": anchor_rejected["code"], "status": anchor_rejected["status"]}]
    for e in base["errors"]:
        order.append({"code": e["code"], "status": e["status"]})
        if e["code"] == "ErrAnchorIntentRejected":
            order.append({"code": clock_skew["code"], "status": clock_skew["status"]})
    assert sum(1 for o in order if o["code"] == clock_skew["code"]) == 1

    def body(code: str, msg: str, retryable: int) -> str:
        return encode({1: code, 2: msg, 3: retryable}).hex()

    return {
        "format": FORMAT, "revision": REVISION, "generator": GENERATOR,
        "description": "API error codes added by spec revision v1.1 (core 18.3, 21), additive to api/errors.json, "
                       "which stays byte-identical. additions: the new codes; match tells where each is matched (first: "
                       "before every row of the 18.3 table). order: the whole match order of v1.1, the codes of "
                       "api/errors.json with the additions in place. bodies: example error bodies (message is not "
                       "normative). A v1.0 client maps an unknown code to edictaapi.ErrInternal (18.3) and keeps the "
                       "status and retryable the server sent.",
        "base": "api/errors.json",
        "additions": [anchor_rejected, clock_skew],
        "order": order,
        "bodies": [
            {"code": anchor_rejected["code"], "status": "502",
             "body_cbor_hex": body(anchor_rejected["code"], "anchor on chain fails the certificate rule", 0)},
            {"code": clock_skew["code"], "status": "503", "retry_after": "optional",
             "body_cbor_hex": body(clock_skew["code"], "local clock skewed against the chain", 1)},
        ],
    }


# ---------------------------------------------------------------- presence trust up to H

def anchor_v1_1(h0: int, d: int, ev: dict | None, head: int, absence: dict, needs_results: bool) -> dict:
    """The anchor check of a pending reference under core 20.6 and 20.6.1 (v1.1)."""
    if ev is not None and ev["verifies"] and h0 <= ev["height"] <= d:
        hh = ev["height"]
        if head >= hh:
            return {"status": "pass", "anchor_height": hh, "publication": "anchored", "needs": hh}
        return {"status": "unchecked", "reason": "anchor_pending", "publication": "unknown", "needs": hh}
    bound = d + 1 if needs_results else d
    if ev is not None and ev["verifies"]:
        bound = max(bound, ev["height"])
    if head < bound:
        return {"status": "unchecked", "reason": "anchor_pending", "publication": "unknown", "needs": bound}
    miss = next((h for h in range(h0, d + 1) if absence.get(h) != "absent"), None)
    if miss is None:
        return {"status": "fail", "rule": "anchor_absent", "publication": "failed", "needs": bound}
    return {"status": "unchecked", "reason": "absence_unproven", "first_unproven": miss, "publication": "unknown",
            "needs": bound}


def anchor_v1_0_text(h0: int, d: int, ev: dict | None, head: int, absence: dict, needs_results: bool) -> dict:
    """The same check under the frozen text (HT1, 20.6): every row needs max(D, H), D + 1 with a results proof."""
    out = anchor_v1_1(h0, d, ev, head, absence, needs_results)
    if out["status"] == "pass" and head < max(d, ev["height"]):
        return {"status": "unchecked", "reason": "anchor_pending", "publication": "unknown"}
    out.pop("needs")
    return out


def verify_file() -> dict:
    old = load("v1/verify.json")
    recs = old["records"]
    base = {c["id"]: c for c in old["cases"]}
    fibre = base["fast_pass_in_window"]
    blob = base["fast_absent_proven_blob"]

    def window(c: dict) -> tuple:
        rep = c["expect"]["report"]
        return int(rep["h0"]), int(rep["anchor_deadline"])

    def mk(cid: str, desc: str, like: dict, head: int, ev=None, absence=(), needs_results=False) -> dict:
        h0, d = window(like)
        evd = None if ev is None else {"height": ev[0], "verifies": ev[1]}
        ab = {int(h): r for h, r in absence}
        new = anchor_v1_1(h0, d, evd, head, ab, needs_results)
        was = anchor_v1_0_text(h0, d, evd, head, ab, needs_results)
        rep = {"version": "1", "mode": "fast", "h0": str(h0), "anchor_deadline": str(d)}
        if "anchor_height" in new:
            rep["anchor_height"] = str(new["anchor_height"])
        rep["publication"] = new["publication"]
        anchor = {"status": new["status"]}
        for k in ("reason", "rule", "first_unproven"):
            if k in new:
                anchor[k] = str(new[k])
        verdict = {"pass": ("valid", "0"), "fail": ("invalid", "1")}.get(new["status"], ("unchecked", "2"))
        c = {"id": cid, "description": desc, "decision": like["decision"], "authorization": like["authorization"],
             "trusted_head": str(head)}
        if evd is not None:
            c["evidence"] = {"height": str(ev[0]), "verifies": ev[1]}
        if absence:
            c["absence"] = [{"height": str(h), "result": r} for h, r in absence]
        if needs_results:
            c["needs_results"] = True
        c["refs"] = []
        c["expect"] = {"authorization": {"status": "pass"}, "anchor": anchor, "header_trust_needs": str(new["needs"]),
                       "report": rep, "verdict": verdict[0], "exit": verdict[1]}
        wa = {"status": was["status"]}
        for k in ("reason", "rule"):
            if k in was:
                wa[k] = str(was[k])
        c["v1_0"] = {"anchor": wa}
        return c

    h0, d = window(fibre)
    bh0, bd = window(blob)
    cases = [
        mk("fast_pass_trust_at_h", "Evidence at H = h0 + 1 verifies; header trust reaches exactly H, below the deadline. "
           "v1.0.N: anchor_pending until a checkpoint >= D; v1.1: pass.", fibre, h0 + 1, ev=(h0 + 1, True)),
        mk("fast_pass_trust_between", "Evidence at H = h0 + 1; header trust at D - 1.", fibre, d - 1, ev=(h0 + 1, True)),
        mk("fast_pass_at_deadline_trust_at_d", "Evidence at H = D; header trust at D: pass in both revisions.", fibre, d,
           ev=(d, True)),
        mk("fast_trust_below_h", "Evidence at H = h0 + 2 verifies once trusted, but header trust stops at h0 + 1: the "
           "header at H is not reached.", fibre, h0 + 1, ev=(h0 + 2, True)),
        mk("fast_evidence_not_verifying_trust_below_d", "Evidence that does not verify, header trust at D - 1: no usable "
           "evidence, so the deadline bound applies.", fibre, d - 1, ev=(h0 + 1, False)),
        mk("fast_absence_needs_deadline", "No evidence; heights h0 to D - 1 proven absent and header trust at D - 1: "
           "absence still needs header trust up to D.", fibre, d - 1,
           absence=[(h, "absent") for h in range(h0, d)]),
        mk("fast_results_proof_needs_deadline_plus_1", "No evidence; header trust at D while an AB5 results proof needs "
           "D + 1: unchanged by v1.1.", fibre, d, needs_results=True),
        mk("fast_blob_pass_trust_at_h", "da = 2: evidence at H = h0 verifies, header trust reaches H only.", blob, bh0,
           ev=(bh0, True)),
    ]
    for c in cases:
        for ref in (c["decision"], c["authorization"]):
            assert ref in recs, ref
    return {
        "format": FORMAT, "revision": REVISION, "generator": GENERATOR,
        "description": "Verifier outcomes of the anchor check of a pending reference under spec revision v1.1 (core "
                       "20.6.1: presence needs header trust up to the anchor height H; every other row still needs the "
                       "deadline D, or D + 1 with an AB5 results proof), in the layout of the cases of v1/verify.json; "
                       "decision and authorization name records of records_from. header_trust_needs is the height header "
                       "trust must reach for the row that decides. v1_0 gives the anchor outcome of the frozen text on "
                       "the same inputs, which a v1.0.N verifier keeps.",
        "records_from": "v1/verify.json",
        "window": old["window"],
        "cases": cases,
    }


def write(rel: str, d: dict, check: bool) -> bool:
    p = VECTORS / rel
    text = dump(d)
    if check:
        return p.exists() and p.read_text() == text
    p.write_text(text)
    return True


def upstream_section() -> dict:
    if "--exec" in sys.argv:
        return json.loads(Path(sys.argv[sys.argv.index("--exec") + 1]).read_text())
    return load(EXEC_FILE)["upstream"]


def main() -> int:
    check = "--check" in sys.argv
    up = upstream_section()
    ok = True
    for rel, d in ((EXEC_FILE, exec_file(up)), (ERRORS_FILE, errors_file()), (VERIFY_FILE, verify_file())):
        if not write(rel, d, check):
            print(f"FAIL (gen v1.1): {rel} differs from the generator output", file=sys.stderr)
            ok = False
    if ok:
        print(f"OK (gen v1.1): {'checked' if check else 'wrote'} {EXEC_FILE}, {ERRORS_FILE}, {VERIFY_FILE}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
