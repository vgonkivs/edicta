#!/usr/bin/env python3
"""Checks the vector files of spec revision v1.1 (minor).

- archive/execution_result_v1.1.json: the upstream blocks are self-consistent (header hashes and links, results
  root, row proofs against data_hash, rail references); every record decodes with the v1.1 reader of kind 19 to
  its input and sits at its path, and the frozen v1.0 general reader refuses it (ErrInvalidEnum); every reject
  gives its cause; every XR case gives its outcome (exec_result.py); every migration case gives its records or
  refusals; the NMT part of XR4 is checked by spec/vectors/tools/execresult-gen -check;
- api/errors_v1.1.json: the additions keep the status semantics of api/errors.json, and order is api/errors.json with
  the additions in place (the spec table itself is compared by check_api_errors.py);
- v1/verify_v1.1.json: every case under the v1.1 rules of core 20.6.1, its v1_0 outcome under the frozen text, and
  references into v1/verify.json;
- verifier/reasons_v1.1.json: every entry names a reason of verifier/reasons_v1.0.3.json with the same group and
  checks, and replaces exactly its frozen meaning and advice;
- the generator (gen_v1_1.py) reproduces the three files byte for byte.

Usage: python3 spec/vectors/check/check_v1_1.py
"""

from __future__ import annotations

import sys

sys.dont_write_bytecode = True

import hashlib
import json
from pathlib import Path

import exec_result as X
import gen_v1_1 as gen
import records as RD
from check_fibre_cert import Failure, fields, header_hash, merkle
from edicta import Reject

VECTORS = Path(__file__).resolve().parent.parent


def expect(cond: bool, msg: str):
    if not cond:
        raise Failure(msg)


def load(rel: str) -> dict:
    return json.loads((VECTORS / rel).read_text())


def header_link(nb: bytes) -> bytes:
    lbid = next((v for n, _, v in fields(nb) if n == 5), b"")
    return next((v for n, _, v in fields(lbid) if n == 1), b"")


def check_upstream(up: dict) -> int:
    expect(set(up) == {"pins", "inputs", "blocks"}, "upstream keys")
    for b in up["blocks"]:
        hb, nb = bytes.fromhex(b["header_hex"]), bytes.fromhex(b["next_header_hex"])
        h, nh = X._header(hb), X._header(nb)
        expect(h["hash"].hex() == b["header_hash_hex"] and nh["hash"].hex() == b["next_header_hash_hex"],
               f"{b['id']}: header hashes")
        expect(header_link(nb) == h["hash"], f"{b['id']}: header H + 1 does not name header H")
        expect(h["height"] == int(b["height"]) and nh["height"] == h["height"] + 1, f"{b['id']}: heights")
        expect(h["chain_id"] == nh["chain_id"] == b["chain_id"] and h["app"] == X.PINNED_APP_VERSION, f"{b['id']}: chain")
        expect(h["data_hash"].hex() == b["data_hash_hex"], f"{b['id']}: data hash")
        leaves = []
        for r in b["results"]:
            leaf = X.results_leaf(int(r["code"]), bytes.fromhex(r["data_hex"]), int(r["gas_wanted"]), int(r["gas_used"]))
            expect(leaf.hex() == r["leaf_hex"], f"{b['id']}: leaf")
            leaves.append(leaf)
        expect(len(leaves) == len(b["txs"]), f"{b['id']}: one result per tx")
        root = merkle(leaves)
        expect(root.hex() == b["results_root_hex"] and root == nh["last_results_hash"], f"{b['id']}: results root")
        classes = [t["class"] for t in b["txs"]]
        expect(classes == sorted(classes, key=["ordinary", "blob", "fibre"].index), f"{b['id']}: tx order")
        keys = [p["key"] for p in b["proofs"]]
        expect(keys == sorted(keys, key=int) and keys[0] == "9", f"{b['id']}: proof keys")
        for p in b["proofs"] + b.get("variants", []):
            sp = X._share_proof(bytes.fromhex(p["proof_hex"]))
            name = p.get("key", p.get("id"))
            expect(X._span(sp, X._width(sp)) == (int(p["start"]), int(p["end"])), f"{b['id']}: proof {name} range")
            expect(X._rows_reach(sp, h["data_hash"]), f"{b['id']}: proof {name} row proofs")
            expect(bytes([sp["namespace_version"]]) + sp["namespace_id"] == bytes.fromhex(p["namespace_hex"]),
                   f"{b['id']}: proof {name} namespace")
        for c in b["captures"]:
            tx = bytes.fromhex(b["txs"][int(c["tx_index"])]["hex"])
            expect(hashlib.sha256(tx).hexdigest() == c["rail_ref"], f"{b['id']}: rail_ref")
            path = bytes.fromhex(c["result_path_hex"])
            aunts = [path[i:i + 32] for i in range(0, len(path), 32)]
            leaf = leaves[int(c["tx_index"])]
            expect(X.root_from_aunts(int(c["tx_index"]), int(c["results_total"]), hashlib.sha256(b"\x00" + leaf).digest(),
                                     aunts) == root, f"{b['id']}: result path")
    return len(up["blocks"])


def check_exec(f: dict) -> str:
    expect(f["format"] == gen.FORMAT and f["revision"] == "v1.1" and f["kind"] == "19", "execution_result header")
    nb = check_upstream(f["upstream"])
    expect(RD.UNASSIGNED == frozenset({3, 6, 16}) and 19 not in RD.ASSIGNED,
           "the v1.0 kind table of core 19.1 changed")
    negative = {b["id"] for b in f["upstream"]["blocks"] if b.get("negative")}
    expect(not any(r["block"] in negative for r in f["records"]), "a negative block's capture is in records")
    for r in f["records"]:
        raw = bytes.fromhex(r["record_cbor_hex"])
        rec = X.decode_record(raw)
        expect(gen.plain(rec) == r["input"], f"{r['id']}: decodes to its input")
        expect(X.path_of(X.key_of(rec)) == r["path"] and r["key"] == {"chain_id": rec["chain_id"],
                                                                     "rail_ref": rec["rail_ref"].hex()}, f"{r['id']}: key")
        expect(hashlib.sha256(raw).hexdigest() == r["record_sha256_hex"], f"{r['id']}: sha256")
        expect(RD.cause(raw) == r["v1_0_reader_cause"] == "ErrInvalidEnum", f"{r['id']}: a v1.0 reader must refuse kind 19")
    for r in f["reject"]:
        try:
            X.decode_record(bytes.fromhex(r["record_cbor_hex"]))
            got = None
        except Reject as e:
            got = e.sentinel
        expect(got == r["cause"] and r["expect_error"] == "archive.ErrCorrupt", f"reject {r['id']}: {got}")
    rules = set()
    for c in f["cases"]:
        raw = bytes.fromhex(c["record_cbor_hex"])
        q = {"chain_id": c["query"]["chain_id"], "rail_ref": bytes.fromhex(c["query"]["rail_ref"])}
        t = {int(h): bytes.fromhex(x) for h, x in c["trusted"].items()}
        try:
            rec = X.decode_record(raw)
        except Reject:
            rec = None
            got = {"result": "set_aside", "rule": "decode", "reason": "tx_proof_invalid"}
        if rec is not None:
            try:
                got = {"result": "pass", "rule": "none", "reason": "none", "facts": X.xr(rec, q, t)}
            except X.SetAside as e:
                got = {"result": "set_aside", "rule": e.rule, "reason": e.reason}
        expect(got == c["expect"], f"case {c['id']}: {got}")
        if c.get("note") == "path_verifies_alone":
            p = rec["result_path"]
            nh = X._header(rec["next_header"])
            expect(X.root_from_aunts(rec["tx_index"], rec["results_total"], hashlib.sha256(b"\x00" + rec["result"]).digest(),
                                     [p[i:i + 32] for i in range(0, len(p), 32)]) == nh["last_results_hash"],
                   f"case {c['id']}: the path must verify on its own")
        rules.add(got["rule"])
    expect(rules == {"none", "decode", "XR1", "XR2", "XR3", "XR4", "XR5", "XR6", "XR7", "XR8"}, f"XR coverage {sorted(rules)}")
    pairs = {(c["expect"]["rule"], c["expect"]["reason"]) for c in f["cases"]}
    for pair in (("XR2", "tx_proof_invalid"), ("XR2", "result_header_unreachable"), ("XR2", "header_not_linking"),
                 ("XR7", "tx_hash_mismatch"), ("XR7", "result_index_unbound")):
        expect(pair in pairs, f"XR coverage: no case for {pair}")
    by_block = {}
    for r in f["records"]:
        by_block.setdefault(r["block"], []).append(r["record_cbor_hex"])
    outcomes = set()
    for m in f["migration"]:
        stored = {p: bytes.fromhex(h) for p, h in m.get("stored", {}).items()}
        got = gen.migrate(m["capture"], stored)
        expect(got == m["expect"], f"migration {m['id']}")
        for x in got:
            outcomes.add(x.get("rule", x["result"]))
            if x["result"] == "kept":
                st = X.decode_record(stored[x["path"]])
                expect(gen.self_check(st) is None, f"migration {m['id']}: the squatting record must pass MG3, so only "
                                                   f"the comparison of MG5 keeps the capture")
            if x["result"] == "written":
                expect(X.decode_record(bytes.fromhex(x["record_cbor_hex"])) is not None, f"migration {m['id']}: decodes")
    written = [x["record_cbor_hex"] for m in f["migration"] if m["id"] == "capture_three_namespaces" for x in m["expect"]]
    expect(written == by_block["three_namespaces"], "migration of a block gives the records byte for byte")
    expect(outcomes == {"written", "already_stored", "MG2", "MG3", "MG5"}, f"migration coverage {sorted(outcomes)}")
    return (f"{nb} blocks, {len(f['records'])} records, {len(f['reject'])} reject, {len(f['cases'])} XR cases, "
            f"{len(f['migration'])} migration cases")


def check_errors(f: dict) -> str:
    base = load("api/errors.json")
    expect(f["base"] == "api/errors.json" and f["revision"] == "v1.1", "errors_v1.1 header")
    statuses = {k: v["retryable"] for k, v in base["statuses"].items()}
    codes = {e["code"] for e in base["errors"]} | {n["name"] for n in base["not_api_visible"]}
    for a in f["additions"]:
        expect(a["code"] not in codes, f"{a['code']} already in api/errors.json")
        expect(a["status"] in statuses and a["retryable"] == statuses[a["status"]], f"{a['code']}: retryable")
        expect(a["stored"] == "none" and a["endpoints"] == ["/v1/publish"], f"{a['code']}: stored, endpoints")
    expect(f["order"] == gen.errors_file()["order"], "order")
    expect([o["code"] for o in f["order"]].index("recorder.ErrAnchorRejected") <
           [o["code"] for o in f["order"]].index("ErrAnchorNotFound"), "ErrAnchorRejected must match before ErrAnchorNotFound")
    return f"{len(f['additions'])} additions, {len(f['order'])} codes in match order"


def check_verify(f: dict) -> str:
    old = load("v1/verify.json")
    for c in f["cases"]:
        expect(c["decision"] in old["records"] and c["authorization"] in old["records"], f"{c['id']}: refs")
    expect(f == gen.verify_file(), "v1/verify_v1.1.json differs from the v1.1 rules")
    relaxed = [c["id"] for c in f["cases"] if c["v1_0"]["anchor"] != {k: v for k, v in c["expect"]["anchor"].items()
                                                                      if k in ("status", "reason", "rule")}]
    for cid in relaxed:
        c = next(x for x in f["cases"] if x["id"] == cid)
        expect(c["v1_0"]["anchor"] == {"status": "unchecked", "reason": "anchor_pending"} and
               c["expect"]["anchor"]["status"] == "pass", f"{cid}: v1.1 may only turn anchor_pending into pass")
    expect(relaxed, "no case shows the relaxation")
    return f"{len(f['cases'])} cases, {len(relaxed)} relaxed from anchor_pending to pass"


def check_reasons(f: dict) -> str:
    base = {r["name"]: r for r in load("verifier/reasons_v1.0.3.json")["reasons"]}
    expect(f["base"] == "verifier/reasons_v1.0.3.json" and f["revision"] == "v1.1", "reasons_v1.1 header")
    for r in f["reasons"]:
        old = base.get(r["name"])
        expect(old is not None, f"{r['name']}: not a reason of the frozen file")
        expect(r["group"] == old["group"] and r["checks"] == old["checks"], f"{r['name']}: group or checks changed")
        expect(r["replaces"] == {"file": f["base"], "meaning": old["meaning"], "advice": old["advice"]},
               f"{r['name']}: replaces must quote the frozen strings")
        expect("v1.1 verifier confirms" not in r["advice"] and "valid verdict requires a paid anchor" in r["meaning"],
               f"{r['name']}: H1 wording")
    return f"{len(f['reasons'])} reason wording"


def main() -> int:
    try:
        parts = [check_exec(load(gen.EXEC_FILE)), check_errors(load(gen.ERRORS_FILE)), check_verify(load(gen.VERIFY_FILE)),
                 check_reasons(load(gen.REASONS_FILE))]
        expect(gen.main.__name__ == "main", "generator")
        for rel, d in ((gen.EXEC_FILE, gen.exec_file(load(gen.EXEC_FILE)["upstream"])), (gen.ERRORS_FILE, gen.errors_file()),
                       (gen.VERIFY_FILE, gen.verify_file()), (gen.REASONS_FILE, gen.reasons_file())):
            expect((VECTORS / rel).read_text() == gen.dump(d), f"{rel} differs from the generator output")
    except (Failure, Reject, KeyError, ValueError) as e:
        print(f"FAIL (v1.1): {e}", file=sys.stderr)
        return 1
    print(f"OK (v1.1): {'; '.join(parts)}; generator output identical")
    return 0


if __name__ == "__main__":
    sys.exit(main())
