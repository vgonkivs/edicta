#!/usr/bin/env python3
"""Verifies spec/vectors/da/absence.json (v1-draft.3, core v1 10.4) without Go and without the network.

Runs AB1 to AB5 on the bytes of every kind 14 record, with the code that
already checks the v0 anchor proof and result proof:
- the record layer: archive_v1.decode_record, and the record names the query
  (da, commitment, namespace, height);
- AB1: the SignedHeader's header at h, its CometBFT hash (check_fibre_cert)
  equal to the trusted hash, the commit at h for that hash;
- AB2: the DAH protobuf, root sizes, ValidateBasic bounds and the RFC 6962
  hash against data_hash (check_fibre_anchor);
- AB3: NamespaceData decoding and Verify against the row roots, NMT
  completeness included (check_fibre_anchor);
- AB4: compact-share reassembly with the re-split check, PFF decoding
  (check_fibre_cert) and the candidate filter;
- AB5: the block results (JSON of /block_results) hashed to last_results_hash
  of the trusted header at h + 1 (leaves from check_execution_outcomes), the
  candidate's result bound as the tail of the block's results (only when
  header(h) has the pinned version.app 10), or by uniform codes.
Then the window result as 10.2 reads it, the coverage of the section 15
names and rules, the refs of v1/verify.json into this file, and the
generator's output.

Usage: python3 spec/vectors/check/check_absence.py [--file FILE]
"""

from __future__ import annotations

import sys

sys.dont_write_bytecode = True

import hashlib
import json
from pathlib import Path

import archive_v1 as A
import check_execution_outcomes as EO
import check_fibre_anchor as FA
import check_fibre_cert as FC

HERE = Path(__file__).resolve().parent
VECTORS = HERE.parent
FORMAT, REVISION = "edicta-vectors/v1", "v1-draft.3"
APP_VERSION = 10
SYNTHETIC = ("fibre_candidate_nonzero_code", "fibre_present", "window_three_heights_proven",
             "window_one_height_missing", "tampered_row_root", "cut_namespace_entry")
LIVE = ("fibre_no_pff_row", "fibre_other_pffs_only", "blob_empty_namespace", "blob_other_blobs", "blob_present")
ROOT_SIZE = 2 * FA.NS_SIZE + 32


class Failure(Exception):
    pass


class Unproven(Exception):
    def __init__(self, rule: str, why: str):
        super().__init__(f"{rule}: {why}")
        self.rule = rule


def expect(cond: bool, msg: str):
    if not cond:
        raise Failure(msg)


def need(cond: bool, rule: str, why: str):
    if not cond:
        raise Unproven(rule, why)


def parse_signed_header(b: bytes, h: int, trusted: dict, rule: str) -> list:
    try:
        sh = FC.fields(b)
        hb = FC.last(sh, 1, 2, b"")
        hf = FC.fields(hb)
        height = FC.int64(FC.last(hf, 3, 0, 0))
        hh = FC.header_hash(hb)
        cf = FC.fields(FC.last(sh, 2, 2, b""))
        commit_height = FC.int64(FC.last(cf, 1, 0, 0))
        commit_hash = FC.last(FC.fields(FC.last(cf, 3, 2, b"")), 1, 2, b"")
    except FC.Failure as e:
        raise Unproven(rule, f"signed header protobuf: {e}")
    need(height == h, rule, f"header height {height}, want {h}")
    need(str(h) in trusted, rule, f"header trust does not reach {h}")
    need(hh.hex() == trusted[str(h)], rule, "header hash differs from the trusted hash")
    need(commit_height == h and commit_hash == hh, rule, "commit is not for this header")
    return hf


def app_version(hf: list) -> int:
    try:
        return FC.int64(FC.last(FC.fields(FC.last(hf, 1, 2, b"")), 2, 0, 0))
    except FC.Failure as e:
        raise Unproven("AB1", f"header version: {e}")


def classify(rec: dict, q: dict, h: int, trusted: dict) -> dict:
    """One height: absent, present or unproven, with the rule that decides."""
    need(rec["da"] == 1 and rec["commitment"] == q["commitment"] and rec["namespace"] == q["namespace"]
         and rec["height"] == h, "record", "the record is not about this query and height")
    hf = parse_signed_header(rec["header"], h, trusted, "AB1")
    data_hash = FC.last(hf, 7, 2, b"")

    try:
        rows, cols = FA.parse_dah_proto(rec["dah"])
    except FC.Failure as e:
        raise Unproven("AB2", f"DAH protobuf: {e}")
    need(all(len(r) == ROOT_SIZE for r in rows + cols), "AB2", "root size")
    try:
        FA.check_dah(rows, cols, data_hash)
    except FA.Reject as e:
        raise Unproven("AB2", str(e))

    try:
        nd = FA.decode_stream(rec["namespace_data"])
        want = FA.verify_rows(nd, rows, FA.PFF_NS)
    except FA.Reject as e:
        raise Unproven("AB3", str(e))
    shares = [s for r in nd for s in r["shares"]]
    out = {"rows": [str(x) for x in want], "pff_txs": "0"}
    if not shares:
        return {**out, "result": "absent", "rule": "AB4"}

    try:
        units = FA.reassemble(shares)
    except FA.Reject as e:
        raise Unproven("AB4", str(e))
    out["pff_txs"] = str(len(units))
    cands = []
    for j, tx in enumerate(units):
        try:
            p = FC.parse_pff(tx)
        except FC.Failure:
            continue
        if (p["namespace"] == q["namespace"] and p["commitment"] == q["commitment"] and p["blob_version"] == 0
                and p["chain_id"] == q["chain_id"] and p["height"] <= h):
            cands.append(j)
    if not cands:
        return {**out, "result": "absent", "rule": "AB4"}

    need("results" in rec and "next_header" in rec, "AB5", "a candidate whose code is not proven")
    nf = parse_signed_header(rec["next_header"], h + 1, trusted, "AB5")
    try:
        served = json.loads(rec["results"])
        res = [{"code": str(x["code"]), "data": x.get("data") or "", "gas_wanted": x["gas_wanted"],
                "gas_used": x["gas_used"]} for x in served["txs_results"]]
        leaves = [EO.results_leaf(r) for r in res]
    except (ValueError, KeyError, TypeError, EO.Failure) as e:
        raise Unproven("AB5", f"results: {e}")
    need(FC.merkle(leaves) == FC.last(nf, 12, 2, b""), "AB5",
         "results do not hash to last_results_hash of header(h + 1)")
    n, p = len(res), len(units)
    codes = {r["code"] for r in res}
    tail = app_version(hf) == APP_VERSION
    found = []
    for j in cands:
        if tail and n >= p:
            i = n - p + j
            found.append({"position": str(j), "result_index": str(i), "code": res[i]["code"]})
        elif len(codes) == 1:
            found.append({"position": str(j), "code": res[0]["code"]})
        else:
            raise Unproven("AB5", "the candidate's result index is not bound")
    out["candidates"] = found
    present = any(c["code"] == "0" for c in found)
    return {**out, "result": "present" if present else "absent", "rule": "AB5"}


def window(heights: list) -> dict:
    present = next((x["height"] for x in heights if x["result"] == "present"), None)
    if present:
        return {"result": "present", "anchor_height": present}
    miss = next((x["height"] for x in heights if x["result"] != "absent"), None)
    return {"result": "absent"} if miss is None else {"result": "unproven", "first_unproven": miss}


def check_case(c: dict, chain_id: str) -> set:
    cid = c["id"]
    expect(set(c) - {"app_versions"} == {"id", "description", "query", "trusted_headers", "records", "expect"},
           f"{cid}: keys")
    qj = c["query"]
    expect(set(qj) == {"da", "namespace", "commitment", "chain_id", "h0", "anchor_deadline"} and qj["da"] == "1"
           and qj["chain_id"] == chain_id, f"{cid}: query")
    q = {"namespace": bytes.fromhex(qj["namespace"]), "commitment": bytes.fromhex(qj["commitment"]),
         "chain_id": qj["chain_id"]}
    h0, d = int(qj["h0"]), int(qj["anchor_deadline"])
    expect(0 < h0 <= d, f"{cid}: window")
    recs = {}
    for r in c["records"]:
        b = bytes.fromhex(r["record_hex"])
        expect(hashlib.sha256(b).hexdigest() == r["sha256"] and r["size"] == str(len(b)), f"{cid}: record hash")
        try:
            rec = A.decode_record(b)
        except A.Reject as e:
            raise Failure(f"{cid}: record at {r['height']} does not decode: {e}")
        expect(rec["kind"] == A.KIND_ABSENCE and str(rec["height"]) == r["height"], f"{cid}: record kind or height")
        expect(r["height"] not in recs, f"{cid}: two records at {r['height']}")
        recs[r["height"]] = rec
    got = []
    for h in range(h0, d + 1):
        if str(h) not in recs:
            got.append({"height": str(h), "result": "unproven", "rule": "none"})
            continue
        try:
            got.append({"height": str(h), **classify(recs[str(h)], q, h, c["trusted_headers"])})
        except Unproven as u:
            got.append({"height": str(h), "result": "unproven", "rule": u.rule})
    exp = c["expect"]["heights"]
    expect(len(exp) == len(got), f"{cid}: heights")
    for e, g in zip(exp, got):
        where = f"{cid} at {g['height']}"
        expect(e.pop("why", None), f"{where}: why")
        if g["result"] == "unproven":
            for k in ("rows", "pff_txs", "candidates"):
                g.pop(k, None)
        expect(e == g, f"{where}: vector {e}, checker {g}")
    expect(c["expect"]["window"] == window(got), f"{cid}: window")
    return {g["rule"] for g in got}


def check_app_versions(c: dict):
    """A case on another chain: every record's header at a listed height carries that version.app."""
    cid = c["id"]
    expect(c["app_versions"] and all(v != str(APP_VERSION) for v in c["app_versions"].values()),
           f"{cid}: app_versions lists only other versions")
    for r in c["records"]:
        if r["height"] not in c["app_versions"]:
            continue
        rec = A.decode_record(bytes.fromhex(r["record_hex"]))
        hf = parse_signed_header(rec["header"], rec["height"], c["trusted_headers"], "AB1")
        expect(str(app_version(hf)) == c["app_versions"][r["height"]], f"{cid}: version.app at {r['height']}")


def verify_refs(f: dict):
    """Every da/absence.json ref of v1/verify.json names a case whose window reads the same way."""
    by_id = {c["id"]: c for c in f["synthetic"]}
    v = json.loads((VECTORS / "v1" / "verify.json").read_text())
    n = 0
    for vc in v["cases"]:
        for ref in vc.get("refs", []):
            if not ref.startswith("da/absence.json"):
                continue
            n += 1
            if "#" not in ref:
                continue
            cid = ref.split("#", 1)[1]
            expect(cid in by_id, f"v1/verify.json {vc['id']}: ref {cid} is not a case")
            rep = vc["expect"]["report"]
            ab = {x["height"]: x["result"] for x in vc["absence"]}
            heights = [{"height": str(h), "result": ab.get(str(h), "unproven")}
                       for h in range(int(rep["h0"]), int(rep["anchor_deadline"]) + 1)]
            expect(window(heights)["result"] == by_id[cid]["expect"]["window"]["result"],
                   f"v1/verify.json {vc['id']}: {cid} reads another way")
    expect(n > 0, "v1/verify.json has no ref into da/absence.json")
    return n


def check(f: dict) -> str:
    expect(f.get("format") == FORMAT and f.get("revision") == REVISION, "format or revision")
    expect(set(f) == {"format", "revision", "generator", "description", "chain_id", "pff_namespace", "blocks",
                      "synthetic", "live", "live_pending"}, "top-level keys")
    expect(f["pff_namespace"] == FA.PFF_NS.hex(), "PFF namespace")
    expect(f["live"] == [] and "P3" in f["live_pending"] and all(x in f["live_pending"] for x in LIVE),
           "live cases are P3: live stays empty and live_pending names them")
    ids = [c["id"] for c in f["synthetic"]]
    expect(len(ids) == len(set(ids)) and all(x in ids for x in SYNTHETIC), "section 15 synthetic case names")
    for c in f["synthetic"]:
        if "app_versions" in c:
            check_app_versions(c)
            continue
        for b in f["blocks"]:
            expect(c["trusted_headers"].get(b["height"]) == b["header_hash"], f"{c['id']}: trusted {b['height']}")
    rules = set()
    for c in f["synthetic"]:
        rules |= check_case(c, f["chain_id"])
    expect({"AB1", "AB2", "AB3", "AB4", "AB5", "none"} <= rules, f"rules without a case: {rules}")
    results = {x["result"] for c in f["synthetic"] for x in c["expect"]["heights"]}
    expect(results == {"absent", "present", "unproven"}, "every per-height result")
    n_refs = verify_refs(f)
    return f"{len(ids)} synthetic cases, {sum(len(c['records']) for c in f['synthetic'])} records, {n_refs} verify refs"


def main() -> int:
    path = VECTORS / "da" / "absence.json"
    if "--file" in sys.argv:
        path = Path(sys.argv[sys.argv.index("--file") + 1]).resolve()
    try:
        text = path.read_text()
        summary = check(json.loads(text))
        import gen_absence as gen
        expect(json.dumps(gen.build()["absence.json"], indent=2, ensure_ascii=True) + "\n" == text,
               "generator output differs")
    except (Failure, FC.Failure, EO.Failure, KeyError, ValueError, StopIteration) as e:
        print(f"FAIL (absence.json): {type(e).__name__}: {e}", file=sys.stderr)
        return 1
    print(f"OK (absence.json, {REVISION}): {summary}; live cases pending (P3); generator output identical")
    return 0


if __name__ == "__main__":
    sys.exit(main())
