#!/usr/bin/env python3
"""Verifies spec/vectors/da/absence.json (v1-draft.5) without Go and without the network.

Runs AB1 to AB5 on the bytes of every kind 14 record, with the code that
already checks the anchor proof and result proof:
- the record layer: archive.decode_record, and the record names the query
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
  header(h) has the pinned version.app 10, with n >= p >= 1); at another
  app version only "every code 0" proves presence, never absence;
- AB6 (da = 2): sparse-share parsing as go-square ParseBlobs and the share
  commitment as go-square CreateCommitment (threshold 64, RFC 6962 root over
  the NMT subtree roots), both written here and first checked against every
  commitment of da/blob_commit.json.
Then the window result as 10.2 reads it, the coverage of the section 15
names and rules, the live Mocha cases (same rules, their own chain_id and
trusted hashes), the tail rule on the live blocks of live_tail_rule, the
refs of v1/verify.json into this file, and the generator's output.

Usage: python3 spec/vectors/check/check_absence.py [--file FILE]
"""

from __future__ import annotations

import sys

sys.dont_write_bytecode = True

import hashlib
import json
import math
from pathlib import Path

import archive as A
import check_execution_outcomes as EO
import check_fibre_anchor as FA
import check_fibre_cert as FC

HERE = Path(__file__).resolve().parent
VECTORS = HERE.parent
FORMAT, REVISION = "edicta-vectors/v1", "v1-draft.5"
APP_VERSION = 10
SYNTHETIC = ("fibre_candidate_nonzero_code", "fibre_present", "window_three_heights_proven",
             "window_one_height_missing", "tampered_row_root", "cut_namespace_entry", "candidate_other_app_version",
             "candidate_other_app_version_all_nonzero", "candidate_other_app_version_all_zero", "tail_n_less_than_p")
LIVE = ("fibre_no_pff_row", "fibre_other_pffs_only", "blob_empty_namespace", "blob_other_blobs", "blob_present")
ROOT_SIZE = 2 * FA.NS_SIZE + 32
THRESHOLD = 64
SIGNER_SIZE = 20
TAIL_PADDING_NS = b"\xff" * 28 + b"\xfe"
RESERVED_PADDING_NS = bytes(28) + b"\xff"


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


def parse_blobs(shares: list) -> list:
    """go-square share.ParseBlobs at v4.0.1: sequences of sparse shares, padding skipped."""
    seqs = []
    for sh in shares:
        need(len(sh) == FA.SHARE_SIZE, "AB6", "share size")
        ns, info = sh[:FA.NS_SIZE], sh[FA.NS_SIZE]
        ver, start = info >> 1, info & 1
        need(ver in (0, 1, 2), "AB6", f"unsupported share version {ver}")
        seq_len = int.from_bytes(sh[FA.NS_SIZE + 1:FA.NS_SIZE + 5], "big") if start else 0
        if (start and seq_len == 0) or ns in (TAIL_PADDING_NS, RESERVED_PADDING_NS):
            continue
        if start:
            at = FA.NS_SIZE + 5
            signer = None
            if ver in (1, 2):
                signer, at = sh[at:at + SIGNER_SIZE], at + SIGNER_SIZE
            seqs.append({"ns": ns, "version": ver, "len": seq_len, "signer": signer, "data": bytearray(sh[at:])})
        else:
            need(bool(seqs) and seqs[-1]["ns"] == ns, "AB6", "continuation share without its sequence start")
            seqs[-1]["data"] += sh[FA.NS_SIZE + 1:]
    blobs = []
    for q in seqs:
        need(q["len"] <= len(q["data"]), "AB6", "sequence length beyond the sequence")
        data = bytes(q["data"][:q["len"]])
        need(q["ns"][0] == 0, "AB6", "namespace version")
        need(q["version"] != 2 or len(data) == 36, "AB6", "share version 2 data size")
        blobs.append({"ns": q["ns"], "version": q["version"], "signer": q["signer"], "data": data})
    return blobs


def split_blob(ns: bytes, version: int, data: bytes, signer: bytes | None) -> list:
    """go-square SparseShareSplitter.Write for one blob."""
    head = ns + bytes([version << 1 | 1]) + len(data).to_bytes(4, "big") + (signer or b"")
    first = FA.SHARE_SIZE - len(head)
    out = [(head + data[:first]).ljust(FA.SHARE_SIZE, b"\x00")]
    cont = FA.SHARE_SIZE - FA.NS_SIZE - 1
    for i in range(first, len(data), cont):
        out.append((ns + bytes([version << 1]) + data[i:i + cont]).ljust(FA.SHARE_SIZE, b"\x00"))
    return out


def nmt_root(leaves: list) -> bytes:
    if len(leaves) == 1:
        return FA.hash_leaf(leaves[0])
    k = FA.split_point(len(leaves))
    return FA.hash_node(nmt_root(leaves[:k]), nmt_root(leaves[k:]), True)


def round_up_pow2(n: int) -> int:
    return 1 if n <= 1 else 1 << (n - 1).bit_length()


def create_commitment(ns: bytes, version: int, data: bytes, signer: bytes | None) -> bytes:
    """go-square inclusion.CreateCommitment with the RFC 6962 root and threshold 64."""
    shares = split_blob(ns, version, data, signer)
    n = len(shares)
    width = min(round_up_pow2(-(-n // THRESHOLD)), round_up_pow2(math.isqrt(n - 1) + 1 if n > 1 else 1))
    roots, at = [], 0
    while at < n:
        left = n - at
        size = width if left >= width else 1 << (left.bit_length() - 1)
        roots.append(nmt_root([ns + sh for sh in shares[at:at + size]]))
        at += size
    return FA.merkle(roots)


def check_commitment_code() -> int:
    """The AB6 commitment code reproduces every share commitment of da/blob_commit.json (upstream go-square output)."""
    d = json.loads((VECTORS / "da" / "blob_commit.json").read_text())
    for c in d["cases"]:
        size = int(c["size"])
        blob = bytes.fromhex(c["blob_hex"]) if "blob_hex" in c else bytes((7 * i + 3) % 256 for i in range(size))
        expect(len(blob) == size and hashlib.sha256(blob).hexdigest() == c["blob_sha256_hex"], f"da_blob {c['id']}: blob")
        com = create_commitment(bytes.fromhex(c["namespace_hex"]), 1, blob, bytes.fromhex(c["signer_hex"]))
        expect(com.hex() == c["commitment_hex"], f"da_blob {c['id']}: commitment code differs from go-square")
    return len(d["cases"])


def classify(rec: dict, q: dict, h: int, trusted: dict) -> dict:
    """One height: absent, present or unproven, with the rule that decides."""
    need(rec["da"] == q["da"] and rec["commitment"] == q["commitment"] and rec["namespace"] == q["namespace"]
         and rec["height"] == h, "record", "the record is not about this query and height")
    ns = FA.PFF_NS if q["da"] == 1 else q["namespace"]
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
        want = FA.verify_rows(nd, rows, ns)
    except FA.Reject as e:
        raise Unproven("AB3", str(e))
    shares = [s for r in nd for s in r["shares"]]
    if q["da"] == 2:
        out = {"rows": [str(x) for x in want]}
        if not shares:
            return {**out, "result": "absent", "rule": "AB6"}
        blobs, present = [], False
        for b in parse_blobs(shares):
            bd = {"share_version": str(b["version"])}
            if b["version"] == 1:
                com = create_commitment(b["ns"], 1, b["data"], b["signer"])
                bd.update(signer=b["signer"].hex(), commitment=com.hex())
                present = present or (com == q["commitment"] and b["signer"] == q["signer"])
            blobs.append(bd)
        return {**out, "blobs": blobs, "result": "present" if present else "absent", "rule": "AB6"}
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
    need(n >= p >= 1, "AB5", "n >= p >= 1 does not hold")
    codes = {r["code"] for r in res}
    if app_version(hf) != APP_VERSION:
        # Other app versions: only every code 0 proves presence; nothing there can prove absence.
        need(codes == {"0"}, "AB5", "another app version without every code 0: not proven")
        out["candidates"] = [{"position": str(j), "code": "0"} for j in cands]
        return {**out, "result": "present", "rule": "AB5"}
    found = []
    for j in cands:
        i = n - p + j
        found.append({"position": str(j), "result_index": str(i), "code": res[i]["code"]})
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
    expect(set(c) - {"app_versions", "results_counts"} == {"id", "description", "query", "trusted_headers", "records",
                                                          "expect"},
           f"{cid}: keys")
    qj = c["query"]
    keys = {"da", "namespace", "commitment", "chain_id", "h0", "anchor_deadline"}
    expect(qj.get("da") in ("1", "2") and set(qj) == keys | ({"signer"} if qj["da"] == "2" else set())
           and qj["chain_id"] == chain_id, f"{cid}: query")
    q = {"da": int(qj["da"]), "namespace": bytes.fromhex(qj["namespace"]), "commitment": bytes.fromhex(qj["commitment"]),
         "chain_id": qj["chain_id"], "signer": bytes.fromhex(qj.get("signer", ""))}
    expect(q["da"] == 1 or len(q["signer"]) == SIGNER_SIZE, f"{cid}: signer")
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
            for k in ("rows", "pff_txs", "candidates", "blobs"):
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


def check_tail_rule(f: dict) -> int:
    """live_tail_rule: on each live block the Fibre txs are the last p of data.txs and are the PFF_NS units in order."""
    t = f["live_tail_rule"]
    expect(set(t) == {"description", "blocks"} and t["blocks"], "live_tail_rule keys")
    cases = {c["id"]: c for c in f["live"]}
    for b in t["blocks"]:
        where = f"live_tail_rule at {b['height']}"
        expect(set(b) == {"height", "case", "app_version", "txs", "fibre_from", "construct_check"}, f"{where}: keys")
        expect(b["app_version"] == str(APP_VERSION), f"{where}: app version")
        c = cases[b["case"]]
        r = next(x for x in c["records"] if x["height"] == b["height"])
        rec = A.decode_record(bytes.fromhex(r["record_hex"]))
        hf = parse_signed_header(rec["header"], rec["height"], c["trusted_headers"], "AB1")
        expect(app_version(hf) == APP_VERSION, f"{where}: header version.app")
        rows, _ = FA.parse_dah_proto(rec["dah"])
        nd = FA.decode_stream(rec["namespace_data"])
        FA.verify_rows(nd, rows, FA.PFF_NS)
        units = FA.reassemble([s for x in nd for s in x["shares"]])
        n, p = len(b["txs"]), len(units)
        expect(p >= 2 and n > p and b["fibre_from"] == str(n - p), f"{where}: n {n}, p {p}")
        for i, tx in enumerate(b["txs"]):
            expect(tx["index"] == str(i) and (tx["class"] == "fibre") == (i >= n - p), f"{where}: tx {i} class")
            if i >= n - p:
                u = units[i - (n - p)]
                expect(tx["sha256"] == hashlib.sha256(u).hexdigest() and tx["size"] == str(len(u)),
                       f"{where}: tx {i} is not PFF_NS unit {i - (n - p)}")
        expect(any(x["class"] != "fibre" for x in b["txs"]), f"{where}: no other tx")
        if "results" in rec:
            expect(len(json.loads(rec["results"])["txs_results"]) == n, f"{where}: n differs from the results count")
    return len(t["blocks"])


def check_live(f: dict) -> tuple:
    src = f["live_source"]
    expect({"fetched_at", "chain_id", "generator", "upstream", "endpoints", "note", "reads"} == set(src),
           "live_source keys")
    ids = [c["id"] for c in f["live"]]
    expect(len(ids) == len(set(ids)) and all(x in ids for x in LIVE), "section 15 live case names")
    rules = set()
    for c in f["live"]:
        rules |= check_case(c, src["chain_id"])
    expect({"AB4", "AB5", "AB6"} <= rules, f"live rules without a case: {rules}")
    das = {c["query"]["da"] for c in f["live"]}
    results = {x["result"] for c in f["live"] for x in c["expect"]["heights"]}
    expect(das == {"1", "2"} and results == {"absent", "present"}, "live coverage")
    return len(ids), check_tail_rule(f)


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
                      "synthetic", "live", "live_source", "live_tail_rule"}, "top-level keys")
    expect(f["pff_namespace"] == FA.PFF_NS.hex(), "PFF namespace")
    n_da_blob = check_commitment_code()
    ids = [c["id"] for c in f["synthetic"]]
    expect(len(ids) == len(set(ids)) and all(x in ids for x in SYNTHETIC), "section 15 synthetic case names")
    for c in f["synthetic"]:
        if "app_versions" in c:
            check_app_versions(c)
            continue
        for b in f["blocks"]:
            if "results_counts" in c and int(b["height"]) > min(int(x) for x in c["results_counts"]):
                continue  # the results of an earlier height differ, so later headers link another results hash
            expect(c["trusted_headers"].get(b["height"]) == b["header_hash"], f"{c['id']}: trusted {b['height']}")
    rules = set()
    for c in f["synthetic"]:
        rules |= check_case(c, f["chain_id"])
    expect({"AB1", "AB2", "AB3", "AB4", "AB5", "none"} <= rules, f"rules without a case: {rules}")
    results = {x["result"] for c in f["synthetic"] for x in c["expect"]["heights"]}
    expect(results == {"absent", "present", "unproven"}, "every per-height result")
    n_live, n_tail = check_live(f)
    n_refs = verify_refs(f)
    return (f"{len(ids)} synthetic cases, {sum(len(c['records']) for c in f['synthetic'])} records, {n_live} live cases "
            f"(Mocha, offline), {n_tail} live tail-rule blocks, {n_refs} verify refs, {n_da_blob} da_blob commitments")


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
    print(f"OK (absence.json, {REVISION}): {summary}; generator output identical")
    return 0


if __name__ == "__main__":
    sys.exit(main())
