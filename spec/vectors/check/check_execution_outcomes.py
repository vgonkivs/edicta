#!/usr/bin/env python3
"""Verifies spec/vectors/verifier/execution_outcomes.json (v1-draft.5).

- structure: format, revision, keys of every section and case, value sets,
  unique ids, decimal uints, lower-case hex;
- the defaults against the bank-send profile vectors (action bytes, chain id,
  commitment hash, the authorized transaction and its rail_ref);
- every transaction: its SHA-256, and for each one whether it hashes to the
  authorized rail_ref, is a canonical TxRaw (BX3) and carries the authorized
  body (BX5), as the cases need;
- the live fixture: SHA-256 of the transaction equals its rail_ref; each
  proof case is well-formed JSON in the transaction namespace shape (the
  proof expectations themselves come from the Go reference VerifyShareProof);
- the live result proof (RP1 to RP6), recomputed with its own code: the
  ExecTxResult leaves of the deterministic fields, the RFC 6962 root against
  last_results_hash of the header at H + 1, the header hashes (protobuf
  rebuilt from the JSON) and the link of H + 1 to H, the raw captures, the
  index from the live share proof (compact-share parse from share 0), the
  selected result, and every mutation;
- every case: an independent classifier of core 20.2.1 and bank-send 3.4
  recomputes execution, header_trust, verdict, exit code, cause, sentinel,
  inclusion, cross_check, proven_execution, the normative source results and
  the named sources;
- coverage: at least one case per cause; a pass only with a proven result;
  cross agreement without a result proof never passes.

Usage: python3 spec/vectors/check/check_execution_outcomes.py [--file FILE]
"""

from __future__ import annotations

import sys

sys.dont_write_bytecode = True

import base64
import hashlib
import json
import re
from pathlib import Path

from edicta import Reject
from check_fibre_cert import header_hash, merkle, put_uvarint
from profile_bank_send import _read_varint, action_decode, check_body

HERE = Path(__file__).resolve().parent
VECTORS = HERE.parent
FORMAT = "edicta-vectors/v0"
REVISION = "v1-draft.5"
PROFILE_REVISION = "bank-send-v0-draft.7"

UNCHECKED_CAUSES = {
    "tx_not_found": "railverify.ErrTxNotFound",
    "tx_source_unavailable": "railverify.ErrTxSourceUnavailable",
    "tx_hash_mismatch": "railverify.ErrTxHashMismatch",
    "tx_proof_invalid": "railverify.ErrTxProof",
    "header_above_checkpoint": None,
    "header_not_linking": None,
    "result_unproven": None,
    "results_root_mismatch": "railverify.ErrResultsProof",
    "result_index_unbound": None,
    "result_header_unreachable": None,
    "code_unproven": "railverify.ErrResultUnconfirmed",
    "height_unproven": None,
    "cross_disagree": None,
    "chain_config": "railverify.ErrChainConfig",
    "chain_unbound": None,
    "header_disagreement": None,
}
FAIL_CAUSES = {
    "rail_ref_malformed": "railverify.ErrRailRefMalformed",
    "tx_malformed": "railverify.ErrTxMalformed",
    "body_mismatch": "bankaction.ErrBodyMismatch",
    "chain_mismatch": "railverify.ErrChainMismatch",
    "height_not_after_anchor": None,
    "tx_failed": "railverify.ErrTxFailed",
}
CASE_KEYS = {"id", "description", "rules", "rail_ref_of", "sources", "expect"}
CASE_OPTIONAL = {"rail_ref", "checker_chain_id", "trusted_chain_id", "checkpoint_height", "header_at_tx_height",
                 "result_proof"}
EXPECT_KEYS = {"execution", "header_trust", "verdict", "exit", "cause", "sentinel", "inclusion", "result",
               "cross_check", "proven_execution", "source_results"}
RP_STATES = {"unavailable", "match_indexed", "match_rebuilt", "match_uniform", "match_unindexed",
             "match_rebuild_mismatch", "root_mismatch", "header_unreachable"}
RP_PROVEN = {"match_indexed", "match_rebuilt", "match_uniform"}
HEX = re.compile(r"^(?:[0-9a-f]{2})*$")
UINT = re.compile(r"^(0|[1-9][0-9]*)$")


class Failure(Exception):
    pass


def expect(cond: bool, msg: str):
    if not cond:
        raise Failure(msg)


def by_id(items: list, ident: str) -> dict:
    return next(x for x in items if x["id"] == ident)


def uint(s) -> int:
    expect(isinstance(s, str) and UINT.match(s) is not None, f"not a decimal uint string: {s!r}")
    return int(s)


def hexb(s) -> bytes:
    expect(isinstance(s, str) and HEX.match(s) is not None, f"not lower-case hex: {s!r}")
    return bytes.fromhex(s)


def txraw_body(raw: bytes):
    """BX3: fields 1 and 2 once each, then 3 at least once, all one-byte tags of wire type 2 with
    shortest lengths, in this order, nothing else. Returns body_bytes or None."""
    i, seen = 0, []
    try:
        while i < len(raw):
            tag = raw[i]
            if tag not in (0x0A, 0x12, 0x1A):
                return None
            n, j = _read_varint(raw, i + 1)
            if n > len(raw) - j:
                return None
            seen.append((tag >> 3, raw[j:j + n]))
            i = j + n
    except ValueError:
        return None
    nums = [s[0] for s in seen]
    if len(nums) < 3 or nums[0] != 1 or nums[1] != 2 or any(x != 3 for x in nums[2:]):
        return None
    return seen[0][1]


def lower_hex32(s: str) -> bool:
    return len(s) == 64 and all(c in "0123456789abcdef" for c in s)


def classify(c: dict, d: dict, txs: dict, msg: bytes, ch: bytes) -> dict:
    """Core 20.2.1 and bank-send 3.4 over the case setup."""
    rail_ref = c.get("rail_ref", txs[c["rail_ref_of"]]["sha256_hex"])
    action_chain = d["chain_id"]
    checker_chain = c.get("checker_chain_id", action_chain)
    trusted_chain = c.get("trusted_chain_id", action_chain)
    t = uint(c.get("checkpoint_height", d["checkpoint_height"]))
    anchor = uint(d["anchor_height"])
    hdr_state = c.get("header_at_tx_height", "trusted")
    cands = [s for s in c["sources"] if s["role"] in ("primary", "alternate")]
    cross = [s for s in c["sources"] if s["role"] == "cross"]
    results, names = {}, []
    out = {"header_trust": "pass", "inclusion": None, "result": None, "cross_check": None,
           "proven_execution": False}
    rpf = c.get("result_proof", {"state": "unavailable"})

    def done(execution, cause, **kw):
        sentinel = {**UNCHECKED_CAUSES, **FAIL_CAUSES}[cause] if cause != "none" else None
        o = {**out, **kw, "execution": execution, "cause": cause, "sentinel": sentinel, "source_results": results}
        o["verdict"] = {"pass": "valid", "fail": "invalid", "unchecked": "unchecked"}[execution]
        o["exit"] = str({"valid": 0, "invalid": 1, "unchecked": 2}[o["verdict"]])
        if names and execution == "unchecked":
            o["names_sources"] = list(names)
            o["suggest_other_source"] = True
        return o

    if not lower_hex32(rail_ref):
        for s in c["sources"]:
            results[s["name"]] = "not_asked"
        return done("fail", "rail_ref_malformed")
    if checker_chain != action_chain:
        for s in c["sources"]:
            results[s["name"]] = "not_asked"
        return done("unchecked", "chain_config")

    chosen, last = None, None
    for s in cands:
        a = s["answer"]
        if a["kind"] == "not_found":
            last = "tx_not_found"
        elif a["kind"] == "unavailable":
            last = "tx_source_unavailable"
        else:
            tx = bytes.fromhex(txs[a["tx"]]["tx_hex"])
            if hashlib.sha256(tx).hexdigest() != rail_ref:
                last = "tx_hash_mismatch"
            else:
                results[s["name"]] = "used"
                body = txraw_body(tx)
                if body is None:
                    return done("fail", "tx_malformed")
                try:
                    check_body(body, msg, ch)
                except Reject:
                    return done("fail", "body_mismatch")
                h = uint(a["height"])
                if h > t:
                    last = "header_above_checkpoint"
                elif hdr_state == "not_linking":
                    last = "header_not_linking"
                elif hdr_state == "cross_mismatch":
                    out["header_trust"] = "unchecked"
                    return done("unchecked", "header_disagreement")
                elif a["proof"] == "invalid":
                    last = "tx_proof_invalid"
                else:
                    chosen = (s, a, tx, h)
                    break
        results[s["name"]] = "set_aside"
        names.append(d["headers_source"] if last == "header_not_linking" else s["name"])
    if chosen is None:
        return done("unchecked", last)

    s, a, tx, h = chosen
    names = [s["name"]]
    proven = a["proof"] == "valid"
    out["inclusion"] = "proven" if proven else "node-attested"
    out["proven_execution"] = proven
    agg = []
    for x in cross:
        xa = x["answer"]
        if xa["kind"] != "tx" or hashlib.sha256(bytes.fromhex(txs[xa["tx"]]["tx_hex"])).hexdigest() != rail_ref:
            r = "fault"
        elif xa["height"] != a["height"] or xa["code"] != a["code"]:
            r = "disagree"
        else:
            r = "agree"
        results[x["name"]] = r
        agg.append(r)
        if r != "agree":
            names.append(x["name"])
    out["cross_check"] = ("off" if not agg else "mismatch" if "disagree" in agg else
                          "unavailable" if "fault" in agg else "pass")
    cross_pass = out["cross_check"] == "pass"
    result_proven = proven and rpf["state"] in RP_PROVEN
    code = uint(rpf["code"]) if result_proven else uint(a["code"])
    out["result"] = "proven" if result_proven else "cross-confirmed" if cross_pass else "node-attested"
    chain_differs = trusted_chain != action_chain
    if chain_differs and proven:
        return done("fail", "chain_mismatch")
    if h <= anchor and proven:
        return done("fail", "height_not_after_anchor")
    if result_proven and code != 0:
        return done("fail", "tx_failed")
    if chain_differs:
        return done("unchecked", "chain_unbound")
    if h <= anchor:
        return done("unchecked", "height_unproven")
    if out["cross_check"] == "mismatch" and not result_proven:
        return done("unchecked", "cross_disagree")
    if not result_proven:
        if code != 0:
            return done("unchecked", "code_unproven")
        cause = {"root_mismatch": "results_root_mismatch", "match_unindexed": "result_index_unbound",
                 "match_rebuild_mismatch": "result_index_unbound",
                 "header_unreachable": "result_header_unreachable"}.get(rpf["state"]) if proven else None
        return done("unchecked", cause or "result_unproven")
    names.clear()
    return done("pass", "none")


def pb_key(n: int, wt: int) -> bytes:
    return put_uvarint(n << 3 | wt)


def pb_int(n: int, v: int) -> bytes:
    return pb_key(n, 0) + put_uvarint(v & (2**64 - 1)) if v else b""


def pb_len(n: int, b: bytes, always: bool = False) -> bytes:
    return pb_key(n, 2) + put_uvarint(len(b)) + b if b or always else b""


def results_leaf(r: dict) -> bytes:
    expect(set(r) >= {"code", "data", "gas_wanted", "gas_used"}, "result keys")
    code = uint(r["code"])
    expect(code < 2**32, "code is uint32")
    gw, gu = int(r["gas_wanted"]), int(r["gas_used"])
    expect(-(2**63) <= gw < 2**63 and -(2**63) <= gu < 2**63, "gas is int64")
    return pb_int(1, code) + pb_len(2, base64.b64decode(r["data"])) + pb_int(5, gw) + pb_int(6, gu)


def rfc3339(s: str) -> tuple:
    m = re.fullmatch(r"(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?Z", s)
    expect(m is not None, f"time {s!r}")
    import calendar
    y, mo, d, hh, mi, ss = (int(m.group(i)) for i in range(1, 7))
    return calendar.timegm((y, mo, d, hh, mi, ss)), int((m.group(7) or "0").ljust(9, "0"))


def header_pb(h: dict) -> bytes:
    """CometBFT Header protobuf from the RPC JSON."""
    hx = bytes.fromhex
    sec, ns = rfc3339(h["time"])
    lb = h["last_block_id"]
    psh = pb_int(1, int(lb["parts"]["total"])) + pb_len(2, hx(lb["parts"]["hash"]))
    out = (pb_len(1, pb_int(1, int(h["version"]["block"])) + pb_int(2, int(h["version"].get("app", "0"))))
           + pb_len(2, h["chain_id"].encode()) + pb_int(3, int(h["height"]))
           + pb_len(4, pb_int(1, sec) + pb_int(2, ns), True)
           + pb_len(5, pb_len(1, hx(lb["hash"])) + pb_len(2, psh)))
    names = ["last_commit_hash", "data_hash", "validators_hash", "next_validators_hash", "consensus_hash",
             "app_hash", "last_results_hash", "evidence_hash", "proposer_address"]
    for i, k in enumerate(names):
        out += pb_len(6 + i, hx(h[k]))
    return out


def unit_index(shares: list, tx: bytes) -> int:
    """Units of a compact-share sequence that starts at share 0: count the units before tx."""
    data, first = b"", True
    for sh in shares:
        expect(len(sh) == 512 and sh[:29] == bytes(28) + b"\x01", "share namespace")
        info = sh[29]
        expect(info >> 1 == 0, "share version 0")
        expect(bool(info & 1) == first, "sequence start only in the first share")
        at = 30 + (4 if first else 0)
        seq_len = int.from_bytes(sh[30:34], "big") if first else None
        if first:
            total = seq_len
        data += sh[at + 4:]
        first = False
    data = data[:total]
    i, n = 0, 0
    while i < len(data):
        ln, i = _read_varint(data, i)
        if data[i:i + ln] == tx:
            return n
        i += ln
        n += 1
    raise Failure("tx is not a unit of the shares")


def check_result_proof(f: dict) -> int:
    rp = f["result_proof"]
    expect(set(rp) == {"description", "reads", "fetched_at", "same_answer_from", "not_served_by", "height",
                       "header_h", "header_h1", "results", "leaves_hex", "root_hex", "index", "selected",
                       "uniform_code", "mutations"}, "result_proof keys")
    for r in rp["reads"]:
        expect(r["url"].startswith("https://") and "?height=" in r["url"], "read url")
        raw = json.loads((VECTORS.parent.parent / r["file"]).read_text())
        if "block_results" in r["url"]:
            served = raw["result"]
            expect(served["height"] == rp["height"], "block_results height")
            expect([{k: str(x[k]) if k == "code" else (x.get(k) or "") if k == "data" else x[k]
                     for k in ("code", "data", "gas_wanted", "gas_used")} for x in served["txs_results"]]
                   == rp["results"], "results are the deterministic fields of the capture")
        else:
            expect(raw["result"]["header"] == rp["header_h1"], "header H + 1 is the capture")
    h, h1 = rp["header_h"], rp["header_h1"]
    expect(int(h1["height"]) == int(h["height"]) + 1 == uint(rp["height"]) + 1, "heights")
    expect(h["chain_id"] == h1["chain_id"] == f["live"]["chain_id"], "chain id")
    expect(h["data_hash"].lower() == f["live"]["data_hash_hex"], "header H is the live header")
    expect(header_hash(header_pb(h)).hex() == h1["last_block_id"]["hash"].lower(),
           "header H + 1 does not link to header H")
    header_hash(header_pb(h1))
    leaves = [results_leaf(r) for r in rp["results"]]
    expect([l.hex() for l in leaves] == rp["leaves_hex"], "leaves")
    root = merkle(leaves)
    expect(root.hex() == rp["root_hex"] == h1["last_results_hash"].lower(), "results root != last_results_hash")
    proof = json.loads(by_id(f["proofs"], "live_as_served")["proof_json"])
    expect(proof["row_proof"]["start_row"] == 0 and proof["share_proofs"][0].get("start", 0) == 0,
           "the live proof does not start at share 0")
    idx = unit_index([base64.b64decode(x) for x in proof["data"]], hexb(f["live"]["tx_hex"]))
    expect(str(idx) == rp["index"]["value"] == rp["selected"]["index"], "index")
    expect(rp["selected"]["code"] == rp["results"][idx]["code"] == f["live"]["code"]
           and rp["selected"]["leaf_hex"] == rp["leaves_hex"][idx], "selected result")
    codes = {r["code"] for r in rp["results"]}
    expect(rp["uniform_code"] == (codes.pop() if len(codes) == 1 else None), "uniform code")
    for m in rp["mutations"]:
        got = merkle([results_leaf(r) for r in m["results"]]) == root
        expect(m["expect"] == ("match" if got else "mismatch"), f"result mutation {m['id']}")
    expect({m["expect"] for m in rp["mutations"]} == {"match", "mismatch"}, "mutations cover both outcomes")
    return len(rp["mutations"])


def check_proofs(f: dict) -> int:
    live = f["live"]
    expect(set(live) == {"source", "provenance", "chain_id", "height", "rail_ref", "code", "tx_hex", "data_hash_hex"}, "live keys")
    tx = hexb(live["tx_hex"])
    expect(hashlib.sha256(tx).hexdigest() == live["rail_ref"], "live: tx does not hash to rail_ref")
    expect(len(hexb(live["data_hash_hex"])) == 32 and uint(live["height"]) > 0 and uint(live["code"]) == 0, "live")
    tx_ns = base64.b64encode(bytes(27) + b"\x01").decode()
    seen = set()
    for p in f["proofs"]:
        expect(set(p) == {"id", "description", "tx_hex", "proof_json", "data_hash_hex", "expect"}, f"{p.get('id')}: keys")
        expect(p["expect"] in ("proven", "railverify.ErrTxProof"), f"{p['id']}: expect")
        pj = json.loads(p["proof_json"])
        expect(set(pj) == {"data", "share_proofs", "namespace_id", "row_proof", "namespace_version"},
               f"{p['id']}: proof shape")
        expect(len(hexb(p["data_hash_hex"])) == 32, f"{p['id']}: data hash")
        same = hexb(p["tx_hex"]) == tx and p["proof_json"] == by_id(f["proofs"], "live_as_served")["proof_json"] \
            and p["data_hash_hex"] == live["data_hash_hex"]
        expect(same == (p["expect"] == "proven"), f"{p['id']}: only the unmodified answer is proven")
        if p["id"] == "live_user_namespace":
            expect(pj["namespace_id"] != tx_ns, "live_user_namespace keeps the namespace")
        elif p["expect"] == "proven":
            expect(pj["namespace_id"] == tx_ns and pj["namespace_version"] == 0, "live namespace")
        seen.add(p["id"])
    expect(len(seen) == len(f["proofs"]) and "live_as_served" in seen, "proof ids")
    return len(seen)


def check(path: Path) -> str:
    f = json.loads(path.read_text())
    expect(f.get("format") == FORMAT and f.get("revision") == REVISION, "format or revision")
    expect(f.get("profile") == "bank-send" and f.get("profile_revision") == PROFILE_REVISION, "profile")
    expect(set(f) == {"format", "revision", "profile", "profile_revision", "generator", "description", "defaults",
                      "outcomes", "txs", "live", "proofs", "result_proof", "cases"}, "top-level keys")
    expect(f["outcomes"] == {"pass": {"verdict": "valid", "exit": "0"}, "fail": {"verdict": "invalid", "exit": "1"},
                             "unchecked": {"verdict": "unchecked", "exit": "2"}}, "outcome map")
    d = f["defaults"]
    prof = VECTORS / "profiles" / "bank-send"
    action = by_id(json.loads((prof / "action.json").read_text())["cases"], "action_minimal_mocha")
    txf = json.loads((prof / "tx.json").read_text())
    signed = by_id(txf["signed"], "signed_minimal_mocha")
    expect(d["action_cbor_hex"] == action["cbor_hex"] and d["chain_id"] == action["input"]["chain_id"], "defaults: action")
    a = action_decode(hexb(d["action_cbor_hex"]))
    expect(a["chain_id"] == d["chain_id"], "defaults: action chain id")
    msg, ch = a["msg"], hexb(d["commitment_hash_hex"])
    expect(len(ch) == 32 and ch.hex() == by_id(txf["body"], "body_minimal")["commitment_hash_hex"], "defaults: hash")
    anchor, txh, t = uint(d["anchor_height"]), uint(d["tx_height"]), uint(d["checkpoint_height"])
    expect(anchor < txh <= t, "defaults: heights")

    txs = f["txs"]
    for k, v in txs.items():
        expect(set(v) == {"description", "tx_hex", "sha256_hex"}, f"tx {k}: keys")
        expect(hashlib.sha256(hexb(v["tx_hex"])).hexdigest() == v["sha256_hex"], f"tx {k}: sha256")
    expect(txs["authorized"]["tx_hex"] == signed["tx_raw_hex"]
           and txs["authorized"]["sha256_hex"] == signed["rail_ref"], "authorized tx is signed_minimal_mocha")
    for k, v in txs.items():
        body = txraw_body(hexb(v["tx_hex"]))
        ok = body is not None
        if ok:
            try:
                check_body(body, msg, ch)
            except Reject:
                ok = False
        expect(ok == (k in ("authorized", "flipped")), f"tx {k}: BX3/BX5 status")

    n_proofs = check_proofs(f)
    n_rp = check_result_proof(f)

    ids, causes = set(), set()
    for c in f["cases"]:
        cid = c.get("id")
        expect(CASE_KEYS <= set(c) <= CASE_KEYS | CASE_OPTIONAL, f"{cid}: keys")
        expect(cid not in ids, f"duplicate id {cid}")
        ids.add(cid)
        expect(c["rail_ref_of"] in txs, f"{cid}: rail_ref_of")
        expect(c.get("header_at_tx_height", "trusted") in ("trusted", "not_linking", "cross_mismatch"), f"{cid}: header")
        rpf = c.get("result_proof", {"state": "unavailable"})
        expect(rpf["state"] in RP_STATES and set(rpf) == ({"state", "code"} if rpf["state"] in RP_PROVEN
                                                          else {"state"}), f"{cid}: result_proof")
        names = [s["name"] for s in c["sources"]]
        expect(len(names) == len(set(names)), f"{cid}: source names repeat")
        roles = [s["role"] for s in c["sources"]]
        expect(roles and roles[0] == "primary" and roles.count("primary") == 1
               and all(r in ("primary", "alternate", "cross") for r in roles), f"{cid}: roles")
        for s in c["sources"]:
            ans = s["answer"]
            expect(ans["kind"] in ("tx", "not_found", "unavailable"), f"{cid}: answer kind")
            if ans["kind"] == "tx":
                expect(set(ans) == {"kind", "tx", "height", "code", "proof"} and ans["tx"] in txs
                       and ans["proof"] in ("valid", "invalid", "none"), f"{cid}: tx answer")
                uint(ans["height"]), uint(ans["code"])
            else:
                expect(set(ans) == {"kind"}, f"{cid}: answer keys")
        e = c["expect"]
        expect(EXPECT_KEYS <= set(e) <= EXPECT_KEYS | {"names_sources", "suggest_other_source"}, f"{cid}: expect keys")
        expect(e["execution"] in ("pass", "fail", "unchecked"), f"{cid}: execution")
        expect(e["cause"] in UNCHECKED_CAUSES if e["execution"] == "unchecked" else
               e["cause"] in FAIL_CAUSES if e["execution"] == "fail" else e["cause"] == "none", f"{cid}: cause class")
        got = classify(c, d, txs, msg, ch)
        for k in sorted(set(e) | set(got)):
            if k == "source_results":
                for name, r in e[k].items():
                    expect(got[k].get(name) == r, f"{cid}: source {name}: {r} != {got[k].get(name)}")
            else:
                expect(e.get(k) == got.get(k), f"{cid}: {k}: vector {e.get(k)!r}, classifier {got.get(k)!r}")
        causes.add(e["cause"])
    missing = (set(UNCHECKED_CAUSES) | set(FAIL_CAUSES) | {"none"}) - causes
    expect(not missing, f"causes without a case: {sorted(missing)}")
    for e in (c["expect"] for c in f["cases"]):
        expect(e["verdict"] != "invalid" or e["execution"] == "fail", "invalid only from an execution fail")
        expect(e["execution"] != "pass" or (e["result"] == "proven" and e["inclusion"] == "proven"),
               "pass only with proven inclusion and a proven result")
    expect(any(c["expect"]["result"] == "cross-confirmed" and c["expect"]["execution"] == "unchecked"
               and c["expect"]["inclusion"] == "node-attested" for c in f["cases"]),
           "a cross-confirmed case without inclusion proof that stays unchecked")
    expect(any(c["expect"]["result"] == "cross-confirmed" and c["expect"]["execution"] == "unchecked"
               and c["expect"]["inclusion"] == "proven" for c in f["cases"]),
           "a cross-confirmed case with proven inclusion that stays unchecked")
    expect(any(c.get("result_proof", {}).get("state") == "match_rebuilt" and c["expect"]["execution"] == "pass"
               for c in f["cases"]), "an index bound by the rebuilt square")
    return f"{len(f['cases'])} cases, {n_proofs} proofs, {n_rp} result-proof mutations, {len(txs)} txs"


def main() -> int:
    path = VECTORS / "verifier" / "execution_outcomes.json"
    if "--file" in sys.argv:
        path = Path(sys.argv[sys.argv.index("--file") + 1]).resolve()
    try:
        summary = check(path)
    except (Failure, Reject, KeyError, StopIteration, ValueError) as e:
        print(f"FAIL (execution_outcomes.json): {type(e).__name__}: {e}", file=sys.stderr)
        return 1
    print(f"OK (execution_outcomes.json, {REVISION}): {summary}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
