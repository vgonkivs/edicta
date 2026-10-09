#!/usr/bin/env python3
"""Writes spec/vectors/verifier/execution_outcomes.json (v1-draft.5).

The outcome table of the execution check (core section 20.2, bank-send
section 3.4): one case per cause of `unchecked` and per cause of `fail`, and
the passing baselines. Transactions are the bank-send profile vectors
(`action_minimal_mocha`, `signed_minimal_mocha`) and mutations of them; the
inclusion proof forms are the live Mocha answer of bank-send section 6
(`celestia/railverify/testdata`), copied in verbatim so that the vector file
stands alone.

Expectations are written out per case. check_execution_outcomes.py recomputes
them with its own classifier of the rule.

The result proof section is live Mocha block 1442606 (spec/vectors/verifier/live/,
read with plain HTTP GET on 2026-10-07; nothing was submitted).

Usage: python3 spec/vectors/check/gen_execution_outcomes.py
"""

from __future__ import annotations

import sys

sys.dont_write_bytecode = True

import base64
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
VECTORS = HERE.parent
REPO = VECTORS.parent.parent
OUT = VECTORS / "verifier" / "execution_outcomes.json"
LIVE_TX = REPO / "celestia" / "railverify" / "testdata" / "tx_prove_1442606.json"
LIVE_HEADER = REPO / "celestia" / "railverify" / "testdata" / "header_1442606.json"

ANCHOR = 6543200
TX_H = 6543290
T = 6543300
RAIL_REF = ""
LIVE_RESULTS = VECTORS / "verifier" / "live" / "block_results_1442606.json"
LIVE_NEXT_HEADER = VECTORS / "verifier" / "live" / "header_1442607.json"


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def field(num: int, v: bytes) -> bytes:
    assert len(v) < 1 << 14
    n = len(v)
    ln = bytes([n]) if n < 0x80 else bytes([(n & 0x7F) | 0x80, n >> 7])
    return bytes([(num << 3) | 2]) + ln + v


def split_txraw(raw: bytes) -> list:
    out, i = [], 0
    while i < len(raw):
        tag = raw[i]
        i += 1
        n, shift = 0, 0
        while True:
            c = raw[i]
            i += 1
            n |= (c & 0x7F) << shift
            shift += 7
            if c < 0x80:
                break
        out.append((tag >> 3, raw[i:i + n]))
        i += n
    return out


def by_id(items: list, ident: str) -> dict:
    return next(x for x in items if x["id"] == ident)


def flip_b64(s: str, at: int) -> str:
    b = bytearray(base64.b64decode(s))
    b[at] ^= 0x01
    return base64.b64encode(bytes(b)).decode()


def uvarint(v: int) -> bytes:
    out = bytearray()
    while v >= 0x80:
        out.append((v & 0x7F) | 0x80)
        v >>= 7
    out.append(v)
    return bytes(out)


def exec_tx_result(r: dict) -> bytes:
    """gogoproto ExecTxResult.Marshal of the deterministic fields only (celestia-core
    types.NewResults): 1 code, 2 data, 5 gas_wanted, 6 gas_used; zero values absent."""
    out = b""
    code, data = int(r["code"]), base64.b64decode(r.get("data") or "")
    gw, gu = int(r["gas_wanted"]), int(r["gas_used"])
    if code:
        out += b"\x08" + uvarint(code)
    if data:
        out += b"\x12" + uvarint(len(data)) + data
    if gw:
        out += b"\x28" + uvarint(gw & (2**64 - 1))
    if gu:
        out += b"\x30" + uvarint(gu & (2**64 - 1))
    return out


def rfc6962(items: list) -> bytes:
    if not items:
        return hashlib.sha256(b"").digest()
    if len(items) == 1:
        return hashlib.sha256(b"\x00" + items[0]).digest()
    k = 1
    while k * 2 < len(items):
        k *= 2
    return hashlib.sha256(b"\x01" + rfc6962(items[:k]) + rfc6962(items[k:])).digest()


def result_proof_live(hdr: dict, proof: dict) -> dict:
    served = json.loads(LIVE_RESULTS.read_text())["result"]
    nxt = json.loads(LIVE_NEXT_HEADER.read_text())["result"]["header"]
    assert served["height"] == hdr["height"] and int(nxt["height"]) == int(hdr["height"]) + 1
    det = [{"code": str(r["code"]), "data": r.get("data") or "", "gas_wanted": r["gas_wanted"],
            "gas_used": r["gas_used"]} for r in served["txs_results"]]
    leaves = [exec_tx_result(r) for r in det]
    root = rfc6962(leaves).hex()
    assert root == nxt["last_results_hash"].lower()
    assert proof["row_proof"]["start_row"] == 0 and proof["share_proofs"][0].get("start", 0) == 0

    def variant(f):
        rs = json.loads(json.dumps(det))
        f(rs)
        return rs

    def setk(i, k, v):
        def go(rs):
            rs[i][k] = v
        return go

    def swap(rs):
        rs[0], rs[1] = rs[1], rs[0]

    def extra(rs):
        rs.append(dict(rs[-1]))

    def noise(rs):
        for r in rs:
            r.update({"log": "ignored", "info": "ignored", "codespace": "sdk", "events": [{"type": "x"}]})

    muts = [
        ("as_served", "The deterministic fields as served.", det, True),
        ("non_deterministic_fields_ignored", "log, info, codespace and events set on every result: not hashed.",
         variant(noise), True),
        ("code_changed", "Result 1 reports code 5.", variant(setk(1, "code", "5")), False),
        ("selected_code_changed", "The selected result 0 reports code 11 (out of gas).",
         variant(setk(0, "code", "11")), False),
        ("gas_used_changed", "Result 4 reports gas_used one higher.",
         variant(setk(4, "gas_used", str(int(det[4]["gas_used"]) + 1))), False),
        ("data_dropped", "Result 0 without data.", variant(setk(0, "data", "")), False),
        ("swapped", "Results 0 and 1 swapped.", variant(swap), False),
        ("dropped_last", "The last result missing.", det[:-1], False),
        ("extra_result", "A copy of the last result appended.", variant(extra), False),
    ]
    return {
        "description": ("Result proof RP1 to RP6 on live Mocha block 1442606, whose tx 0 is the live tx of the "
                        "proofs section. Read-only HTTP GET only; nothing was submitted."),
        "reads": [
            {"url": "https://celestia-testnet-rpc.itrocket.net/block_results?height=1442606",
             "file": "spec/vectors/verifier/live/block_results_1442606.json"},
            {"url": "https://celestia-testnet-rpc.itrocket.net/header?height=1442607",
             "file": "spec/vectors/verifier/live/header_1442607.json"},
        ],
        "fetched_at": "2026-10-07T10:48:36Z",
        "same_answer_from": ["https://rpc-1.testnet.celestia.nodes.guru",
                             "https://public-endpoint.celestia-mocha.quiknode.pro"],
        "not_served_by": {"https://rpc-mocha.pops.one": "node is not persisting finalize block responses"},
        "height": hdr["height"],
        "header_h": hdr,
        "header_h1": nxt,
        "results": det,
        "leaves_hex": [l.hex() for l in leaves],
        "root_hex": root,
        "index": {"value": "0", "why": ("The live proof's first share is share 0 of the square (start_row 0, "
                                         "start 0), and the tx is the first unit parsed from it.")},
        "selected": {"index": "0", "code": det[0]["code"], "leaf_hex": leaves[0].hex()},
        "uniform_code": "0" if all(r["code"] == "0" for r in det) else None,
        "mutations": [{"id": i, "description": d, "results": r, "expect": "match" if m else "mismatch"}
                      for i, d, r, m in muts],
    }


def tx_answer(tx: str = "authorized", height: int = TX_H, code: int = 0, proof: str = "valid") -> dict:
    return {"kind": "tx", "tx": tx, "height": str(height), "code": str(code), "proof": proof}


def src(name: str, role: str, answer: dict) -> dict:
    return {"name": name, "role": role, "answer": answer}


def rp(state: str, code: int | None = None) -> dict:
    out = {"state": state}
    if code is not None:
        out["code"] = str(code)
    return out


def expect(execution: str, cause: str, *, sentinel=None, header_trust="pass", inclusion=None, result=None,
           cross_check=None, proven=False, results=None, names=None) -> dict:
    verdict = {"pass": "valid", "fail": "invalid", "unchecked": "unchecked"}[execution]
    if header_trust == "unchecked" and verdict == "valid":
        verdict = "unchecked"
    e = {
        "execution": execution, "header_trust": header_trust, "verdict": verdict,
        "exit": str({"valid": 0, "invalid": 1, "unchecked": 2}[verdict]),
        "cause": cause, "sentinel": sentinel, "inclusion": inclusion, "result": result,
        "cross_check": cross_check, "proven_execution": proven, "source_results": results or {},
    }
    if names is not None:
        e["names_sources"] = names
        e["suggest_other_source"] = True
    return e


def case(ident: str, description: str, rules: list, sources: list, ex: dict, **setup) -> dict:
    c = {"id": ident, "description": description, "rules": rules}
    c["rail_ref_of"] = setup.pop("rail_ref_of", "authorized")
    for k in ("rail_ref", "checker_chain_id", "trusted_chain_id", "checkpoint_height", "header_at_tx_height",
              "result_proof"):
        if k in setup:
            c[k] = setup.pop(k)
    assert not setup, setup
    c["sources"] = sources
    c["expect"] = ex
    return c


def build() -> dict:
    action = by_id(json.loads((VECTORS / "profiles/bank-send/action.json").read_text())["cases"], "action_minimal_mocha")
    txf = json.loads((VECTORS / "profiles/bank-send/tx.json").read_text())
    signed = by_id(txf["signed"], "signed_minimal_mocha")
    body = by_id(txf["body"], "body_minimal")
    other_memo = by_id(txf["body_reject"], "body_memo_other_hash")
    other_msg = by_id(txf["body_reject"], "body_other_msg")
    assert signed["body_ref"] == "body_minimal" and other_memo["commitment_hash_hex"] == body["commitment_hash_hex"]

    raw = bytes.fromhex(signed["tx_raw_hex"])
    parts = split_txraw(raw)
    assert [p[0] for p in parts] == [1, 2, 3] and parts[0][1].hex() == body["body_hex"]
    _, auth = parts[1]
    _, sig = parts[2]
    flipped = bytearray(raw)
    flipped[-1] ^= 0x01
    dup_body = field(1, bytes.fromhex(other_msg["body_hex"])) + raw
    memo_tx = field(1, bytes.fromhex(other_memo["body_hex"])) + field(2, auth) + field(3, sig)
    txs = {
        "authorized": ("The signed minimal transaction of the profile vectors: the authorized action.", raw),
        "flipped": ("The authorized transaction with its last byte changed: it does not hash to the "
                    "authorized rail_ref.", bytes(flipped)),
        "duplicate_body": ("body_bytes twice (another MsgSend first, the authorized body second), then the "
                           "authorized auth_info and signature. The chain's decoder keeps the last body; BX3 "
                           "refuses the repeat.", dup_body),
        "other_memo": ("A canonical TxRaw whose body has the authorized MsgSend but another commitment hash "
                       "in the memo (tx.json body_memo_other_hash), with the authorized auth_info and "
                       "signature.", memo_tx),
    }
    assert sha(raw) == signed["rail_ref"]
    global RAIL_REF
    RAIL_REF = signed["rail_ref"]

    live = json.loads(LIVE_TX.read_text())["result"]
    hdr = json.loads(LIVE_HEADER.read_text())["result"]["header"]
    live_tx = base64.b64decode(live["tx"])
    assert sha(live_tx) == live["hash"].lower() and live["height"] == hdr["height"]
    proof = live["proof"]
    data_hash = hdr["data_hash"].lower()

    def pj(p: dict) -> str:
        return json.dumps(p, separators=(",", ":"))

    def mut(f) -> dict:
        p = json.loads(json.dumps(proof))
        f(p)
        return p

    def edit(path, f):
        def go(p):
            o = p
            for k in path[:-1]:
                o = o[k]
            o[path[-1]] = f(o[path[-1]])
        return go

    flipped_live = bytearray(live_tx)
    flipped_live[len(flipped_live) // 2] ^= 0x01
    proofs = [
        ("live_as_served", "The proof as the node served it, against data_hash of the trusted header at 1442606.",
         live_tx, proof, data_hash, "proven"),
        ("live_other_data_hash", "The same proof against another 32-byte root (the header's app_hash): the row "
         "proof does not reach it.", live_tx, proof, hdr["app_hash"].lower(), "railverify.ErrTxProof"),
        ("live_nmt_node_flipped", "One byte of the first NMT node of the share proof changed.", live_tx,
         mut(edit(["share_proofs", 0, "nodes", 0], lambda s: flip_b64(s, 40))), data_hash, "railverify.ErrTxProof"),
        ("live_row_root_flipped", "One byte of the row root changed.", live_tx,
         mut(edit(["row_proof", "row_roots", 0], lambda s: s[:-1] + ("0" if s[-1] != "0" else "1"))), data_hash,
         "railverify.ErrTxProof"),
        ("live_share_flipped", "One byte inside the transaction's unit in the share changed.", live_tx,
         mut(edit(["data", 0], lambda s: flip_b64(s, 120))), data_hash, "railverify.ErrTxProof"),
        ("live_other_tx", "A valid proof, but the transaction checked is the live one with one byte changed: no "
         "unit in the shares equals it.", bytes(flipped_live), proof, data_hash, "railverify.ErrTxProof"),
        ("live_user_namespace", "namespace_id changed to a user namespace (last byte 0x02).", live_tx,
         mut(edit(["namespace_id"], lambda s: base64.b64encode(base64.b64decode(s)[:-1] + b"\x02").decode())),
         data_hash, "railverify.ErrTxProof"),
        ("live_row_index", "The row proof claims index 1 (start_row stays 0): not the row it proves.", live_tx,
         mut(edit(["row_proof", "proofs", 0, "index"], lambda s: "1")), data_hash, "railverify.ErrTxProof"),
        ("live_total_not_4k", "The row proof's total is 96 (k = 24 is not a power of two).", live_tx,
         mut(edit(["row_proof", "proofs", 0, "total"], lambda s: "96")), data_hash, "railverify.ErrTxProof"),
    ]

    a, b, c, x, y = "tx-a.example", "tx-b.example", "tx-c.example", "cross-x.example", "cross-y.example"
    used = "used"
    ok0 = rp("match_indexed", 0)
    cases = [
        case("pass_proven_single_source", "One tx source. The proof verifies against the trusted header at H, "
             "and the block H results recompute to last_results_hash of the trusted header at H + 1. The "
             "share proof starts at share 0, which binds the index. Everything is proven; no cross source is "
             "needed.", ["BX6", "RP1", "RP5", "EX9"],
             [src(a, "primary", tx_answer())],
             expect("pass", "none", inclusion="proven", result="proven", cross_check="off", proven=True,
                    results={a: used}), result_proof=ok0),
        case("pass_proven_uniform_results", "The share proof does not start at share 0, so the index is not "
             "bound, but every result of block H has code 0: any tx of block H succeeded.", ["RP5"],
             [src(a, "primary", tx_answer())],
             expect("pass", "none", inclusion="proven", result="proven", cross_check="off", proven=True,
                    results={a: used}), result_proof=rp("match_uniform", 0)),
        case("pass_proven_index_rebuilt", "The tx is not at share 0, so its share proof does not bind the index, "
             "and the results of block H have different codes. A source serves the txs of block H; rebuilt as "
             "ProcessProposal builds the square, they give data_hash of the trusted header at H, and the tx is a "
             "normal tx at a known index. That binds the index.", ["RP5", "RP6", "EX9"],
             [src(a, "primary", tx_answer())],
             expect("pass", "none", inclusion="proven", result="proven", cross_check="off", proven=True,
                    results={a: used}), result_proof=rp("match_rebuilt", 0)),
        case("pass_after_alternate", "The primary does not know the tx; the alternate does, with a proof, and "
             "the result is proven.", ["BX1", "EX10", "RP1"],
             [src(a, "primary", {"kind": "not_found"}), src(b, "alternate", tx_answer())],
             expect("pass", "none", inclusion="proven", result="proven", cross_check="off", proven=True,
                    results={a: "set_aside", b: used}), result_proof=ok0),
        case("pass_proven_cross_contradicts", "Everything is proven; a cross source reports code 5. A source "
             "that contradicts proven facts is reported and does not change the outcome.", ["EX6", "RP6"],
             [src(a, "primary", tx_answer()), src(x, "cross", tx_answer(code=5, proof="none"))],
             expect("pass", "none", inclusion="proven", result="proven", cross_check="mismatch", proven=True,
                    results={a: used, x: "disagree"}), result_proof=ok0),

        case("unchecked_tx_not_found", "The only tx source answers not found.", ["BX1", "EX10"],
             [src(a, "primary", {"kind": "not_found"})],
             expect("unchecked", "tx_not_found", sentinel="railverify.ErrTxNotFound", results={a: "set_aside"},
                    names=[a])),
        case("unchecked_tx_source_unavailable", "The only tx source fails (transport error, 5xx, 429 after "
             "retries).", ["BX1", "EX10"],
             [src(a, "primary", {"kind": "unavailable"})],
             expect("unchecked", "tx_source_unavailable", sentinel="railverify.ErrTxSourceUnavailable",
                    results={a: "set_aside"}, names=[a])),
        case("unchecked_tx_hash_mismatch", "The source answers with bytes that do not hash to rail_ref. They "
             "are not the transaction the receipt names, so they say nothing about the execution.",
             ["BX2", "EX10"],
             [src(a, "primary", tx_answer(tx="flipped"))],
             expect("unchecked", "tx_hash_mismatch", sentinel="railverify.ErrTxHashMismatch",
                    results={a: "set_aside"}, names=[a])),
        case("unchecked_tx_proof_invalid", "The bytes hash to rail_ref and the body is the authorized one, but "
             "the proof fails BX6 against the trusted header.", ["BX6", "EX10"],
             [src(a, "primary", tx_answer(proof="invalid"))],
             expect("unchecked", "tx_proof_invalid", sentinel="railverify.ErrTxProof",
                    results={a: "set_aside"}, names=[a])),
        case("unchecked_all_candidates_fault", "Primary bytes do not hash; the alternate's proof fails. Both "
             "sources are named with their faults.", ["BX2", "BX6", "EX10"],
             [src(a, "primary", tx_answer(tx="flipped")), src(b, "alternate", tx_answer(proof="invalid"))],
             expect("unchecked", "tx_proof_invalid", sentinel="railverify.ErrTxProof",
                    results={a: "set_aside", b: "set_aside"}, names=[a, b])),
        case("unchecked_header_above_checkpoint", "The tx height is above the checkpoint T and no wait (OH4, "
             "MAY) reaches it.", ["EX5", "OH4"],
             [src(a, "primary", tx_answer(height=T + 10))],
             expect("unchecked", "header_above_checkpoint", results={a: "set_aside"}, names=[a]),
             checkpoint_height=str(T)),
        case("unchecked_header_not_linking", "The header the headers source serves at the tx height does not "
             "link to the trusted chain: that source's fault (OH6).", ["EX5", "OH6"],
             [src(a, "primary", tx_answer())],
             expect("unchecked", "header_not_linking", results={a: "set_aside"}, names=["headers-rpc"]),
             header_at_tx_height="not_linking"),
        case("unchecked_header_disagreement", "A header cross-check source gives another hash at the tx height "
             "than the trusted chain. Nothing tells whether the trusted header, the cross source or a fork is at "
             "fault, and none of them is about the decision: header_trust and execution are unchecked, with the "
             "distinct reason.", ["OH7", "EX5"],
             [src(a, "primary", tx_answer())],
             expect("unchecked", "header_disagreement", header_trust="unchecked", results={a: used}),
             header_at_tx_height="cross_mismatch", result_proof=ok0),
        case("unchecked_result_unproven_single_source", "Proof verifies, code 0, no result proof (the sources "
             "do not serve block_results) and no cross source. The code rests on one source: never a pass.",
             ["EX9", "RP1"],
             [src(a, "primary", tx_answer())],
             expect("unchecked", "result_unproven", inclusion="proven", result="node-attested", cross_check="off",
                    proven=True, results={a: used}, names=[a])),
        case("unchecked_result_root_mismatch", "The block H results do not recompute to last_results_hash of "
             "the trusted header at H + 1: that results source's fault.", ["RP3", "RP4"],
             [src(a, "primary", tx_answer())],
             expect("unchecked", "results_root_mismatch", sentinel="railverify.ErrResultsProof",
                    inclusion="proven", result="node-attested", cross_check="off", proven=True, results={a: used},
                    names=[a]), result_proof=rp("root_mismatch")),
        case("unchecked_result_index_unbound", "The results root matches, but the share proof does not start "
             "at share 0 and the results have different codes, so nothing binds which result is this tx's.",
             ["RP5"],
             [src(a, "primary", tx_answer())],
             expect("unchecked", "result_index_unbound", inclusion="proven", result="node-attested",
                    cross_check="off", proven=True, results={a: used}, names=[a]),
             result_proof=rp("match_unindexed")),
        case("unchecked_result_cross_confirmed_only", "No inclusion proof and no result proof; two cross sources "
             "agree on height, bytes and code 0. Agreement of sources is reported only: it never gives pass. Until "
             "v0-draft.27 this was the interim cross-confirmed pass.", ["EX9", "EO3", "BX8"],
             [src(a, "primary", tx_answer(proof="none")), src(x, "cross", tx_answer(proof="none")),
              src(y, "cross", tx_answer(proof="none"))],
             expect("unchecked", "result_unproven", inclusion="node-attested", result="cross-confirmed",
                    cross_check="pass", results={a: used, x: "agree", y: "agree"}, names=[a])),
        case("unchecked_result_cross_confirmed_inclusion_proven", "Inclusion is proven, no source serves "
             "block_results, and the cross source agrees on code 0. Proven inclusion does not make agreement "
             "proof of the result.", ["EX9", "EO3", "RP1"],
             [src(a, "primary", tx_answer()), src(x, "cross", tx_answer(proof="none"))],
             expect("unchecked", "result_unproven", inclusion="proven", result="cross-confirmed",
                    cross_check="pass", proven=True, results={a: used, x: "agree"}, names=[a])),
        case("unchecked_result_index_rebuild_mismatch", "The results root matches and the codes differ. The tx is "
             "not at share 0, and the block txs a source serves do not rebuild to data_hash of the trusted header "
             "at H: that source's fault, and nothing else binds the index.", ["RP5"],
             [src(a, "primary", tx_answer())],
             expect("unchecked", "result_index_unbound", inclusion="proven", result="node-attested",
                    cross_check="off", proven=True, results={a: used}, names=[a]),
             result_proof=rp("match_rebuild_mismatch")),
        case("unchecked_result_header_unreachable", "The tx is at T, so the header at H + 1 that carries "
             "last_results_hash is above the checkpoint.", ["RP4", "OH4"],
             [src(a, "primary", tx_answer(height=T))],
             expect("unchecked", "result_header_unreachable", inclusion="proven", result="node-attested",
                    cross_check="off", proven=True, results={a: used}, names=[a]),
             checkpoint_height=str(T), result_proof=rp("header_unreachable")),
        case("unchecked_result_no_proof_of_inclusion", "The results root matches, but the tx carries no "
             "inclusion proof: nothing binds the tx to block H, so the results of H say nothing about it.",
             ["RP2", "EX9"],
             [src(a, "primary", tx_answer(proof="none"))],
             expect("unchecked", "result_unproven", inclusion="node-attested", result="node-attested",
                    cross_check="off", results={a: used}, names=[a]), result_proof=ok0),
        case("unchecked_result_cross_unavailable", "No result proof; the one cross source is unreachable.",
             ["EX9", "BX8"],
             [src(a, "primary", tx_answer()), src(x, "cross", {"kind": "unavailable"})],
             expect("unchecked", "result_unproven", inclusion="proven", result="node-attested",
                    cross_check="unavailable", proven=True, results={a: used, x: "fault"}, names=[a, x])),
        case("unchecked_code_unproven", "The source reports code 5; no result proof and no cross source.",
             ["EX9"],
             [src(a, "primary", tx_answer(code=5))],
             expect("unchecked", "code_unproven", sentinel="railverify.ErrResultUnconfirmed", inclusion="proven",
                    result="node-attested", cross_check="off", proven=True, results={a: used}, names=[a])),
        case("unchecked_code_cross_confirmed_only", "Code 5, and the cross source agrees. Agreement of sources "
             "is not verified data, so a failed result needs the result proof for invalid.", ["EX9", "EO1"],
             [src(a, "primary", tx_answer(code=5)), src(x, "cross", tx_answer(code=5, proof="none"))],
             expect("unchecked", "code_unproven", sentinel="railverify.ErrResultUnconfirmed", inclusion="proven",
                    result="cross-confirmed", cross_check="pass", proven=True, results={a: used, x: "agree"},
                    names=[a])),
        case("unchecked_height_unproven", "The source puts the tx at the anchor height without a proof.",
             ["EX4"],
             [src(a, "primary", tx_answer(height=ANCHOR, proof="none"))],
             expect("unchecked", "height_unproven", inclusion="node-attested", result="node-attested",
                    cross_check="off", results={a: used}, names=[a])),
        case("unchecked_height_cross_confirmed_only", "No proof; the cross source agrees on a height below the "
             "anchor. Agreement is not proof, so not invalid.", ["EX4", "EO1"],
             [src(a, "primary", tx_answer(height=ANCHOR - 50, proof="none")),
              src(x, "cross", tx_answer(height=ANCHOR - 50, proof="none"))],
             expect("unchecked", "height_unproven", inclusion="node-attested", result="cross-confirmed",
                    cross_check="pass", results={a: used, x: "agree"}, names=[a])),
        case("unchecked_cross_disagree_code", "Primary: code 0 with a valid proof, no result proof. Cross: "
             "code 5. Nothing binds the code.", ["BX8", "EX6"],
             [src(a, "primary", tx_answer()), src(x, "cross", tx_answer(code=5, proof="none"))],
             expect("unchecked", "cross_disagree", inclusion="proven", result="node-attested",
                    cross_check="mismatch", proven=True, results={a: used, x: "disagree"}, names=[a, x])),
        case("unchecked_cross_disagree_height", "No proof. Primary and cross put the tx at different heights, "
             "both above the anchor.", ["BX8", "EX6"],
             [src(a, "primary", tx_answer(proof="none")),
              src(x, "cross", tx_answer(height=TX_H + 1, proof="none"))],
             expect("unchecked", "cross_disagree", inclusion="node-attested", result="node-attested",
                    cross_check="mismatch", results={a: used, x: "disagree"}, names=[a, x])),
        case("unchecked_cross_bytes_not_hashing", "The cross source answers with bytes that do not hash to "
             "rail_ref: that source's fault, so it confirms nothing.", ["BX8", "EX9"],
             [src(a, "primary", tx_answer()), src(x, "cross", tx_answer(tx="flipped", proof="none"))],
             expect("unchecked", "result_unproven", inclusion="proven", result="node-attested",
                    cross_check="unavailable", proven=True, results={a: used, x: "fault"}, names=[a, x])),
        case("unchecked_chain_config", "The checker is configured for another chain than the action names. "
             "An auditor configuration mismatch, not a finding; no source is asked.", ["BX0"],
             [src(a, "primary", tx_answer())],
             expect("unchecked", "chain_config", sentinel="railverify.ErrChainConfig",
                    results={a: "not_asked"}),
             checker_chain_id="mocha-5"),
        case("unchecked_chain_unbound", "The trusted header at the tx height names another chain, and "
             "inclusion is not proven. Unreachable in the reference verifier (OH2 pins every header to the "
             "configured chain id); a checker tested alone must still give unchecked.", ["BX4"],
             [src(a, "primary", tx_answer(proof="none"))],
             expect("unchecked", "chain_unbound", inclusion="node-attested", result="node-attested",
                    cross_check="off", results={a: used}, names=[a]),
             trusted_chain_id="mocha-5"),

        case("fail_rail_ref_malformed", "The receipt's rail_ref is upper-case hex. The receipt is gate-signed, "
             "so the malformed reference is proven; no source is asked.", ["BX1"],
             [src(a, "primary", tx_answer())],
             expect("fail", "rail_ref_malformed", sentinel="railverify.ErrRailRefMalformed",
                    results={a: "not_asked"}),
             rail_ref=RAIL_REF.upper()),
        case("fail_tx_malformed", "The bytes hash to rail_ref, so the receipt binds them, and they are not a "
             "canonical TxRaw (body_bytes twice).", ["BX2", "BX3"],
             [src(a, "primary", tx_answer(tx="duplicate_body"))],
             expect("fail", "tx_malformed", sentinel="railverify.ErrTxMalformed", results={a: used}),
             rail_ref_of="duplicate_body"),
        case("fail_body_mismatch", "The bytes hash to rail_ref and the body is not the authorized one "
             "(another memo).", ["BX2", "BX5"],
             [src(a, "primary", tx_answer(tx="other_memo"))],
             expect("fail", "body_mismatch", sentinel="bankaction.ErrBodyMismatch", results={a: used}),
             rail_ref_of="other_memo"),
        case("fail_body_mismatch_header_unreachable", "As above, with the tx height above T: the body finding "
             "needs no header, so it is still fail.", ["BX5", "EX5"],
             [src(a, "primary", tx_answer(tx="other_memo", height=T + 10))],
             expect("fail", "body_mismatch", sentinel="bankaction.ErrBodyMismatch", results={a: used}),
             rail_ref_of="other_memo", checkpoint_height=str(T)),
        case("fail_body_mismatch_after_alternate", "The primary's bytes do not hash (set aside); the "
             "alternate's do, and their body is not the authorized one.", ["BX2", "BX5", "EX10"],
             [src(a, "primary", tx_answer(tx="flipped")), src(b, "alternate", tx_answer(tx="other_memo"))],
             expect("fail", "body_mismatch", sentinel="bankaction.ErrBodyMismatch",
                    results={a: "set_aside", b: used}),
             rail_ref_of="other_memo"),
        case("fail_chain_mismatch_proven", "Inclusion is proven in a trusted header whose chain id differs from "
             "the action's.", ["BX4", "BX6"],
             [src(a, "primary", tx_answer())],
             expect("fail", "chain_mismatch", sentinel="railverify.ErrChainMismatch", inclusion="proven",
                    result="node-attested", cross_check="off", proven=True, results={a: used}),
             trusted_chain_id="mocha-5"),
        case("fail_height_not_after_anchor_proven", "Proof verifies at the anchor height. The result is not "
             "proven, but the proven ordering violation is enough.", ["EX4", "BX6"],
             [src(a, "primary", tx_answer(height=ANCHOR))],
             expect("fail", "height_not_after_anchor", inclusion="proven", result="node-attested",
                    cross_check="off", proven=True, results={a: used})),
        case("fail_tx_failed_proven", "Code 5, proven by the result proof (index bound by the share proof).",
             ["RP5", "RP6", "EX9"],
             [src(a, "primary", tx_answer(code=5))],
             expect("fail", "tx_failed", sentinel="railverify.ErrTxFailed", inclusion="proven", result="proven",
                    cross_check="off", proven=True, results={a: used}), result_proof=rp("match_indexed", 5)),
        case("fail_tx_failed_index_rebuilt", "Code 5, proven by the result proof; the tx is not at share 0 and "
             "the index is bound by the rebuilt square.", ["RP5", "RP6", "EX9"],
             [src(a, "primary", tx_answer(code=5))],
             expect("fail", "tx_failed", sentinel="railverify.ErrTxFailed", inclusion="proven", result="proven",
                    cross_check="off", proven=True, results={a: used}), result_proof=rp("match_rebuilt", 5)),
        case("fail_tx_failed_proven_source_says_success", "The tx source reports code 0, the result proof "
             "shows code 5. The proven code wins.", ["RP6", "EX9"],
             [src(a, "primary", tx_answer(code=0))],
             expect("fail", "tx_failed", sentinel="railverify.ErrTxFailed", inclusion="proven", result="proven",
                    cross_check="off", proven=True, results={a: used}), result_proof=rp("match_indexed", 5)),
    ]

    return {
        "format": "edicta-vectors/v0",
        "revision": "v1-draft.5",
        "profile": "bank-send",
        "profile_revision": "bank-send-v0-draft.7",
        "generator": "spec/vectors/check/gen_execution_outcomes.py",
        "description": (
            "Outcome table of the execution check (core 20.2, bank-send 3.4). Every case assumes that every other "
            "check passed and the record state is authorized, so the verdict follows from execution and "
            "header_trust alone. Defaults: rail_ref is SHA-256 of the transaction named by rail_ref_of; the "
            "checker and the trusted chain have the action's chain id; T is checkpoint_height; the header at the "
            "tx height is trusted; sources are asked in list order. proof 'valid' is an inclusion proof of the "
            "answer's bytes that passes BX6 against data_hash of the trusted header at the answer's height, "
            "'invalid' one that fails it (forms: the proofs section), 'none' an absent proof. result_proof "
            "(default state 'unavailable': no source serves block_results) is the outcome of RP1 to RP6 for block "
            "H: 'match_indexed' (root equals last_results_hash of the trusted header at H + 1 and the share proof "
            "binds the index; code is the selected result's), 'match_rebuilt' (root matches, the tx is not at share "
            "0, and the block txs rebuild to data_hash and bind the index; code is the selected result's), "
            "'match_uniform' (root matches, index unbound, every result has code), 'match_unindexed' (root "
            "matches, index unbound, codes differ, no source serves the block txs), 'match_rebuild_mismatch' "
            "(root matches, codes differ, the block txs served do not rebuild to data_hash), 'root_mismatch', "
            "'header_unreachable' (H + 1 above T). Forms: the result_proof section. Cross agreement "
            "(result 'cross-confirmed') is reported only and never gives pass."),
        "defaults": {
            "action_ref": "profiles/bank-send/action.json#action_minimal_mocha",
            "signed_ref": "profiles/bank-send/tx.json#signed_minimal_mocha",
            "action_type": "application/vnd.edicta.cosmos.bank-send.v0+cbor",
            "action_cbor_hex": action["cbor_hex"],
            "commitment_hash_hex": body["commitment_hash_hex"],
            "chain_id": action["input"]["chain_id"],
            "anchor_height": str(ANCHOR),
            "tx_height": str(TX_H),
            "checkpoint_height": str(T + 1000),
            "headers_source": "headers-rpc",
        },
        "outcomes": {
            "pass": {"verdict": "valid", "exit": "0"},
            "fail": {"verdict": "invalid", "exit": "1"},
            "unchecked": {"verdict": "unchecked", "exit": "2"},
        },
        "txs": {k: {"description": d, "tx_hex": b.hex(), "sha256_hex": sha(b)} for k, (d, b) in txs.items()},
        "live": {
            "source": "celestia/railverify/testdata/tx_prove_1442606.json and header_1442606.json (Mocha, "
                      "2026-10-07, bank-send section 6)",
            "provenance": "Captured from a decision of the unsupported v0 drafts; the commitment hash in the tx memo "
                          "is an opaque 32-byte input here. The capture is a Celestia fact and is not recaptured.",
            "chain_id": hdr["chain_id"],
            "height": hdr["height"],
            "rail_ref": live["hash"].lower(),
            "code": str(live["tx_result"]["code"]),
            "tx_hex": live_tx.hex(),
            "data_hash_hex": data_hash,
        },
        "proofs": [{"id": i, "description": d, "tx_hex": t.hex(), "proof_json": pj(p), "data_hash_hex": h,
                    "expect": e} for i, d, t, p, h, e in proofs],
        "result_proof": result_proof_live(hdr, proof),
        "cases": cases,
    }


def main() -> int:
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(build(), indent=2, ensure_ascii=True) + "\n")
    print(f"wrote {OUT.relative_to(REPO)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
