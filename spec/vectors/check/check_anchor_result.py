#!/usr/bin/env python3
"""Verifies spec/vectors/da/anchor_result.json and v1/verify_anchor_result.json (v1.0-s1) without Go and without
the network.

da/anchor_result.json: runs RA1 to RA6 of core v1 20.6.1 on the bytes, with the code that already checks the
anchor proof (check_fibre_anchor: DAH, NMT namespace proofs with completeness, compact-share reassembly), headers
(check_absence, check_fibre_cert: CometBFT header hash) and results (check_execution_outcomes: ExecTxResult
leaves). The PFB_NS units (go-square IndexWrapper of a MsgPayForBlobs tx) and bech32 are decoded here.

v1/verify_anchor_result.json: recomputes the anchor check, the report fields and the verdict from the rows of
20.6 with the anchor result, on the records of v1/verify.json, and checks every ref into da/anchor_result.json
against that file's outcome.

Both files are compared with the generator's output.

Usage: python3 spec/vectors/check/check_anchor_result.py
"""

from __future__ import annotations

import sys

sys.dont_write_bytecode = True

import json
from pathlib import Path

import archive as A
import check_absence as CA
import check_archive_v1 as V
import check_execution_outcomes as EO
import check_fibre_anchor as FA
import check_fibre_cert as FC

VECTORS = Path(__file__).resolve().parent.parent
FORMAT, REVISION = "edicta-vectors/v1", "v1.0-s1"
APP_VERSION = 10
PFB_NS = bytes(28) + b"\x04"
PFB_URL = b"/celestia.blob.v1.MsgPayForBlobs"
BECH32 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
REQUIRED_DA = ("fibre_code_0", "fibre_code_nonzero", "fibre_results_missing", "blob_code_0", "blob_code_nonzero",
               "blob_results_missing")
REQUIRED_VERIFY = ("fast_result_proven", "fast_result_unproven", "fast_result_failed_absence_proven",
                   "fast_result_at_deadline_head_d", "fast_evidence_head_below_deadline")


class Failure(Exception):
    pass


Unproven = CA.Unproven


def expect(cond: bool, msg: str):
    if not cond:
        raise Failure(msg)


def need(cond: bool, rule: str, why: str):
    if not cond:
        raise Unproven(rule, why)


def bech32_decode(s: str, hrp: str) -> bytes | None:
    """BIP 173 bech32 with the given human-readable part; None if anything is off."""
    if s.lower() != s or "1" not in s:
        return None
    at = s.rindex("1")
    if s[:at] != hrp or len(s) - at - 1 < 6 or any(ch not in BECH32 for ch in s[at + 1:]):
        return None
    data = [BECH32.index(ch) for ch in s[at + 1:]]
    chk = 1
    for v in [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp] + data:
        top = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ v
        for i, g in enumerate((0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)):
            chk ^= g if top >> i & 1 else 0
    if chk != 1:
        return None
    acc, bits, out = 0, 0, bytearray()
    for v in data[:-6]:
        acc, bits = acc << 5 | v, bits + 5
        if bits >= 8:
            bits -= 8
            out.append(acc >> bits & 0xFF)
    if bits >= 5 or acc & ((1 << bits) - 1):
        return None
    return bytes(out)


def packed_uvarints(b: bytes) -> list:
    out, i = [], 0
    while i < len(b):
        v, i = FC.uvarint(b, i)
        out.append(v)
    return out


def parse_pfb_unit(unit: bytes) -> dict:
    """RA4: IndexWrapper -> TxRaw -> TxBody with exactly one MsgPayForBlobs."""
    iw = FC.fields(unit)
    expect(FC.last(iw, 3, 2, b"") == b"INDX", "type_id is not INDX")
    body = FC.fields(FC.last(FC.fields(FC.last(iw, 1, 2, b"")), 1, 2, b""))
    msgs = FC.every(body, 1)
    expect(len(msgs) == 1, "not exactly one message")
    anyf = FC.fields(msgs[0])
    expect(FC.last(anyf, 1, 2, b"") == PFB_URL, "not a MsgPayForBlobs")
    m = FC.fields(FC.last(anyf, 2, 2, b""))
    versions = []
    for n, w, x in m:
        if n == 8:
            versions += packed_uvarints(x) if w == 2 else [x]
    return {"signer": FC.last(m, 1, 2, b"").decode(), "namespaces": FC.every(m, 2),
            "commitments": FC.every(m, 4), "versions": versions}


def units_of(nd_bytes: bytes, rows: list, ns: bytes) -> list:
    nd = FA.decode_stream(nd_bytes)
    FA.verify_rows(nd, rows, ns)
    shares = [s for r in nd for s in r["shares"]]
    if not shares:
        return []
    txs = FA.parse_txs(shares)
    if FA.split_txs(txs, ns) != list(shares):
        raise FA.Reject("NA4", "re-split differs")
    return txs


def proven_results(next_header: bytes | None, results: bytes | None, h: int, trusted: dict) -> list:
    need(next_header is not None, "RA1", "no source serves header(H + 1)")
    nf = CA.parse_signed_header(next_header, h + 1, trusted, "RA1")
    need(results is not None, "RA2", "no source serves results(H)")
    try:
        served = json.loads(results)
        res = [{"code": str(x["code"]), "data": x.get("data") or "", "gas_wanted": x["gas_wanted"],
                "gas_used": x["gas_used"]} for x in served["txs_results"]]
        leaves = [EO.results_leaf(r) for r in res]
    except (ValueError, KeyError, TypeError, EO.Failure) as e:
        raise Unproven("RA2", f"results: {e}")
    need(FC.merkle(leaves) == FC.last(nf, 12, 2, b""), "RA2", "results do not hash to last_results_hash")
    need(len(res) >= 1, "RA2", "no results")
    return [int(r["code"]) for r in res]


def outcome(code: int, binding: str, index: int | None) -> dict:
    out = {"anchor_result": "proven" if code == 0 else "failed", "rule": "RA6", "binding": binding}
    if index is not None:
        out["result_index"] = str(index)
    out["code"] = str(code)
    return out


def run_fibre(c: dict) -> dict:
    q, trusted = c["query"], c["trusted_headers"]
    h = int(q["height"])
    rec = A.decode_record(bytes.fromhex(c["record_hex"]))
    expect(rec["kind"] == A.KIND_ABSENCE and rec["da"] == 1 and rec["height"] == h
           and rec["commitment"].hex() == q["commitment"] and rec["namespace"].hex() == q["namespace"],
           "record names another query")
    # The evidence already verified at H (CV8): a failure here is a broken vector, not an RA outcome.
    try:
        hf = CA.parse_signed_header(rec["header"], h, trusted, "evidence")
        rows, cols = FA.parse_dah_proto(rec["dah"])
        FA.check_dah(rows, cols, FC.last(hf, 7, 2, b""))
        units = units_of(rec["namespace_data"], rows, FA.PFF_NS)
    except (Unproven, FA.Reject, FC.Failure) as e:
        raise Failure(f"evidence precondition: {e}")
    try:
        anchor = bytes.fromhex(c["anchor_tx_hex"])
        p = FC.parse_pff(anchor)
        expect(p["commitment"].hex() == q["commitment"] and p["namespace"].hex() == q["namespace"],
               "anchor is not the query's PFF")
        pos = [j for j, u in enumerate(units) if u == anchor]
        need(len(pos) == 1, "RA3", "the anchor is not exactly one unit of PFF_NS")
        j, pn = pos[0], len(units)
        codes = proven_results(rec.get("next_header"), rec.get("results"), h, trusted)
        n = len(codes)
        if CA.app_version(hf) == APP_VERSION and n >= pn >= 1:
            return outcome(codes[n - pn + j], "tail", n - pn + j)
        need(n >= pn and len(set(codes)) == 1, "RA5", "neither the tail nor uniform codes bind")
        return outcome(codes[0], "uniform", None)
    except Unproven as u:
        return {"anchor_result": "unproven", "rule": u.rule}


def run_blob(c: dict) -> dict:
    q, trusted, pr = c["query"], c["trusted_headers"], c["proof"]
    h = int(q["height"])
    signer = bytes.fromhex(q["signer"])
    hexed = lambda k: bytes.fromhex(pr[k]) if k in pr else None  # noqa: E731
    try:
        hf = CA.parse_signed_header(bytes.fromhex(pr["header_hex"]), h, trusted, "evidence")
    except Unproven as e:
        raise Failure(f"evidence precondition: {e}")
    try:
        codes = proven_results(hexed("next_header_hex"), hexed("results_hex"), h, trusted)
        n = len(codes)
        try:
            rows, cols = FA.parse_dah_proto(bytes.fromhex(pr["dah_hex"]))
            FA.check_dah(rows, cols, FC.last(hf, 7, 2, b""))
            pfb = units_of(bytes.fromhex(pr["pfb_namespace_data_hex"]), rows, PFB_NS)
            pff = units_of(bytes.fromhex(pr["pff_namespace_data_hex"]), rows, FA.PFF_NS)
        except (FA.Reject, FC.Failure, ValueError) as e:
            raise Unproven("RA4", str(e))
        cands = []
        for k, u in enumerate(pfb):
            try:
                m = parse_pfb_unit(u)
            except (Failure, FC.Failure, UnicodeDecodeError) as e:
                raise Unproven("RA4", f"PFB unit {k}: {e}")
            if bech32_decode(m["signer"], "celestia") != signer:
                continue
            if any(ns.hex() == q["namespace"] and cm.hex() == q["commitment"] and v == 1
                   for ns, cm, v in zip(m["namespaces"], m["commitments"], m["versions"])):
                cands.append(k)
        need(bool(cands), "RA4", "no candidate PFB")
        p_, q_ = len(pff), len(pfb)
        if CA.app_version(hf) == APP_VERSION and n >= p_ + q_ and q_ >= 1:
            idx = [n - p_ - q_ + k for k in cands]
            zero = next((i for i in idx if codes[i] == 0), None)
            i = idx[0] if zero is None else zero
            return outcome(codes[i], "tail", i)
        need(len(set(codes)) == 1, "RA5", "neither the tail nor uniform codes bind")
        return outcome(codes[0], "uniform", None)
    except Unproven as u:
        return {"anchor_result": "unproven", "rule": u.rule}


def check_da(f: dict) -> tuple:
    expect(f["format"] == FORMAT and f["revision"] == REVISION, "da: format or revision")
    expect(f["pfb_namespace"] == PFB_NS.hex() and f["pff_namespace"] == FA.PFF_NS.hex(), "da: namespaces")
    ids = [c["id"] for c in f["cases"]]
    expect(len(ids) == len(set(ids)) and all(i in ids for i in REQUIRED_DA), "da: required cases")
    seen, out = set(), {}
    for c in f["cases"]:
        got = run_fibre(c) if c["query"]["da"] == "1" else run_blob(c)
        expect(got == c["expect"], f"{c['id']}: vector {c['expect']}, checker {got}")
        seen.add((c["query"]["da"], got["anchor_result"]))
        seen.add(got["rule"])
        out[c["id"]] = got
    for da in ("1", "2"):
        for r in ("proven", "failed", "unproven"):
            expect((da, r) in seen, f"da: no da = {da} case with {r}")
    expect({"RA1", "RA2", "RA4", "RA5", "RA6"} <= seen, f"da: rules without a case: {seen}")
    return out, f"{len(ids)} anchor result cases"


def verify_outcome(c: dict, records: dict) -> dict:
    dec = A.decode_record(bytes.fromhex(records[c["decision"]]["record_cbor_hex"]))
    au = A.decode_record(bytes.fromhex(records[c["authorization"]]["record_cbor_hex"]))
    ref = V.commitment_ref(V.commitment_bytes(dec["envelope"]))["ref"]
    a = V.auth_map(au["signed_authorization"])
    expect(ref.get(6) == 2 and a.get(7) == 2, f"{c['id']}: a pending reference with a fast-mode Authorization")
    h0, dl, head = ref[4], a[8], int(c["trusted_head"])
    expect(h0 < dl <= h0 + 1000, f"{c['id']}: AM2")
    ev = c["evidence"]
    hh = int(ev["height"])
    expect(ev["verifies"] and h0 <= hh <= dl, f"{c['id']}: in-window evidence that verifies")
    rep = {"version": "1", "mode": "fast", "h0": str(h0), "anchor_deadline": str(dl)}
    out = {"authorization": {"status": "pass"}}
    if head < max(dl, hh + 1):
        out["anchor"] = {"status": "unchecked", "reason": "anchor_pending"}
        rep["publication"] = "unknown"
    else:
        ar = ev["anchor_result"]
        rep |= {"anchor_height": str(hh), "anchor_result": ar["result"]}
        if ar["result"] == "proven":
            out["anchor"] = {"status": "pass"}
            rep["publication"] = "anchored"
        elif ar["result"] == "unproven":
            out["anchor"] = {"status": "unchecked", "reason": "anchor_result_unproven", "rule": ar["rule"]}
            rep["publication"] = "unknown"
        else:
            rep["anchor_result_code"] = ar["code"]
            ab = {int(x["height"]): x["result"] for x in c.get("absence", [])}
            # The failed anchor's own height is never evidence again, and a proof that shows it present (AB6 reads
            # no code) does not prove it absent.
            other = [h for h in range(h0, dl + 1) if h != hh and ab.get(h) == "present"]
            gap = next((h for h in range(h0, dl + 1) if ab.get(h) != "absent"), None)
            if other:
                out["anchor"] = {"status": "unchecked", "reason": "evidence_unavailable"}
                rep |= {"anchor_height": str(other[0]), "publication": "unknown"}
            elif gap is None:
                out["anchor"] = {"status": "fail", "rule": "anchor_absent"}
                rep |= {"publication": "failed", "intent_signer": ref[5].hex() if ref[1] == 2 else "unknown"}
            else:
                out["anchor"] = {"status": "unchecked", "reason": "absence_unproven", "first_unproven": str(gap)}
                rep["publication"] = "unknown"
    sts = [x["status"] for x in out.values()]
    verdict, code = ("invalid", 1) if "fail" in sts else ("unchecked", 2) if "unchecked" in sts else ("valid", 0)
    return out | {"report": rep, "verdict": verdict, "exit": str(code)}


def check_verify(f: dict, da: dict) -> str:
    expect(f["format"] == FORMAT and f["revision"] == REVISION, "verify: format or revision")
    records = json.loads((VECTORS / "v1" / "verify.json").read_text())["records"]
    absence_ids = {c["id"] for c in json.loads((VECTORS / "da" / "absence.json").read_text())["synthetic"]}
    ids = [c["id"] for c in f["cases"]]
    expect(len(ids) == len(set(ids)) and all(i in ids for i in REQUIRED_VERIFY), "verify: required cases")
    for c in f["cases"]:
        got = verify_outcome(c, records)
        expect(got == c["expect"], f"{c['id']}: vector {c['expect']}, checker {got}")
        for ref in c["refs"]:
            rel, _, ident = ref.partition("#")
            if rel == "da/absence.json":
                expect(ident in absence_ids, f"{c['id']}: unresolved ref {ref}")
                continue
            expect(rel == "da/anchor_result.json" and ident in da, f"{c['id']}: unresolved ref {ref}")
            ar, d = c["evidence"]["anchor_result"], da[ident]
            expect(ar["result"] == d["anchor_result"] and ar.get("code") == d.get("code")
                   and ar.get("rule", "RA6") == d["rule"], f"{c['id']}: {ref} reads another way")
    verdicts = {c["expect"]["verdict"] for c in f["cases"]}
    expect(verdicts == {"valid", "invalid", "unchecked"}, "verify: every verdict")
    return f"{len(ids)} verify cases"


def main() -> int:
    try:
        import gen_anchor_result as gen
        files = {}
        for name, obj in gen.build().items():
            text = json.dumps(obj, indent=2, ensure_ascii=True) + "\n"
            expect((VECTORS / name).read_text() == text, f"{name}: generator output differs")
            files[name] = obj
        da, s1 = check_da(files["da/anchor_result.json"])
        s2 = check_verify(files["v1/verify_anchor_result.json"], da)
    except (Failure, CA.Failure, FC.Failure, FA.Reject, A.Reject, KeyError, ValueError) as e:
        print(f"FAIL (anchor result): {type(e).__name__}: {e}", file=sys.stderr)
        return 1
    print(f"OK (anchor result, {REVISION}): {s1}; {s2}; generator output identical")
    return 0


if __name__ == "__main__":
    sys.exit(main())
