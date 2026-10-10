#!/usr/bin/env python3
"""Writes spec/vectors/da/anchor_result.json and v1/verify_anchor_result.json (v1.0-s1, core v1 20.6 and 20.6.1).
Deterministic.

da/anchor_result.json: the anchor result proof (RA1 to RA6) on bytes. da = 1 reuses the synthetic chain of
gen_absence.py (blocks D and E) with a kind 14 record at H as the carrier of header(H + 1) and results(H); the
anchor is a PFF unit of that block. da = 2 builds its own blocks: a normal tx, IndexWrapper units of
MsgPayForBlobs in PFB_NS (one the candidate, one of another signer), one PFF in PFF_NS, chained headers, results.
The expected outcome comes from how the block was built; check_anchor_result.py runs the rules on the bytes.

What is synthetic, as in gen_absence.py: parity quadrants, commit and tx signatures, the blobs themselves (RA reads
no blob share, only the PFB units).

v1/verify_anchor_result.json: the rows of 20.6 with the result proof, on the records of v1/verify.json by name.

Usage: python3 spec/vectors/check/gen_anchor_result.py
"""

from __future__ import annotations

import sys

sys.dont_write_bytecode = True

import json
from pathlib import Path

import archive as A
import gen_absence as G

VECTORS = Path(__file__).resolve().parent.parent
FORMAT, REVISION = "edicta-vectors/v1", "v1.0-s1"
PFB_NS = bytes(28) + b"\x04"
PFB_URL = b"/celestia.blob.v1.MsgPayForBlobs"
H2 = G.BASE + 21


def pfb_unit(label: str, signer: bytes, ns: bytes, commitment: bytes, share_version: int = 1) -> bytes:
    """go-square IndexWrapper of the inner sdk tx of a blob tx with one MsgPayForBlobs for one blob."""
    msg = (G.plen(1, G.bech32("celestia", signer).encode()) + G.plen(2, ns) + G.plen(3, G.uv(300))
           + G.plen(4, commitment) + G.plen(8, G.uv(share_version), True))
    tx = G.tx_raw([G.plen(1, PFB_URL) + G.plen(2, msg)], label)
    return G.plen(1, tx) + G.plen(2, G.uv(3)) + G.plen(3, b"INDX")


def blob_chain(query: dict, codes: list, app: int = G.APP_VERSION, results_codes: list | None = None) -> dict:
    """Block H2 (da = 2) and its successor. Txs in block order: one normal tx, two blob txs (another signer, then
    the candidate), one PFF. Results follow that order; results_codes overrides what results(H2) serves (the
    header at H2 + 1 commits to it, so the chain stays consistent)."""
    other = G.stream("another blob signer", 20)
    units = [pfb_unit("pfb/0", other, query["namespace"], G.sha(b"another blob")),
             pfb_unit("pfb/1", query["signer"], query["namespace"], query["commitment"])]
    pfb_sh = G.compact_shares(PFB_NS, units)
    assert len(pfb_sh) == 2
    pff = G.pff_tx("blob-block/pff", G.USER_NS, G.sha(b"a fibre blob"), G.CHAIN_ID, H2)
    pff_sh = G.compact_shares(G.PFF_NS, [pff])
    tx_sh = G.compact_shares(G.TX_NS, [G.normal_tx("blob-block/normal")])
    assert len(pff_sh) == 1 and len(tx_sh) == 1
    sq = G.square(tx_sh + pfb_sh + pff_sh, f"blob/{app}/{codes}")
    nxt = G.square(tx_sh + [G.tail_share()] * 3, "blob/next")
    served = codes if results_codes is None else results_codes
    prev = G.stream(f"block/{H2 - 1}", 32)
    hpb, hh = G.header(H2, sq["data_hash"], prev, G.rfc6962([]), app)
    leaves = [G.results_leaf(c, 80000 + 1000 * i) for i, c in enumerate(served)]
    npb, nh = G.header(H2 + 1, nxt["data_hash"], hh, G.rfc6962(leaves))
    return {"square": sq, "units": units, "header": G.signed_header(hpb, hh, H2), "hash": hh,
            "next_header": G.signed_header(npb, nh, H2 + 1), "next_hash": nh,
            "results": G.results_json(H2, served), "codes": served}


def fibre_record(query: dict, blocks: dict, h: int, **kw) -> bytes:
    return G.record(query, blocks, h, **kw)


def build_da() -> dict:
    valid = json.loads((VECTORS / "v1" / "valid.json").read_text())
    pf = next(c for c in valid["cases"] if c["id"] == "v1_pending_fibre")["input"]["payload_ref"]
    pb = next(c for c in valid["cases"] if c["id"] == "v1_pending_blob")["input"]["payload_ref"]
    fq = {"namespace": bytes.fromhex(pf["namespace"]), "commitment": bytes.fromhex(pf["commitment"])}
    bq = {"namespace": bytes.fromhex(pb["namespace"]), "commitment": bytes.fromhex(pb["commitment"]),
          "signer": bytes.fromhex(pb["signer"])}
    blocks = G.build_chain(fq)
    other_app = G.build_chain(fq, {G.BASE + 3: 11})
    other_zero = G.build_chain(fq, {G.BASE + 3: 11}, {G.BASE + 3: [0, 0, 0, 0]})
    short = G.build_chain(fq, None, {G.BASE + 3: [11]})
    th = lambda ch: {str(h): ch[h]["hash"].hex() for h in sorted(ch)}  # noqa: E731
    d_h, e_h = G.BASE + 3, G.BASE + 5

    def anchor_of(ch, h, j):
        return ch[h]["pffs"][j][1]

    def fibre(cid, desc, ch, h, j, rec, exp, trusted=None):
        return {"id": cid, "description": desc,
                "query": {"da": "1", "namespace": fq["namespace"].hex(), "commitment": fq["commitment"].hex(),
                          "chain_id": G.CHAIN_ID, "height": str(h)},
                "anchor_tx_hex": anchor_of(ch, h, j).hex(), "trusted_headers": trusted or th(ch),
                "record_hex": rec.hex(), "expect": exp}

    def res(result, rule, binding=None, index=None, code=None):
        out = {"anchor_result": result, "rule": rule}
        if binding:
            out["binding"] = binding
        if index is not None:
            out["result_index"] = str(index)
        if code is not None:
            out["code"] = str(code)
        return out

    def forged_next(h):
        hb = blocks[h + 1]["header"]
        old = G.stream(f"app/{h + 1}", 32)
        assert hb.count(old) == 1
        return hb.replace(old, G.stream(f"app/{h + 1}/forged", 32))

    def code_rewritten(h):
        j = json.loads(blocks[h]["results_bytes"])
        j["txs_results"][2]["code"] = 9
        return json.dumps(j, separators=(",", ":")).encode()

    def rec_with_next(h, next_header):
        rec = A.decode_record(fibre_record(fq, blocks, h))
        rec["next_header"] = next_header
        return A.encode_record(rec)

    cases = [
        fibre("fibre_code_0", "Block E: the archived anchor is the only PFF (j = 0, p = 1, n = 3); the tail binds "
              "index n - p + j = 2, code 0: proven. The first normal tx failed (code 7), so binding by the PFF "
              "position alone would read code 7.", blocks, e_h, 0, fibre_record(fq, blocks, e_h),
              res("proven", "RA6", "tail", 2, 0)),
        fibre("fibre_code_nonzero", "Block D: the archived anchor is the candidate at j = 1 (p = 2, n = 4); index "
              "4 - 2 + 1 = 3, code 11: failed. The evidence is not usable; the missing-anchor rows of 20.6 apply.",
              blocks, d_h, 1, fibre_record(fq, blocks, d_h), res("failed", "RA6", "tail", 3, 11)),
        fibre("fibre_results_missing", "Block E, and no source serves header(H + 1) or results(H): the kind 14 "
              "record at H carries neither (keys 10 and 11 go together), and no online source is configured.", blocks, e_h, 0,
              fibre_record(fq, blocks, e_h, drop_results=True), res("unproven", "RA1")),
        fibre("fibre_results_root_mismatch", "Block E with the anchor's result code rewritten to 9 in results: they "
              "no longer hash to last_results_hash of header(H + 1).", blocks, e_h, 0,
              fibre_record(fq, blocks, e_h, results_edit=code_rewritten), res("unproven", "RA2")),
        fibre("fibre_next_header_not_linking", "Block E with another app_hash in next_header: its hash differs from "
              "the one header trust reached at H + 1.", blocks, e_h, 0, rec_with_next(e_h, forged_next(e_h)),
              res("unproven", "RA1")),
        fibre("fibre_other_app_version_mixed", "Block D with version.app = 11 at H: the tail binds only at the "
              "pinned version, and the codes 0, 0, 0, 11 are not uniform.", other_app, d_h, 1,
              fibre_record(fq, other_app, d_h), res("unproven", "RA5")),
        fibre("fibre_other_app_version_uniform_zero", "Block D with version.app = 11 at H and every code 0: uniform "
              "codes bind at any app version, so the code is 0 whatever the index.", other_zero, d_h, 1,
              fibre_record(fq, other_zero, d_h), res("proven", "RA6", "uniform", None, 0)),
        fibre("fibre_tail_n_less_than_p", "Block D whose results hold one result (code 11) while two PFF units were "
              "reassembled: n >= p fails for the tail and for uniform codes.", short, d_h, 1,
              fibre_record(fq, short, d_h), res("unproven", "RA5")),
    ]

    def blob(cid, desc, ch, exp, ns_edit=None, drop_results=False, trusted=None):
        sq = ch["square"]
        pfb_entries = G.namespace_entries(sq, PFB_NS)
        if ns_edit:
            pfb_entries = ns_edit(pfb_entries)
        proof = {"header_hex": ch["header"].hex(), "dah_hex": G.dah_bytes(sq["rows"], sq["cols"]).hex(),
                 "pfb_namespace_data_hex": G.ns_stream(pfb_entries).hex(),
                 "pff_namespace_data_hex": G.ns_stream(G.namespace_entries(sq, G.PFF_NS)).hex()}
        if not drop_results:
            proof["results_hex"] = ch["results"].hex()
        proof["next_header_hex"] = ch["next_header"].hex()
        return {"id": cid, "description": desc,
                "query": {"da": "2", "namespace": bq["namespace"].hex(), "commitment": bq["commitment"].hex(),
                          "signer": bq["signer"].hex(), "chain_id": G.CHAIN_ID, "height": str(H2)},
                "trusted_headers": trusted or {str(H2): ch["hash"].hex(), str(H2 + 1): ch["next_hash"].hex()},
                "proof": proof, "expect": exp}

    zero = blob_chain(bq, [0, 9, 0, 9])
    nonzero = blob_chain(bq, [0, 0, 13, 0])
    other_mixed = blob_chain(bq, [0, 0, 13, 0], 11)
    other_uniform = blob_chain(bq, [0, 0, 0, 0], 11)
    too_few = blob_chain(bq, [0, 0, 0, 0], results_codes=[0, 13])
    cases += [
        blob("blob_code_0", "Txs: normal, PFB of another signer, the candidate PFB, a PFF; codes 0, 9, 0, 9. n = 4, "
             "p = 1, q = 2, candidate k = 1: index 4 - 1 - 2 + 1 = 2, code 0: proven. Binding by the PFB position "
             "alone would read index 1, code 9.", zero, res("proven", "RA6", "tail", 2, 0)),
        blob("blob_code_nonzero", "The same block with codes 0, 0, 13, 0: the candidate's index 2 has code 13: "
             "failed. Binding by the PFB position alone would read code 0 and a false valid.", nonzero,
             res("failed", "RA6", "tail", 2, 13)),
        blob("blob_results_missing", "The same block; header(H + 1) is served, results(H) by no source (format 1 "
             "archives none for da = 2).", zero, res("unproven", "RA2"), drop_results=True),
        blob("blob_pfb_namespace_cut", "PFB_NS lies in two rows; the namespace data gives the entry of row 0 only "
             "(NA3 completeness).", zero, res("unproven", "RA4"), ns_edit=lambda e: e[:1]),
        blob("blob_other_app_version_mixed", "version.app = 11 at H, codes 0, 0, 13, 0: no tail at another version, "
             "codes not uniform.", other_mixed, res("unproven", "RA5")),
        blob("blob_other_app_version_uniform_zero", "version.app = 11 at H, every code 0: uniform codes bind; no "
             "namespace data is needed.", other_uniform, res("proven", "RA6", "uniform", None, 0)),
        blob("blob_n_less_than_p_plus_q", "Results of two txs (0, 13) committed in header(H + 1), while the square "
             "holds two PFB units and one PFF unit: n >= p + q fails, codes not uniform.",
             too_few, res("unproven", "RA5")),
    ]
    return {
        "format": FORMAT,
        "revision": REVISION,
        "generator": "spec/vectors/check/gen_anchor_result.py",
        "description": (
            "Anchor result proof of core v1 20.6.1 (RA1 to RA6) for in-window evidence of a pending reference. "
            "query: da, the payload namespace, commitment (and signer for da = 2), the expected chain_id and the "
            "anchor height H. trusted_headers: height -> header hash, the result of header trust (an input). "
            "da = 1: anchor_tx_hex is the archived anchor (the PFF the evidence verified), record_hex a kind 14 "
            "record (1, commitment, H) carrying header(H), the DAH, the PFF_NS namespace data, results(H) and "
            "header(H + 1), as an archive copy holds them; its blocks are those of da/absence.json. da = 2: proof "
            "gives header(H), the DAH, the namespace data of PFB_NS (0x00 || 0^27 || 0x04) and PFF_NS, results(H) "
            "and header(H + 1) as separate sources. A missing results_hex or record results means no source "
            "serves them. expect: anchor_result (proven, failed, unproven), the deciding rule (RA6 for an outcome, "
            "else the first rule that failed), the binding (tail, uniform), the result index (tail only) and the "
            "code. Synthetic: parity quadrants, signatures, the blobs themselves; no RA rule reads them."),
        "chain_id": G.CHAIN_ID,
        "pff_namespace": G.PFF_NS.hex(),
        "pfb_namespace": PFB_NS.hex(),
        "cases": cases,
    }


def build_verify() -> dict:
    def case(cid, desc, dec, auth, head, evidence, expect, absence=None, refs=None):
        c = {"id": cid, "description": desc, "decision": dec, "authorization": auth, "trusted_head": str(head),
             "evidence": evidence}
        if absence is not None:
            c["absence"] = [{"height": str(h), "result": r} for h, r in absence]
        c["refs"] = refs or []
        c["expect"] = expect
        return c

    def ev(h, result, code=None, rule=None):
        r = {"result": result}
        if code is not None:
            r["code"] = str(code)
        if rule:
            r["rule"] = rule
        return {"height": str(h), "verifies": True, "anchor_result": r}

    def rep(h0, dl, **kw):
        return {"version": "1", "mode": "fast", "h0": str(h0), "anchor_deadline": str(dl),
                **{k: str(v) for k, v in kw.items()}}

    def out(anchor, report, verdict, code):
        return {"authorization": {"status": "pass"}, "anchor": anchor, "report": report, "verdict": verdict,
                "exit": str(code)}

    F, FA_ = "decision_pending_fibre", "authorization_fast_fibre"
    B, BA = "decision_pending_blob", "authorization_fast_blob"
    h0, dl = 4200123, 4200126
    bh0, bdl = 4200000, 4200003
    pend = {"status": "unchecked", "reason": "anchor_pending"}
    cases = [
        case("fast_result_proven", "Evidence at H = h0 + 1, anchor result proven with code 0, trusted head D + 1.",
             F, FA_, dl + 1, ev(h0 + 1, "proven", 0), out({"status": "pass"},
             rep(h0, dl, anchor_height=h0 + 1, publication="anchored", anchor_result="proven"), "valid", 0),
             refs=["da/anchor_result.json#fibre_code_0"]),
        case("fast_result_proven_at_deadline", "Evidence at H = D, result proven; the trusted head D + 1 = H + 1 "
             "reaches the header the proof needs.", F, FA_, dl + 1, ev(dl, "proven", 0), out({"status": "pass"},
             rep(h0, dl, anchor_height=dl, publication="anchored", anchor_result="proven"), "valid", 0)),
        case("fast_result_at_deadline_head_d", "Evidence at H = D, trusted head D: the result proof needs the header "
             "at D + 1, so max(D, H + 1) is not reached.", F, FA_, dl, ev(dl, "proven", 0),
             out(pend, rep(h0, dl, publication="unknown"), "unchecked", 2)),
        case("fast_evidence_head_below_deadline", "Evidence at H = h0 + 1, trusted head h0 + 2 in [H + 1, D): the "
             "deadline is not reached, so no verdict yet, as in v1.0.", F, FA_, h0 + 2, ev(h0 + 1, "proven", 0),
             out(pend, rep(h0, dl, publication="unknown"), "unchecked", 2)),
        case("fast_result_unproven", "Evidence at H = h0 + 1 verifies, no source serves a results proof.", F, FA_,
             dl + 1, ev(h0 + 1, "unproven", rule="RA1"),
             out({"status": "unchecked", "reason": "anchor_result_unproven", "rule": "RA1"},
                 rep(h0, dl, anchor_height=h0 + 1, publication="unknown", anchor_result="unproven"), "unchecked", 2),
             refs=["da/anchor_result.json#fibre_results_missing"]),
        case("fast_result_failed_absence_proven", "Evidence at H = h0 + 1 with a proven nonzero code; absence proven "
             "at every height of the window, H included (AB5: its only candidate has the nonzero code).", F, FA_,
             dl + 1, ev(h0 + 1, "failed", 11), out({"status": "fail", "rule": "anchor_absent"},
             rep(h0, dl, anchor_height=h0 + 1, publication="failed", anchor_result="failed", anchor_result_code=11,
                 intent_signer="unknown"), "invalid", 1),
             absence=[(h, "absent") for h in range(h0, dl + 1)],
             refs=["da/anchor_result.json#fibre_code_nonzero", "da/absence.json#fibre_candidate_nonzero_code"]),
        case("fast_result_failed_absence_unproven", "Evidence at H = h0 + 1 with a proven nonzero code; no absence "
             "proof for h0.", F, FA_, dl + 1, ev(h0 + 1, "failed", 11),
             out({"status": "unchecked", "reason": "absence_unproven", "first_unproven": str(h0)},
                 rep(h0, dl, anchor_height=h0 + 1, publication="unknown", anchor_result="failed",
                     anchor_result_code=11), "unchecked", 2),
             absence=[(h, "absent") for h in range(h0 + 1, dl + 1)]),
        case("fast_result_proven_blob", "da = 2: evidence at H = h0 + 1, the candidate PFB's code proven 0.", B, BA,
             bdl + 1, ev(bh0 + 1, "proven", 0), out({"status": "pass"},
             rep(bh0, bdl, anchor_height=bh0 + 1, publication="anchored", anchor_result="proven"), "valid", 0),
             refs=["da/anchor_result.json#blob_code_0"]),
        case("fast_result_failed_blob", "da = 2: the candidate PFB's code proven 13. AB6 reads no code and shows "
             "the blob present at H, so H is not proven absent and is not used as evidence again.", B, BA, bdl + 1,
             ev(bh0 + 1, "failed", 13),
             out({"status": "unchecked", "reason": "absence_unproven", "first_unproven": str(bh0 + 1)},
                 rep(bh0, bdl, anchor_height=bh0 + 1, publication="unknown", anchor_result="failed",
                     anchor_result_code=13), "unchecked", 2),
             absence=[(bh0, "absent"), (bh0 + 1, "present"), (bh0 + 2, "absent"), (bh0 + 3, "absent")],
             refs=["da/anchor_result.json#blob_code_nonzero"]),
        case("fast_result_unproven_blob", "da = 2: the PFB namespace data is incomplete and the codes are not "
             "uniform.", B, BA, bdl + 1, ev(bh0 + 1, "unproven", rule="RA4"),
             out({"status": "unchecked", "reason": "anchor_result_unproven", "rule": "RA4"},
                 rep(bh0, bdl, anchor_height=bh0 + 1, publication="unknown", anchor_result="unproven"),
                 "unchecked", 2),
             refs=["da/anchor_result.json#blob_pfb_namespace_cut"]),
    ]
    return {
        "format": FORMAT,
        "revision": REVISION,
        "generator": "spec/vectors/check/gen_anchor_result.py",
        "description": (
            "Verifier outcomes of the anchor check for in-window evidence with the anchor result proof (core v1 "
            "20.6, 20.6.1; v1.0-s1). decision and authorization name records of v1/verify.json. evidence: the "
            "anchor height, whether the evidence verifies, and the result of the anchor result proof (proven or "
            "failed with the code, unproven with the first failing rule). absence: per-height results of absence "
            "proofs, as in v1/verify.json; a height not listed has no proof. trusted_head is the height header "
            "trust reached. expect as in v1/verify.json, with the report field anchor_result (and "
            "anchor_result_code for failed); anchor_result is absent when the trusted head is below max(D, H + 1)."),
        "cases": cases,
    }


def build() -> dict:
    return {"da/anchor_result.json": build_da(), "v1/verify_anchor_result.json": build_verify()}


def main():
    for name, obj in build().items():
        p = VECTORS / name
        p.write_text(json.dumps(obj, indent=2, ensure_ascii=True) + "\n")
        print(f"wrote {p}")


if __name__ == "__main__":
    main()
