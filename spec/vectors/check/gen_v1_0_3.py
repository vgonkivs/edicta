#!/usr/bin/env python3
"""Writes the vector files of spec revision v1.0.3 (security: a PFF candidate inside the window is never absence).

- da/absence_v1.0.3.json: the superseded cases of da/absence.json on the same inputs with the v1.0.3
  expectations, and two windows built from the same records that pin the order of the window results;
- v1/verify_v1.0.3.json: pending decisions whose window holds an unpaid candidate, end to end, on the
  records of v1/verify.json;
- verifier/reasons_v1.0.3.json: the reason anchor_unpaid and its case, additive to verifier/reasons.json.

The frozen files are read, never written. spec/vectors/SUPERSEDED.json is hand-written.

Usage: python3 spec/vectors/check/gen_v1_0_3.py [--check]
"""

from __future__ import annotations

import sys

sys.dont_write_bytecode = True

import copy
import json
from pathlib import Path

VECTORS = Path(__file__).resolve().parent.parent
FORMAT, REVISION = "edicta-vectors/v1", "v1.0.3"
GENERATOR = "spec/vectors/check/gen_v1_0_3.py"
UNPAID_WHY = "one candidate; its result (index n - p + j = 4 - 2 + 1 = 3) has code 11: present unpaid, never absent"


def load(rel: str) -> dict:
    return json.loads((VECTORS / rel).read_text())


def unpaid(height: dict) -> dict:
    out = copy.deepcopy(height)
    out["result"], out["why"] = "present_unpaid", UNPAID_WHY
    return out


def absence_file() -> dict:
    old = load("da/absence.json")
    by_id = {c["id"]: c for c in old["synthetic"]}
    nonzero, three, present = by_id["fibre_candidate_nonzero_code"], by_id["window_three_heights_proven"], \
        by_id["fibre_present"]
    trusted = three["trusted_headers"]
    rec = {r["height"]: r for c in (nonzero, three, present) for r in c["records"]}
    hts = {x["height"]: x for c in (nonzero, three, present) for x in c["expect"]["heights"]}

    def query(h0: str, d: str) -> dict:
        q = dict(three["query"])
        q["h0"], q["anchor_deadline"] = h0, d
        return q

    cases = [
        {"id": "fibre_candidate_nonzero_code",
         "description": "Same inputs as da/absence.json#fibre_candidate_nonzero_code. One candidate, its result bound "
                        "as the tail of the block's results, code 11: an included PFF whose escrow did not pay. "
                        "Present unpaid, never absent (v1.0.3); the verifier reports anchor_unpaid.",
         "query": copy.deepcopy(nonzero["query"]), "trusted_headers": copy.deepcopy(nonzero["trusted_headers"]),
         "records": copy.deepcopy(nonzero["records"]),
         "expect": {"heights": [unpaid(nonzero["expect"]["heights"][0])],
                    "window": {"result": "present_unpaid", "unpaid_height": "4200203"}}},
        {"id": "window_three_heights_proven",
         "description": "Same inputs as da/absence.json#window_three_heights_proven. Absent at h0 and h0 + 1; at "
                        "h0 + 2 a candidate with a proven nonzero code is present unpaid. Absence over the window is "
                        "not proven, so a pending reference with this window is anchor_unpaid, never anchor_absent.",
         "query": copy.deepcopy(three["query"]), "trusted_headers": copy.deepcopy(three["trusted_headers"]),
         "records": copy.deepcopy(three["records"]),
         "expect": {"heights": [copy.deepcopy(three["expect"]["heights"][0]),
                                copy.deepcopy(three["expect"]["heights"][1]),
                                unpaid(three["expect"]["heights"][2])],
                    "window": {"result": "present_unpaid", "unpaid_height": "4200203"}}},
        {"id": "window_unpaid_with_unproven_height",
         "description": "No proof for h0; absent at h0 + 1; present unpaid at h0 + 2. A present-unpaid height decides "
                        "the window ahead of a height not proven.",
         "query": query("4200201", "4200203"), "trusted_headers": copy.deepcopy(trusted),
         "records": [copy.deepcopy(rec["4200202"]), copy.deepcopy(rec["4200203"])],
         "expect": {"heights": [{"height": "4200201", "result": "unproven", "rule": "none",
                                 "why": "no proof for this height"},
                                copy.deepcopy(hts["4200202"]), unpaid(hts["4200203"])],
                    "window": {"result": "present_unpaid", "unpaid_height": "4200203"}}},
        {"id": "window_paid_after_unpaid",
         "description": "Present unpaid at h0, absent at h0 + 1, present with a proven code 0 at h0 + 2. A paid anchor "
                        "decides the window ahead of an unpaid one: the proof is used as evidence at H = h0 + 2.",
         "query": query("4200203", "4200205"), "trusted_headers": copy.deepcopy(trusted),
         "records": [copy.deepcopy(rec[h]) for h in ("4200203", "4200204", "4200205")],
         "expect": {"heights": [unpaid(hts["4200203"]), copy.deepcopy(hts["4200204"]), copy.deepcopy(hts["4200205"])],
                    "window": {"result": "present", "anchor_height": "4200205"}}},
    ]
    return {
        "format": FORMAT, "revision": REVISION, "generator": GENERATOR,
        "description": "Absence proofs under spec revision v1.0.3 (core 20.8). Same layout as the synthetic cases of "
                       "da/absence.json (query, trusted_headers, kind 14 records, expect per height and for the "
                       "window), on the chain of that file (its blocks). New per-height result present_unpaid: "
                       "every candidate's code proven and none 0; a height with a candidate is never absent. New "
                       "window result present_unpaid with unpaid_height, the first such height; order: present, "
                       "present_unpaid, absent at every height, otherwise unproven. Cases with an id of "
                       "da/absence.json replace that case (spec/vectors/SUPERSEDED.json) on byte-identical inputs.",
        "chain_id": old["chain_id"], "pff_namespace": old["pff_namespace"], "cases": cases,
    }


def verify_case(cid: str, description: str, absence: dict, refs: list, anchor: dict, report: dict,
                trusted_head: str = "4200127", evidence: dict | None = None, needs_results: bool = False) -> dict:
    c = {"id": cid, "description": description, "decision": "decision_pending_fibre",
         "authorization": "authorization_fast_fibre", "trusted_head": trusted_head}
    if evidence:
        c["evidence"] = evidence
    if needs_results:
        c["needs_results"] = True
    c["absence"] = [{"height": h, "result": r} for h, r in absence.items()]
    c["refs"] = refs
    status = anchor["status"]
    verdict, code = ("invalid", "1") if status == "fail" else ("unchecked", "2") if status == "unchecked" else \
        ("valid", "0")
    c["expect"] = {"authorization": {"status": "pass"}, "anchor": anchor,
                   "report": {"version": "1", "mode": "fast", "h0": "4200123", "anchor_deadline": "4200126",
                              **report},
                   "verdict": verdict, "exit": code}
    return c


def verify_file() -> dict:
    a, u, p = "absent", "present_unpaid", "present"
    cases = [
        verify_case("fast_unpaid_in_window",
                    "No evidence; the absence proofs show every height absent except h0 + 2, where a candidate with a "
                    "proven nonzero code is present unpaid. Up to v1.0.2 that height read absent and the verdict was "
                    "invalid (anchor_absent); since v1.0.3 it is unchecked, anchor_unpaid.",
                    {"4200123": a, "4200124": a, "4200125": u, "4200126": a},
                    ["da/absence_v1.0.3.json#window_three_heights_proven"],
                    {"status": "unchecked", "reason": "anchor_unpaid", "unpaid_height": "4200125"},
                    {"publication": "unknown"}),
        verify_case("fast_unpaid_with_unproven_height",
                    "No evidence; no proof for h0 + 1; present unpaid at the deadline. anchor_unpaid names the unpaid "
                    "height ahead of the height not proven.",
                    {"4200123": a, "4200125": a, "4200126": u},
                    ["da/absence_v1.0.3.json#window_unpaid_with_unproven_height"],
                    {"status": "unchecked", "reason": "anchor_unpaid", "unpaid_height": "4200126"},
                    {"publication": "unknown"}),
        verify_case("fast_paid_after_unpaid",
                    "No evidence; present unpaid at h0 + 1 and present with code 0 at h0 + 2: the paid anchor decides, "
                    "used as evidence, which the verifier cannot build in full here.",
                    {"4200123": a, "4200124": u, "4200125": p, "4200126": a},
                    ["da/absence_v1.0.3.json#window_paid_after_unpaid"],
                    {"status": "unchecked", "reason": "evidence_unavailable"},
                    {"anchor_height": "4200125", "publication": "unknown"}),
        verify_case("fast_late_evidence_unpaid_in_window",
                    "Evidence at H = deadline + 1 verifies; inside the window h0 + 1 is present unpaid. The payload was "
                    "included inside the window, so absence is not proven: anchor_unpaid, never anchor_absent.",
                    {"4200123": a, "4200124": u, "4200125": a, "4200126": a},
                    ["da/absence_v1.0.3.json#fibre_candidate_nonzero_code"],
                    {"status": "unchecked", "reason": "anchor_unpaid", "unpaid_height": "4200124"},
                    {"anchor_height": "4200127", "publication": "unknown"},
                    evidence={"height": "4200127", "verifies": True}),
        verify_case("fast_unpaid_results_wait",
                    "No evidence; present unpaid at h0 + 1, and the deadline height's results proof waits for the "
                    "header at deadline + 1, which header trust does not reach yet: anchor_pending decides first.",
                    {"4200123": a, "4200124": u, "4200125": a},
                    [],
                    {"status": "unchecked", "reason": "anchor_pending"},
                    {"publication": "unknown"}, trusted_head="4200126", needs_results=True),
    ]
    return {
        "format": FORMAT, "revision": REVISION, "generator": GENERATOR,
        "description": "Verifier outcomes of the authorization and anchor checks under spec revision v1.0.3 (core "
                       "20.6), in the layout of the cases of v1/verify.json; decision and authorization name records "
                       "of records_from. absence gives the per-height results, with the new value present_unpaid "
                       "(core 20.8, AB5); a height of [h0, deadline] not listed has no proof. The anchor check of an "
                       "anchor_unpaid outcome carries unpaid_height.",
        "records_from": "v1/verify.json", "window": "3", "cases": cases,
    }


def reasons_file() -> dict:
    return {
        "format": FORMAT, "revision": REVISION, "generator": GENERATOR,
        "description": "Reasons added by spec revision v1.0.3, in the layout of verifier/reasons.json. The enum of "
                       "v1.0.3 is the reasons of extends plus these; the cases of extends stay as they are.",
        "extends": "verifier/reasons.json",
        "reasons": [{"name": "anchor_unpaid", "group": "configuration", "checks": ["anchor"],
                     "meaning": "Anchor included, non-zero result code; not confirmable by v1.0 verifiers. Pending "
                                "reference, no evidence inside the window, and an absence proof shows a PFF candidate "
                                "at a height of [h0, anchor_deadline] whose result code is proven non-zero, with no "
                                "height showing one with code 0. Names the first such height.",
                     "advice": "none in v1.0 (a v1.1 verifier confirms inclusion without the code); another archive "
                               "copy or --absence-source if a paid anchor may sit at a height not proven"}],
        "cases": [{"id": "anchor_unpaid",
                   "description": "Fast mode: no evidence, and an in-window candidate whose result code is proven "
                                  "non-zero.",
                   "setup": {}, "refs": ["v1/verify_v1.0.3.json#fast_unpaid_in_window"],
                   "expect": {"check": "anchor", "status": "unchecked", "reason": "anchor_unpaid",
                              "record_state": "authorized", "verdict": "unchecked", "exit": "2"}}],
        "boundary": [],
    }


def build() -> dict:
    return {"da/absence_v1.0.3.json": absence_file(), "v1/verify_v1.0.3.json": verify_file(),
            "verifier/reasons_v1.0.3.json": reasons_file()}


def text(obj: dict) -> str:
    return json.dumps(obj, indent=2, ensure_ascii=True) + "\n"


def main() -> int:
    check = "--check" in sys.argv
    bad = 0
    for rel, obj in build().items():
        path = VECTORS / rel
        if check:
            if not path.exists() or path.read_text() != text(obj):
                print(f"differs: {rel}", file=sys.stderr)
                bad = 1
        else:
            path.write_text(text(obj))
            print(f"wrote {rel}")
    return bad


if __name__ == "__main__":
    sys.exit(main())
