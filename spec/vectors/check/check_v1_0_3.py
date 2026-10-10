#!/usr/bin/env python3
"""Checks spec revision v1.0.3 (security): the frozen files under the current rules, and the new files.

- spec/vectors/SUPERSEDED.json: every entry names an existing case of an existing file and a replacing case
  that exists; it is the only way a frozen case is skipped below;
- da/absence.json under the v1.0.3 rules: every case not listed gives its frozen expectation; every listed
  case no longer does (so the list holds exactly the cases the revision changed);
- da/absence_v1.0.3.json: every case under the v1.0.3 rules, a replacing case on inputs byte-identical to the
  case it replaces, and the new per-height and window results covered;
- v1/verify.json under the v1.0.3 rules (no case listed: each gives its frozen outcome) and
  v1/verify_v1.0.3.json on the records of v1/verify.json; their refs into the absence files read the same
  window, a ref into a listed case resolved through the list;
- verifier/reasons_v1.0.3.json: the enum of verifier/reasons.json plus its reasons, checked as one enum, its
  cases against v1/verify_v1.0.3.json;
- the generator (gen_v1_0_3.py) reproduces the three new files byte for byte.

Usage: python3 spec/vectors/check/check_v1_0_3.py
"""

from __future__ import annotations

import sys

sys.dont_write_bytecode = True

import json
from pathlib import Path

import check_absence as CA
import check_archive_v1 as CV
import check_verifier_reasons as CR
import gen_v1_0_3 as gen

VECTORS = Path(__file__).resolve().parent.parent
REVISION = "v1.0.3"


class Failure(Exception):
    pass


def expect(cond: bool, msg: str):
    if not cond:
        raise Failure(msg)


def load(rel: str) -> dict:
    return json.loads((VECTORS / rel).read_text())


def case_ids(d) -> set:
    out = set()

    def walk(x):
        if isinstance(x, dict):
            if isinstance(x.get("id"), str):
                out.add(x["id"])
            for v in x.values():
                walk(v)
        elif isinstance(x, list):
            for v in x:
                walk(v)
    walk(d)
    return out


def superseded() -> dict:
    """file -> {case: replaced_by}."""
    s = load("SUPERSEDED.json")
    expect(set(s) == {"format", "revision", "description", "entries"} and s["format"] == "edicta-vectors/v1",
           "SUPERSEDED.json keys")
    out = {}
    for e in s["entries"]:
        expect(set(e) == {"file", "case", "revision", "type", "replaced_by"} and e["type"] == "security",
               f"SUPERSEDED.json entry {e}")
        expect(e["case"] in case_ids(load(e["file"])), f"SUPERSEDED.json: no case {e['file']}#{e['case']}")
        rel, _, cid = e["replaced_by"].partition("#")
        expect(cid in case_ids(load(rel)), f"SUPERSEDED.json: no replacing case {e['replaced_by']}")
        expect(e["case"] not in out.setdefault(e["file"], {}), f"SUPERSEDED.json: {e['case']} twice")
        out[e["file"]][e["case"]] = e["replaced_by"]
    return out


def outcome_of(c: dict, chain_id: str) -> bool:
    try:
        CA.check_case(c, chain_id, CA.V1_0_3)
        return True
    except (CA.Failure, Failure):
        return False


def check_absence(sup: dict) -> str:
    old = load("da/absence.json")
    skip = sup.get("da/absence.json", {})
    ran = 0
    for c in old["synthetic"]:
        if c["id"] in skip:
            expect(not outcome_of(c, old["chain_id"]), f"absence.json {c['id']}: listed, but v1.0.3 agrees with it")
            continue
        CA.check_case(c, old["chain_id"], CA.V1_0_3)
        ran += 1
    for c in old["live"]:
        expect(c["id"] not in skip, f"absence.json {c['id']}: a live case is listed")
        CA.check_case(c, old["live_source"]["chain_id"], CA.V1_0_3)
        ran += 1

    new = load("da/absence_v1.0.3.json")
    expect(new["format"] == "edicta-vectors/v1" and new["revision"] == REVISION, "absence_v1.0.3.json header")
    expect(set(new) == {"format", "revision", "generator", "description", "chain_id", "pff_namespace", "cases"},
           "absence_v1.0.3.json keys")
    expect(new["chain_id"] == old["chain_id"] and new["pff_namespace"] == old["pff_namespace"], "same chain")
    by_old = {c["id"]: c for c in old["synthetic"]}
    ids = [c["id"] for c in new["cases"]]
    expect(len(ids) == len(set(ids)), "absence_v1.0.3.json ids")
    for cid, repl in skip.items():
        expect(repl == f"da/absence_v1.0.3.json#{cid}", f"{cid}: replaced by {repl}")
    results = set()
    for c in new["cases"]:
        if c["id"] in by_old:
            expect(c["id"] in skip, f"{c['id']}: reuses an id of absence.json that is not listed")
            o = by_old[c["id"]]
            expect(all(c[k] == o[k] for k in ("query", "trusted_headers", "records")),
                   f"{c['id']}: inputs differ from the case it replaces")
        CA.check_case(c, new["chain_id"], CA.V1_0_3)
        results |= {x["result"] for x in c["expect"]["heights"]} | {c["expect"]["window"]["result"]}
    expect({"absent", "present", "present_unpaid", "unproven"} <= results, f"absence_v1.0.3.json coverage {results}")
    return f"absence.json {ran} cases under v1.0.3 ({len(skip)} superseded), absence_v1.0.3.json {len(ids)} cases"


def window_of(vc: dict) -> str:
    rep = vc["expect"]["report"]
    ab = {x["height"]: x["result"] for x in vc["absence"]}
    heights = [{"height": str(h), "result": ab.get(str(h), "unproven")}
               for h in range(int(rep["h0"]), int(rep["anchor_deadline"]) + 1)]
    return CA.window(heights, CA.V1_0_3)["result"]


def check_verify(sup: dict) -> str:
    old = load("v1/verify.json")
    skip = sup.get("v1/verify.json", {})
    files = {"da/absence.json": load("da/absence.json"), "da/absence_v1.0.3.json": load("da/absence_v1.0.3.json")}
    abs_cases = {rel: {c["id"]: c for c in (f.get("synthetic", []) + f.get("cases", []))} for rel, f in files.items()}

    def check_refs(vc: dict):
        for ref in vc.get("refs", []):
            rel, _, cid = ref.partition("#")
            if rel not in files or not cid:
                continue
            if cid in sup.get(rel, {}):
                # A frozen verify case is checked on its abstract per-height inputs; its ref into a superseded
                # case belongs to the revision of the frozen file, where check_absence.py reads it.
                continue
            expect(window_of(vc) == abs_cases[rel][cid]["expect"]["window"]["result"],
                   f"{vc['id']}: {ref} reads another way")

    ran = 0
    for c in old["cases"]:
        if c["id"] in skip:
            continue
        got = CV.outcome(c, old["records"], int(old["window"]), "v1.0.3")
        expect(got == c["expect"], f"verify.json {c['id']} under v1.0.3: {got} != {c['expect']}")
        check_refs(c)
        ran += 1
    new = load("v1/verify_v1.0.3.json")
    expect(new["format"] == "edicta-vectors/v1" and new["revision"] == REVISION, "verify_v1.0.3.json header")
    expect(set(new) == {"format", "revision", "generator", "description", "records_from", "window", "cases"},
           "verify_v1.0.3.json keys")
    recs = load(new["records_from"])["records"]
    reasons = set()
    for c in new["cases"]:
        got = CV.outcome(c, recs, int(new["window"]), "v1.0.3")
        expect(got == c["expect"], f"verify_v1.0.3.json {c['id']}: {got} != {c['expect']}")
        check_refs(c)
        reasons.add(c["expect"]["anchor"].get("reason"))
    expect({"anchor_unpaid", "evidence_unavailable", "anchor_pending"} <= reasons, "verify_v1.0.3.json coverage")
    expect(all(c["expect"]["verdict"] != "invalid" for c in new["cases"]
               if any(x["result"] == "present_unpaid" for x in c["absence"])),
           "an unpaid candidate in the window gives invalid")
    return f"verify.json {ran} cases under v1.0.3, verify_v1.0.3.json {len(new['cases'])} cases"


def check_reasons() -> str:
    old, add = load("verifier/reasons.json"), load("verifier/reasons_v1.0.3.json")
    expect(set(add) == {"format", "revision", "generator", "description", "extends", "reasons", "cases", "boundary"}
           and add["extends"] == "verifier/reasons.json", "reasons_v1.0.3.json keys")
    merged = {"format": add["format"], "revision": add["revision"], "generator": add["generator"],
              "description": add["description"], "reasons": old["reasons"] + add["reasons"],
              "cases": old["cases"] + add["cases"], "boundary": old["boundary"] + add["boundary"]}
    try:
        summary = CR.check_data(merged, REVISION)
    except CR.Failure as e:
        raise Failure(f"reasons v1.0.3: {e}")
    vby = {f"v1/verify_v1.0.3.json#{c['id']}": c for c in load("v1/verify_v1.0.3.json")["cases"]}
    for c in add["cases"]:
        for ref in c["refs"]:
            ve, e = vby[ref]["expect"], c["expect"]
            expect(ve["exit"] == e["exit"] and ve["verdict"] == e["verdict"], f"{c['id']}: verdict differs")
            vc = ve[e["check"]]
            expect(vc["status"] == e["status"] and vc.get("reason") == e["reason"], f"{c['id']}: check differs")
    return f"reasons {summary}"


def main() -> int:
    try:
        for rel, obj in gen.build().items():
            expect((VECTORS / rel).read_text() == gen.text(obj), f"{rel}: generator output differs")
        sup = superseded()
        out = [check_absence(sup), check_verify(sup), check_reasons()]
    except (Failure, CA.Failure, CV.Failure, KeyError, ValueError) as e:
        print(f"FAIL (v1.0.3): {type(e).__name__}: {e}", file=sys.stderr)
        return 1
    print(f"OK (v1.0.3): " + "; ".join(out) + "; generator output identical")
    return 0


if __name__ == "__main__":
    sys.exit(main())
