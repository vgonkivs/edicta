#!/usr/bin/env python3
"""Verifies spec/vectors/verifier/reasons.json (v1.0-s1).

- the reason enum: unique lower-case names, known groups and checks;
- every reason has at least one case, and every case's reason is in the enum
  and allowed on the check that carries it;
- the outcome rule: an unchecked check gives verdict unchecked (exit 2),
  except that an unknown record state never becomes not_authorized, and that
  a reason carried only by gate_integrity (other than gate_equivocation)
  leaves the verdict valid (exit 0); a fail
  gives invalid (exit 1); no unchecked case expects invalid;
- every ref resolves to a vector id in the named file;
- the execution reasons agree with execution_outcomes.json (the referenced
  case is unchecked with that cause), and every unchecked cause there is in
  the enum;
- the generator reproduces the file byte for byte.

Usage: python3 spec/vectors/check/check_verifier_reasons.py [--file FILE]
(with --file, the generator comparison is skipped)
"""

from __future__ import annotations

import sys

sys.dont_write_bytecode = True

import json
import re
from pathlib import Path

import gen_verifier_reasons as gen

HERE = Path(__file__).resolve().parent
VECTORS = HERE.parent
FILE = VECTORS / "verifier" / "reasons.json"
CHECKS = {"decision", "envelope", "action", "authorization", "payload", "anchor", "anchor_time", "header_trust",
          "receipt", "retention_replay", "execution", "policy", "gate_integrity", "any"}
GROUPS = {"archive", "configuration", "header", "dependency", "input", "run", "execution", "policy", "integrity"}


class Failure(Exception):
    pass


def expect(cond: bool, msg: str):
    if not cond:
        raise Failure(msg)


def ids_in(rel: str) -> set:
    d = json.loads((VECTORS / rel).read_text())
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


def check(path: Path) -> str:
    raw = path.read_text()
    f = json.loads(raw)
    if path == FILE:
        expect(raw == json.dumps(gen.build(), indent=2, ensure_ascii=True) + "\n", "generator output differs")
    expect(f["format"] == "edicta-vectors/v1" and f["revision"] == "v1.0-s1", "format or revision")
    expect(set(f) == {"format", "revision", "generator", "description", "reasons", "cases", "boundary"}, "keys")
    enum = {}
    for r in f["reasons"]:
        expect(set(r) == {"name", "group", "checks", "meaning", "advice"}, f"reason keys {r.get('name')}")
        expect(re.fullmatch(r"[a-z][a-z0-9_]*", r["name"]) is not None and r["name"] not in enum, f"name {r['name']}")
        expect(r["group"] in GROUPS and set(r["checks"]) <= CHECKS and r["checks"], f"reason {r['name']}")
        enum[r["name"]] = r
    for need in ("payload_unavailable", "source_corrupt", "chain_mismatch", "header_disagreement", "anchor_pending",
                 "absence_unproven", "anchor_result_unproven", "policy_private", "principal_scheme_unsupported"):
        expect(need in enum, f"missing reason {need}")
    seen_ids, used, ref_cache = set(), set(), {}

    def check_refs(c):
        for ref in c["refs"]:
            rel, _, ident = ref.partition("#")
            if rel not in ref_cache:
                ref_cache[rel] = ids_in(rel)
            expect(ident in ref_cache[rel], f"{c['id']}: unresolved ref {ref}")

    for c in f["cases"] + f["boundary"]:
        expect(set(c) <= {"id", "description", "setup", "refs", "expect", "request"} and c["id"] not in seen_ids,
               f"case {c.get('id')}")
        seen_ids.add(c["id"])
        check_refs(c)
        e = c["expect"]
        expect(set(e) == {"check", "status", "reason", "record_state", "verdict", "exit"}, f"{c['id']}: expect keys")
        expect(e["check"] in CHECKS - {"any"}, f"{c['id']}: check")
    for c in f["cases"]:
        e = c["expect"]
        if e["status"] == "violated":
            expect(e["check"] == "gate_integrity" and e["reason"] in ("gate_equivocation",
                                                                      "gate_signed_inconsistent_private_part")
                   and e["verdict"] == "unchecked" and e["exit"] == "5", f"{c['id']}: a violation gives unchecked, exit 5")
            used.add(e["reason"])
            continue
        expect(e["status"] == "unchecked" and e["reason"] in enum, f"{c['id']}: reason")
        r = enum[e["reason"]]
        expect(e["check"] in r["checks"] or "any" in r["checks"], f"{c['id']}: {e['reason']} not on {e['check']}")
        expect(e["record_state"] in ("authorized", "unknown"), f"{c['id']}: state")
        if e["check"] == "gate_integrity" and r["checks"] == ["gate_integrity"]:
            # The gate's history was not fully read; the decision's own checks are untouched.
            expect(r["group"] == "integrity" and e["record_state"] == "authorized" and e["verdict"] == "valid"
                   and e["exit"] == "0", f"{c['id']}: an integrity-only unchecked keeps the verdict")
        else:
            expect(e["verdict"] == "unchecked" and e["exit"] == "2", f"{c['id']}: an unchecked check gives unchecked")
        used.add(e["reason"])
    for c in f["boundary"]:
        e = c["expect"]
        expect(e["status"] == "fail" and e["reason"] is None and e["verdict"] == "invalid" and e["exit"] == "1",
               f"{c['id']}: boundary")
        expect(c["refs"], f"{c['id']}: a boundary case needs concrete bytes")
    expect(used == set(enum), f"reasons without a case: {sorted(set(enum) - used)}")

    ex = json.loads((VECTORS / "verifier" / "execution_outcomes.json").read_text())
    by = {c["id"]: c for c in ex["cases"]}
    for c in f["cases"]:
        for ref in c["refs"]:
            if ref.startswith("verifier/execution_outcomes.json#"):
                xc = by[ref.partition("#")[2]]
                expect(xc["expect"]["cause"] == c["expect"]["reason"], f"{c['id']}: cause differs from reason")
    for xc in ex["cases"]:
        if xc["expect"]["execution"] == "unchecked":
            expect(xc["expect"]["cause"] in enum, f"execution_outcomes {xc['id']}: cause not in the enum")
    return f"{len(enum)} reasons, {len(f['cases'])} cases, {len(f['boundary'])} boundary"


def main() -> int:
    path = Path(sys.argv[sys.argv.index("--file") + 1]).resolve() if "--file" in sys.argv else FILE
    try:
        summary = check(path)
    except (Failure, KeyError, ValueError) as e:
        print(f"FAIL (reasons.json): {type(e).__name__}: {e}", file=sys.stderr)
        return 1
    pby = {}
    for rel in ("policy/verify.json", "policy/private.json"):
        pby |= {f"{rel}#{c['id']}": c for c in json.loads((VECTORS / rel).read_text())["cases"]}
    v1f = json.loads((VECTORS / "v1" / "verify.json").read_text())
    vby = {f"v1/verify.json#{c['id']}": c for c in v1f["cases"]}
    s1f = json.loads((VECTORS / "v1" / "verify_anchor_result.json").read_text())
    vby |= {f"v1/verify_anchor_result.json#{c['id']}": c for c in s1f["cases"]}
    aby = {f"v1/verify.json#{c['id']}": c for c in v1f["action_cases"]}
    f = json.loads(path.read_text())
    try:
        expect("anchor" in next(r for r in f["reasons"] if r["name"] == "blocked")["checks"], "blocked on anchor")
        for c in f["cases"] + f["boundary"]:
            for ref in c["refs"]:
                if ref in vby:
                    ve, e = vby[ref]["expect"], c["expect"]
                    expect(ve["exit"] == e["exit"] and ve["verdict"] == e["verdict"], f"{c['id']}: verdict differs")
                    vc = ve[e["check"]]
                    expect(vc["status"] == e["status"] and vc.get("reason") == e["reason"], f"{c['id']}: check differs")
                if ref in aby:
                    ae, e = aby[ref]["expect"]["action"], c["expect"]
                    expect(e["check"] == "action" and ae["status"] == e["status"] and ae.get("reason") == e["reason"],
                           f"{c['id']}: action check differs")
                if ref in pby:
                    pe = pby[ref]["expect"]
                    e = c["expect"]
                    expect(pe["exit"] == e["exit"] and pe["verdict"] == e["verdict"], f"{c['id']}: verdict differs")
                    if e["check"] == "policy" and e["status"] == "unchecked":
                        expect(pe["policy"]["reason"] == e["reason"], f"{c['id']}: reason differs")
                    if e["check"] == "gate_integrity":
                        expect(pe["gate_integrity"]["status"] == e["status"]
                               and pe["gate_integrity"]["reason"] == e["reason"], f"{c['id']}: integrity differs")
    except (Failure, KeyError) as ex:
        print(f"FAIL (reasons.json): {ex}", file=sys.stderr)
        return 1
    print(f"OK (reasons.json, v1.0-s1): {summary}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
