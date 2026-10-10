#!/usr/bin/env python3
"""Cross-suite check of the archive record vectors (core 19.1, policy 12).

Every suite that lists format 1 records (core v1/archive.json and
archive/records.json, policy/archive.json, policy/private_cap.json, and the
record pools of policy/verify.json and policy/private.json) is run through the
one general reader of records.py together:

- each listed record gives exactly its expected outcome (accepted, or the
  expected cause) under that reader;
- a record listed by more than one suite has the same expectation in each;
- the kind tables the decoders and the vector files carry equal the frozen
  core 19.1 table, so a kind the core assigns is never expected to be refused
  as unassigned, and an unassigned kind is never accepted.

Usage: python3 spec/vectors/check/check_records.py
"""

from __future__ import annotations

import sys

sys.dont_write_bytecode = True

import json  # noqa: E402
from pathlib import Path  # noqa: E402

import archive as A  # noqa: E402
import policy_v1 as P  # noqa: E402
import records as R  # noqa: E402

VECTORS = Path(__file__).resolve().parents[1]
ACCEPT = "accepted"


class Failure(Exception):
    pass


def expect(cond: bool, what: str):
    if not cond:
        raise Failure(what)


def collect() -> dict:
    """{record bytes: [(where, expected outcome)]} over every suite."""
    seen: dict = {}

    def add(b: bytes, where: str, outcome: str):
        seen.setdefault(b, []).append((where, outcome))

    for rel in ("v1/archive.json", "archive/records.json", "policy/archive.json", "policy/private_cap.json"):
        f = json.loads((VECTORS / rel).read_text())
        for c in f["cases"]:
            if "record_cbor_hex" not in c:
                continue
            add(bytes.fromhex(c["record_cbor_hex"]), f"{rel} {c['id']}", ACCEPT)
        for r in f["reject"]:
            if "record_cbor_hex" in r:
                expect(r["expect_error"] == "archive.ErrCorrupt", f"{rel} {r['id']}: expect_error")
                add(bytes.fromhex(r["record_cbor_hex"]), f"{rel} {r['id']}", r["cause"])
    for rel in ("policy/verify.json", "policy/private.json"):
        for path, hexed in json.loads((VECTORS / rel).read_text())["records"].items():
            add(bytes.fromhex(hexed), f"{rel} records {path}", ACCEPT)
    return seen


def check_tables():
    expect(set(A.SCHEMAS) | R.POLICY_KINDS == R.ASSIGNED, "core and policy decoder kinds = core 19.1 assigned kinds")
    expect(set(A.UNASSIGNED_KINDS) == R.UNASSIGNED, "archive.py unassigned kinds = core 19.1")
    expect(set(P.KIND_NAMES) <= R.ASSIGNED, "policy_v1 kinds are assigned in core 19.1")
    v1 = json.loads((VECTORS / "v1/archive.json").read_text())
    expect({int(k) for k in v1["unassigned_kinds"]} == R.UNASSIGNED, "v1/archive.json unassigned_kinds")
    pol = json.loads((VECTORS / "policy/archive.json").read_text())
    expect({int(k) for k in pol["kinds"]} <= R.ASSIGNED, "policy/archive.json kinds are assigned")
    expect({int(k) for k in pol["reserved_kinds"]} <= R.UNASSIGNED, "policy/archive.json reserved_kinds are unassigned")
    core = json.loads((VECTORS / "archive/records.json").read_text())
    expect({int(k) for k in core["params"]["kinds"].values()} <= R.ASSIGNED, "archive/records.json kinds are assigned")


def main() -> int:
    try:
        check_tables()
        seen = collect()
        shared = 0
        for b, exps in seen.items():
            outcomes = {o for _, o in exps}
            where = ", ".join(w for w, _ in exps)
            expect(len(outcomes) == 1, f"conflicting expectations for one record: {exps}")
            if len({w.split(' ', 1)[0] for w, _ in exps}) > 1:
                shared += 1
            got = R.cause(b) or ACCEPT
            want = outcomes.pop()
            expect(got == want, f"{where}: expected {want}, the general reader gives {got}")
    except Failure as e:
        print(f"FAIL (records): {e}", file=sys.stderr)
        return 1
    print(f"OK (records): {len(seen)} distinct records through one reader, {shared} listed by more than one suite, "
          f"kind tables = core 19.1 (assigned {sorted(R.ASSIGNED)}, unassigned {sorted(R.UNASSIGNED)})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
