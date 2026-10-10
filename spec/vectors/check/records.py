"""The general archive record decoder of format 1 (core 19.1), for every assigned kind.

One reader decodes every record, whatever suite its vector sits in: the header
steps (size, generic well-formedness, map, format, kind) run once in the core
order, and only then does the kind's schema decide. Core kinds go through
archive.py, the policy kinds 7 to 12 through policy_v1.py. A suite-local reader
that refuses a kind it does not know as an unassigned one gives another cause
than the general reader for the same bytes; this module exists so that the
generators and the cross-suite check compute causes the same way.

The kind table is read from the frozen core text, so that a decoder table that
drifts from it fails loudly instead of silently re-deriving the expectations.
"""

from __future__ import annotations

import re
from pathlib import Path

import archive as A
import policy_v1 as P
from cbor_strict import CBORError
from edicta import Reject

SPEC = Path(__file__).resolve().parents[2] / "decision-commitment-v1.md"
POLICY_KINDS = frozenset(range(7, 13))


def frozen_kind_table() -> tuple[frozenset, frozenset]:
    """(assigned, unassigned) kinds of format 1 from the `kind` row of core 19.1 and its strict decoding step 3."""
    text = SPEC.read_text()
    row = next(line for line in text.splitlines() if line.startswith("| 2 | `kind` | uint enum |"))
    unassigned = set()
    for m in re.finditer(r"([\d, and]+?) (?:are|is) (?:not assigned|reserved)", row):
        unassigned |= {int(x) for x in re.findall(r"\d+", m.group(1))}
    step = re.search(r"then `kind` outside ([\d,\sto]+?)\s+\(`ErrInvalidEnum`\)", text)
    assigned = set()
    for part in re.split(r",\s*", " ".join(step.group(1).split())):
        lo, _, hi = part.partition(" to ")
        assigned |= set(range(int(lo), int(hi or lo) + 1))
    if assigned & unassigned or assigned | unassigned != set(range(1, max(assigned | unassigned) + 1)):
        raise ValueError(f"core 19.1 kind table unreadable: {sorted(assigned)} / {sorted(unassigned)}")
    return frozenset(assigned), frozenset(unassigned)


ASSIGNED, UNASSIGNED = frozen_kind_table()


def header(data: bytes) -> int:
    """Core 19.1 steps 1 to 3; returns the kind or raises Reject with the cause."""
    if len(data) > A.MAX_RECORD_SIZE:
        raise Reject("ErrTooLarge", f"{len(data)} bytes")
    try:
        it = A._generic(data)
    except CBORError as e:
        raise Reject(e.sentinel, e.detail)
    if it.major != 5:
        raise Reject("ErrWrongType", "record: expected map")
    top = {k.value: v for k, v in it.value}
    for key, name in ((1, "format"), (2, "kind")):
        if key not in top:
            raise Reject("ErrMissingField", f"record.{name}")
        if top[key].major != 0:
            raise Reject("ErrWrongType", f"record.{name}")
    if top[1].value != A.FORMAT:
        raise Reject("ErrUnsupportedVersion", f"format {top[1].value}")
    if top[2].value not in ASSIGNED:
        raise Reject("ErrInvalidEnum", f"kind {top[2].value}")
    return top[2].value


def decode(data: bytes) -> int:
    """Decodes one record of any assigned kind; returns its kind or raises Reject with the cause."""
    kind = header(data)
    if kind in POLICY_KINDS:
        try:
            P.decode_record(data)
        except P.PolicyError as e:
            raise Reject(e.cause, "policy record")
        return kind
    return A.decode_record(data)["kind"]


def cause(data: bytes) -> str | None:
    try:
        decode(data)
    except Reject as e:
        return e.sentinel
    return None
