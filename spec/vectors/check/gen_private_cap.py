#!/usr/bin/env python3
"""Generates spec/vectors/policy/private_cap.json: well-formed kind 15 records around the cap of the kind.

The cap of kind 15 is 69,760 bytes (core 19.2), checked at core 19.1 step 4, after the header and before
the field limits of step 5. The envelope limit of plaintext kind 5 is 69,632 bytes, so the largest kind 15
record a reader accepts is 69,680 bytes: no record at the cap itself is accepted. The file pins:

- private_action_max: 69,680 bytes, envelope 69,632, accepted;
- private_action_envelope_69633: 69,681 bytes, ErrFieldSize (the envelope limit, not the cap);
- private_at_cap: exactly 69,760 bytes, ErrFieldSize (the cap passes: it is inclusive);
- private_over_cap_well_formed: 69,761 bytes, envelope 69,713, ErrTooLarge (step 4 before step 5).

Additive vector file under the v1.0 freeze: no existing byte string changes.

Usage: python3 spec/vectors/check/gen_private_cap.py [--out DIR]
"""

from __future__ import annotations

import sys

sys.dont_write_bytecode = True

import hashlib  # noqa: E402
import json  # noqa: E402
from pathlib import Path  # noqa: E402

import policy_v1 as P  # noqa: E402
import records as R  # noqa: E402
from vecjson import pattern_bytes  # noqa: E402

VECTORS = Path(__file__).resolve().parents[1]
REL = "policy/private_cap.json"
PATTERN = "affine-7-3"
HASH = hashlib.sha256(b"edicta private cap vector|action_hash").digest()


def record(envelope_size: int) -> bytes:
    return P.record(15, plaintext_kind=5, hash=HASH, envelope=pattern_bytes(PATTERN, envelope_size))


ACCEPTED = [("private_action_max", "Kind 15, plaintext kind 5, envelope of 69,632 bytes (the limit of plaintext "
             "kind 5): 69,680 bytes, the largest kind 15 record any reader accepts.", 69632)]
REJECTED = [
    ("private_action_envelope_69633", "Kind 15, plaintext kind 5, envelope of 69,633 bytes: 69,681 bytes, under "
     "the cap, refused by the envelope limit.", 69633, "ErrFieldSize"),
    ("private_at_cap", "Kind 15, plaintext kind 5, exactly 69,760 bytes (envelope 69,712): the cap is inclusive, so "
     "the size passes and the envelope limit refuses.", 69712, "ErrFieldSize"),
    ("private_over_cap_well_formed", "Kind 15, plaintext kind 5, 69,761 bytes (envelope 69,713), well formed: the "
     "cap of the kind refuses it before the envelope limit is checked.", 69713, "ErrTooLarge"),
]
SIZES = {"private_action_max": 69680, "private_action_envelope_69633": 69681, "private_at_cap": 69760,
         "private_over_cap_well_formed": 69761}


def policy_cause(b: bytes):
    try:
        P.decode_record(b)
    except P.PolicyError as e:
        return e.cause
    return None


def build() -> dict:
    cases, rejects = [], []
    for i, d, n in ACCEPTED:
        b = record(n)
        assert len(b) == SIZES[i] and R.cause(b) is None and policy_cause(b) is None, i
        r = P.decode_record(b)
        cases.append({"id": i, "description": d, "kind": "15", "path": r["path"], "key_hex": HASH.hex(),
                      "plaintext_kind": "5", "envelope_pattern": PATTERN, "envelope_size": str(n),
                      "record_size": str(len(b)), "record_cbor_hex": b.hex()})
    for i, d, n, cause in REJECTED:
        b = record(n)
        assert len(b) == SIZES[i] and R.cause(b) == cause and policy_cause(b) == cause, i
        rejects.append({"id": i, "description": d, "envelope_pattern": PATTERN, "envelope_size": str(n),
                        "record_size": str(len(b)), "record_cbor_hex": b.hex(), "expect_error": "archive.ErrCorrupt",
                        "cause": cause})
    return {REL: {
        "format": "edicta-policy-vectors/v1",
        "revision": "policy-v1.0",
        "generator": "spec/vectors/check/gen_private_cap.py",
        "description": "Kind 15 records around the cap of the kind (69,760 bytes) and the envelope limit of "
                       "plaintext kind 5 (69,632 bytes). Every record is {1: 1, 2: 15, 3: 5, 4: hash, 5: envelope}; "
                       "the envelope is opaque to the reader and is the affine-7-3 pattern of envelope_size bytes.",
        "cap": "69760",
        "envelope_limit_plaintext_kind_5": "69632",
        "cases": cases,
        "reject": rejects,
    }}


def render() -> dict:
    return {rel: json.dumps(obj, indent=2, ensure_ascii=True) + "\n" for rel, obj in build().items()}


def main() -> int:
    out = Path(sys.argv[sys.argv.index("--out") + 1]).resolve() if "--out" in sys.argv else VECTORS
    for rel, text in render().items():
        p = out / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
        print(f"wrote {p}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
