#!/usr/bin/env python3
"""Checks spec/vectors/policy/private_cap.json (kind 15 around the cap of the kind).

- The generator (gen_private_cap.py) reproduces the file byte for byte.
- Each record is rebuilt here from literal CBOR bytes (not from an encoder) and equals the listed hex.
- The expected outcome is derived here from the two frozen numbers and the decoding order (cap of the kind
  at step 4, envelope limit at step 5), and both the general record reader (records.py) and the policy
  reader (policy_v1.py) give it.

Usage: python3 spec/vectors/check/check_private_cap.py
"""

from __future__ import annotations

import sys

sys.dont_write_bytecode = True

import json  # noqa: E402
from pathlib import Path  # noqa: E402

import policy_v1 as P  # noqa: E402
import records as R  # noqa: E402
from vecjson import pattern_bytes  # noqa: E402

VECTORS = Path(__file__).resolve().parents[1]
REL = "policy/private_cap.json"
CAP = 69760
ENVELOPE_LIMIT_KIND_5 = 69632
ACCEPT = "accepted"


class Failure(Exception):
    pass


def expect(cond: bool, what: str):
    if not cond:
        raise Failure(what)


def literal(key: bytes, envelope: bytes) -> bytes:
    # {1: 1, 2: 15, 3: 5, 4: bstr 32, 5: bstr with a 4-byte length head}
    expect(65536 <= len(envelope) < 1 << 32 and len(key) == 32, "literal record shape")
    return (bytes([0xa5, 0x01, 0x01, 0x02, 0x0f, 0x03, 0x05, 0x04, 0x58, 0x20]) + key
            + bytes([0x05, 0x5a]) + len(envelope).to_bytes(4, "big") + envelope)


def rule(size: int, envelope_size: int) -> str:
    if size > CAP:
        return "ErrTooLarge"
    if envelope_size > ENVELOPE_LIMIT_KIND_5:
        return "ErrFieldSize"
    return ACCEPT


def policy_outcome(b: bytes) -> str:
    try:
        P.decode_record(b)
    except P.PolicyError as e:
        expect(e.sentinel == "archive.ErrCorrupt", "policy reader sentinel")
        return e.cause
    return ACCEPT


def main() -> int:
    try:
        import gen_private_cap as gen
        text = (VECTORS / REL).read_text()
        expect(gen.render()[REL] == text, f"{REL}: generator output differs")
        f = json.loads(text)
        expect(f["format"] == "edicta-policy-vectors/v1" and f["revision"] == "policy-v1.0", "format or revision")
        expect(int(f["cap"]) == CAP and int(f["envelope_limit_plaintext_kind_5"]) == ENVELOPE_LIMIT_KIND_5, "limits")
        rows = [(c, ACCEPT) for c in f["cases"]] + [(r, r["cause"]) for r in f["reject"]]
        seen = set()
        for c, want in rows:
            i = c["id"]
            b = bytes.fromhex(c["record_cbor_hex"])
            env = pattern_bytes(c["envelope_pattern"], int(c["envelope_size"]))
            key = bytes.fromhex(c["key_hex"]) if "key_hex" in c else b[10:42]
            expect(literal(key, env) == b, f"{i}: record bytes")
            expect(len(b) == int(c["record_size"]), f"{i}: record_size")
            expect(rule(len(b), len(env)) == want, f"{i}: expected {want}, the frozen limits give "
                                                   f"{rule(len(b), len(env))}")
            expect((R.cause(b) or ACCEPT) == want, f"{i}: general reader gives {R.cause(b)}")
            expect(policy_outcome(b) == want, f"{i}: policy reader gives {policy_outcome(b)}")
            if want == ACCEPT:
                expect(c["path"] == f"private/5/{key.hex()}", f"{i}: path")
            else:
                expect(c["expect_error"] == "archive.ErrCorrupt", f"{i}: expect_error")
            seen.add(want)
        sizes = sorted(len(bytes.fromhex(c["record_cbor_hex"])) for c, _ in rows)
        expect(sizes == [CAP - 80, CAP - 79, CAP, CAP + 1], f"sizes {sizes}")
        expect(seen == {ACCEPT, "ErrFieldSize", "ErrTooLarge"}, "outcomes covered")
    except Failure as e:
        print(f"FAIL (private cap): {e}", file=sys.stderr)
        return 1
    print(f"OK (private cap, policy-v1.0): {len(f['cases'])} accepted, {len(f['reject'])} reject, kind 15 cap "
          f"{CAP} inclusive, largest accepted {CAP - 80}; generator output identical")
    return 0


if __name__ == "__main__":
    sys.exit(main())
