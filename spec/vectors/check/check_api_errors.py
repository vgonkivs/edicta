#!/usr/bin/env python3
"""Verifies spec/vectors/api/errors.json (v0-draft.15) against the spec text and the core vectors.

- Every sentinel named in section 12 of the spec is either mapped (errors) or
  listed in not_api_visible, never both; codes are unique.
- The mapping equals the section 18.3 table of the spec, status by status and
  in match order; retryable follows the status; stored bytes only on 409 for
  ErrNonceUsed and ErrReceiptExists; ErrAnchorTooOld precedes ErrPayloadUnavailable.
- Every example decodes as canonical CBOR with its wrapper schema; 200
  responses carry objects that verify (Authorization, receipt, PublishResponse,
  Health); error bodies name a mapped code with its status and retryable flag;
  stored bytes are the referenced core objects.

Usage: python3 spec/vectors/check/check_api_errors.py [--dir DIR] [--core DIR] [--spec FILE]
"""

from __future__ import annotations

import sys

sys.dont_write_bytecode = True

import json
import re
from pathlib import Path

import edicta_publish_v0 as pr
from cbor_strict import CBORError, decode_strict, encode, to_plain
from edicta_v0 import (ID_CHARS, AuthorizationCheck, Reject, _schema_decode, decode_signed, verify_authorization,
                       verify_receipt)

HERE = Path(__file__).resolve().parent
VECTORS = HERE.parent


def arg(name: str, default: Path) -> Path:
    if name in sys.argv:
        return Path(sys.argv[sys.argv.index(name) + 1]).resolve()
    return default


DIR = arg("--dir", VECTORS / "api")
CORE = arg("--core", VECTORS / "v0")
SPEC = arg("--spec", VECTORS.parent / "decision-commitment-v0.md")
PLACEHOLDERS = {"commitment.ErrX", "pkg.ErrName"}
RETRYABLE = {425, 429, 503, 504}

AUTHORIZE_REQ = {1: ("envelope", "bstr", True, (1, 2176)), 2: ("action", "bstr", True, (1, 65536))}
AUTHORIZE_RESP = {1: ("signed_authorization", "bstr", True, (1, 256))}
RECORD_REQ = {1: ("envelope", "bstr", True, (1, 2176)), 2: ("rail_ref", "tstr", True, (1, 128, ID_CHARS)),
              3: ("executor_pubkey", "bstr", True, (32, 32)), 4: ("executor_signature", "bstr", True, (64, 64))}
RECORD_RESP = {1: ("signed_receipt", "bstr", True, (1, 512))}
ERROR = {1: ("code", "tstr", True, (1, 64, frozenset(ID_CHARS))), 2: ("message", "tstr", True, (0, 1024, None)),
         3: ("retryable", "uint", True, None), 4: ("stored", "bstr", False, (1, 512))}


class Failure(Exception):
    pass


def expect(cond: bool, msg: str):
    if not cond:
        raise Failure(msg)


def canonical(b: bytes):
    it = decode_strict(b)
    expect(encode(to_plain(it)) == b, "not canonical")
    return it


def decode(b: bytes, schema: dict, where: str) -> dict:
    it = canonical(b)
    if schema is ERROR:
        expect(it.major == 5, f"{where}: not a map")
        out = {}
        for k, v in it.value:
            expect(k.value in ERROR, f"{where}: key {k.value}")
            out[ERROR[k.value][0]] = v.value
        expect(all(n in out for n in ("code", "message", "retryable")), f"{where}: missing key")
        expect(isinstance(out["code"], str) and isinstance(out["message"], str) and out["retryable"] in (0, 1),
               f"{where}: types")
        return out
    return _schema_decode(it, schema, where)


def spec_section(text: str, start: str, end: str | None) -> str:
    a = text.index(start)
    return text[a:text.index(end, a)] if end else text[a:]


def check_mapping(f: dict, spec: str) -> dict:
    sec12 = spec_section(spec, "## 12. Sentinel errors", "## 13. Test vectors")
    names = set(re.findall(r"`((?:[a-z]+\.)?Err[A-Za-z0-9]+)`", sec12)) - PLACEHOLDERS
    codes = [e["code"] for e in f["errors"]]
    expect(len(codes) == len(set(codes)), "duplicate codes")
    hidden = [n["name"] for n in f["not_api_visible"]]
    expect(len(hidden) == len(set(hidden)) and not set(hidden) & set(codes), "not_api_visible overlaps or repeats")
    missing = names - set(codes) - set(hidden)
    expect(not missing, f"section 12 sentinels neither mapped nor hidden: {sorted(missing)}")
    extra = (set(codes) | set(hidden)) - names
    expect(not extra, f"names not in section 12: {sorted(extra)}")
    expect(all(n["reason"] for n in f["not_api_visible"]), "hidden name without reason")

    statuses = {int(k): int(v["retryable"]) for k, v in f["statuses"].items()}
    expect({s for s, r in statuses.items() if r} == RETRYABLE, "retryable statuses")
    for e in f["errors"]:
        st = int(e["status"])
        expect(st in statuses and int(e["retryable"]) == statuses[st], f"{e['code']}: retryable")
        want_stored = {"ErrNonceUsed": "authorization", "ErrReceiptExists": "receipt"}.get(e["code"], "none")
        expect(e["stored"] == want_stored, f"{e['code']}: stored")
        expect(set(e["endpoints"]) <= {v["path"] for v in f["endpoints"].values()} and e["endpoints"], f"{e['code']}: endpoints")
    expect(codes.index("ErrAnchorTooOld") < codes.index("ErrPayloadUnavailable"), "ErrAnchorTooOld must match first")
    expect(codes[-1] == "edictaapi.ErrInternal", "ErrInternal is the catch-all, last")

    sec18 = spec_section(spec, "## 18. HTTP API", None)
    table = spec_section(sec18, "| Status | Codes, in match order |", "\n\n")
    spec_order = []
    for line in table.splitlines()[2:]:
        cells = [c.strip() for c in line.strip("|").split("|")]
        st = int(cells[0])
        for code in re.findall(r"`([^`]+)`", cells[1]):
            spec_order.append((code, st))
    expect(spec_order == [(e["code"], int(e["status"])) for e in f["errors"]],
           "errors.json differs from the section 18.3 table (codes, statuses or order)")
    return {e["code"]: e for e in f["errors"]}


def check_examples(f: dict, by_code: dict):
    valid = {c["id"]: c for c in json.loads((CORE / "valid.json").read_text())["cases"]}
    auth = {c["id"]: c for c in json.loads((CORE / "authorization.json").read_text())["cases"]}
    rcp = {c["id"]: c for c in json.loads((CORE / "receipt.json").read_text())["cases"]}
    pub = json.loads((DIR / "publish_request.json").read_text())
    pub_cases = {c["id"]: c for c in pub["cases"]}
    pub_resp = {c["id"]: c for c in pub["response"]}
    for x in f["examples"]:
        w = x["id"]
        resp = bytes.fromhex(x["response_cbor_hex"])
        st = int(x["status"])
        req = bytes.fromhex(x["request_cbor_hex"]) if "request_cbor_hex" in x else None
        if x["endpoint"] == "/v0/authorize" and st != 400:
            r = decode(req, AUTHORIZE_REQ, w)
            if "commitment_ref" in x:
                expect(r["envelope"].hex() == valid[x["commitment_ref"]]["envelope_hex"], f"{w}: envelope")
        if x["endpoint"] == "/v0/record":
            r = decode(req, RECORD_REQ, w)
            decode_signed(r["envelope"])
        if x["endpoint"] == "/v0/publish" and "publish_ref" in x:
            expect(x["request_cbor_hex"] == pub_cases[x["publish_ref"]]["request_cbor_hex"], f"{w}: publish request")
            pr.decode_request(req, 1 << 20)
        if x["endpoint"] == "/v0/health":
            expect(req is None and x["method"] == "GET", f"{w}: health has no body")
        if st == 200:
            if x["endpoint"] == "/v0/authorize":
                sa = decode(resp, AUTHORIZE_RESP, w)["signed_authorization"]
                a = auth[x["authorization_ref"]]
                expect(sa.hex() == a["signed_authorization_hex"], f"{w}: authorization")
                c = a["check"]
                ab = bytes.fromhex(c["action_hex"])
                expect(ab == r["action"], f"{w}: action")
                verify_authorization(sa, AuthorizationCheck(bytes.fromhex(c["gate_pubkey_hex"]), c["gate_id"],
                                                            c["action_type"], ab, int(c["now"]), int(c["skew_s"])))
            elif x["endpoint"] == "/v0/record":
                sr = decode(resp, RECORD_RESP, w)["signed_receipt"]
                rc = rcp[x["receipt_ref"]]
                expect(sr.hex() == rc["signed_receipt_hex"], f"{w}: receipt")
                verify_receipt(sr)
                expect(r["rail_ref"] == rc["input"]["rail_ref"]
                       and r["executor_signature"].hex() == rc["input"]["executor_signature"], f"{w}: record request")
            elif x["endpoint"] == "/v0/publish":
                expect(x["response_cbor_hex"] == pub_resp[x["response_ref"]]["response_cbor_hex"], f"{w}: response")
                pr_resp = decode(resp, pr.PUBLISH_RESPONSE, w)
                pr.decode_payload_ref(pr_resp["payload_ref"])
            else:
                check_health(resp, w)
            continue
        body = decode(resp, ERROR, w)
        e = by_code.get(body["code"])
        expect(e is not None and int(e["status"]) == st and int(e["retryable"]) == body["retryable"], f"{w}: code/status")
        expect(x["endpoint"] in e["endpoints"], f"{w}: endpoint")
        if "stored" in body:
            expect(e["stored"] != "none", f"{w}: stored on {body['code']}")
            if e["stored"] == "authorization":
                expect(body["stored"].hex() == auth[x["authorization_ref"]]["signed_authorization_hex"], f"{w}: stored")
            else:
                expect(body["stored"].hex() == rcp[x["receipt_ref"]]["signed_receipt_hex"], f"{w}: stored")


def check_health(b: bytes, w: str):
    it = canonical(b)
    m = {k.value: v for k, v in it.value}
    expect(set(m) <= set(range(1, 10)) and {1, 2, 3, 4, 5, 6, 9} <= set(m), f"{w}: health keys")
    expect(m[1].value in (1, 2) and isinstance(m[2].value, str) and len(m[6].value) == 32, f"{w}: health fields")
    expect((7 in m) == (8 in m), f"{w}: recorder keys together")
    if 7 in m:
        expect(len(m[7].value) == 20 and len(m[8].value) == 29, f"{w}: recorder fields")
    da = [x.value for x in m[9].value]
    expect(m[9].major == 4 and da and da == sorted(set(da)) and set(da) <= {1, 2}, f"{w}: allowed_da")


def main() -> int:
    try:
        f = json.loads((DIR / "errors.json").read_text())
        expect(f["format"] == "edicta-vectors/v0" and f["revision"] == "v0-draft.15", "header")
        expect(f["content_type"] == "application/cbor", "content type")
        spec = SPEC.read_text()
        by_code = check_mapping(f, spec)
        check_examples(f, by_code)
        ids = [x["id"] for x in f["examples"]]
        expect(len(ids) == len(set(ids)), "duplicate example ids")
    except (Failure, Reject, CBORError) as e:
        print(f"FAIL (api errors): {e}", file=sys.stderr)
        return 1
    print(f"OK (api errors, v0-draft.15): {len(f['errors'])} codes, {len(f['not_api_visible'])} not API-visible, "
          f"{len(f['examples'])} examples; section 12 fully covered, section 18.3 table matches")
    return 0


if __name__ == "__main__":
    sys.exit(main())
