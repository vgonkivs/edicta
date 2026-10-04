#!/usr/bin/env python3
"""Verifies spec/vectors/api/publish_request.json (v0-draft.11).

Rebuilds every publish message from literal tag bytes, checks the agent
signatures, the request and response encodings, and runs the stateless
publish checks PR1..PR5 on every reject.

Usage: python3 spec/vectors/check/check_api_vectors.py [--dir DIR] [--core DIR]
"""

from __future__ import annotations

import sys

sys.dont_write_bytecode = True

import hashlib
import json
import struct
from pathlib import Path

import edicta_publish_v0 as pr
from edicta_v0 import Reject, decode_signed
from vecjson import commitment_from_json, pattern_bytes

HERE = Path(__file__).resolve().parent
VECTORS = HERE.parent


def arg(name: str, default: Path) -> Path:
    if name in sys.argv:
        return Path(sys.argv[sys.argv.index(name) + 1]).resolve()
    return default


DIR = arg("--dir", VECTORS / "api")
CORE = arg("--core", VECTORS / "v0")
TAG_HEX = "19" + b"edicta/v0/publish-request".hex()


class Failure(Exception):
    pass


def expect(cond: bool, msg: str):
    if not cond:
        raise Failure(msg)


def main() -> int:
    try:
        f = json.loads((DIR / "publish_request.json").read_text())
        expect(f["format"] == "edicta-vectors/v0" and f["revision"] == "v0-draft.11", "header")
        expect(f["tag"]["tagged_hex"] == TAG_HEX and f["tag"]["ascii"] == "edicta/v0/publish-request", "tag")
        expect(int(f["publish_window_s"]) == pr.PUBLISH_WINDOW_S and int(f["request_overhead"]) == pr.REQUEST_OVERHEAD,
               "constants")
        srv = f["server"]

        def run(req: bytes, override: dict | None):
            s = dict(srv, **(override or {}))
            return pr.verify_request(req, s["gate_id"], int(s["now"]), int(s["skew_s"]), int(s["max_blob_bytes"]),
                                     {k: bytes.fromhex(v) for k, v in s["allowlist"].items()},
                                     [bytes.fromhex(k) for k in s["gate_keys"]])

        for c in f["cases"]:
            blob = bytes.fromhex(c["blob_hex"]) if "blob_hex" in c else pattern_bytes(c["blob_pattern"], int(c["blob_size"]))
            expect(hashlib.sha256(blob).hexdigest() == c["blob_sha256_hex"], f"{c['id']}: blob")
            aid = c["agent_id"].encode("ascii")
            gid = srv["gate_id"].encode("ascii")
            msg = (bytes.fromhex(TAG_HEX) + bytes([len(gid)]) + gid + bytes([len(aid)]) + aid + struct.pack(">Q", int(c["requested_at"]))
                   + hashlib.sha256(blob).digest())
            expect(msg.hex() == c["publish_message_hex"], f"{c['id']}: publish message")
            expect(70 <= len(msg) <= 196, f"{c['id']}: message length")
            sig = bytes.fromhex(c["signature_hex"])
            req = pr.encode_request(blob, c["agent_id"], int(c["requested_at"]), sig)
            if "request_cbor_hex" in c:
                expect(req.hex() == c["request_cbor_hex"], f"{c['id']}: request bytes")
            else:
                expect(len(req) == int(c["request_size"]) and hashlib.sha256(req).hexdigest() == c["request_sha256_hex"],
                       f"{c['id']}: request digest")
            r = run(req, None)
            expect(r["blob"] == blob and r["agent_id"] == c["agent_id"], f"{c['id']}: decoded request")
        for c in f["reject"]:
            try:
                run(bytes.fromhex(c["request_cbor_hex"]), c.get("server"))
                got = None
            except Reject as e:
                got = e.sentinel
            expect(got == c["expect_error"], f"{c['id']}: got {got}, want {c['expect_error']}")
        valid = {c["id"]: c for c in json.loads((CORE / "valid.json").read_text())["cases"]}
        for c in f["response"]:
            v = valid[c["commitment_ref"]]
            ref = bytes.fromhex(c["payload_ref_cbor_hex"])
            _, canon = decode_signed(bytes.fromhex(v["envelope_hex"]))
            expect(pr.decode_payload_ref(ref) == commitment_from_json(v["input"])["payload_ref"], f"{c['id']}: payload_ref")
            expect(b"\x0a" + ref in canon, f"{c['id']}: payload_ref bytes are commitment key 10")
            body = pr.encode_response(ref, int(c["block_time"]), int(c["retention_start"]))
            expect(body.hex() == c["response_cbor_hex"], f"{c['id']}: response bytes")
        ids = [c["id"] for c in f["cases"] + f["reject"] + f["response"]]
        expect(len(ids) == len(set(ids)), "duplicate ids")
    except (Failure, Reject) as e:
        print(f"FAIL (api): {e}", file=sys.stderr)
        return 1
    print(f"OK (api, v0-draft.11): {len(f['cases'])} publish request, {len(f['reject'])} publish reject, "
          f"{len(f['response'])} publish response")
    return 0


if __name__ == "__main__":
    sys.exit(main())
