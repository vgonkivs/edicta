#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Checks the vector files of spec revision v1.2 (minor: the JSON transport of core 18.4) and of the security patch
revisions v1.0.5 and v1.1.1 (an undefined payload_ref.da is unsupported_revision, core 20.1).

- SUPERSEDED_v1.2.json: every entry names a case of a frozen file and a replacing case on the same inputs, and
  SUPERSEDED.json holds no minor entry;
- api/errors_v1.2.json: the order is that of api/errors_v1.1.json, no code added; the replacing case carries the
  inputs of the frozen case;
- api/json_v1.2.json: every converted request decodes to the values Python's json module reads from the body (for
  bodies that are plain JSON);
- v1/unknown_da_v1.0.5.json: every envelope re-decoded with this file's own reader, its hash and signature
  re-verified, its da undefined, and its gate outcome a refusal;
- verifier/reasons_v1.0.5.json: the reason is new to the enum (45 reasons), every case names a commitment above with
  an undefined da, every archive reader case holds that envelope under its path, with the strict reader's cause;
- the generator (gen_v1_2.py) reproduces the five files byte for byte.

Usage: python3 spec/vectors/check/check_v1_2.py
"""

from __future__ import annotations

import sys

sys.dont_write_bytecode = True

import base64
import hashlib
import json
import subprocess
from pathlib import Path

import gen_v1_2 as gen
import records as RD
from cbor_strict import decode_strict, to_plain
from ed25519_point import cofactorless_ok
from edicta import Reject

HERE = Path(__file__).resolve().parent
VECTORS = HERE.parent
TAG_COMMITMENT = bytes([29]) + b"edicta/v1/decision-commitment"
TAG_SIG = bytes([13]) + b"edicta/v1/sig"


class Failure(Exception):
    pass


def expect(cond: bool, msg: str):
    if not cond:
        raise Failure(msg)


def load(rel: str) -> dict:
    return json.loads((VECTORS / rel).read_text())


def find(d, cid: str) -> dict:
    hit = []

    def walk(x):
        if isinstance(x, dict):
            if x.get("id") == cid:
                hit.append(x)
            for v in x.values():
                walk(v)
        elif isinstance(x, list):
            for v in x:
                walk(v)
    walk(d)
    expect(len(hit) == 1, f"{cid}: {len(hit)} cases")
    return hit[0]


# ---------------------------------------------------------------- SUPERSEDED_v1.2.json

def check_superseded() -> str:
    frozen_list = load("SUPERSEDED.json")
    expect(frozen_list["revision"] == "v1.0.3" and all(e["type"] == "security" for e in frozen_list["entries"]),
           "SUPERSEDED.json is never edited after v1.0.3")
    s = load("SUPERSEDED_v1.2.json")
    expect(s["revision"] == "v1.2", "SUPERSEDED_v1.2.json revision")
    minor = s["entries"]
    expect(minor and all(e["revision"] == "v1.2" and e["type"] == "minor" for e in minor), "minor entries")
    listed = {(e["file"], e["case"]) for e in frozen_list["entries"]}
    expect(all((e["file"], e["case"]) not in listed for e in minor), "a case superseded twice")
    for e in minor:
        frozen = find(load(e["file"]), e["case"])
        rel, _, cid = e["replaced_by"].partition("#")
        repl = find(load(rel), cid)
        expect(repl.get("replaces") == f"{e['file']}#{e['case']}", f"{cid}: replaces")
        for k in ("endpoint", "method", "content_type", "request_cbor_hex"):
            expect(repl.get(k) == frozen.get(k), f"{cid}: input {k} differs from the frozen case")
        expect(repl["status"] != frozen["status"], f"{cid}: the outcome does not change")
    return f"{len(minor)} minor entries"


# ---------------------------------------------------------------- API

def check_errors(e: dict) -> str:
    v11 = load("api/errors_v1.1.json")
    expect([o["code"] for o in e["order"]] == [o["code"] for o in v11["order"]], "order differs from v1.1")
    expect(e["additions"] == [] and e["bodies"] == [], "v1.2 adds no code")
    return f"{len(e['order'])} codes in match order"


def no_dups(pairs):
    keys = [k for k, _ in pairs]
    if len(keys) != len(set(keys)):
        raise ValueError("duplicate")
    return dict(pairs)


def check_json(j: dict) -> str:
    n = 0
    for r in j["requests"]:
        if "cbor_hex" not in r["expect"] or "body" not in r:
            continue
        schema = gen.JT.SCHEMAS[gen.JT.ROUTES[r["endpoint"]][0]]
        try:
            obj = json.loads(r["body"], object_pairs_hook=no_dups)
        except ValueError:
            continue
        m = to_plain(decode_strict(bytes.fromhex(r["expect"]["cbor_hex"])))
        expect(set(m) == {schema[k][0] for k in obj}, f"{r['id']}: keys")
        for k, v in obj.items():
            key, kind = schema[k]
            want = base64.b64decode(v) if kind == "bytes" else v
            expect(m[key] == want, f"{r['id']}: {k}")
        n += 1
    refused = {r["expect"].get("error") for r in j["requests"]}
    expect({"ErrMalformed", "ErrWrongType"} <= refused, "both JSON refusals have cases")
    return f"{len(j['requests'])} requests ({n} cross-read with Python's json), {len(j['media_types'])} media types, " \
           f"{len(j['accept'])} Accept, {len(j['responses'])} responses"


# ---------------------------------------------------------------- unknown da

def own_payload_ref(env: bytes) -> tuple:
    """The commitment of an envelope read with cbor_strict only: (commitment map, its payload_ref, signature)."""
    e = to_plain(decode_strict(env))
    c = e[1]
    return c, c[10], e[2]


def check_unknown_da(f: dict) -> str:
    pub = bytes.fromhex(load("keys.json")["keys"]["agent1"]["public_key_hex"])
    for x in f["cases"]:
        env = bytes.fromhex(x["envelope_hex"])
        c, pr, sig = own_payload_ref(env)
        canon = bytes.fromhex(x["commitment_cbor_hex"])
        expect(canon in env, f"{x['id']}: the envelope carries the commitment bytes")
        h = hashlib.sha256(TAG_COMMITMENT + canon).digest()
        expect(h.hex() == x["commitment_hash_hex"], f"{x['id']}: hash")
        expect(cofactorless_ok(pub, TAG_SIG + h, sig), f"{x['id']}: signature")
        expect(isinstance(pr[1], int) and pr[1] not in gen.DEFINED_DA, f"{x['id']}: da {pr[1]} is defined")
        expect(x["gate"] != "ok", f"{x['id']}: a gate accepts an undefined da")
    return f"{len(f['cases'])} undefined-da commitments"


def check_reasons() -> str:
    r = load("verifier/reasons_v1.0.5.json")
    expect(r["revision"] == "v1.0.5" and r["extends"] == "verifier/reasons_v1.0.3.json", "reasons header")
    known = set()
    for rel in ("verifier/reasons.json", "verifier/reasons_v1.0.3.json"):
        known |= {x["name"] for x in load(rel)["reasons"]}
    names = [x["name"] for x in r["reasons"]]
    expect(names == ["unsupported_revision"] and not known & set(names), "the reason is new to the enum")
    expect(len(known) + len(names) == 45, f"the enum has {len(known) + len(names)} reasons, the spec says 45")
    core = {x["id"]: x for x in load(gen.UNKNOWN_DA_FILE)["cases"]}
    for c in r["cases"]:
        rel, _, cid = c["setup"]["commitment"].partition("#")
        expect(rel == gen.UNKNOWN_DA_FILE and cid in core, f"{c['id']}: commitment")
        expect(c["v1_0_4"]["status"] == "fail" and c["expect"]["status"] == "unchecked"
               and c["expect"]["reason"] == "unsupported_revision" and c["v1_2"]["status"] == "unchecked",
               f"{c['id']}: outcomes")
    for b in r["boundary"]:
        for ref in b["refs"]:
            rel, _, cid = ref.partition("#")
            find(load(rel), cid)
        expect(b["expect"]["status"] == "fail", f"{b['id']}: a boundary case stays fail")
    for c in r["archive_reader"]:
        raw = bytes.fromhex(c["record_cbor_hex"])
        expect(RD.cause(raw) == c["v1_0_4_reader_cause"], f"{c['id']}: the strict reader's cause")
        x = core[c["commitment"].partition("#")[2]]
        h = hashlib.sha256(TAG_COMMITMENT + bytes.fromhex(x["commitment_cbor_hex"])).digest()
        expect(c["path"] == f"decision/{h.hex()}" == c["expect"]["path"], f"{c['id']}: path")
        expect(bytes.fromhex(x["envelope_hex"]) in raw, f"{c['id']}: the record holds the envelope")
    return f"{len(r['cases'])} reason cases, {len(r['boundary'])} boundary, {len(r['archive_reader'])} archive reader"


def main() -> int:
    try:
        sup = check_superseded()
        errs = check_errors(load(gen.ERRORS_FILE))
        js = check_json(load(gen.JSON_FILE))
        unk = check_unknown_da(load(gen.UNKNOWN_DA_FILE))
        rsn = check_reasons()
        r = subprocess.run([sys.executable, str(HERE / "gen_v1_2.py"), "--check"], capture_output=True, text=True)
        expect(r.returncode == 0, "generator output differs: " + (r.stderr or r.stdout).strip())
    except (Failure, Reject, KeyError, ValueError) as e:
        print(f"FAIL (v1.2): {e}", file=sys.stderr)
        return 1
    print(f"OK (v1.2): {sup}; {errs}; {js}; {unk}; {rsn}; generator output identical")
    return 0


if __name__ == "__main__":
    sys.exit(main())
