#!/usr/bin/env python3
"""Verifies spec/vectors/archive/records.json and state.json (v0-draft.20).

- every case: the record rebuilt from `input` encodes to the listed bytes,
  decodes strictly back to `input`, and sits under the listed key;
- cross-references: payloads against v0/da_blob.json and
  da/fibre_commit.json, decisions against v0/valid.json (a re-signed envelope
  must carry another valid agent signature over the same commitment),
  Authorizations against v0/authorization.json and the gate key, K2 inputs
  against the decision (same da; K2 failing implies path = 2), rejection
  markers against the decision's hash and gate_id;
- every reject fails strict decoding with its cause;
- state scenarios replayed on the reference store give every step result,
  state and the final stored records;
- the generator reproduces both files byte for byte.

Usage: python3 spec/vectors/check/check_archive.py [--dir DIR] [--core DIR]
"""

from __future__ import annotations

import sys

sys.dont_write_bytecode = True

import hashlib
import json
import subprocess
import tempfile
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

import archive_v0 as av
from edicta_v0 import (
    Reject, TAG_AUTHORIZATION_SIG, action_hash, authorization_hash, commitment_hash, decode_signed,
    decode_signed_authorization, tagged,
)

HERE = Path(__file__).resolve().parent
VECTORS = HERE.parent
FORMAT = "edicta-vectors/v0"
REVISION = "v0-draft.20"


class Failure(Exception):
    pass


def expect(cond: bool, msg: str):
    if not cond:
        raise Failure(msg)


def arg(name: str, default: Path) -> Path:
    if name in sys.argv:
        return Path(sys.argv[sys.argv.index(name) + 1]).resolve()
    return default


def pattern(size: int) -> bytes:
    return bytes((7 * i + 3) & 0xFF for i in range(size))


def from_json(j: dict) -> dict:
    kind = av.KIND_BY_NAME[j["kind"]]

    def conv(obj: dict, schema: dict, where: str) -> dict:
        by_name = {f[0]: f for f in schema.values()}
        out = {}
        for name, val in obj.items():
            if name == "kind":
                continue
            expect(name in by_name, f"{where}: unknown input field {name}")
            _, typ, _, _ = by_name[name]
            if isinstance(typ, dict):
                out[name] = conv(val, typ, f"{where}.{name}")
            elif typ == "uint":
                expect(isinstance(val, str) and val.isdigit(), f"{where}.{name}: uint not a decimal string")
                out[name] = int(val)
            elif typ == "bstr":
                if isinstance(val, dict):
                    expect(val["pattern"] == "affine-7-3", f"{where}.{name}: pattern")
                    b = pattern(int(val["size"]))
                    expect(len(b) > 1024, f"{where}.{name}: pattern for a small field")
                    expect(hashlib.sha256(b).hexdigest() == val["sha256_hex"], f"{where}.{name}: sha256")
                    out[name] = b
                else:
                    expect(val == val.lower(), f"{where}.{name}: hex not lowercase")
                    out[name] = bytes.fromhex(val)
            else:
                out[name] = val
        return out

    return {"kind": kind, **conv(j, av.SCHEMAS[kind], j["kind"])}


def record_bytes(c: dict, rec: dict) -> bytes:
    data = av.encode_record(rec)
    if "record_cbor_hex" in c:
        expect(len(data) <= 4096, f"{c['id']}: inline record above 4096 bytes")
        expect(data.hex() == c["record_cbor_hex"], f"{c['id']}: record bytes differ")
    else:
        expect(len(data) > 4096, f"{c['id']}: small record given by hash")
        expect(str(len(data)) == c["record_size"], f"{c['id']}: record_size")
        expect(hashlib.sha256(data).hexdigest() == c["record_sha256_hex"], f"{c['id']}: record_sha256_hex")
    return data


def ed_ok(pub: bytes, msg: bytes, sig: bytes) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(pub).verify(sig, msg)
        return True
    except InvalidSignature:
        return False


def check_records(f: dict, core: Path):
    expect(f["format"] == FORMAT and f["revision"] == REVISION, "records.json header")
    p = f["params"]
    expect(p["format"] == "0" and p["max_depth"] == "2" and p["max_entries"] == "24", "params")
    expect(p["kinds"] == {"payload": "1", "evidence": "2", "decision": "3", "authorization": "4", "rejection": "5"},
           "kinds")
    expect(p["max_record_size"] == str((1 << 27) + 4096) and p["max_opaque_size"] == str(1 << 22), "sizes")
    expect(p["max_kind_size"] == {"payload": str((1 << 27) + 4096), "evidence": str(1 << 25), "decision": "69632",
                                  "authorization": "512", "rejection": "256"}, "kind sizes")
    expect(p["verdicts"] == sorted(p["verdicts"]) and set(p["verdicts"]) == set(av.VERDICTS), "verdicts")

    valid = {c["id"]: c for c in json.loads((core / "valid.json").read_text())["cases"]}
    auths = {c["id"]: c for c in json.loads((core / "authorization.json").read_text())["cases"]}
    keys = json.loads((core / "keys.json").read_text())["keys"]
    da_blob = {c["id"]: c for c in json.loads((core / "da_blob.json").read_text())["cases"]}
    fibre = {c["id"]: c for c in json.loads((VECTORS / "da" / "fibre_commit.json").read_text())["cases"]}
    gate_pub = bytes.fromhex(keys["gate1"]["public_key_hex"])

    ids = [c["id"] for c in f["cases"] + f["reject"]]
    expect(len(ids) == len(set(ids)), "duplicate ids")
    recs = {}
    for c in f["cases"]:
        cid = c["id"]
        rec = from_json(c["input"])
        data = record_bytes(c, rec)
        expect(av.decode_record(data) == rec, f"{cid}: decode round trip")
        expect(c["kind"] == c["input"]["kind"], f"{cid}: kind")
        expect(av.key_path(av.record_key(rec)) == c["key"], f"{cid}: key")
        for name in c.get("placeholders", []):
            expect(name in rec, f"{cid}: placeholder {name} absent")
        kind, refs = rec["kind"], c["refs"]
        if kind in (av.KIND_PAYLOAD, av.KIND_EVIDENCE):
            if rec["da"] == 2:
                d = da_blob[refs["da_blob"]]
                expect(rec["namespace"].hex() == d["namespace_hex"], f"{cid}: namespace")
                if kind == av.KIND_PAYLOAD:
                    expect(rec["signer"].hex() == d["signer_hex"], f"{cid}: signer")
                    expect(hashlib.sha256(rec["blob"]).hexdigest() == d["blob_sha256_hex"], f"{cid}: blob")
            else:
                d = fibre[refs["fibre_commit"]]
                if kind == av.KIND_PAYLOAD:
                    expect(hashlib.sha256(rec["blob"]).hexdigest() == d["blob_sha256_hex"], f"{cid}: blob")
                else:
                    expect(rec["namespace"].hex() == d["live"]["namespace_hex"], f"{cid}: namespace")
            matches = rec["commitment"].hex() == d["commitment_hex"]
            expect(matches == (cid != "payload_da2_wrong_commitment"), f"{cid}: commitment")
        elif kind == av.KIND_DECISION:
            v = valid[refs["valid"]]
            signed, canon = decode_signed(rec["envelope"])
            expect(commitment_hash(canon).hex() == v["commitment_hash_hex"], f"{cid}: commitment hash")
            expect(action_hash(v["action_type"], rec["action"]).hex() == v["action_hash_hex"], f"{cid}: action")
            msg = bytes.fromhex(v["signed_message_hex"])
            expect(ed_ok(signed["commitment"]["agent_pubkey"], msg, signed["signature"]), f"{cid}: agent signature")
            resigned = rec["envelope"].hex() != v["envelope_hex"]
            expect(resigned == cid.endswith("_resigned"), f"{cid}: envelope")
        elif kind == av.KIND_AUTHORIZATION:
            a = auths[refs["authorization"]]
            expect(rec["signed_authorization"].hex() == a["signed_authorization_hex"], f"{cid}: Authorization bytes")
            expect(str(rec["authorized_at"]) == a["authorized_at"], f"{cid}: authorized_at")
            sa, canon = decode_signed_authorization(rec["signed_authorization"])
            msg = tagged(TAG_AUTHORIZATION_SIG) + authorization_hash(canon)
            expect(ed_ok(gate_pub, msg, sa["signature"]), f"{cid}: gate signature")
            v = valid[a["commitment_ref"]]
            auth = sa["authorization"]
            expect(auth["commitment_hash"].hex() == v["commitment_hash_hex"], f"{cid}: commitment_hash")
            expect(auth["action_hash"].hex() == v["action_hash_hex"], f"{cid}: action_hash")
            if "k2" in rec:
                env, _ = decode_signed(bytes.fromhex(v["envelope_hex"]))
                expect(rec["k2"]["da"] == env["commitment"]["payload_ref"]["da"], f"{cid}: K2 da")
                expect(rec["k2"]["checked_at"] <= rec["authorized_at"], f"{cid}: checked_at after authorized_at")
                if not av.k2_holds(env, rec["k2"]):
                    expect(auth["path"] == 2, f"{cid}: K2 fails but path = 1")
        elif kind == av.KIND_REJECTION:
            v = valid[refs["valid"]]
            expect(rec["commitment_hash"].hex() == v["commitment_hash_hex"], f"{cid}: commitment_hash")
            expect(rec["gate_id"] == v["input"]["scope"]["gate_id"], f"{cid}: gate_id")
        recs[cid] = rec

    for r in f["reject"]:
        expect(r["expect_error"] == "archive.ErrCorrupt", f"{r['id']}: expect_error")
        try:
            av.decode_record(bytes.fromhex(r["record_cbor_hex"]))
            raise Failure(f"{r['id']}: decodes")
        except Reject as e:
            expect(e.sentinel == r["cause"], f"{r['id']}: cause {e.sentinel}, want {r['cause']}")
    return recs, da_blob, fibre


def check_state(s: dict, recs: dict, da_blob: dict, fibre: dict) -> int:
    expect(s["format"] == FORMAT and s["revision"] == REVISION, "state.json header")
    want_pairs = {("2", k, v["commitment_hex"], v["blob_sha256_hex"]) for k, v in da_blob.items()}
    want_pairs |= {("1", k, v["commitment_hex"], v["blob_sha256_hex"]) for k, v in fibre.items()}
    got_pairs = {(p["da"], p["ref"], p["commitment_hex"], p["blob_sha256_hex"]) for p in s["da_check"]}
    expect(got_pairs == want_pairs, "da_check differs from the DA vector files")
    known = {(int(p[0]), p[2], p[3]) for p in got_pairs}

    def da_check(rec):
        return (rec["da"], rec["commitment"].hex(), hashlib.sha256(rec["blob"]).hexdigest()) in known

    results = set()
    steps = 0
    for sc in s["scenarios"]:
        store = av.Store(da_check)
        for st in sc["steps"]:
            try:
                got = "written" if store.put(recs[st["put"]]) else "unchanged"
            except (av.Conflict, av.NotFound, av.DAMismatch) as e:
                got = e.sentinel
            expect(got == st["expect"], f"{sc['id']}/{st['put']}: {got}, want {st['expect']}")
            results.add(got)
            if "state_after" in st:
                w = st["state_after"]
                expect(store.state(bytes.fromhex(w["commitment_hash_hex"])) ==
                       {"state": w["state"], "rejections": w["rejections"]}, f"{sc['id']}/{st['put']}: state")
            steps += 1
        stored = {k: v for k, v in store.records.items()}
        final = {av.record_key(recs[r]): av.encode_record(recs[r]) for r in sc["final_records"]}
        expect(stored == final, f"{sc['id']}: final records")
    expect(results == {"written", "unchanged", "archive.ErrConflict", "archive.ErrNotFound",
                       "gate.ErrDACommitmentMismatch"}, f"results covered: {results}")
    return steps


def check_regenerates(d: Path, core: Path):
    with tempfile.TemporaryDirectory() as tmp:
        subprocess.run([sys.executable, str(HERE / "gen_archive.py"), "--core", str(core), "--out", tmp],
                       check=True, capture_output=True)
        for name in ("records.json", "state.json"):
            expect((Path(tmp) / name).read_bytes() == (d / name).read_bytes(), f"{name}: generator output differs")


def main() -> int:
    d = arg("--dir", VECTORS / "archive")
    core = arg("--core", VECTORS / "v0")
    try:
        f = json.loads((d / "records.json").read_text())
        recs, da_blob, fibre = check_records(f, core)
        steps = check_state(json.loads((d / "state.json").read_text()), recs, da_blob, fibre)
        check_regenerates(d, core)
    except (Failure, Reject, KeyError, AssertionError) as e:
        print(f"FAIL (archive): {type(e).__name__}: {e}", file=sys.stderr)
        return 1
    s = json.loads((d / "state.json").read_text())
    print(f"OK (archive, {REVISION}): {len(f['cases'])} records, {len(f['reject'])} reject, "
          f"{len(s['scenarios'])} scenarios ({steps} steps); generator output identical")
    return 0


if __name__ == "__main__":
    sys.exit(main())
