#!/usr/bin/env python3
"""Verifies spec/vectors/v1/archive.json and spec/vectors/v1/verify.json (v1-draft.4).

- the generator (gen_archive_v1.py) reproduces both files byte for byte;
- every record decodes with archive_v1 to its input, re-encodes to its bytes,
  and its path is recomputed here from the literal key formulas of core v1
  11.1 (not from archive_v1);
- every reject is refused, every read case compares path and key;
- the verify outcomes are recomputed here from the rule tables of core v1
  10.1 to 10.3, independently of archive_v1's rule functions, with the
  Authorization and commitment re-read from the record bytes.

Usage: python3 spec/vectors/check/check_archive_v1.py
"""

from __future__ import annotations

import sys

sys.dont_write_bytecode = True

import hashlib
import json
from pathlib import Path

import archive_v0 as a0
import archive_v1 as A
from edicta_v0 import Reject

DIR = Path(__file__).resolve().parent.parent / "v1"
REQUIRED_VERIFY = ("fast_pass_in_window", "fast_h_below_h0", "fast_late_absence_proven", "fast_late_absence_unproven",
                   "fast_pending", "fast_absent_proven", "fast_absence_missing_height", "auth_mode_mismatch",
                   "auth_deadline_over_1000", "auth_version_mismatch", "replay_fast_window_inconsistent")
REQUIRED_REJECT = ("signer_on_fibre_intent", "fast_window_on_strict", "kind_16_reserved", "decision_v1_form1_missing_salt",
                   "decision_v1_form2_with_action", "decision_v1_salt_31", "decision_v1_form_3", "decision_v1_v0_envelope",
                   "kind3_with_v1_envelope", "private_envelope_empty", "private_envelope_65537",
                   "private_action_envelope_69633", "header_empty")
REQUIRED_READS = ("absence_key_mismatch", "decision_v1_key_mismatch")
REVISION = "v1-draft.4"


class Failure(Exception):
    pass


def expect(c, msg):
    if not c:
        raise Failure(msg)


def H(*parts):
    return hashlib.sha256(b"".join(parts)).digest()


def path_of(rec: dict, b: bytes) -> str:
    k = rec["kind"]
    if k == 13:
        return f"intent/{rec['da']}/{rec['commitment'].hex()}/{rec['ref_height']}"
    if k == 14:
        return f"absence/{rec['da']}/{rec['commitment'].hex()}/{rec['height']}"
    if k == 15:
        return f"private/{rec['plaintext_kind']}/{rec['hash'].hex()}"
    if k == 5:
        return f"rejection/{rec['commitment_hash'].hex()}/{rec['error']}"
    if k in (3, 17):
        canon = commitment_bytes(rec["envelope"])
        ver = canon_version(canon)
        expect(ver == (1 if k == 17 else 0), "kind 3 holds v0 envelopes, kind 17 v1 envelopes")
        t = b"edicta/v1/decision-commitment" if ver == 1 else b"edicta/v0/decision-commitment"
        tag = bytes([len(t)]) + t
        return f"decision/{H(tag, canon).hex()}"
    if k == 18:
        return f"reveal/{small_map(commitment_bytes(rec['signed_receipt']))[2].hex()}"
    a = auth_map(rec["signed_authorization"])
    return f"authorization/{a[2].hex()}"


def head(b: bytes, i: int):
    ib = b[i]
    major, ai = ib >> 5, ib & 31
    if ai < 24:
        return major, ai, i + 1
    n = 1 << (ai - 24)
    return major, int.from_bytes(b[i + 1:i + 1 + n], "big"), i + 1 + n


def skip(b: bytes, i: int) -> int:
    major, arg, i = head(b, i)
    if major in (2, 3):
        return i + arg
    if major == 4:
        for _ in range(arg):
            i = skip(b, i)
        return i
    if major == 5:
        for _ in range(2 * arg):
            i = skip(b, i)
        return i
    return i


def commitment_bytes(env: bytes) -> bytes:
    """Key 1 of the signed envelope, spliced verbatim (both versions)."""
    _, n, i = head(env, 0)
    _, key, i = head(env, i)
    expect(key == 1, "envelope key 1")
    return env[i:skip(env, i)]


def small_map(b: bytes) -> dict:
    """Flat decode of a map of uints and byte strings (enough for the Authorization and for version reads)."""
    _, n, i = head(b, 0)
    out = {}
    for _ in range(n):
        _, key, i = head(b, i)
        major, arg, j = head(b, i)
        if major in (2, 3):
            out[key] = b[j:j + arg] if major == 2 else b[j:j + arg].decode()
            i = j + arg
        elif major == 0:
            out[key] = arg
            i = j
        else:
            out[key] = None
            i = skip(b, i)
    return out


def skip_to_key(m: bytes, want: int) -> int:
    """Offset of the value of key `want` in a CBOR map."""
    _, n, i = head(m, 0)
    for _ in range(n):
        _, key, i = head(m, i)
        if key == want:
            return i
        i = skip(m, i)
    raise Failure(f"key {want} absent")


def canon_version(canon: bytes) -> int:
    return small_map(canon)[1]


def auth_map(sa: bytes) -> dict:
    return small_map(commitment_bytes(sa))


def commitment_ref(canon: bytes) -> dict:
    """version and payload_ref (key 10) of a commitment."""
    _, n, i = head(canon, 0)
    out = {}
    for _ in range(n):
        _, key, i = head(canon, i)
        end = skip(canon, i)
        if key == 1:
            out["version"] = head(canon, i)[1]
        if key == 10:
            out["ref"] = small_map(canon[i:end])
        i = end
    return out


def check_archive(f: dict, verify: dict) -> str:
    expect(f["format"] == "edicta-vectors/v1" and f["revision"] == REVISION, "archive header")
    kinds = set()
    for c in f["cases"]:
        b = bytes.fromhex(c["record_cbor_hex"])
        rec = A.decode_record(b)
        expect(A.encode_record(rec) == b and str(rec["kind"]) == c["kind"], c["id"])
        expect(path_of(rec, b) == c["path"], f"{c['id']}: path")
        try:
            a0.decode_record(b)
            v0r = "accepts"
        except Reject as e:
            v0r = e.sentinel
        expect(v0r == c["v0_reader"], f"{c['id']}: v0 reader")
        if rec["kind"] in (13, 14, 15, 17, 18):
            expect(v0r == "ErrInvalidEnum", f"{c['id']}: a v0 reader refuses the new kinds")
        if rec["kind"] == 4 and "k2" in rec:
            a = auth_map(rec["signed_authorization"])
            fast = a[1] == 1 and a.get(7) == 2
            expect(("fast_window" in rec["k2"]) == fast, f"{c['id']}: key 9 iff mode 2")
            if fast:
                h0 = None
                for d in f["cases"]:
                    if d["kind"] == "17" and d["path"] == f"decision/{a[2].hex()}":
                        h0 = commitment_ref(commitment_bytes(bytes.fromhex(d["input"]["envelope"])))["ref"][4]
                expect(h0 is not None and a[8] - h0 == rec["k2"]["fast_window"], f"{c['id']}: fast_window")
        if c["id"] in verify["records"]:
            expect(verify["records"][c["id"]]["record_cbor_hex"] == c["record_cbor_hex"], f"{c['id']}: verify.json")
        kinds.add(rec["kind"])
        if rec["kind"] == 17:
            expect(rec["form"] in (1, 2) and (("action" in rec) == ("action_salt" in rec) == (rec["form"] == 1)),
                   f"{c['id']}: form and keys 5, 6")
            if rec["form"] == 1:
                ok = form1_ok(rec)
                expect(ok == (not c["id"].endswith("_wrong_salt")),
                       f"{c['id']}: form 1 bytes and salt give the committed action_hash")
    expect({4, 5, 13, 14, 15, 17, 18} <= kinds and 3 not in kinds, "kinds covered (no kind 3 for v1 decisions)")
    for r in f["reject"]:
        try:
            A.decode_record(bytes.fromhex(r["record_cbor_hex"]))
            raise Failure(f"{r['id']} accepted")
        except Reject as e:
            expect(e.sentinel == r["cause"] and r["expect_error"] == "archive.ErrCorrupt", r["id"])
    for x in f["reject_large"]:
        base = next(c for c in f["cases"] if c["id"] == x["base_case"])
        rec = A.decode_record(bytes.fromhex(base["record_cbor_hex"]))
        m = a0._to_int_keys({"format": 0, **rec}, A.schema_of(rec["kind"]))
        n = int(x["field_size"])
        m[int(x["field"])] = b"".join(hashlib.sha256(f"edicta/v0 test archive placeholder|{x['placeholder_label']}|{i}"
                                                     .encode()).digest() for i in range((n + 31) // 32))[:n]
        from cbor_strict import encode
        b = encode(m)
        expect(len(b) == int(x["record_size"]) and hashlib.sha256(b).hexdigest() == x["record_sha256_hex"], x["id"])
        try:
            A.decode_record(b)
            cause = None
        except Reject as e:
            cause = e.sentinel
        expect(cause == x["cause"] and (x["expect_error"] is None) == (cause is None), f"{x['id']}: {cause}")
        lim = {7: 1 << 22, 9: 1 << 24}[int(x["field"])]
        expect((n <= lim and len(b) <= 1 << 24) == (cause is None), f"{x['id']}: limit")
    for x in f["reads"]:
        b = bytes.fromhex(x["record_cbor_hex"])
        ok = path_of(A.decode_record(b), b) == x["path"]
        expect(ok == (x["expect_error"] is None), x["id"])
    ids = {r["id"] for r in f["reject"]}
    expect(all(i in ids for i in REQUIRED_REJECT), "required rejects")
    expect(all(i in {x["id"] for x in f["reads"]} for i in REQUIRED_READS), "required reads")
    expect(f["reserved_kinds"] == ["6", "16"], "reserved kinds")
    return f"{len(f['cases'])} records, {len(f['reject'])} reject, {len(f['reads'])} reads"


def outcome(c: dict, records: dict, window: int) -> dict:
    dec = A.decode_record(bytes.fromhex(records[c["decision"]]["record_cbor_hex"]))
    au = A.decode_record(bytes.fromhex(records[c["authorization"]]["record_cbor_hex"]))
    cm = commitment_ref(commitment_bytes(dec["envelope"]))
    a = auth_map(au["signed_authorization"])
    ref = cm["ref"]
    pending, h0 = ref.get(6) == 2, ref[4]
    head_ = int(c["trusted_head"])
    out = {}
    if a[1] != cm["version"]:
        rule = "A1"
    elif a.get(7) != (2 if pending else 1):
        rule = "A2"
    elif pending and not (h0 < a[8] <= h0 + 1000):
        rule = "A3"
    else:
        rule = None
    out["authorization"] = {"status": "fail", "rule": rule} if rule else {"status": "pass"}
    rep = {"version": "1"}
    if 7 in a:
        rep["mode"] = "fast" if a[7] == 2 else "strict"
    if pending:
        rep["h0"] = str(h0)
        if rule:
            out["anchor"] = {"status": "unchecked", "reason": "blocked", "blocked_by": "authorization"}
        else:
            dl = a[8]
            rep["anchor_deadline"] = str(dl)
            ab = {int(x["height"]): x["result"] for x in c.get("absence", [])}
            window_ = range(h0, dl + 1)
            all_absent = all(ab.get(h) == "absent" for h in window_)
            gap = next((h for h in window_ if ab.get(h) != "absent"), None)
            ev = c.get("evidence")
            if ev and ev["verifies"] and int(ev["height"]) < h0:
                out["anchor"] = {"status": "unchecked", "reason": "source_corrupt"}
            elif ev and ev["verifies"] and int(ev["height"]) <= dl:
                out["anchor"] = {"status": "pass"}
                rep |= {"anchor_height": ev["height"], "publication": "anchored"}
            elif ev and ev["verifies"]:
                rep["anchor_height"] = ev["height"]
                if all_absent:
                    out["anchor"] = {"status": "fail", "rule": "anchor_absent"}
                    rep["publication"] = "failed"
                else:
                    out["anchor"] = {"status": "unchecked", "reason": "absence_unproven", "first_unproven": str(gap)}
                    rep["publication"] = "unknown"
            elif head_ < dl + (1 if c.get("needs_results") else 0):
                out["anchor"] = {"status": "unchecked", "reason": "anchor_pending"}
                rep["publication"] = "unknown"
            elif any(ab.get(h) == "present" for h in window_):
                out["anchor"] = {"status": "unchecked", "reason": "evidence_unavailable"}
                rep |= {"anchor_height": str(min(h for h in window_ if ab.get(h) == "present")),
                        "publication": "unknown"}
            elif all_absent:
                out["anchor"] = {"status": "fail", "rule": "anchor_absent"}
                rep["publication"] = "failed"
            else:
                out["anchor"] = {"status": "unchecked", "reason": "absence_unproven", "first_unproven": str(gap)}
                rep["publication"] = "unknown"
            if out["anchor"].get("rule") == "anchor_absent":
                rep["intent_signer"] = ref[5].hex() if ref[1] == 2 else "unknown"
    if c.get("request") == "replay":
        k2 = au.get("k2")
        if k2 is None:
            out["retention_replay"] = {"status": "unchecked", "reason": "replay_inputs_missing"}
        elif "fast_window" in k2 and a[8] - h0 > k2["fast_window"]:
            out["retention_replay"] = {"status": "unchecked", "reason": "replay_inconsistent"}
        else:
            vu = small_map(commitment_bytes(dec["envelope"]))[6]
            if k2["da"] == 2:
                r, start = k2["blob_retention_s"], k2["block_time"]
            else:
                r = min(k2["retention_latest_s"], k2["retention_at_height_s"])
                start = min(k2["block_time"], k2["promise_created"])
            holds = vu + min(600, r // 8) <= start + r
            out["retention_replay"] = ({"status": "unchecked", "reason": "replay_inconsistent"}
                                       if not holds and a[6] == 1 else {"status": "pass"})
    sts = [x["status"] for x in out.values()]
    verdict, code = ("invalid", 1) if "fail" in sts else ("unchecked", 2) if "unchecked" in sts else ("valid", 0)
    return out | {"report": rep, "verdict": verdict, "exit": str(code)}


TAG_ACTION_V1 = b"\x10edicta/v1/action"


def committed_action(env: bytes) -> tuple:
    canon = commitment_bytes(env)
    act = small_map(canon[skip_to_key(canon, 8):])
    return act[3], act[4]


def ahash(atype: str, salt: bytes, data: bytes) -> bytes:
    t = atype.encode()
    return H(TAG_ACTION_V1, bytes([len(t)]), t, salt, data)


def form1_ok(rec: dict) -> bool:
    atype, ah = committed_action(rec["envelope"])
    return ahash(atype, rec["action_salt"], rec["action"]) == ah


def action_outcome(c: dict, records: dict, sks: dict) -> dict:
    """Core v1 10.7 from the table, independently of archive_v1.action_rules."""
    import check_policy as CP
    b = bytes.fromhex(records[c["decision"]]["record_cbor_hex"])
    try:
        dec = A.decode_record(b)
        path_of(dec, b)
    except (Reject, Failure):
        return {"decision": {"status": "unchecked", "reason": "source_corrupt"}}
    out = {"decision": {"status": "pass"}}
    atype, ah = committed_action(dec["envelope"])
    if dec["form"] == 1:
        if ahash(atype, dec["action_salt"], dec["action"]) != ah:
            return out | {"action": {"status": "unchecked", "reason": "source_corrupt"}}
        res, salt = {"status": "pass", "action_source": "decision_record"}, dec["action_salt"]
    else:
        pt = None
        if "private_record" in c and "auditor_key" in c:
            pr = A.decode_record(bytes.fromhex(records[c["private_record"]]["record_cbor_hex"]))
            st, pt, _ = CP.open_private(pr["envelope"], [sks[c["auditor_key"]]], 5, ah, atype)
            if st == "corrupt":
                return out | {"action": {"status": "unchecked", "reason": "source_corrupt"}}
            pt = pt if st == "ok" else None
        ck = c.get("checker") or {}
        if pt is not None:
            if ahash(atype, pt[:32], pt[32:]) != ah:
                return out | {"action": {"status": "unchecked", "reason": "source_corrupt"}}
            res, salt = {"status": "pass", "action_source": "private_blob"}, pt[:32]
        elif "private_record" not in c:
            return out | {"action": {"status": "unchecked", "reason": "decision_unavailable"}}
        elif "reveal" in c and ck.get("public_execution"):
            rv = A.decode_record(bytes.fromhex(records[c["reveal"]]["record_cbor_hex"]))
            if ahash(atype, rv["action_salt"], bytes.fromhex(ck["tx_action_hex"])) != ah:
                return out | {"action": {"status": "unchecked", "reason": "source_corrupt"}}
            res, salt = {"status": "pass", "action_source": "reveal"}, rv["action_salt"]
        else:
            return out | {"action": {"status": "unchecked", "reason": "policy_private"}}
    if "payload_salt_hex" in c and bytes.fromhex(c["payload_salt_hex"]) != salt:
        return out | {"action": {"status": "unchecked", "reason": "source_corrupt"}}
    return out | {"action": res}


def check_verify(f: dict) -> str:
    expect(f["format"] == "edicta-vectors/v1" and f["revision"] == REVISION, "verify header")
    corrupt = {c["decision"] for c in f["action_cases"] if c["expect"]["decision"]["status"] != "pass"}
    for n, r in f["records"].items():
        b = bytes.fromhex(r["record_cbor_hex"])
        if n in corrupt:
            try:
                A.decode_record(b)
                raise Failure(f"{n}: a corrupt decision record decodes")
            except Reject:
                continue
        expect(path_of(A.decode_record(b), b) == r["path"], n)
    priv = json.loads((DIR.parent / "policy" / "private.json").read_text())
    sks = {n: bytes.fromhex(k["sk_hex"]) for n, k in priv["auditor_keys"].items()}
    for c in f["action_cases"]:
        got = action_outcome(c, f["records"], sks)
        expect(got == c["expect"], f"{c['id']}: {got} != {c['expect']}")
    need = {"decision_v1_public_pass", "decision_v1_public_wrong_salt", "decision_v1_private_without_key",
            "decision_v1_private_with_key", "decision_v1_private_blob_missing", "reveal_public_execution_pass",
            "reveal_wrong_salt", "reveal_offchain_profile", "payload_archive_salt_mismatch", "kind3_with_v1_envelope"}
    expect(need <= {c["id"] for c in f["action_cases"]}, "required action cases")
    for c in f["cases"]:
        got = outcome(c, f["records"], int(f["window"]))
        expect(got == c["expect"], f"{c['id']}: {got} != {c['expect']}")
    ids = [c["id"] for c in f["cases"]]
    expect(len(ids) == len(set(ids)) and all(i in ids for i in REQUIRED_VERIFY), "required verify cases")
    return f"{len(f['cases'])} verify cases, {len(f['action_cases'])} action cases"


def main() -> int:
    try:
        import gen_archive_v1 as gen
        files = {}
        for name, obj in gen.build().items():
            text = json.dumps(obj, indent=2, ensure_ascii=True) + "\n"
            expect((DIR / name).read_text() == text, f"{name}: generator output differs")
            files[name] = obj
        out = [check_archive(files["archive.json"], files["verify.json"]), check_verify(files["verify.json"])]
        out[0] += f", {len(files['archive.json']['reject_large'])} large reject"
    except (Failure, Reject, KeyError, ValueError) as e:
        print(f"FAIL (v1 archive): {type(e).__name__}: {e}", file=sys.stderr)
        return 1
    print(f"OK (v1 archive, {REVISION}): " + "; ".join(out) + "; generator output identical")
    return 0


if __name__ == "__main__":
    sys.exit(main())
