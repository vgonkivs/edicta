#!/usr/bin/env python3
"""Verifies the format v1 vectors (v1-draft.4) under spec/vectors/v1.

Checks every case against the v1 rules (edicta_v1, with the frozen v0 rules of
edicta_v0 for the v0 path), recomputes hashes and signed messages from literal
tags, re-signs deterministically with the core keys, requires every case name
listed in core v1 section 15, and requires the generator to reproduce every
file byte for byte. archive.json and verify.json are checked by
check_archive_v1.py.

Usage: python3 spec/vectors/check/check_vectors_v1.py
"""

from __future__ import annotations

import sys

sys.dont_write_bytecode = True

import hashlib
import json
from pathlib import Path

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
except ImportError:
    sys.exit("missing dependency 'cryptography'; see spec/vectors/check/requirements.txt")

import edicta_v0 as v0
import edicta_v1 as v1
from cbor_strict import Raw, encode
from edicta_v0 import AuthorizationCheck, Reject
from vecjson import _conv, action_from_case, gate_from_json, params_from_json

HERE = Path(__file__).resolve().parent
DIR = HERE.parent / "v1"
KEYS = HERE.parent / "v0" / "keys.json"
FORMAT = "edicta-vectors/v1"
REVISION = "v1-draft.4"
REVISIONS: dict = {}

LIT = {
    "commitment": {"v1": b"\x1dedicta/v1/decision-commitment", "v0": b"\x1dedicta/v0/decision-commitment"},
    "sig": {"v1": b"\x0dedicta/v1/sig", "v0": b"\x0dedicta/v0/sig"},
    "auth": {"v1": b"\x17edicta/v1/authorization", "v0": b"\x17edicta/v0/authorization"},
    "auth_sig": {"v1": b"\x1bedicta/v1/authorization-sig", "v0": b"\x1bedicta/v0/authorization-sig"},
    "action": {"v1": b"\x10edicta/v1/action", "v0": b"\x10edicta/v0/action"},
}


def ahash(version: int, action_type: str, salt: bytes | None, action: bytes) -> bytes:
    """Action hash from the literal tags: v1 4.7 (salt between type and bytes), v0 core 5.1."""
    t = action_type.encode()
    mid = salt if version == 1 else b""
    return hashlib.sha256(LIT["action"]["v1" if version == 1 else "v0"] + bytes([len(t)]) + t + mid + action).digest()

REQUIRED = {
    "valid.json": ["v1_minimal_included_fibre", "v1_minimal_included_blob", "v1_pending_fibre", "v1_pending_blob",
                   "v1_mandate_ref", "v1_pending_fibre_mandate_ref", "v1_pending_blob_mandate_ref", "v1_maximal"],
    "reject.json": ["da_3_reserved", "payload_ref_key_7_reserved", "payload_ref_key_8_reserved",
                    "commitment_key_15_reserved", "anchor_1", "anchor_3", "anchor_tstr", "mandate_ref_31_bytes",
                    "mandate_ref_33_bytes", "mandate_ref_tstr", "version_2", "v1_signed_under_v0_tags",
                    "v0_signed_under_v1_tags", "v1_bytes_v0_reader_minimal", "v1_bytes_v0_reader_key_14",
                    "retired_key_9", "signer_on_fibre_pending", "missing_signer_blob_pending"],
    "authorization.json": ["auth_v1_strict_da", "auth_v1_strict_archive", "auth_v1_fast_fibre",
                           "auth_v1_fast_blob_timeout_lowered", "auth_v1_max_size", "auth_v1_fast_without_deadline",
                           "auth_v1_strict_with_deadline", "auth_v1_mode_3", "auth_v1_mode_0", "auth_v1_missing_mode",
                           "auth_v1_deadline_0", "auth_v1_under_v0_tags", "auth_v0_under_v1_tags",
                           "v0_executor_refuses_v1", "executor_accept_v0_only", "exec_v1_salt_missing",
                           "exec_v1_wrong_salt", "exec_v0_salt_present"],
    "anchor.json": ["window_gate_min", "window_mandate_min", "window_chain_min", "timeout_lowers_deadline",
                    "timeout_zero_ignored", "h0_age_at_bound", "h0_too_old", "window_closed", "window_chain_zero",
                    "window_at_bound", "window_slack_at_bound", "window_slack_one_short", "timeout_below_head",
                    "timeout_at_head_plus_slack", "slack_waived_included", "slack_not_waived_nonzero",
                    "promise_slack"],
    "action.json": ["action_v1_minimal", "action_v1_max", "action_v1_wrong_salt", "action_v1_salt_missing",
                    "action_v1_salt_31", "action_v1_salt_33", "action_v1_v0_tag", "action_v1_unsalted",
                    "action_v1_salt_after_bytes", "action_v0_with_salt", "action_v0_salt_prefixed_bytes"],
    "gate.json": ["fast_mode_without_mandate", "age_plus_slack_over_window", "max_h0_age_equals_window"],
    "payload.json": ["payload_v1_minimal", "payload_v1_salt_missing", "payload_v1_version_0", "payload_v1_wrong_salt",
                     "payload_v0_with_salt"],
}


class Failure(Exception):
    pass


def expect(cond: bool, msg: str):
    if not cond:
        raise Failure(msg)


def load(name: str) -> dict:
    d = json.loads((DIR / name).read_text())
    expect(d.get("format") == FORMAT and d.get("revision") == REVISIONS.get(name, REVISION), f"{name}: format or revision")
    return d


def keys() -> dict:
    out = {}
    for name, k in json.loads(KEYS.read_text())["keys"].items():
        priv = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(k["seed_hex"]))
        expect(priv.public_key().public_bytes_raw().hex() == k["public_key_hex"], f"keys.json {name}")
        out[name] = priv
    return out


def check_signed_fields(case: dict, canon: bytes, ks: dict, kind: str):
    """The case's hash, signed message and signature follow from canon under its declared tags."""
    cid, tags = case["id"], case["signed_tags"]
    hk, sk_ = ("commitment", "sig") if kind == "commitment" else ("auth", "auth_sig")
    hh = hashlib.sha256(LIT[hk][tags] + canon).digest()
    expect(case[f"{kind}_hash_hex"] == hh.hex(), f"{cid}: {kind} hash under {tags} tags")
    msg = LIT[sk_][tags] + hh
    expect(case["signed_message_hex"] == msg.hex(), f"{cid}: signed message")
    expect(len(msg) == (46 if kind == "commitment" else 60), f"{cid}: signed message length")
    sig = ks[case["signer"]].sign(msg)
    expect(case["signature_hex"] == sig.hex(), f"{cid}: not the deterministic Ed25519 signature")
    return sig


def commitment_input(j: dict) -> dict:
    return _conv(j, v1.COMMITMENT_V1 if j.get("version") == "1" else v0.COMMITMENT, False)


def check_valid(f: dict, ks: dict) -> dict:
    gate, params = gate_from_json(f["gate"]), params_from_json(f["params"])
    out = {}
    for case in f["cases"]:
        cid = case["id"]
        c = commitment_input(case["input"])
        canon = encode(v1.to_cbor(c, v1.COMMITMENT_V1))
        expect(canon.hex() == case["commitment_cbor_hex"], f"{cid}: canonical encoding")
        expect(case["signed_tags"] == "v1" and case["signer"] == "agent1", f"{cid}: signer or tags")
        sig = check_signed_fields(case, canon, ks, "commitment")
        envb = encode({1: Raw(canon), 2: sig})
        expect(envb.hex() == case["envelope_hex"], f"{cid}: envelope")
        try:
            ver, signed, h = v1.verify_for_gate_any(envb, int(case["now"]), gate_from_json(case.get("gate", f["gate"])),
                                                    params)
        except Reject as e:
            raise Failure(f"{cid}: rejected with {e}")
        expect(ver == 1 and signed["commitment"] == c and h.hex() == case["commitment_hash_hex"], f"{cid}: round trip")
        expect(case["pending"] is v1.is_pending(c), f"{cid}: pending flag")
        action = action_from_case(case)
        salt = bytes.fromhex(case["action_salt_hex"])
        expect(len(salt) == 32 and ahash(1, case["action_type"], salt, action) == c["action"]["hash"]
               and case["action_hash_hex"] == c["action"]["hash"].hex(), f"{cid}: salted action hash")
        expect(case["action_type"] == c["action"]["type"]
               and case["action_type"] in gate_from_json(case.get("gate", f["gate"]))["action_types"],
               f"{cid}: action type")
        out[cid] = (c, canon, case)
    mx = out["v1_maximal"]
    expect(len(mx[1]) == 596 and len(bytes.fromhex(mx[2]["envelope_hex"])) == 665, "v1_maximal sizes")
    for cid in ("v1_pending_fibre", "v1_pending_blob", "v1_pending_fibre_mandate_ref"):
        expect(out[cid][0]["payload_ref"].get("anchor") == 2, f"{cid}: not pending")
    expect({out["v1_pending_fibre"][0]["payload_ref"]["da"], out["v1_pending_blob"][0]["payload_ref"]["da"]} == {1, 2},
           "pending references for both da")
    expect("mandate_ref" in out["v1_mandate_ref"][0], "v1_mandate_ref without key 14")
    return out


def check_reject(f: dict, ks: dict) -> set:
    gate, params = gate_from_json(f["gate"]), params_from_json(f["params"])
    seen = set()
    for case in f["cases"]:
        cid, want = case["id"], case["expect_error"]
        canon = bytes.fromhex(case["commitment_cbor_hex"])
        sig = check_signed_fields(case, canon, ks, "commitment")
        envb = encode({1: Raw(canon), 2: sig})
        expect(envb.hex() == case["envelope_hex"], f"{cid}: envelope")
        if "input" in case:
            c = commitment_input(case["input"])
            schema = v1.COMMITMENT_V1 if c["version"] == 1 else v0.COMMITMENT
            expect(encode(v1.to_cbor(c, schema)) == canon, f"{cid}: bytes do not carry the input")
        try:
            if case["reader"] == "v0":
                v0.verify_for_gate(envb, int(case["now"]), gate, params)
            else:
                v1.verify_for_gate_any(envb, int(case["now"]), gate, params)
        except Reject as e:
            expect(e.sentinel == want, f"{cid}: got {e.sentinel}, want {want}")
        else:
            raise Failure(f"{cid}: accepted, want {want}")
        seen.add(want)
    return seen


def check_authorization(f: dict, ks: dict, valid: dict) -> set:
    ttl = int(f["max_authorization_ttl_s"])
    gid = gate_from_json(f["gate"])["gate_id"]
    gate_pub = ks["gate1"].public_key().public_bytes_raw()

    def chk(blk: dict) -> v1.CheckV1:
        acc = frozenset(int(x) for x in blk.get("accept_versions", ["0", "1"]))
        expect(bytes.fromhex(blk["gate_pubkey_hex"]) == gate_pub and blk["gate_id"] == gid, "check pins gate1")
        salt = bytes.fromhex(blk["action_salt_hex"]) if "action_salt_hex" in blk else None
        return v1.CheckV1(gate_pub, gid, blk["action_type"], action_from_case(blk), int(blk["now"]),
                          int(blk["skew_s"]), acc, salt)

    for case in f["cases"]:
        cid = case["id"]
        a = _conv(case["input"], v1.AUTHORIZATION_V1, False)
        canon = encode(v1.to_cbor(a, v1.AUTHORIZATION_V1))
        expect(canon.hex() == case["authorization_cbor_hex"], f"{cid}: canonical encoding")
        expect(case["signed_tags"] == "v1" and case["signer"] == "gate1", f"{cid}: signer or tags")
        sig = check_signed_fields(case, canon, ks, "authorization")
        data = encode({1: Raw(canon), 2: sig})
        expect(data.hex() == case["signed_authorization_hex"] and len(data) <= v0.MAX_AUTHORIZATION_SIZE,
               f"{cid}: signed Authorization")
        if "commitment_ref" not in case:
            expect(cid == "auth_v1_max_size" and len(data) == 233, f"{cid}: only the size case has no commitment")
            signed, canon2 = v1._decode_signed(data, 256, v1.SIGNED_AUTHORIZATION_V1, v1._parse(data, 256), "a")
            v1.validate_authorization_v1(signed["authorization"], frozenset({1}))
            continue
        c, ccanon, _ = valid[case["commitment_ref"]]
        expect(a["version"] == 1 and a["commitment_hash"] == v1.commitment_hash_v1(ccanon), f"{cid}: commitment")
        expect(a["action_hash"] == c["action"]["hash"] and a["gate_id"] == c["scope"]["gate_id"] == gid, f"{cid}: binding")
        expect(a["expires"] == v0.authorization_expires(c["valid_until"], int(case["authorized_at"]), ttl)
               and a["expires"] <= c["valid_until"], f"{cid}: expires")
        pend = v1.is_pending(c)
        expect(a["mode"] == (2 if pend else 1), f"{cid}: mode does not follow the reference form (A2)")
        if pend:
            h0 = c["payload_ref"]["height"]
            expect(h0 < a["anchor_deadline"] <= h0 + 1000, f"{cid}: deadline outside (h0, h0 + 1000] (A3)")
            wi = case["window_inputs"]
            opt = lambda k: int(wi[k]) if k in wi else None
            expect(int(wi["h0"]) == h0, f"{cid}: window h0")
            d = v1.fast_window(int(wi["da"]), h0, int(wi["head"]), int(wi["fast_window_blocks"]), int(wi["max_h0_age"]),
                               int(wi["fast_mode_max_delay"]), opt("chain_window"), opt("timeout_height") or 0,
                               int(wi["min_fast_slack_blocks"]))
            expect(d >= int(wi["head"]) + int(wi["min_fast_slack_blocks"]), f"{cid}: deadline below the slack")
            expect(d == a["anchor_deadline"], f"{cid}: anchor_deadline is not the K-fast result")
        else:
            expect("anchor_deadline" not in a, f"{cid}: deadline on a strict Authorization")
        try:
            ver, signed, h = v1.verify_authorization_any(data, chk(case["check"]))
        except Reject as e:
            raise Failure(f"{cid}: rejected with {e}")
        expect(ver == 1 and signed["authorization"] == a and h.hex() == case["authorization_hash_hex"], f"{cid}: round trip")
    seen = set()
    for case in f["reject"]:
        cid, want = case["id"], case["expect_error"]
        canon = bytes.fromhex(case["authorization_cbor_hex"])
        sig = check_signed_fields(case, canon, ks, "authorization")
        data = bytes.fromhex(case["signed_authorization_hex"])
        if data != encode({1: Raw(canon), 2: sig}):
            expect(want == "ErrTooLarge" and data.startswith(encode({1: Raw(canon), 2: sig})), f"{cid}: bytes")
        blk = case["check"]
        try:
            if case["executor"] == "v0":
                v0.verify_authorization(data, AuthorizationCheck(gate_pub, gid, blk["action_type"], action_from_case(blk),
                                                                 int(blk["now"]), int(blk["skew_s"])))
            else:
                v1.verify_authorization_any(data, chk(blk))
        except Reject as e:
            expect(e.sentinel == want, f"{cid}: got {e.sentinel}, want {want}")
        else:
            raise Failure(f"{cid}: accepted, want {want}")
        seen.add(want)
    return seen


def check_limits(f: dict, gate: dict, params) -> int:
    for case in f["cases"]:
        cid = case["id"]
        if "envelope_hex" in case:
            data = bytes.fromhex(case["envelope_hex"])
            expect(len(data) == int(case["size"]), f"{cid}: size")
            try:
                v1.verify_for_gate_any(data, int(case["now"]), gate_from_json(case["gate"]) if "gate" in case else gate,
                                       params)
                got = None
            except Reject as e:
                got = e.sentinel
        else:
            data = bytes.fromhex(case["signed_authorization_hex"])
            expect(len(data) == int(case["size"]), f"{cid}: size")
            try:
                signed, _ = v1._decode_signed(data, 256, v1.SIGNED_AUTHORIZATION_V1, v1._parse(data, 256), "a")
                v1.validate_authorization_v1(signed["authorization"], frozenset({1}))
                got = None
            except Reject as e:
                got = e.sentinel
        expect(got == case.get("expect_error"), f"{cid}: got {got}, want {case.get('expect_error')}")
    return len(f["cases"])


def check_anchor(f: dict) -> int:
    for c in f["k1"]:
        try:
            v0.check_anchor_time(int(c["issued_at"]), int(c["t_ref"]), int(c["skew_s"]))
            got = None
        except Reject as e:
            got = e.sentinel
        expect(got == c.get("expect_error"), f"{c['id']}: K1 got {got}")
    for c in f["k2"]:
        da, pend, t = int(c["da"]), c["form"] == "pending", int(c["t_ref"])
        if da == 1:
            expect(("intent_created_at" in c) == pend and ("creation_timestamp" in c) != pend, f"{c['id']}: inputs")
            other = int(c.get("intent_created_at") or c.get("creation_timestamp"))
            start = min(t, other)
        else:
            start = t
        r = int(c["retention_s"])
        margin = min(600, r // 8)
        within = int(c["valid_until"]) + margin <= start + r
        e = c["expect"]
        expect(e["start"] == str(start) and e["margin"] == str(margin) and e["within"] is within, f"{c['id']}: K2")
    for c in f["window"]:
        i = {k: int(v) for k, v in c["input"].items() if k != "promise"}
        pr = {k: int(v) for k, v in c["input"]["promise"].items()} if "promise" in c["input"] else None
        got = window_independent(i, pr)
        expect(got == c["expect"], f"{c['id']}: window got {got}, want {c['expect']}")
        inc = (i["included_at"], i["included_code"]) if "included_at" in i else None
        try:
            mod = {"anchor_deadline": str(v1.fast_window(i["da"], i["h0"], i["head"], i["fast_window_blocks"],
                                                         i["max_h0_age"], i["fast_mode_max_delay"],
                                                         i.get("chain_window"), i.get("timeout_height", 0),
                                                         i["min_fast_slack_blocks"], inc, pr))}
        except Reject as e:
            mod = {"expect_error": e.sentinel}
        expect(mod == got, f"{c['id']}: edicta_v1 disagrees with the independent window rule")
        if "anchor_deadline" in got:
            d = int(got["anchor_deadline"])
            expect(i["h0"] < d <= i["h0"] + 1000, f"{c['id']}: deadline outside (h0, h0 + 1000]")
    return len(f["k1"]) + len(f["k2"]) + len(f["window"])


def window_independent(i: dict, pr: dict | None) -> dict:
    """8.1 F5/F6, 8.2 B4/B5, 8.3 from the text: age, window >= 1, then slack and promise slack as provisional
    failures that only an inclusion with code 0 inside [h0, deadline] waives."""
    h0, head = i["h0"], i["head"]
    if head < h0:
        return {"expect_error": "ErrChainUnavailable"}
    if head - h0 > i["max_h0_age"]:
        return {"expect_error": "ErrH0TooOld"}
    w = min(i["fast_window_blocks"], i["fast_mode_max_delay"], i["chain_window"] if i["da"] == 1 else 10**9)
    if w < 1:
        return {"expect_error": "ErrAnchorWindowClosed"}
    d = h0 + w
    t = i.get("timeout_height", 0)
    if i["da"] == 2 and 0 < t < d:
        d = t
    prov = d - head < i["min_fast_slack_blocks"]
    if i["da"] == 1 and pr and not pr["t_head"] + pr["min_slack"] < pr["creation"] + pr["timeout"]:
        prov = True
    if "included_at" in i:
        ok = i["included_code"] == 0 and h0 <= i["included_at"] <= d
        return {"anchor_deadline": str(d)} if ok else {"expect_error": "ErrAnchorWindowClosed"}
    return {"expect_error": "ErrAnchorWindowClosed"} if prov else {"anchor_deadline": str(d)}


def check_action(f: dict) -> int:
    expect(bytes.fromhex(f["tag"]) == LIT["action"]["v1"], "action.json tag")
    for c in f["cases"]:
        salt = bytes.fromhex(c["action_salt_hex"])
        act = action_from_case(c)
        h = ahash(1, c["action_type"], salt, act)
        expect(h.hex() == c["action_hash_hex"], f"{c['id']}: hash")
        t = c["action_type"].encode()
        pre = LIT["action"]["v1"] + bytes([len(t)]) + t + salt + act
        expect(len(pre) == int(c["preimage_size"]), f"{c['id']}: preimage size")
        if "preimage_hex" in c:
            expect(c["preimage_hex"] == pre.hex(), f"{c['id']}: preimage")
    for r in f["reject"]:
        ver, act = int(r["version"]), bytes.fromhex(r["action_hex"])
        salt = bytes.fromhex(r["action_salt_hex"]) if "action_salt_hex" in r else None
        committed = bytes.fromhex(r["committed_action_hash_hex"])
        if "committed_preimage_hex" in r:
            expect(hashlib.sha256(bytes.fromhex(r["committed_preimage_hex"])).digest() == committed, f"{r['id']}: pre")
        if ver == 1 and salt is None:
            got = "ErrMissingField"
        elif ver == 1 and len(salt) != 32:
            got = "ErrFieldSize"
        elif ver == 0 and salt is not None:
            got = "ErrUnknownKey"
        else:
            got = None if ahash(ver, r["action_type"], salt, act) == committed else "ErrActionMismatch"
        expect(got == r["expect_error"], f"{r['id']}: got {got}")
        try:
            v1.gate_stage_a(ver, {"action": {"type": r["action_type"], "hash": committed}}, act, salt)
            mod = None
        except Reject as e:
            mod = e.sentinel
        expect(mod == got, f"{r['id']}: edicta_v1 disagrees")
    return len(f["cases"]) + len(f["reject"])


def check_gate(f: dict) -> int:
    for c in f["cases"]:
        cfg = {}
        for k, v in c["config"].items():
            if k == "pending_namespaces":
                cfg[k] = [bytes.fromhex(x) for x in v]
            elif isinstance(v, str):
                cfg[k] = int(v)
            else:
                cfg[k] = v
        try:
            v1.validate_gate_config(cfg, c["mandate"], f["allowlist"])
            got = {"result": "ok"}
        except Reject as e:
            got = {"error": e.sentinel, "cause": e.detail}
        expect(got == c["expect"], f"{c['id']}: got {got}")
        full = dict({"fast_window_blocks": 100, "max_h0_age_blocks": 10, "min_fast_slack_blocks": 3}, **cfg)
        if got == {"result": "ok"}:
            expect(full["max_h0_age_blocks"] + full["min_fast_slack_blocks"] <= full["fast_window_blocks"]
                   and (c["mandate"] or not cfg.get("fast_mode")), f"{c['id']}: accepted against 7.4")
    return len(f["cases"])


def check_payload(f: dict) -> int:
    import edicta_payload_v0 as pv0
    c = f["cases"][0]
    blob = bytes.fromhex(c["blob_hex"])
    expect(hashlib.sha256(blob).hexdigest() == c["ciphertext_hash_hex"] and len(blob) == int(c["payload_size"]),
           "payload: blob hashes")
    pv0.blob_decode(blob)
    aead = pv0.open_blob(blob, bytes.fromhex(c["recipient"]["sk_hex"]))
    expect(hashlib.sha256(aead).hexdigest() == c["plaintext_hash_hex"], "payload: O7")
    expect(aead == bytes.fromhex(c["aead_salt_hex"]) + bytes.fromhex(c["plaintext_cbor_hex"]), "payload: plaintext")
    p = v1.o8(1, aead, c["action_type"], bytes.fromhex(c["committed_action_hash_hex"]))
    expect(p["action"]["action_salt"].hex() == c["action_salt_hex"]
           and ahash(1, c["action_type"], p["action"]["action_salt"], p["action"]["data"]).hex()
           == c["committed_action_hash_hex"], "payload: O8 v1 independent")
    for r in f["reject"]:
        try:
            v1.o8(int(r["commitment_version"]), b"\x00" * 32 + bytes.fromhex(r["plaintext_cbor_hex"]), r["action_type"],
                  bytes.fromhex(r["committed_action_hash_hex"]))
            got = None
        except Reject as e:
            got = e.sentinel
        expect(got == r["expect_error"], f"{r['id']}: got {got}")
    return 1 + len(f["reject"])


def check_regenerated(files: dict):
    import gen_vectors_v1 as gen
    for name, obj in gen.build().items():
        expect(json.dumps(obj, indent=2, ensure_ascii=True) + "\n" == (DIR / name).read_text(),
               f"{name}: generator output differs")


def main() -> int:
    try:
        ks = keys()
        files = {n: load(n) for n in ("valid.json", "reject.json", "authorization.json", "limits.json", "anchor.json",
                                      "action.json", "gate.json", "payload.json")}
        for name, ids in REQUIRED.items():
            f = files[name]
            have = [c["id"] for k in ("cases", "reject", "window") for c in f.get(k, [])]
            expect(len(have) == len(set(have)), f"{name}: duplicate ids")
            missing = [i for i in ids if i not in have]
            expect(not missing, f"{name}: missing cases {missing}")
        valid = check_valid(files["valid.json"], ks)
        seen = check_reject(files["reject.json"], ks)
        aseen = check_authorization(files["authorization.json"], ks, valid)
        gate, params = gate_from_json(files["valid.json"]["gate"]), params_from_json(files["valid.json"]["params"])
        nl = check_limits(files["limits.json"], gate, params)
        na = check_anchor(files["anchor.json"])
        nac = check_action(files["action.json"])
        ng = check_gate(files["gate.json"])
        npl = check_payload(files["payload.json"])
        check_regenerated(files)
    except (Failure, Reject) as e:
        print(f"FAIL (v1): {e}", file=sys.stderr)
        return 1
    a = files["authorization.json"]
    print(f"OK (v1, {REVISION}): {len(valid)} valid, {len(files['reject.json']['cases'])} reject "
          f"({len(seen)} sentinels), {len(a['cases'])} authorization, {len(a['reject'])} authorization reject "
          f"({len(aseen)} sentinels), {nl} limits, {na} anchor, {nac} action, {ng} gate config, {npl} payload; "
          f"generator output identical")
    return 0


if __name__ == "__main__":
    sys.exit(main())
