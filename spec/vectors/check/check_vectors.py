#!/usr/bin/env python3
"""Verifies the Edicta vectors (v1.0) against an independent implementation of the rules.

This script checks the core set under spec/vectors/v1 (valid, reject, authorization, receipt,
record_request, payload, limits, anchor, action, gate; payload_blob.json through
check_payload_blob.py, which runs the RFC 9180 known-answer tests of the hand-written HPKE first) and
the test keys spec/vectors/keys.json, and then runs every other checker: the profiles, the API vectors,
the Fibre and Celestia DA vectors, the archive records, the verifier vectors, the policy vectors and
the principal signature vectors. Hashes and signed messages are rebuilt from literal tags.

Files under spec/vectors/historical/ are not checked: they belong to the unsupported v0 drafts.

Usage: python3 spec/vectors/check/check_vectors.py [--core-only]
Exit status 0 when all vectors pass. Requires Python 3.11+ and 'cryptography' (see requirements.txt
next to this file).
"""

from __future__ import annotations

import sys

sys.dont_write_bytecode = True

import hashlib
import json
import re
import subprocess
from pathlib import Path

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
except ImportError:
    sys.exit(
        "missing dependency 'cryptography'. Install it in a virtualenv, for example:\n"
        "  python3 -m venv .venv && .venv/bin/pip install -r spec/vectors/check/requirements.txt\n"
        "  .venv/bin/python spec/vectors/check/check_vectors.py"
    )

import check_payload_blob
import ed25519_point as ed
import edicta as E
import edicta_payload as pv
import hpke_base
from cbor_strict import Raw, decode_strict, encode, to_plain
from edicta import AuthorizationCheck, Reject
from vecjson import _conv, action_from_case, gate_from_json, params_from_json, pattern_bytes

HERE = Path(__file__).resolve().parent
VECTORS = HERE.parent
DIR = VECTORS / "v1"
FORMAT = "edicta-vectors/v1"
REVISION = "v1.0"
REVISIONS = {"limits.json": "v1.0", "gate.json": "v1.0"}

LIT = {
    "commitment": b"\x1dedicta/v1/decision-commitment",
    "sig": b"\x0dedicta/v1/sig",
    "action": b"\x10edicta/v1/action",
    "auth": b"\x17edicta/v1/authorization",
    "auth_sig": b"\x1bedicta/v1/authorization-sig",
    "receipt": b"\x11edicta/v1/receipt",
    "receipt_sig": b"\x15edicta/v1/receipt-sig",
    "record": b"\x18edicta/v1/record-request",
    "publish": b"\x19edicta/v1/publish-request",
    "payload": b"\x11edicta/v1/payload",
    "payload_dek": b"\x15edicta/v1/payload-dek",
    "auditor_kid": b"\x15edicta/v1/auditor-kid",
    "batch_leaf": b"\x14edicta/v1/batch-leaf",
}

STAGE_OF = {
    "ErrTooLarge": "D", "ErrMalformed": "D", "ErrTrailingData": "D", "ErrFloat": "D",
    "ErrSimpleValue": "D", "ErrTag": "D", "ErrIndefiniteLength": "D", "ErrNonMinimalInt": "D",
    "ErrUnsortedMap": "D", "ErrDuplicateKey": "D", "ErrKeyType": "D", "ErrUnknownKey": "D",
    "ErrWrongType": "D", "ErrMissingField": "D", "ErrFieldSize": "D", "ErrInvalidString": "D",
    "ErrNestingTooDeep": "D", "ErrNonCanonical": "D",
    "ErrUnsupportedVersion": "S", "ErrIntRange": "S", "ErrInvalidEnum": "S", "ErrZeroValue": "S",
    "ErrPayloadTooLarge": "S", "ErrInvalidNamespace": "S", "ErrTimeOrder": "S",
    "ErrTTLTooLong": "S", "ErrInvalidParams": "S", "ErrKeyRole": "S",
    "ErrInvalidPublicKey": "G", "ErrSignatureInvalid": "G", "ErrNotYetValid": "T", "ErrExpired": "T",
    "ErrScopeMismatch": "C", "ErrActionTypeNotAllowed": "C", "ErrActionSize": "A", "ErrActionMismatch": "A",
    "ErrPayloadSizeMismatch": "P", "ErrPayloadHashMismatch": "P",
}
NOT_VECTORED = {"ErrNonCanonical", "ErrInvalidParams", "ErrKeyRole"}
# Stage A also refuses a missing or wrong-size salt with these decoding sentinels.
A_EXTRA = {"ErrMissingField", "ErrFieldSize"}
X_SENTINELS = {"ErrScopeMismatch", "ErrActionSize", "ErrMissingField", "ErrFieldSize", "ErrActionMismatch",
               "ErrExpired"}
GATE_VECTORED = {"ErrIssuedBeforeAnchor", "ErrBeforeRegistryEpoch", "ErrArchiveRecomputeUnsupported",
                 "ErrRetentionUnavailable"}
RECORD_STAGES = {"D": {"ErrFieldSize", "ErrInvalidString"}, "G": {"ErrInvalidPublicKey", "ErrSignatureInvalid"},
                 "R": {"ErrExecutorNotAllowed", "ErrKeyRole"}}
UNASSIGNED = {"commitment": (E.COMMITMENT, {9, 15}), "action": (E.ACTION, {1, 2}), "scope": (E.SCOPE, {2, 3, 4}),
              "payload_ref": (E.PAYLOAD_REF, {7, 8}), "receipt": (E.RECEIPT, {5, 7})}

REQUIRED = {
    "valid.json": ["minimal_lmt", "ttl_exactly_max", "fibre_small_payload", "action_max_size", "action_json_bytes",
                   "v1_minimal_included_fibre", "v1_minimal_included_blob", "v1_pending_fibre", "v1_pending_blob",
                   "v1_mandate_ref", "v1_pending_fibre_mandate_ref", "v1_pending_blob_mandate_ref", "v1_maximal"],
    "reject.json": ["too_large", "commitment_too_large", "sig_torsion_r", "version_0", "version_2",
                    "action_unsalted", "action_wrong_salt", "action_salt_31", "da_3_reserved",
                    "payload_ref_key_7_reserved", "payload_ref_key_8_reserved", "commitment_key_15_reserved",
                    "anchor_1", "anchor_3", "anchor_tstr", "mandate_ref_31_bytes", "mandate_ref_33_bytes",
                    "mandate_ref_tstr", "retired_key_9", "signer_on_fibre_pending", "missing_signer_blob_pending"],
    "authorization.json": ["auth_minimal_lmt_da", "auth_v1_strict_da", "auth_v1_strict_archive", "auth_v1_fast_fibre",
                           "auth_v1_fast_blob_timeout_lowered", "auth_v1_max_size", "authorization_version_0",
                           "auth_v1_fast_without_deadline", "auth_v1_strict_with_deadline", "auth_v1_mode_3",
                           "auth_v1_mode_0", "auth_v1_missing_mode", "auth_v1_deadline_0", "exec_v1_salt_missing",
                           "exec_v1_wrong_salt"],
    "receipt.json": ["receipt_minimal_lmt", "receipt_version_0"],
    "record_request.json": ["rec_minimal_lmt"],
    "payload.json": ["ciphertext_hash_small_blob", "plaintext_hash_basic", "payload_v1_minimal",
                     "payload_v1_salt_missing", "payload_version_0", "payload_v1_wrong_salt", "blob_truncated"],
    "anchor.json": ["window_gate_min", "window_mandate_min", "window_chain_min", "timeout_lowers_deadline",
                    "timeout_zero_ignored", "h0_age_at_bound", "h0_too_old", "window_closed", "window_chain_zero",
                    "window_at_bound", "window_slack_at_bound", "window_slack_one_short", "timeout_below_head",
                    "timeout_at_head_plus_slack", "slack_waived_included", "slack_not_waived_nonzero",
                    "promise_slack", "k1_at_limit", "k2_blob_at_limit", "k2_fibre_at_height_unreadable",
                    "epoch_at_limit"],
    "action.json": ["action_v1_minimal", "action_v1_max", "action_v1_wrong_salt", "action_v1_salt_missing",
                    "action_v1_salt_31", "action_v1_salt_33", "action_unsalted", "action_v1_salt_after_bytes"],
    "gate.json": ["fast_mode_without_mandate", "age_plus_slack_over_window", "max_h0_age_equals_window",
                  "reveal_type_offchain_profile", "reveal_type_without_profile", "fast_delay_below_slack"],
}
FILES = ["valid.json", "reject.json", "authorization.json", "receipt.json", "record_request.json", "payload.json",
         "limits.json", "anchor.json", "action.json", "gate.json"]


class Failure(Exception):
    pass


def expect(cond: bool, msg: str):
    if not cond:
        raise Failure(msg)


def load(name: str) -> dict:
    d = json.loads((DIR / name).read_text())
    expect(d.get("format") == FORMAT and d.get("revision") == REVISIONS.get(name, REVISION),
           f"{name}: format or revision")
    return d


def check_constants():
    """Tag bytes and lengths, written out literally so a typo in one place cannot hide."""
    import edicta_publish
    mod = {"commitment": E.TAG_COMMITMENT, "sig": E.TAG_SIG, "action": E.TAG_ACTION, "auth": E.TAG_AUTHORIZATION,
           "auth_sig": E.TAG_AUTHORIZATION_SIG, "receipt": E.TAG_RECEIPT, "receipt_sig": E.TAG_RECEIPT_SIG,
           "record": E.TAG_RECORD_REQUEST, "publish": edicta_publish.TAG_PUBLISH_REQUEST,
           "payload": pv.TAG_PAYLOAD_AEAD, "payload_dek": pv.TAG_PAYLOAD_DEK, "auditor_kid": E.TAG_AUDITOR_KID,
           "batch_leaf": E.TAG_BATCH_LEAF}
    for k, t in mod.items():
        expect(E.tagged(t) == LIT[k], f"tag {k}")
    signed = {"sig": 46, "receipt_sig": 54, "auth_sig": 60}
    for k, n in signed.items():
        expect(len(LIT[k]) + 32 == n, f"signed message length under {k}")
    expect(len(set(signed.values())) == len(signed), "signed message lengths must differ")
    # Messages signed directly (record, publish) must not share a first byte with any hashed or
    # signed preimage; the payload tags are never hashed or signed.
    direct = [LIT["record"][0], LIT["publish"][0]]
    others = [LIT[k][0] for k in ("commitment", "sig", "action", "auth", "auth_sig", "receipt", "receipt_sig",
                                  "auditor_kid", "batch_leaf")]
    expect(len(set(direct)) == 2 and not set(direct) & set(others), "directly signed tags must have unique lengths")
    hashed = ["commitment", "action", "auth", "receipt", "auditor_kid", "batch_leaf"]
    expect(len({LIT[k] for k in hashed}) == len(hashed), "hash tags must differ")
    kid_pre = LIT["auditor_kid"] + bytes(32)
    expect(len(kid_pre) == 54 == len(LIT["receipt_sig"]) + 32 and kid_pre[:1] == LIT["receipt_sig"][:1]
           and kid_pre[11] != LIT["receipt_sig"][11], "kid preimage vs receipt signed message")
    for name, (schema, keys) in UNASSIGNED.items():
        expect(not keys & set(schema), f"{name}: an unassigned key is defined")
    expect(set(E.AUTHORIZATION) == set(range(1, 9)), "Authorization keys")


def check_keys() -> dict:
    keys = json.loads((VECTORS / "keys.json").read_text())
    expect(keys.get("format") == FORMAT, "keys.json format")
    out = {}
    for name, k in keys["keys"].items():
        priv = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(k["seed_hex"]))
        pub = priv.public_key().public_bytes_raw()
        expect(pub.hex() == k["public_key_hex"], f"{name}: public key does not match seed")
        msg = bytes.fromhex(k["kat_message_hex"])
        sig = priv.sign(msg)
        expect(sig.hex() == k["kat_signature_hex"], f"{name}: RFC 8032 known-answer signature mismatch")
        out[name] = priv
    return out


def supplied_action(case: dict) -> bytes:
    a = action_from_case(case)
    if "action_pattern" in case:
        expect(len(a) == int(case["action_size"]), f"{case.get('id', 'check')}: action size")
        expect(hashlib.sha256(a).hexdigest() == case["action_sha256_hex"], f"{case.get('id', 'check')}: action sha256")
    return a


def salt_of(case: dict):
    return bytes.fromhex(case["action_salt_hex"]) if "action_salt_hex" in case else None


def ahash(action_type: str, salt: bytes, action: bytes) -> bytes:
    """Salted action hash from the literal tag."""
    t = action_type.encode()
    return hashlib.sha256(LIT["action"] + bytes([len(t)]) + t + salt + action).digest()


def chash(canon: bytes) -> bytes:
    return hashlib.sha256(LIT["commitment"] + canon).digest()


def cin(j: dict) -> dict:
    return _conv(j, E.COMMITMENT, False)


def run_pipeline(case: dict, top: dict):
    envb = bytes.fromhex(case["envelope_hex"])
    gate = gate_from_json(case.get("gate", top["gate"]))
    params = params_from_json(case.get("params", top["params"]))
    signed, h = E.verify_for_gate(envb, int(case["now"]), gate, params)
    if "action_type" in case:
        expect(case["action_type"] == signed["commitment"]["action"]["type"], f"{case['id']}: action_type")
        E.check_action(signed["commitment"], supplied_action(case), salt_of(case))
    return signed, h


def check_valid(top: dict, ks: dict) -> dict:
    expect(top["patterns"] == {"affine-7-3": "byte i of the action is (7*i + 3) mod 256, for i from 0"}, "patterns")
    expect(top["keys"] == "spec/vectors/keys.json", "valid.json keys reference")
    out = {}
    for case in top["cases"]:
        cid = case["id"]
        c = cin(case["input"])
        canon = encode(E.to_cbor(c))
        expect(canon.hex() == case["commitment_cbor_hex"], f"{cid}: canonical encoding")
        h = chash(canon)
        expect(h.hex() == case["commitment_hash_hex"], f"{cid}: commitment_hash")
        msg = LIT["sig"] + h
        expect(len(msg) == 46 and msg.hex() == case["signed_message_hex"], f"{cid}: signed message")
        priv = ks[case["signer"]]
        expect(c["agent_pubkey"] == priv.public_key().public_bytes_raw(), f"{cid}: agent_pubkey is not the signer's")
        sig = bytes.fromhex(case["signature_hex"])
        expect(priv.sign(msg) == sig, f"{cid}: not the deterministic Ed25519 signature")
        envb = encode({1: Raw(canon), 2: sig})
        expect(envb.hex() == case["envelope_hex"], f"{cid}: envelope")
        a = supplied_action(case)
        salt = salt_of(case)
        expect(salt is not None and len(salt) == 32, f"{cid}: salt")
        t = case["action_type"].encode()
        expect(case["action_preimage_prefix_hex"] == (LIT["action"] + bytes([len(t)]) + t).hex(), f"{cid}: prefix")
        expect(ahash(case["action_type"], salt, a) == c["action"]["hash"]
               and case["action_hash_hex"] == c["action"]["hash"].hex(), f"{cid}: salted action hash")
        try:
            signed, h2 = run_pipeline(case, top)
        except Reject as e:
            raise Failure(f"{cid}: valid vector rejected with {e}")
        expect(signed["commitment"] == c and h2 == h, f"{cid}: round trip")
        expect(case["pending"] is E.is_pending(c), f"{cid}: pending flag")
        expect(len(canon) <= 596, f"{cid}: commitment above the 596-byte schema maximum")
        out[cid] = (c, canon, case)
    mx = out["v1_maximal"]
    expect(len(mx[1]) == 596 and len(bytes.fromhex(mx[2]["envelope_hex"])) == 665, "v1_maximal sizes")
    for cid in ("v1_pending_fibre", "v1_pending_blob", "v1_pending_fibre_mandate_ref"):
        expect(out[cid][0]["payload_ref"].get("anchor") == 2, f"{cid}: not pending")
    expect("mandate_ref" in out["v1_mandate_ref"][0], "v1_mandate_ref without key 14")
    return out


def check_torsion_r(c: dict, canon: bytes, sig: bytes):
    """sig_torsion_r must fail for the right reason: valid key, S < L, cofactored equation holds,
    R has an order-8 component, only the cofactorless equation rejects it."""
    msg = LIT["sig"] + chash(canon)
    expect(ed.public_key_problem(c["agent_pubkey"]) is None, "sig_torsion_r: agent_pubkey fails G0")
    expect(int.from_bytes(sig[32:], "little") < E.ED25519_L, "sig_torsion_r: S >= L")
    r = ed.decode(sig[:32])
    expect(r is not None and ed.order(ed.mul(ed.L, r)) == 8, "sig_torsion_r: R has no order-8 component")
    expect(ed.cofactored_ok(c["agent_pubkey"], msg, sig), "sig_torsion_r: cofactored equation fails")
    expect(not ed.cofactorless_ok(c["agent_pubkey"], msg, sig), "sig_torsion_r: cofactorless equation holds")


def check_single_action_defect(case: dict, c: dict):
    """A stage A vector has exactly one defect: the presented salt, the presented bytes, or the hash
    construction."""
    cid = case["id"]
    pre = bytes.fromhex(case["committed_preimage_hex"])
    expect(hashlib.sha256(pre).digest() == c["action"]["hash"], f"{cid}: committed preimage")
    supplied, salt = supplied_action(case), salt_of(case)
    t = c["action"]["type"].encode("ascii")
    prefix = LIT["action"] + bytes([len(t)]) + t
    if case["rule"] in ("A0", "A0s"):
        expect(pre.startswith(prefix) and (not 1 <= len(supplied) <= E.MAX_ACTION_SIZE or salt is None
                                           or len(salt) != 32), f"{cid}: not a size defect")
    elif salt is not None and pre.startswith(prefix + salt):
        expect(pre[len(prefix) + 32:] != supplied, f"{cid}: supplied bytes equal the committed bytes")
    elif pre.startswith(prefix) and pre.endswith(supplied) and len(pre) == len(prefix) + 32 + len(supplied):
        expect(pre[len(prefix):len(prefix) + 32] != salt, f"{cid}: neither salt nor bytes differ")
    else:
        expect(pre.endswith(supplied) and 1 <= len(supplied) <= E.MAX_ACTION_SIZE, f"{cid}: supplied bytes are not "
               "the committed bytes")


def check_reject(top: dict, ks: dict) -> set:
    seen = set()
    for case in top["cases"]:
        cid, want = case["id"], case["expect_error"]
        stage = case["stage"]
        expect(want in STAGE_OF, f"{cid}: unknown sentinel {want}")
        expect(STAGE_OF[want] == stage or (stage == "A" and want in A_EXTRA), f"{cid}: {want} is not a stage {stage} "
               "error")
        expect(("action_type" in case) == (stage == "A") == ("committed_preimage_hex" in case),
               f"{cid}: action bytes belong to stage A cases only")
        envb = bytes.fromhex(case["envelope_hex"])
        if "commitment_cbor_hex" in case and "signed_message_hex" in case:
            canon = bytes.fromhex(case["commitment_cbor_hex"])
            h = chash(canon)
            expect(case["commitment_hash_hex"] == h.hex() and case["signed_message_hex"] == (LIT["sig"] + h).hex(),
                   f"{cid}: hash or signed message")
            sig = ks[case["signer"]].sign(LIT["sig"] + h)
            expect(case["signature_hex"] == sig.hex() and envb == encode({1: Raw(canon), 2: sig}), f"{cid}: envelope")
        if "input" in case:
            c = cin(case["input"])
            canon = encode(E.to_cbor(c))
            expect(canon.hex() == case["commitment_cbor_hex"], f"{cid}: canonical encoding")
            expect(chash(canon).hex() == case["commitment_hash_hex"], f"{cid}: commitment_hash")
            if stage != "D":
                signed, canon2 = E.decode_signed(envb)
                expect(canon2 == canon and signed["commitment"] == c, f"{cid}: envelope does not carry the input")
            if stage in ("T", "C", "A"):
                E.verify_signature(c, canon, signed["signature"])
            if stage == "A":
                check_single_action_defect(case, c)
            if cid == "sig_torsion_r":
                check_torsion_r(c, canon, signed["signature"])
        try:
            run_pipeline(case, top)
        except Reject as e:
            expect(e.sentinel == want, f"{cid}: got {e.sentinel}, want {want}")
        else:
            raise Failure(f"{cid}: accepted, want {want}")
        seen.add(want)
    missing = set(STAGE_OF) - NOT_VECTORED - {"ErrPayloadSizeMismatch", "ErrPayloadHashMismatch"} - seen
    expect(not missing, f"reject.json: sentinels without a must-reject vector: {sorted(missing)}")
    return seen


def check_authorization(f: dict, ks: dict, valid: dict) -> set:
    ttl = int(f["max_authorization_ttl_s"])
    gid = gate_from_json(f["gate"])["gate_id"]
    gate_pub = ks["gate1"].public_key().public_bytes_raw()

    def chk(blk: dict) -> AuthorizationCheck:
        return AuthorizationCheck(bytes.fromhex(blk["gate_pubkey_hex"]), blk["gate_id"], blk["action_type"],
                                  supplied_action(blk), int(blk["now"]), int(blk["skew_s"]), salt_of(blk))

    def signed_fields(case: dict, canon: bytes) -> bytes:
        cid = case["id"]
        ah = hashlib.sha256(LIT["auth"] + canon).digest()
        expect(case["authorization_hash_hex"] == ah.hex(), f"{cid}: authorization hash")
        msg = LIT["auth_sig"] + ah
        expect(case["signed_message_hex"] == msg.hex() and len(msg) == 60, f"{cid}: signed message")
        sig = ks[case["signer"]].sign(msg)
        expect(case["signature_hex"] == sig.hex(), f"{cid}: not the deterministic signature")
        return sig

    for case in f["cases"]:
        cid = case["id"]
        a = _conv(case["input"], E.AUTHORIZATION, False)
        canon = encode(E.to_cbor(a, E.AUTHORIZATION))
        expect(canon.hex() == case["authorization_cbor_hex"], f"{cid}: canonical encoding")
        expect(case["signer"] == "gate1", f"{cid}: signer")
        sig = signed_fields(case, canon)
        data = encode({1: Raw(canon), 2: sig})
        expect(data.hex() == case["signed_authorization_hex"] and len(data) <= E.MAX_AUTHORIZATION_SIZE,
               f"{cid}: signed Authorization")
        if "commitment_ref" not in case:
            expect(cid == "auth_v1_max_size" and len(data) == 233, f"{cid}: only the size case has no commitment")
            signed, _ = E.decode_signed_authorization(data)
            E.validate_authorization_static(signed["authorization"])
            continue
        c, ccanon, _ = valid[case["commitment_ref"]]
        expect(a["version"] == 1 and a["commitment_hash"] == chash(ccanon), f"{cid}: commitment")
        expect(a["action_hash"] == c["action"]["hash"] and a["gate_id"] == c["scope"]["gate_id"] == gid, f"{cid}: binding")
        expect(a["expires"] == min(c["valid_until"], int(case["authorized_at"]) + ttl) and a["expires"] <= c["valid_until"],
               f"{cid}: expires")
        pend = E.is_pending(c)
        expect(a["mode"] == (2 if pend else 1), f"{cid}: mode does not follow the reference form")
        if pend:
            h0 = c["payload_ref"]["height"]
            expect(h0 < a["anchor_deadline"] <= h0 + 1000, f"{cid}: deadline outside (h0, h0 + 1000]")
            wi = {k: int(v) for k, v in case["window_inputs"].items()}
            expect(wi["h0"] == h0, f"{cid}: window h0")
            got = window_independent(dict(wi, chain_window=wi.get("chain_window", 10 ** 9)), None)
            expect(got == {"anchor_deadline": str(a["anchor_deadline"])}, f"{cid}: anchor_deadline is not the K-fast "
                   "result")
        else:
            expect("anchor_deadline" not in a, f"{cid}: deadline on a strict Authorization")
        blk = case["check"]
        expect(bytes.fromhex(blk["gate_pubkey_hex"]) == gate_pub and blk["gate_id"] == gid, f"{cid}: check pins gate1")
        expect(ahash(blk["action_type"], salt_of(blk), supplied_action(blk)) == a["action_hash"], f"{cid}: check bytes")
        try:
            signed, h = E.verify_authorization(data, chk(blk))
        except Reject as e:
            raise Failure(f"{cid}: rejected with {e}")
        expect(signed["authorization"] == a and h.hex() == case["authorization_hash_hex"], f"{cid}: round trip")
    seen = set()
    for case in f["reject"]:
        cid, want, stage = case["id"], case["expect_error"], case["stage"]
        if stage == "X":
            expect(want in X_SENTINELS, f"{cid}: {want} is not an executor-check error")
        else:
            expect(STAGE_OF.get(want) == stage, f"{cid}: {want} is not a stage {stage} error")
        data = bytes.fromhex(case["signed_authorization_hex"])
        if "input" in case:
            a = _conv(case["input"], E.AUTHORIZATION, False)
            canon = encode(E.to_cbor(a, E.AUTHORIZATION))
            expect(canon.hex() == case["authorization_cbor_hex"], f"{cid}: canonical encoding")
            expect(hashlib.sha256(LIT["auth"] + canon).hexdigest() == case["authorization_hash_hex"], f"{cid}: hash")
            if stage != "D":
                signed, canon2 = E.decode_signed_authorization(data)
                expect(canon2 == canon and signed["authorization"] == a, f"{cid}: bytes do not carry the input")
        try:
            E.verify_authorization(data, chk(case["check"]))
        except Reject as e:
            expect(e.sentinel == want, f"{cid}: got {e.sentinel}, want {want}")
        else:
            raise Failure(f"{cid}: accepted, want {want}")
        seen.add(want)
    for s in ("ErrUnsupportedVersion", "ErrIntRange", "ErrInvalidEnum", "ErrZeroValue", "ErrInvalidPublicKey",
              "ErrSignatureInvalid", "ErrTooLarge") + tuple(X_SENTINELS):
        expect(s in seen, f"authorization.json: no must-reject vector for {s}")
    return seen


def literal_record_message(ch: bytes, gate_id: str, rail_ref: str) -> bytes:
    g, r = gate_id.encode("ascii"), rail_ref.encode("ascii")
    return LIT["record"] + ch + bytes([len(g)]) + g + bytes([len(r)]) + r


def check_record_requests(rq: dict, valid: dict) -> set:
    gate = rq["gate"]
    executors = [bytes.fromhex(k) for k in gate["executor_keys"]]
    gate_keys = [bytes.fromhex(gate["gate_pubkey_hex"])]
    privs = {}
    for name, k in rq["keys"].items():
        priv = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(k["seed_hex"]))
        pub = priv.public_key().public_bytes_raw()
        expect(pub.hex() == k["public_key_hex"], f"{name}: public key does not match seed")
        if "kat_signature_hex" in k:
            expect(priv.sign(bytes.fromhex(k["kat_message_hex"])).hex() == k["kat_signature_hex"], f"{name}: KAT")
        expect(ed.public_key_problem(pub) is None and pub in executors and pub not in gate_keys, f"{name}: key role")
        privs[pub] = priv
    for c in rq["cases"]:
        cid = c["id"]
        ch = bytes.fromhex(c["commitment_hash_hex"])
        expect(ch == chash(valid[c["commitment_ref"]][1]), f"{cid}: commitment_hash")
        msg = literal_record_message(ch, gate["gate_id"], c["rail_ref"])
        expect(msg.hex() == c["record_message_hex"] and len(msg) == 59 + len(gate["gate_id"]) + len(c["rail_ref"]),
               f"{cid}: record message")
        pub, sig = bytes.fromhex(c["executor_pubkey_hex"]), bytes.fromhex(c["signature_hex"])
        expect(privs[pub].sign(msg) == sig, f"{cid}: not the deterministic signature")
        E.verify_record_request(ch, bytes.fromhex(c["agent_pubkey_hex"]), gate["gate_id"], c["rail_ref"], pub, sig,
                                executors, gate_keys)
    seen = set()
    for c in rq["reject"]:
        cid, want = c["id"], c["expect_error"]
        expect(want in RECORD_STAGES.get(c["stage"], ()), f"{cid}: {want} is not a stage {c['stage']} Record error")
        ek = [bytes.fromhex(k) for k in c["executor_keys"]] if "executor_keys" in c else executors
        try:
            E.verify_record_request(bytes.fromhex(c["commitment_hash_hex"]), bytes.fromhex(c["agent_pubkey_hex"]),
                                    gate["gate_id"], c["rail_ref"], bytes.fromhex(c["executor_pubkey_hex"]),
                                    bytes.fromhex(c["signature_hex"]), ek, gate_keys)
        except Reject as e:
            expect(e.sentinel == want, f"{cid}: got {e.sentinel}, want {want}")
        else:
            raise Failure(f"{cid}: accepted, want {want}")
        seen.add(want)
    expect(seen == set().union(*RECORD_STAGES.values()), f"record_request.json sentinels: {sorted(seen)}")
    return seen


def check_receipts(rf: dict, ks: dict, valid: dict, af: dict, rq: dict) -> set:
    authorized = {c.get("commitment_ref") for c in af["cases"]}
    gate = gate_from_json(rf["gate"])
    for case in rf["cases"]:
        cid = case["id"]
        r = _conv(case["input"], E.RECEIPT, False)
        expect(r["version"] == 1, f"{cid}: version")
        expect(r["commitment_hash"] == chash(valid[case["commitment_ref"]][1]), f"{cid}: commitment_hash")
        expect(case["commitment_ref"] in authorized, f"{cid}: receipt for a commitment with no Authorization vector")
        expect(r["gate_id"] == gate["gate_id"], f"{cid}: gate_id")
        expect(r["executor_pubkey"].hex() in rq["gate"]["executor_keys"], f"{cid}: executor is not allowlisted")
        Ed25519PublicKey.from_public_bytes(r["executor_pubkey"]).verify(
            r["executor_signature"], literal_record_message(r["commitment_hash"], r["gate_id"], r["rail_ref"]))
        canon = encode(E.to_cbor(r, E.RECEIPT))
        expect(canon.hex() == case["receipt_cbor_hex"], f"{cid}: canonical encoding")
        rh = hashlib.sha256(LIT["receipt"] + canon).digest()
        expect(rh.hex() == case["receipt_hash_hex"], f"{cid}: receipt_hash")
        msg = LIT["receipt_sig"] + rh
        expect(len(msg) == 54 and msg.hex() == case["signed_message_hex"], f"{cid}: signed message")
        priv = ks[case["signer"]]
        expect(r["gate_pubkey"] == priv.public_key().public_bytes_raw(), f"{cid}: gate_pubkey")
        sig = bytes.fromhex(case["signature_hex"])
        expect(priv.sign(msg) == sig, f"{cid}: not the deterministic signature")
        data = encode({1: Raw(canon), 2: sig})
        expect(data.hex() == case["signed_receipt_hex"] and len(data) <= E.MAX_RECEIPT_SIZE, f"{cid}: signed receipt")
        signed, h2 = E.verify_receipt(data)
        expect(signed["receipt"] == r and h2 == rh, f"{cid}: round trip")
    seen = set()
    for case in rf["reject"]:
        cid, want = case["id"], case["expect_error"]
        expect(STAGE_OF.get(want) == case["stage"], f"{cid}: {want} is not a stage {case['stage']} error")
        data = bytes.fromhex(case["signed_receipt_hex"])
        if "input" in case:
            r = _conv(case["input"], E.RECEIPT, False)
            canon = encode(E.to_cbor(r, E.RECEIPT))
            expect(canon.hex() == case["receipt_cbor_hex"], f"{cid}: canonical encoding")
            expect(hashlib.sha256(LIT["receipt"] + canon).hexdigest() == case["receipt_hash_hex"], f"{cid}: hash")
        try:
            E.verify_receipt(data)
        except Reject as e:
            expect(e.sentinel == want, f"{cid}: got {e.sentinel}, want {want}")
        else:
            raise Failure(f"{cid}: accepted, want {want}")
        seen.add(want)
    return seen


def check_payload(f: dict, valid: dict) -> int:
    cases = {c["id"]: c for c in f["cases"]}
    small = cases["ciphertext_hash_small_blob"]
    blob = bytes.fromhex(small["blob_hex"])
    expect(hashlib.sha256(blob).hexdigest() == small["ciphertext_hash_hex"] and len(blob) == int(small["payload_size"]),
           "small blob: hashes")
    expect(encode(to_plain(decode_strict(blob))) == blob, "small blob: not canonical CBOR")
    pt = cases["plaintext_hash_basic"]
    got = hashlib.sha256(bytes.fromhex(pt["salt_hex"]) + bytes.fromhex(pt["plaintext_hex"])).digest()
    expect(got.hex() == pt["plaintext_hash_hex"], "plaintext_hash")
    mc = valid["minimal_lmt"][0]
    E.check_payload(mc, blob)
    expect(mc["plaintext_hash"] == got, "minimal_lmt: plaintext_hash is not plaintext_hash_basic")
    for r in f["reject"]:
        c = {"payload_size": int(r["payload_size"]), "ciphertext_hash": bytes.fromhex(r["ciphertext_hash_hex"])}
        if "commitment_ref" in r:
            ref = valid[r["commitment_ref"]][0]
            expect(ref["payload_size"] == c["payload_size"] and ref["ciphertext_hash"] == c["ciphertext_hash"],
                   f"{r['id']}: does not match {r['commitment_ref']}")
        if "framed_hex" in r:
            expect(hashlib.sha256(bytes.fromhex(r["framed_hex"])).hexdigest() == r["ciphertext_hash_hex"], f"{r['id']}")
        try:
            E.check_payload(c, bytes.fromhex(r["blob_hex"]))
        except Reject as e:
            expect(e.sentinel == r["expect_error"], f"{r['id']}: got {e.sentinel}")
        else:
            raise Failure(f"{r['id']}: accepted")
    c = cases["payload_v1_minimal"]
    blob = bytes.fromhex(c["blob_hex"])
    expect(hashlib.sha256(blob).hexdigest() == c["ciphertext_hash_hex"] and len(blob) == int(c["payload_size"]),
           "payload_v1_minimal: blob hashes")
    aead = pv.open_blob(blob, bytes.fromhex(c["recipient"]["sk_hex"]))
    expect(hashlib.sha256(aead).hexdigest() == c["plaintext_hash_hex"], "payload_v1_minimal: O7")
    expect(aead == bytes.fromhex(c["aead_salt_hex"]) + bytes.fromhex(c["plaintext_cbor_hex"]), "payload: plaintext")
    p = pv.o8(aead, c["action_type"], bytes.fromhex(c["committed_action_hash_hex"]))
    expect(p["version"] == 1 and p["action"]["action_salt"].hex() == c["action_salt_hex"]
           and ahash(c["action_type"], p["action"]["action_salt"], p["action"]["data"]).hex()
           == c["committed_action_hash_hex"], "payload: O8 independent")
    for r in f["open_reject"]:
        try:
            pv.o8(bytes(32) + bytes.fromhex(r["plaintext_cbor_hex"]), r["action_type"],
                  bytes.fromhex(r["committed_action_hash_hex"]))
            got = None
        except Reject as e:
            got = e.sentinel
        expect(got == r["expect_error"], f"{r['id']}: got {got}")
    return len(f["cases"]) + len(f["reject"]) + len(f["open_reject"])


def check_limits(f: dict, gate: dict, params) -> int:
    for case in f["cases"]:
        cid = case["id"]
        if "envelope_hex" in case:
            data = bytes.fromhex(case["envelope_hex"])
            expect(len(data) == int(case["size"]), f"{cid}: size")
            try:
                E.verify_for_gate(data, int(case["now"]), gate_from_json(case["gate"]) if "gate" in case else gate,
                                  params)
                got = None
            except Reject as e:
                got = e.sentinel
        else:
            data = bytes.fromhex(case["signed_authorization_hex"])
            expect(len(data) == int(case["size"]), f"{cid}: size")
            try:
                signed, _ = E.decode_signed_authorization(data)
                E.validate_authorization_static(signed["authorization"])
                got = None
            except Reject as e:
                got = e.sentinel
        expect(got == case.get("expect_error"), f"{cid}: got {got}, want {case.get('expect_error')}")
    return len(f["cases"])


def outcome(fn, *args):
    try:
        fn(*args)
    except Reject as e:
        return e.sentinel
    return None


def window_independent(i: dict, pr: dict | None) -> dict:
    """K-fast window from the text: age, window >= 1, then slack and promise slack as provisional failures
    that only an inclusion with code 0 inside [h0, deadline] waives."""
    h0, head = i["h0"], i["head"]
    if head < h0:
        return {"expect_error": "ErrChainUnavailable"}
    if head - h0 > i["max_h0_age"]:
        return {"expect_error": "ErrH0TooOld"}
    w = min(i["fast_window_blocks"], i["fast_mode_max_delay"], i["chain_window"] if i["da"] == 1 else 10 ** 9)
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


def check_anchor(f: dict) -> set:
    expect(f["margin_cap"] == "600", "anchor.json: margin cap")
    seen = set()
    for c in f["k1"]:
        ia, t, s = int(c["issued_at"]), int(c["t_ref"]), int(c["skew_s"])
        want = "ErrIssuedBeforeAnchor" if min(ia + s, E.U64_MAX) < t else None
        expect(want == c.get("expect_error") == outcome(E.check_anchor_time, ia, t, s), f"{c['id']}: K1")
        seen.add(want)
    for c in f["k2"]:
        da, pend, t = int(c["da"]), c["form"] == "pending", int(c["t_ref"])
        if da == 1:
            expect(("intent_created_at" in c) == pend and ("creation_timestamp" in c) != pend, f"{c['id']}: inputs")
            start = min(t, int(c.get("intent_created_at") or c.get("creation_timestamp")))
        else:
            start = t
        r = int(c["retention_s"])
        margin = min(600, r // 8)
        within = int(c["valid_until"]) + margin <= start + r
        e = c["expect"]
        expect(e["start"] == str(start) and e["margin"] == str(margin) and e["within"] is within, f"{c['id']}: K2")
    for c in f["k2_included"]:
        cid, da, e = c["id"], int(c["da"]), c["expect"]
        opt = lambda k: int(c[k]) if k in c else None
        p = E.Params(opt("fibre_retention_latest_s") or 14400, opt("blob_retention_s") or 14400, 30)
        try:
            w = E.retention_window(da, int(c["t_ref"]), p, opt("fibre_retention_latest_s"),
                                   opt("fibre_retention_at_height_s"), opt("creation_timestamp") or 0)
        except Reject as err:
            expect(err.sentinel == e.get("expect_error") and set(e) == {"expect_error"}, f"{cid}: got {err.sentinel}")
            seen.add(err.sentinel)
            continue
        if w is None:
            expect("r" not in e and e["within"] is False, f"{cid}: window expected")
            within = False
        else:
            r, start = w
            expect(str(r) == e["r"] and str(start) == e["start"] and str(min(600, r // 8)) == e["margin"], f"{cid}: r")
            within = min(int(c["valid_until"]) + min(600, r // 8), E.U64_MAX) <= min(start + r, E.U64_MAX)
        expect(within is e["within"], f"{cid}: within")
        try:
            got_route, got_err = E.route(da, within), None
        except Reject as err:
            got_route, got_err = None, err.sentinel
        expect(got_route == e.get("route") and got_err == e.get("expect_error"), f"{cid}: route")
        seen.add(got_err)
    for c in f["epoch"]:
        got = outcome(E.check_registry_epoch, int(c["issued_at"]), int(c["epoch"]), int(c["skew_s"]))
        expect(got == c.get("expect_error"), f"{c['id']}: got {got}")
        seen.add(got)
    for c in f["window"]:
        i = {k: int(v) for k, v in c["input"].items() if k != "promise"}
        pr = {k: int(v) for k, v in c["input"]["promise"].items()} if "promise" in c["input"] else None
        got = window_independent(i, pr)
        expect(got == c["expect"], f"{c['id']}: window got {got}, want {c['expect']}")
        inc = (i["included_at"], i["included_code"]) if "included_at" in i else None
        try:
            mod = {"anchor_deadline": str(E.fast_window(i["da"], i["h0"], i["head"], i["fast_window_blocks"],
                                                        i["max_h0_age"], i["fast_mode_max_delay"],
                                                        i.get("chain_window"), i.get("timeout_height", 0),
                                                        i["min_fast_slack_blocks"], inc, pr))}
        except Reject as e:
            mod = {"expect_error": e.sentinel}
        expect(mod == got, f"{c['id']}: edicta.py disagrees with the independent window rule")
        if "anchor_deadline" in got:
            d = int(got["anchor_deadline"])
            expect(i["h0"] < d <= i["h0"] + 1000, f"{c['id']}: deadline outside (h0, h0 + 1000]")
    seen.discard(None)
    expect(seen == GATE_VECTORED, f"anchor.json sentinels: {sorted(seen)}")
    return seen


def check_action(f: dict) -> int:
    expect(bytes.fromhex(f["tag"]) == LIT["action"], "action.json tag")
    for c in f["cases"]:
        salt, act = salt_of(c), supplied_action(c)
        expect(ahash(c["action_type"], salt, act).hex() == c["action_hash_hex"], f"{c['id']}: hash")
        t = c["action_type"].encode()
        pre = LIT["action"] + bytes([len(t)]) + t + salt + act
        expect(len(pre) == int(c["preimage_size"]), f"{c['id']}: preimage size")
        if "preimage_hex" in c:
            expect(c["preimage_hex"] == pre.hex(), f"{c['id']}: preimage")
    for r in f["reject"]:
        act, salt = bytes.fromhex(r["action_hex"]), salt_of(r)
        committed = bytes.fromhex(r["committed_action_hash_hex"])
        if "committed_preimage_hex" in r:
            expect(hashlib.sha256(bytes.fromhex(r["committed_preimage_hex"])).digest() == committed, f"{r['id']}: pre")
        if salt is None:
            got = "ErrMissingField"
        elif len(salt) != 32:
            got = "ErrFieldSize"
        else:
            got = None if ahash(r["action_type"], salt, act) == committed else "ErrActionMismatch"
        expect(got == r["expect_error"], f"{r['id']}: got {got}")
        mod = outcome(E.check_action, {"action": {"type": r["action_type"], "hash": committed}}, act, salt)
        expect(mod == got, f"{r['id']}: edicta.py disagrees")
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
        delay = int(c["mandate_fast_mode_max_delay"]) if "mandate_fast_mode_max_delay" in c else None
        try:
            E.validate_gate_config(cfg, c["mandate"], c.get("allowlist", f["allowlist"]), f["profile_registry"], delay)
            got = {"result": "ok"}
        except Reject as e:
            got = {"error": e.sentinel, "cause": e.detail}
        expect(got == c["expect"], f"{c['id']}: got {got}")
        full = dict({"fast_window_blocks": 100, "max_h0_age_blocks": 10, "min_fast_slack_blocks": 3}, **cfg)
        if got == {"result": "ok"}:
            expect(full["max_h0_age_blocks"] + full["min_fast_slack_blocks"] <= full["fast_window_blocks"]
                   and (c["mandate"] or not cfg.get("fast_mode")), f"{c['id']}: accepted against the config rules")
            expect(all(f["profile_registry"].get(t) is True for t in cfg.get("reveal_on_execution", [])),
                   f"{c['id']}: reveals a type without public execution")
            expect(delay is None or not cfg.get("fast_mode") or delay >= full["min_fast_slack_blocks"] + 1,
                   f"{c['id']}: fast_mode_max_delay below the slack")
    # The registry restates the profile documents (dca-agent 3.4, bank-send 3.5).
    expect(f["profile_registry"] == {"application/vnd.edicta.ibkr.order.v0+cbor": False,
                                     "application/vnd.edicta.cosmos.bank-send.v0+cbor": True}, "gate.json: registry")
    expect("accept_v0" not in f["defaults"], "gate.json: no v0 acceptance switch")
    return len(f["cases"])


def check_da_blob_inputs(valid: dict):
    """The share commitments of da/blob_commit.json come from upstream go-square and are checked by Go
    (and by check_absence.py's own CreateCommitment); here only the blob descriptions, and the link to the
    minimal_lmt payload."""
    df = json.loads((VECTORS / "da" / "blob_commit.json").read_text())
    minimal = valid["minimal_lmt"][0]
    for c in df["cases"] + df["reject"]:
        blob = bytes.fromhex(c["blob_hex"]) if "blob_hex" in c else pattern_bytes("affine-7-3", int(c["size"]))
        expect(len(blob) == int(c["size"]), f"{c['id']}: size")
        expect(hashlib.sha256(blob).hexdigest() == c["blob_sha256_hex"], f"{c['id']}: blob sha256")
    ref = next(c for c in df["cases"] if c["id"] == "blob_v1_minimal_lmt_payload")
    expect(bytes.fromhex(ref["namespace_hex"]) == minimal["payload_ref"]["namespace"]
           and bytes.fromhex(ref["signer_hex"]) == minimal["payload_ref"]["signer"]
           and ref["blob_sha256_hex"] == minimal["ciphertext_hash"].hex(),
           "da/blob_commit.json blob_v1_minimal_lmt_payload no longer describes the minimal_lmt payload")
    return len(df["cases"]) + len(df["reject"])


def check_regenerated():
    import gen_vectors as gen
    for name, obj in gen.build().items():
        expect(gen.dump(obj) == (DIR / name).read_text(), f"{name}: generator output differs")
    expect(gen.dump(gen.keys_file()) == (VECTORS / "keys.json").read_text(), "keys.json: generator output differs")


def check_core() -> int:
    try:
        check_constants()
        ks = check_keys()
        files = {n: load(n) for n in FILES}
        for name, ids in REQUIRED.items():
            f = files[name]
            have = [c["id"] for k in ("cases", "reject", "open_reject", "window", "k1", "k2", "k2_included", "epoch")
                    for c in f.get(k, [])]
            expect(len(have) == len(set(have)), f"{name}: duplicate ids")
            missing = [i for i in ids if i not in have]
            expect(not missing, f"{name}: missing cases {missing}")
        valid = check_valid(files["valid.json"], ks)
        seen = check_reject(files["reject.json"], ks)
        aseen = check_authorization(files["authorization.json"], ks, valid)
        rq_seen = check_record_requests(files["record_request.json"], valid)
        r_seen = check_receipts(files["receipt.json"], ks, valid, files["authorization.json"],
                                files["record_request.json"])
        npl = check_payload(files["payload.json"], valid)
        top = files["valid.json"]
        nl = check_limits(files["limits.json"], gate_from_json(top["gate"]), params_from_json(top["params"]))
        gseen = check_anchor(files["anchor.json"])
        nac = check_action(files["action.json"])
        ng = check_gate(files["gate.json"])
        nda = check_da_blob_inputs(valid)
        blob_summary, _ = check_payload_blob.check(DIR)
        check_regenerated()
    except (Failure, Reject, check_payload_blob.Failure, hpke_base.HPKEError) as e:
        print(f"FAIL (core): {e}", file=sys.stderr)
        return 1
    a, r, rq = files["authorization.json"], files["receipt.json"], files["record_request.json"]
    print(f"OK (core, {REVISION}): {len(valid)} valid, {len(files['reject.json']['cases'])} reject ({len(seen)} "
          f"sentinels), {len(a['cases'])} authorization, {len(a['reject'])} authorization reject ({len(aseen)} "
          f"sentinels), {len(rq['cases'])} record request, {len(rq['reject'])} record request reject, "
          f"{len(r['cases'])} receipt, {len(r['reject'])} receipt reject ({len(r_seen)} sentinels), {npl} payload, "
          f"{nl} limits, anchor ({len(gseen)} gate sentinels), {nac} action, {ng} gate config, {nda} da blob inputs; "
          f"generator output identical")
    print(f"OK (core): {blob_summary}", flush=True)
    return 0


def run_script(script: Path, *args: str) -> int:
    return subprocess.run([sys.executable, str(script), *args]).returncode


OTHER_CHECKERS = [
    "check_profile_dca_agent.py", "check_profile_bank_send.py", "check_bank_send_action_from_tx.py",
    "check_api_vectors.py", "check_api_errors.py", "check_fibre_commit.py", "check_archive.py",
    "check_fibre_cert.py", "check_fibre_anchor.py", "check_execution_outcomes.py", "check_verifier_reasons.py",
    "check_policy.py", "check_private_cap.py", "check_archive_v1.py", "check_principal.py", "check_absence.py",
    "check_records.py",
]


SUPERSEDED_TAG = re.compile(rb"edicta/v" rb"0/(decision-commitment|sig|action|authorization|authorization-sig|receipt|"
                            rb"receipt-sig|record-request|publish-request|payload|payload-dek|auditor-kid|batch-leaf)"
                            rb"(?![a-z-])")


def check_no_superseded_tags() -> int:
    """No live vector file or checker module may carry a protocol tag of the superseded drafts: a
    stale import or a file regenerated under the old tags would otherwise pass unnoticed. Test
    derivation labels that merely start with the old prefix are not tags."""
    bad = []
    for p in sorted(VECTORS.rglob("*")):
        rel = p.relative_to(VECTORS).as_posix()
        if not p.is_file() or rel.startswith(("historical/", "tools/")) or p.suffix not in (".json", ".py"):
            continue
        if SUPERSEDED_TAG.search(p.read_bytes()):
            bad.append(rel)
    if bad:
        print(f"FAIL (superseded tags): {', '.join(bad)}", file=sys.stderr)
        return 1
    print("OK (superseded tags): no live vector file or checker module holds a protocol tag of the superseded drafts")
    return 0


def main() -> int:
    if sys.version_info < (3, 11):
        print("Python 3.11 or later is required", file=sys.stderr)
        return 2
    rc = check_no_superseded_tags()
    rc |= check_core()
    if "--core-only" in sys.argv:
        return rc
    for name in OTHER_CHECKERS:
        rc |= run_script(HERE / name)
    print_revisions()
    return rc


def print_revisions():
    """One line per live vector file: the revision of its last content change."""
    rows = []
    for p in sorted(VECTORS.rglob("*.json")):
        rel = p.relative_to(VECTORS).as_posix()
        if rel.startswith(("historical/", "check/", "tools/")):
            continue
        try:
            d = json.loads(p.read_text())
        except ValueError:
            continue
        if isinstance(d, dict) and "revision" in d:
            rows.append(f"{rel}={d['revision']}")
    print("revisions: " + ", ".join(rows))


if __name__ == "__main__":
    sys.exit(main())
