#!/usr/bin/env python3
"""Verifies the Edicta v0 vectors (v0-draft.9) against an independent implementation of the rules.

da_blob.json share commitments are upstream go-square output and are checked
by Go only; this script checks their blob descriptions. payload_blob.json is
checked by check_payload_blob.py, which runs the RFC 9180 known-answer tests of
the hand-written HPKE first. The dca-agent profile vectors are checked by
check_profile_dca_agent.py, the bank-send profile vectors by
check_profile_bank_send.py and the API vectors by check_api_vectors.py
(publish request) and check_api_errors.py (HTTP error mapping), and
da/fibre_commit.json by check_fibre_commit.py.

Usage: python3 spec/vectors/check/check_vectors.py [--dir DIR]
Without --dir, spec/vectors/v0, the profile and the API vectors are checked; with
--dir, only that core set. Exit status 0 when all vectors pass. Requires
Python 3.11+ and 'cryptography' (see requirements.txt next to this file).
"""

from __future__ import annotations

import sys

sys.dont_write_bytecode = True

import hashlib
import json
import subprocess
from pathlib import Path

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
except ImportError:
    sys.exit(
        "missing dependency 'cryptography'. Install it in a virtualenv, for example:\n"
        "  python3 -m venv .venv && .venv/bin/pip install -r spec/vectors/check/requirements.txt\n"
        "  .venv/bin/python spec/vectors/check/check_vectors.py"
    )

import ed25519_point as ed
import edicta_v0 as core
from cbor_strict import Raw, decode_strict, encode, to_plain
from edicta_v0 import (ACTION, AUTHORIZATION, COMMITMENT, ED25519_L, MAX_ACTION_SIZE, MAX_AUTHORIZATION_SIZE,
                      MAX_RECEIPT_SIZE, RECEIPT, SCOPE, TAG_ACTION, TAG_AUTHORIZATION,
                      TAG_AUTHORIZATION_SIG, TAG_COMMITMENT, TAG_RECEIPT, TAG_RECEIPT_SIG, TAG_SIG,
                      AuthorizationCheck, Params, Reject, action_hash, authorization_expires,
                      authorization_hash, check_action, check_anchor_time, check_payload,
                      check_registry_epoch, commitment_hash, decode_signed,
                      decode_signed_authorization, decode_signed_receipt, plaintext_hash,
                      receipt_hash, retention_margin, retention_window, route, signing_message,
                      tagged, to_cbor, verify_authorization, verify_for_gate, verify_receipt,
                      verify_record_request, verify_signature, within_retention)
from vecjson import (action_from_case, authorization_from_json, commitment_from_json, gate_from_json,
                     params_from_json, pattern_bytes, receipt_from_json)
import check_payload_blob
import hpke_base

HERE = Path(__file__).resolve().parent
VECTORS = HERE.parent
FORMAT = "edicta-vectors/v0"
REVISION = "v0-draft.9"

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
NOT_VECTORED = {"ErrNonCanonical", "ErrInvalidParams"}
# Sentinels the executor-side Authorization check (stage X) may return.
X_SENTINELS = {"ErrScopeMismatch", "ErrActionSize", "ErrActionMismatch", "ErrExpired"}
# Gate sentinels with stateless vectors; the stateful ones (allowlist, nonce,
# anchor lookup, availability) have none.
GATE_VECTORED = {"ErrIssuedBeforeAnchor", "ErrBeforeRegistryEpoch", "ErrArchiveRecomputeUnsupported",
                 "ErrRetentionUnavailable"}
# Sentinels of the gate's stateless Record checks, by stage.
RECORD_STAGES = {"D": {"ErrFieldSize", "ErrInvalidString"}, "G": {"ErrInvalidPublicKey", "ErrSignatureInvalid"},
                 "R": {"ErrExecutorNotAllowed", "ErrKeyRole"}}
RETIRED = {"commitment": (COMMITMENT, {9}), "action": (ACTION, {1, 2}), "scope": (SCOPE, {2, 3, 4}),
           "receipt": (RECEIPT, {5, 7})}


class Failure(Exception):
    pass


def expect(cond: bool, msg: str):
    if not cond:
        raise Failure(msg)


def load(d: Path, name: str, revision: bool = True) -> dict:
    obj = json.loads((d / name).read_text())
    expect(obj.get("format") == FORMAT, f"{name}: unexpected format {obj.get('format')!r}")
    if revision:
        expect(obj.get("revision") == REVISION, f"{name}: unexpected revision {obj.get('revision')!r}")
    return obj


def check_constants():
    """Tag bytes and lengths, written out literally so a typo in one place cannot hide."""
    want = {
        TAG_COMMITMENT: b"\x1dedicta/v0/decision-commitment", TAG_SIG: b"\x0dedicta/v0/sig",
        TAG_RECEIPT: b"\x11edicta/v0/receipt", TAG_RECEIPT_SIG: b"\x15edicta/v0/receipt-sig",
        TAG_ACTION: b"\x10edicta/v0/action", TAG_AUTHORIZATION: b"\x17edicta/v0/authorization",
        TAG_AUTHORIZATION_SIG: b"\x1bedicta/v0/authorization-sig",
        core.TAG_RECORD_REQUEST: b"\x18edicta/v0/record-request",
    }
    for t, enc in want.items():
        expect(tagged(t) == enc, f"tag {t!r}")
    signed = {TAG_SIG: 46, TAG_RECEIPT_SIG: 54, TAG_AUTHORIZATION_SIG: 60}
    for t, n in signed.items():
        expect(len(signing_message(bytes(32), t)) == n, f"signed message length under {t!r}")
    expect(len(set(signed.values())) == len(signed), "signed message lengths must differ")
    # Every hashed or signed preimage starts with its tag's length byte. The record message is
    # signed without hashing, so distinct first bytes keep it apart from every other preimage.
    firsts = [tagged(t)[0] for t in want]
    expect(len(set(firsts)) == len(firsts), "hashed and signed tags must have distinct lengths")
    hashed = [TAG_COMMITMENT, TAG_RECEIPT, TAG_ACTION, TAG_AUTHORIZATION]
    expect(len({tagged(t) for t in hashed}) == len(hashed), "hash tags must differ")
    for name, (schema, keys) in RETIRED.items():
        expect(not keys & set(schema), f"{name}: a retired key is defined again")
    expect(set(AUTHORIZATION) == {1, 2, 3, 4, 5, 6}, "Authorization keys")


def check_keys(keys: dict) -> dict:
    pubs = {}
    for name, k in keys["keys"].items():
        priv = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(k["seed_hex"]))
        pub = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        expect(pub.hex() == k["public_key_hex"], f"{name}: public key does not match seed")
        msg = bytes.fromhex(k["kat_message_hex"])
        sig = priv.sign(msg)
        expect(sig.hex() == k["kat_signature_hex"], f"{name}: RFC 8032 known-answer signature mismatch")
        Ed25519PublicKey.from_public_bytes(pub).verify(sig, msg)
        pubs[name] = (priv, pub)
    return pubs


def supplied_action(case: dict) -> bytes:
    """Action bytes of a case; a pattern-described action must match its stated SHA-256."""
    a = action_from_case(case)
    if "action_pattern" in case:
        expect(len(a) == int(case["action_size"]), f"{case.get('id', 'check')}: action size")
        expect(hashlib.sha256(a).hexdigest() == case["action_sha256_hex"], f"{case.get('id', 'check')}: action sha256")
    return a


def check_action_hash(case: dict, cid: str, committed: bytes):
    """The action hash rebuilt byte by byte from its definition, not through action_hash()."""
    t = case["action_type"].encode("ascii")
    a = supplied_action(case)
    prefix = b"\x10" + b"edicta/v0/action" + bytes([len(t)]) + t
    expect(prefix.hex() == case["action_preimage_prefix_hex"], f"{cid}: action preimage prefix")
    h = hashlib.sha256(prefix + a).digest()
    expect(h.hex() == case["action_hash_hex"] and h == committed, f"{cid}: action hash")
    expect(action_hash(case["action_type"], a) == h, f"{cid}: action_hash() disagrees with the definition")
    expect(1 <= len(a) <= MAX_ACTION_SIZE, f"{cid}: action size out of range")


def run_pipeline(case: dict, top: dict):
    env = bytes.fromhex(case["envelope_hex"])
    now = int(case["now"])
    gate = gate_from_json(case.get("gate", top["gate"]))
    params = params_from_json(case.get("params", top["params"]))
    signed, h = verify_for_gate(env, now, gate, params)
    if "action_type" in case:
        expect(case["action_type"] == signed["commitment"]["action"]["type"], f"{case['id']}: action_type differs from the commitment")
        check_action(signed["commitment"], supplied_action(case))
    return signed, h


def check_valid(top: dict, pubs: dict):
    expect(top["patterns"] == {"affine-7-3": "byte i of the action is (7*i + 3) mod 256, for i from 0"}, "patterns")
    for case in top["cases"]:
        cid = case["id"]
        c = commitment_from_json(case["input"])
        canon = encode(to_cbor(c))
        expect(canon.hex() == case["commitment_cbor_hex"], f"{cid}: canonical encoding mismatch")
        h = commitment_hash(canon)
        expect(h.hex() == case["commitment_hash_hex"], f"{cid}: commitment_hash mismatch")
        msg = tagged(TAG_SIG) + h
        expect(len(msg) == 46 and msg.hex() == case["signed_message_hex"], f"{cid}: signed message mismatch")
        priv, pub = pubs[case["signer"]]
        expect(c["agent_pubkey"] == pub, f"{cid}: agent_pubkey is not the signer's key")
        sig = bytes.fromhex(case["signature_hex"])
        expect(priv.sign(msg) == sig, f"{cid}: signature is not the deterministic Ed25519 signature")
        env = encode({1: Raw(canon), 2: sig})
        expect(env.hex() == case["envelope_hex"], f"{cid}: envelope mismatch")
        signed, canon2 = decode_signed(env)
        expect(signed["commitment"] == c and canon2 == canon, f"{cid}: decode round-trip mismatch")
        expect(case["action_type"] == c["action"]["type"], f"{cid}: action_type is not the committed type")
        check_action_hash(case, cid, c["action"]["hash"])
        try:
            _, h2 = run_pipeline(case, top)
        except Reject as e:
            raise Failure(f"{cid}: valid vector rejected with {e}")
        expect(h2 == h, f"{cid}: pipeline hash mismatch")
        expect(len(canon) <= 559, f"{cid}: commitment above the 559-byte schema maximum")


def check_torsion_r(c: dict, canon: bytes, sig: bytes):
    """sig_torsion_r must fail the signature equation for the right reason:
    the public key is valid, S < L, the cofactored equation holds, R has an
    order-8 component, and only the cofactorless equation rejects it."""
    msg = signing_message(commitment_hash(canon))
    expect(ed.public_key_problem(c["agent_pubkey"]) is None, "sig_torsion_r: agent_pubkey fails G0")
    expect(int.from_bytes(sig[32:], "little") < ED25519_L, "sig_torsion_r: S >= L")
    r = ed.decode(sig[:32])
    expect(r is not None and ed.order(ed.mul(ed.L, r)) == 8, "sig_torsion_r: R has no order-8 component")
    expect(ed.cofactored_ok(c["agent_pubkey"], msg, sig), "sig_torsion_r: cofactored equation fails")
    expect(not ed.cofactorless_ok(c["agent_pubkey"], msg, sig), "sig_torsion_r: cofactorless equation holds")
    try:
        verify_signature(c, canon, sig)
    except Reject as e:
        expect(e.sentinel == "ErrSignatureInvalid" and e.detail == "cofactorless equation fails",
               f"sig_torsion_r: rejected for the wrong reason: {e}")
    else:
        raise Failure("sig_torsion_r: accepted")


def check_single_action_defect(case: dict, c: dict):
    """A stage A vector has exactly one defect: either the supplied bytes differ
    from the committed ones (correct hash construction), or the bytes are the
    committed ones and only the hash construction is wrong."""
    cid = case["id"]
    pre = bytes.fromhex(case["committed_preimage_hex"])
    expect(hashlib.sha256(pre).digest() == c["action"]["hash"], f"{cid}: committed preimage does not hash to action.hash")
    supplied = supplied_action(case)
    t = c["action"]["type"].encode("ascii")
    correct = b"\x10edicta/v0/action" + bytes([len(t)]) + t
    if case["rule"] == "A0":
        expect(pre.startswith(correct) and not 1 <= len(supplied) <= MAX_ACTION_SIZE, f"{cid}: not a size defect")
    elif pre.startswith(correct):
        expect(pre[len(correct):] != supplied, f"{cid}: supplied bytes equal the committed bytes")
    else:
        expect(pre.endswith(supplied) and 1 <= len(supplied) <= MAX_ACTION_SIZE, f"{cid}: supplied bytes are not the committed bytes")


def check_reject(top: dict) -> set:
    seen = set()
    for case in top["cases"]:
        cid = case["id"]
        want = case["expect_error"]
        expect(want in STAGE_OF, f"{cid}: unknown sentinel {want}")
        expect(STAGE_OF[want] == case["stage"], f"{cid}: sentinel {want} is not a stage {case['stage']} error")
        expect(("action_type" in case) == (case["stage"] == "A") == ("committed_preimage_hex" in case),
               f"{cid}: action bytes belong to stage A cases only")
        if "input" in case:
            c = commitment_from_json(case["input"])
            canon = encode(to_cbor(c))
            expect(canon.hex() == case["commitment_cbor_hex"], f"{cid}: canonical encoding mismatch")
            expect(commitment_hash(canon).hex() == case["commitment_hash_hex"], f"{cid}: commitment_hash mismatch")
            signed, canon2 = decode_signed(bytes.fromhex(case["envelope_hex"]))
            expect(canon2 == canon and signed["commitment"] == c, f"{cid}: envelope does not carry the input")
            if case["stage"] in ("S", "T", "C", "A"):
                verify_signature(c, canon, signed["signature"])
            if case["stage"] == "A":
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
    return seen


def check_payload_vectors(p: dict, valid: dict) -> set:
    cases = {c["id"]: c for c in p["cases"]}
    small = cases["ciphertext_hash_small_blob"]
    blob = bytes.fromhex(small["blob_hex"])
    expect(hashlib.sha256(blob).hexdigest() == small["ciphertext_hash_hex"], "small blob: ciphertext_hash mismatch")
    expect(len(blob) == int(small["payload_size"]), "small blob: payload_size mismatch")
    expect(encode(to_plain(decode_strict(blob))) == blob, "small blob: envelope is not canonical CBOR")
    pt = cases["plaintext_hash_basic"]
    got = plaintext_hash(bytes.fromhex(pt["salt_hex"]), bytes.fromhex(pt["plaintext_hex"]))
    expect(got.hex() == pt["plaintext_hash_hex"], "plaintext_hash mismatch")

    minimal = next(c for c in valid["cases"] if c["id"] == "minimal_lmt")
    mc = commitment_from_json(minimal["input"])
    check_payload(mc, blob)
    expect(mc["plaintext_hash"] == got, "minimal_lmt: plaintext_hash is not plaintext_hash_basic")

    seen = set()
    for r in p["reject"]:
        c = {"payload_size": int(r["payload_size"]), "ciphertext_hash": bytes.fromhex(r["ciphertext_hash_hex"])}
        if "commitment_ref" in r:
            ref = commitment_from_json(next(v for v in valid["cases"] if v["id"] == r["commitment_ref"])["input"])
            expect(ref["payload_size"] == c["payload_size"] and ref["ciphertext_hash"] == c["ciphertext_hash"],
                   f"{r['id']}: does not match {r['commitment_ref']}")
        if "framed_hex" in r:
            expect(hashlib.sha256(bytes.fromhex(r["framed_hex"])).hexdigest() == r["ciphertext_hash_hex"],
                   f"{r['id']}: hash is not over the framed bytes")
        try:
            check_payload(c, bytes.fromhex(r["blob_hex"]))
        except Reject as e:
            expect(e.sentinel == r["expect_error"], f"{r['id']}: got {e.sentinel}, want {r['expect_error']}")
        else:
            raise Failure(f"{r['id']}: accepted, want {r['expect_error']}")
        seen.add(r["expect_error"])
    return seen


def chk_of(blk: dict) -> AuthorizationCheck:
    return AuthorizationCheck(bytes.fromhex(blk["gate_pubkey_hex"]), blk["gate_id"], blk["action_type"],
                              supplied_action(blk), int(blk["now"]), int(blk["skew_s"]))


def check_authorizations(af: dict, pubs: dict, valid: dict) -> set:
    by_id = {c["id"]: c for c in valid["cases"]}
    ttl = int(af["max_authorization_ttl_s"])
    gate = gate_from_json(af["gate"])
    skew = Params().skew_s
    expect(ttl > skew, "MaxAuthorizationTTL must exceed skew_s")
    for case in af["cases"]:
        cid = case["id"]
        a = authorization_from_json(case["input"])
        ref = by_id[case["commitment_ref"]]
        rc = commitment_from_json(ref["input"])
        # The gate's statement: this commitment, this action, this gate, never past valid_until.
        expect(a["commitment_hash"].hex() == ref["commitment_hash_hex"], f"{cid}: commitment_hash is not {case['commitment_ref']}")
        expect(a["action_hash"] == rc["action"]["hash"], f"{cid}: action_hash is not the committed one")
        expect(a["gate_id"] == rc["scope"]["gate_id"] == gate["gate_id"], f"{cid}: gate_id")
        expect(a["expires"] == authorization_expires(rc["valid_until"], int(case["authorized_at"]), ttl), f"{cid}: expires formula")
        expect(a["expires"] <= rc["valid_until"], f"{cid}: expires after valid_until")
        expect(int(case["authorized_at"]) + skew < rc["valid_until"], f"{cid}: authorized too late")
        canon = encode(to_cbor(a, AUTHORIZATION))
        expect(canon.hex() == case["authorization_cbor_hex"], f"{cid}: canonical encoding mismatch")
        ah = hashlib.sha256(b"\x17edicta/v0/authorization" + canon).digest()
        expect(ah.hex() == case["authorization_hash_hex"] and ah == authorization_hash(canon), f"{cid}: authorization_hash mismatch")
        msg = b"\x1bedicta/v0/authorization-sig" + ah
        expect(len(msg) == 60 and msg.hex() == case["signed_message_hex"], f"{cid}: signed message mismatch")
        priv, pub = pubs[case["signer"]]
        sig = bytes.fromhex(case["signature_hex"])
        expect(priv.sign(msg) == sig, f"{cid}: signature is not the deterministic Ed25519 signature")
        data = encode({1: Raw(canon), 2: sig})
        expect(data.hex() == case["signed_authorization_hex"] and len(data) <= MAX_AUTHORIZATION_SIZE,
               f"{cid}: signed Authorization mismatch")
        blk = case["check"]
        expect(bytes.fromhex(blk["gate_pubkey_hex"]) == pub, f"{cid}: check pins another key")
        expect(blk["action_type"] == rc["action"]["type"], f"{cid}: check type is not the committed type")
        expect(action_hash(blk["action_type"], supplied_action(blk)) == a["action_hash"], f"{cid}: check bytes")
        try:
            signed, h2 = verify_authorization(data, chk_of(blk))
        except Reject as e:
            raise Failure(f"{cid}: valid Authorization rejected with {e}")
        expect(signed["authorization"] == a and h2 == ah, f"{cid}: decode round-trip mismatch")
        expect(case["signer"] == "gate1", f"{cid}: signed by a non-gate key")
    seen = set()
    for case in af["reject"]:
        cid = case["id"]
        want = case["expect_error"]
        stage = case["stage"]
        if stage == "X":
            expect(want in X_SENTINELS, f"{cid}: {want} is not an executor-check error")
        else:
            expect(STAGE_OF.get(want) == stage, f"{cid}: sentinel {want} is not a stage {stage} error")
        data = bytes.fromhex(case["signed_authorization_hex"])
        if "input" in case:
            a = authorization_from_json(case["input"])
            canon = encode(to_cbor(a, AUTHORIZATION))
            expect(canon.hex() == case["authorization_cbor_hex"], f"{cid}: canonical encoding mismatch")
            expect(authorization_hash(canon).hex() == case["authorization_hash_hex"], f"{cid}: authorization_hash mismatch")
            signed, canon2 = decode_signed_authorization(data)
            expect(canon2 == canon and signed["authorization"] == a, f"{cid}: bytes do not carry the input")
        try:
            verify_authorization(data, chk_of(case["check"]))
        except Reject as e:
            expect(e.sentinel == want, f"{cid}: got {e.sentinel}, want {want}")
        else:
            raise Failure(f"{cid}: accepted, want {want}")
        seen.add(want)
    for s in ("ErrUnsupportedVersion", "ErrIntRange", "ErrInvalidEnum", "ErrZeroValue", "ErrInvalidPublicKey",
              "ErrSignatureInvalid", "ErrTooLarge") + tuple(X_SENTINELS):
        expect(s in seen, f"authorization.json: no must-reject vector for {s}")
    return seen


def literal_record_message(chash: bytes, gate_id: str, rail_ref: str) -> bytes:
    g, r = gate_id.encode("ascii"), rail_ref.encode("ascii")
    return b"\x18edicta/v0/record-request" + chash + bytes([len(g)]) + g + bytes([len(r)]) + r


def check_record_requests(rq: dict, valid: dict) -> set:
    hashes = {c["id"]: c["commitment_hash_hex"] for c in valid["cases"]}
    gate = rq["gate"]
    executors = [bytes.fromhex(k) for k in gate["executor_keys"]]
    gate_keys = [bytes.fromhex(gate["gate_pubkey_hex"])]
    privs = {}
    for name, k in rq["keys"].items():
        priv = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(k["seed_hex"]))
        pub = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        expect(pub.hex() == k["public_key_hex"], f"{name}: public key does not match seed")
        if "kat_signature_hex" in k:
            expect(priv.sign(bytes.fromhex(k["kat_message_hex"])).hex() == k["kat_signature_hex"], f"{name}: RFC 8032 KAT")
        expect(ed.public_key_problem(pub) is None and pub in executors and pub not in gate_keys, f"{name}: executor key role")
        privs[pub] = priv
    for c in rq["cases"]:
        cid = c["id"]
        ch = bytes.fromhex(c["commitment_hash_hex"])
        expect(c["commitment_hash_hex"] == hashes[c["commitment_ref"]], f"{cid}: commitment_hash")
        msg = literal_record_message(ch, gate["gate_id"], c["rail_ref"])
        expect(msg.hex() == c["record_message_hex"] and len(msg) == 59 + len(gate["gate_id"]) + len(c["rail_ref"]),
               f"{cid}: record message")
        pub, sig = bytes.fromhex(c["executor_pubkey_hex"]), bytes.fromhex(c["signature_hex"])
        expect(privs[pub].sign(msg) == sig, f"{cid}: not the deterministic signature")
        try:
            verify_record_request(ch, bytes.fromhex(c["agent_pubkey_hex"]), gate["gate_id"], c["rail_ref"], pub, sig,
                                  executors, gate_keys)
        except Reject as e:
            raise Failure(f"{cid}: valid record request rejected with {e}")
    seen = set()
    for c in rq["reject"]:
        cid, want = c["id"], c["expect_error"]
        expect(want in RECORD_STAGES.get(c["stage"], ()), f"{cid}: {want} is not a stage {c['stage']} Record error")
        ek = [bytes.fromhex(k) for k in c["executor_keys"]] if "executor_keys" in c else executors
        try:
            verify_record_request(bytes.fromhex(c["commitment_hash_hex"]), bytes.fromhex(c["agent_pubkey_hex"]),
                                  gate["gate_id"], c["rail_ref"],
                                  bytes.fromhex(c["executor_pubkey_hex"]), bytes.fromhex(c["signature_hex"]), ek, gate_keys)
        except Reject as e:
            expect(e.sentinel == want, f"{cid}: got {e.sentinel}, want {want}")
        else:
            raise Failure(f"{cid}: accepted, want {want}")
        seen.add(want)
    expect(seen == set().union(*RECORD_STAGES.values()), f"record_request.json sentinels: {sorted(seen)}")
    return seen


def check_receipts(rf: dict, pubs: dict, valid: dict, af: dict, rq: dict) -> set:
    hashes = {c["id"]: c["commitment_hash_hex"] for c in valid["cases"]}
    authorized = {c["commitment_ref"] for c in af["cases"]}
    gate = gate_from_json(rf["gate"])
    for case in rf["cases"]:
        cid = case["id"]
        r = receipt_from_json(case["input"])
        expect(r["commitment_hash"].hex() == hashes[case["commitment_ref"]], f"{cid}: commitment_hash is not {case['commitment_ref']}")
        expect(case["commitment_ref"] in authorized, f"{cid}: receipt for a commitment with no Authorization vector")
        expect(r["gate_id"] == gate["gate_id"], f"{cid}: gate_id differs from the gate")
        expect(r["executor_pubkey"].hex() in rq["gate"]["executor_keys"], f"{cid}: executor is not allowlisted")
        expect(Ed25519PublicKey.from_public_bytes(r["executor_pubkey"]).verify(
            r["executor_signature"], literal_record_message(r["commitment_hash"], r["gate_id"], r["rail_ref"])) is None,
            f"{cid}: executor signature")
        canon = encode(to_cbor(r, RECEIPT))
        expect(canon.hex() == case["receipt_cbor_hex"], f"{cid}: canonical encoding mismatch")
        rh = receipt_hash(canon)
        expect(rh.hex() == case["receipt_hash_hex"], f"{cid}: receipt_hash mismatch")
        msg = signing_message(rh, TAG_RECEIPT_SIG)
        expect(len(msg) == 54 and msg.hex() == case["signed_message_hex"], f"{cid}: signed message mismatch")
        priv, pub = pubs[case["signer"]]
        expect(r["gate_pubkey"] == pub, f"{cid}: gate_pubkey is not the signer's key")
        sig = bytes.fromhex(case["signature_hex"])
        expect(priv.sign(msg) == sig, f"{cid}: signature is not the deterministic Ed25519 signature")
        data = encode({1: Raw(canon), 2: sig})
        expect(data.hex() == case["signed_receipt_hex"] and len(data) <= MAX_RECEIPT_SIZE, f"{cid}: signed receipt mismatch")
        try:
            signed, h2 = verify_receipt(data)
        except Reject as e:
            raise Failure(f"{cid}: valid receipt rejected with {e}")
        expect(signed["receipt"] == r and h2 == rh, f"{cid}: decode round-trip mismatch")
    seen = set()
    for case in rf["reject"]:
        cid = case["id"]
        want = case["expect_error"]
        expect(STAGE_OF.get(want) == case["stage"], f"{cid}: sentinel {want} is not a stage {case['stage']} error")
        data = bytes.fromhex(case["signed_receipt_hex"])
        if "input" in case:
            r = receipt_from_json(case["input"])
            canon = encode(to_cbor(r, RECEIPT))
            expect(canon.hex() == case["receipt_cbor_hex"], f"{cid}: canonical encoding mismatch")
            expect(receipt_hash(canon).hex() == case["receipt_hash_hex"], f"{cid}: receipt_hash mismatch")
            signed, canon2 = decode_signed_receipt(data)
            expect(canon2 == canon and signed["receipt"] == r, f"{cid}: signed receipt does not carry the input")
        try:
            verify_receipt(data)
        except Reject as e:
            expect(e.sentinel == want, f"{cid}: got {e.sentinel}, want {want}")
        else:
            raise Failure(f"{cid}: accepted, want {want}")
        seen.add(want)
    return seen


def outcome(fn, *args):
    try:
        fn(*args)
    except Reject as e:
        return e.sentinel
    return None


def check_anchor(af: dict) -> set:
    expect(af["margin_cap"] == "600", "anchor.json: margin cap is not 600")
    seen = set()
    for c in af["k1"]:
        got = outcome(check_anchor_time, int(c["issued_at"]), int(c["block_time"]), int(c["skew_s"]))
        expect(got == c.get("expect_error"), f"{c['id']}: got {got}, want {c.get('expect_error')}")
        seen.add(got)
    for c in af["k2"]:
        cid, da, e = c["id"], int(c["da"]), c["expect"]
        opt = lambda k: int(c[k]) if k in c else None
        p = Params(opt("fibre_retention_latest_s") or 14400, opt("blob_retention_s") or 14400, 30)
        try:
            w = retention_window(da, int(c["block_time"]), p, opt("fibre_retention_latest_s"),
                                 opt("fibre_retention_at_height_s"), opt("creation_timestamp") or 0)
        except Reject as err:
            expect(err.sentinel == e.get("expect_error") and set(e) == {"expect_error"}, f"{cid}: got {err.sentinel}")
            seen.add(err.sentinel)
            continue
        if w is None:
            expect("r" not in e and e["within"] is False, f"{cid}: window expected but none established")
            within = False
        else:
            r, start = w
            expect(str(r) == e["r"] and str(start) == e["start"], f"{cid}: r or start mismatch")
            expect(str(retention_margin(r)) == e["margin"], f"{cid}: margin mismatch")
            within = within_retention(int(c["valid_until"]), start, r)
        expect(within is e["within"], f"{cid}: within={within}, want {e['within']}")
        try:
            got_route, got_err = route(da, within), None
        except Reject as err:
            got_route, got_err = None, err.sentinel
        expect(got_route == e.get("route") and got_err == e.get("expect_error"), f"{cid}: route {got_route}/{got_err}")
        seen.add(got_err)
    for c in af["epoch"]:
        got = outcome(check_registry_epoch, int(c["issued_at"]), int(c["epoch"]), int(c["skew_s"]))
        expect(got == c.get("expect_error"), f"{c['id']}: got {got}, want {c.get('expect_error')}")
        seen.add(got)
    seen.discard(None)
    return seen


def check_da_blob_inputs(df: dict, valid: dict):
    """The share commitments come from upstream go-square and are checked by Go
    only. Here only the blob descriptions are checked, so a pattern or hex
    mistake shows up in both languages."""
    minimal = commitment_from_json(next(c for c in valid["cases"] if c["id"] == "minimal_lmt")["input"])
    for c in df["cases"] + df["reject"]:
        if "blob_hex" in c:
            blob = bytes.fromhex(c["blob_hex"])
        else:
            expect(c["blob_pattern"] in df["patterns"], f"{c['id']}: unknown pattern")
            blob = pattern_bytes("affine-7-3", int(c["size"]))
        expect(len(blob) == int(c["size"]), f"{c['id']}: size mismatch")
        expect(hashlib.sha256(blob).hexdigest() == c["blob_sha256_hex"], f"{c['id']}: blob sha256 mismatch")
        expect(len(bytes.fromhex(c["namespace_hex"])) == 29 and len(bytes.fromhex(c["signer_hex"])) == 20
               and len(bytes.fromhex(c["commitment_hex"])) == 32, f"{c['id']}: field size")
    ref = next(c for c in df["cases"] if c["id"] == "blob_v1_minimal_lmt_payload")
    expect(bytes.fromhex(ref["namespace_hex"]) == minimal["payload_ref"]["namespace"]
           and bytes.fromhex(ref["signer_hex"]) == minimal["payload_ref"]["signer"]
           and ref["blob_sha256_hex"] == minimal["ciphertext_hash"].hex(),
           "da_blob.json blob_v1_minimal_lmt_payload no longer describes the minimal_lmt payload")


def check_set(d: Path) -> int:
    try:
        check_constants()
        pubs = check_keys(load(d, "keys.json", revision=False))
        valid = load(d, "valid.json")
        check_valid(valid, pubs)
        reject = load(d, "reject.json")
        seen = check_reject(reject)
        payload = load(d, "payload.json", revision=False)
        seen |= check_payload_vectors(payload, valid)
        auth = load(d, "authorization.json")
        seen |= check_authorizations(auth, pubs, valid)
        rq = load(d, "record_request.json")
        seen |= check_record_requests(rq, valid)
        receipts = load(d, "receipt.json")
        seen |= check_receipts(receipts, pubs, valid, auth, rq)
        anchor = load(d, "anchor.json", revision=False)
        gate_seen = check_anchor(anchor)
        da_blob = load(d, "da_blob.json", revision=False)
        check_da_blob_inputs(da_blob, valid)
        expect(not (d / "client_order_id.json").exists(), "client_order_id.json belongs to the dca-agent profile now")
        blob_summary, blob_ids = check_payload_blob.check(d)
        ids = [c["id"] for c in valid["cases"] + reject["cases"] + payload["cases"] + payload["reject"]
               + auth["cases"] + auth["reject"] + rq["cases"] + rq["reject"] + receipts["cases"] + receipts["reject"] + anchor["k1"]
               + anchor["k2"] + anchor["epoch"] + da_blob["cases"] + da_blob["reject"]] + blob_ids
        expect(len(ids) == len(set(ids)), "duplicate vector ids")
        expect("sig_torsion_r" in ids, "missing vector sig_torsion_r (cofactorless G1)")
        missing = set(STAGE_OF) - NOT_VECTORED - seen
        expect(not missing, f"sentinels without a must-reject vector: {sorted(missing)}")
        expect(gate_seen == GATE_VECTORED, f"anchor.json sentinels: {sorted(gate_seen)}")
    except (Failure, Reject, check_payload_blob.Failure, hpke_base.HPKEError) as e:
        print(f"FAIL ({d.name}): {e}", file=sys.stderr)
        return 1
    print(f"OK ({d.name}, {REVISION}): {len(valid['cases'])} valid, {len(reject['cases'])} reject, "
          f"{len(payload['cases'])} payload, {len(payload['reject'])} payload reject, "
          f"{len(auth['cases'])} authorization, {len(auth['reject'])} authorization reject, "
          f"{len(rq['cases'])} record request, {len(rq['reject'])} record request reject, "
          f"{len(receipts['cases'])} receipt, {len(receipts['reject'])} receipt reject, "
          f"{len(anchor['k1'])} K1, {len(anchor['k2'])} K2, {len(anchor['epoch'])} epoch, "
          f"{len(da_blob['cases'])} da_blob inputs, {len(da_blob['reject'])} da_blob reject inputs")
    print(f"OK ({d.name}): {blob_summary}", flush=True)
    return 0


def run_script(script: Path, *args: str) -> int:
    return subprocess.run([sys.executable, str(script), *args]).returncode


def main() -> int:
    if sys.version_info < (3, 11):
        print("Python 3.11 or later is required", file=sys.stderr)
        return 2
    if "--dir" in sys.argv:
        return check_set(Path(sys.argv[sys.argv.index("--dir") + 1]).resolve())
    rc = check_set(VECTORS / "v0")
    rc |= run_script(HERE / "check_profile_dca_agent.py")
    rc |= run_script(HERE / "check_profile_bank_send.py")
    rc |= run_script(HERE / "check_api_vectors.py")
    rc |= run_script(HERE / "check_api_errors.py")
    rc |= run_script(HERE / "check_fibre_commit.py")
    return rc


if __name__ == "__main__":
    sys.exit(main())
