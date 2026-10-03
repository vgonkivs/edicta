#!/usr/bin/env python3
"""Verifies every vector in spec/vectors/v0 against an independent reading of the spec.

Usage: python3 spec/vectors/check/check_vectors.py [--dir DIR]
Exit status 0 when all vectors pass. Requires Python 3.11+ and 'cryptography'
(see requirements.txt next to this file).
"""

from __future__ import annotations

import sys

sys.dont_write_bytecode = True

import hashlib
import json
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
from cbor_strict import Raw, decode_strict, encode, to_plain
from prior_v0 import (ED25519_L, TAG_SIG, Reject, check_action, check_payload,
                      commitment_hash, decode_signed, plaintext_hash,
                      signing_message, tagged, to_cbor, verify_for_gate,
                      verify_signature)
from vecjson import (commitment_from_json, gate_from_json, order_from_json,
                     params_from_json)

DIR = Path(__file__).resolve().parent.parent / "v0"
if "--dir" in sys.argv:
    DIR = Path(sys.argv[sys.argv.index("--dir") + 1]).resolve()
FORMAT = "prior-vectors/v0"

STAGE_OF = {
    "ErrTooLarge": "D", "ErrMalformed": "D", "ErrTrailingData": "D", "ErrFloat": "D",
    "ErrSimpleValue": "D", "ErrTag": "D", "ErrIndefiniteLength": "D", "ErrNonMinimalInt": "D",
    "ErrUnsortedMap": "D", "ErrDuplicateKey": "D", "ErrKeyType": "D", "ErrUnknownKey": "D",
    "ErrWrongType": "D", "ErrMissingField": "D", "ErrFieldSize": "D", "ErrInvalidString": "D",
    "ErrNestingTooDeep": "D", "ErrNonCanonical": "D", "ErrUnsupportedActionKind": "D",
    "ErrUnsupportedVersion": "S", "ErrIntRange": "S", "ErrInvalidEnum": "S",
    "ErrUnsupportedRail": "S", "ErrUnsupportedOrderType": "S", "ErrZeroValue": "S",
    "ErrPayloadTooLarge": "S", "ErrInvalidNamespace": "S", "ErrLimitPrice": "S",
    "ErrAccountMismatch": "S", "ErrChainIDRule": "S", "ErrTimeOrder": "S",
    "ErrDeadlineRange": "S", "ErrTTLTooLong": "S", "ErrPriceBound": "S",
    "ErrNotionalExceeded": "S", "ErrInvalidParams": "S",
    "ErrInvalidPublicKey": "G", "ErrSignatureInvalid": "G", "ErrNotYetValid": "T", "ErrExpired": "T",
    "ErrScopeMismatch": "C", "ErrActionMismatch": "A",
    "ErrPayloadSizeMismatch": "P", "ErrPayloadHashMismatch": "P",
}
NOT_VECTORED = {"ErrNonCanonical", "ErrInvalidParams"}


class Failure(Exception):
    pass


def expect(cond: bool, msg: str):
    if not cond:
        raise Failure(msg)


def load(name: str) -> dict:
    obj = json.loads((DIR / name).read_text())
    expect(obj.get("format") == FORMAT, f"{name}: unexpected format {obj.get('format')!r}")
    return obj


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


def run_pipeline(case: dict, top: dict):
    env = bytes.fromhex(case["envelope_hex"])
    now = int(case["now"])
    gate = gate_from_json(case.get("gate", top["gate"]))
    params = params_from_json(case.get("params", top["params"]))
    signed, h = verify_for_gate(env, now, gate, params)
    if "request" in case:
        check_action(signed["commitment"], order_from_json(case["request"]))
    return signed, h


def check_valid(top: dict, pubs: dict):
    for case in top["cases"]:
        cid = case["id"]
        c = commitment_from_json(case["input"])
        canon = encode(to_cbor(c))
        expect(canon.hex() == case["commitment_cbor_hex"], f"{cid}: canonical encoding mismatch")
        h = commitment_hash(canon)
        expect(h.hex() == case["commitment_hash_hex"], f"{cid}: commitment_hash mismatch")
        msg = tagged(TAG_SIG) + h
        expect(len(msg) == 45 and msg.hex() == case["signed_message_hex"], f"{cid}: signed message mismatch")
        priv, pub = pubs[case["signer"]]
        expect(c["agent_pubkey"] == pub, f"{cid}: agent_pubkey is not the signer's key")
        sig = bytes.fromhex(case["signature_hex"])
        expect(priv.sign(msg) == sig, f"{cid}: signature is not the deterministic Ed25519 signature")
        env = encode({1: Raw(canon), 2: sig})
        expect(env.hex() == case["envelope_hex"], f"{cid}: envelope mismatch")
        signed, canon2 = decode_signed(env)
        expect(signed["commitment"] == c and canon2 == canon, f"{cid}: decode round-trip mismatch")
        try:
            _, h2 = run_pipeline(case, top)
        except Reject as e:
            raise Failure(f"{cid}: valid vector rejected with {e}")
        expect(h2 == h, f"{cid}: pipeline hash mismatch")
        expect("request" in case, f"{cid}: valid case lacks a request")


def check_torsion_r(c: dict, canon: bytes, sig: bytes):
    """sig_torsion_r must fail G1 for the right reason: G0 and G2 pass, the
    cofactored equation holds, R has an order-8 component, and only the
    cofactorless equation rejects it."""
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


def check_reject(top: dict) -> set:
    seen = set()
    for case in top["cases"]:
        cid = case["id"]
        want = case["expect_error"]
        expect(want in STAGE_OF, f"{cid}: unknown sentinel {want}")
        expect(STAGE_OF[want] == case["stage"], f"{cid}: sentinel {want} is not a stage {case['stage']} error")
        if "input" in case:
            c = commitment_from_json(case["input"])
            canon = encode(to_cbor(c))
            expect(canon.hex() == case["commitment_cbor_hex"], f"{cid}: canonical encoding mismatch")
            expect(commitment_hash(canon).hex() == case["commitment_hash_hex"], f"{cid}: commitment_hash mismatch")
            signed, canon2 = decode_signed(bytes.fromhex(case["envelope_hex"]))
            expect(canon2 == canon and signed["commitment"] == c, f"{cid}: envelope does not carry the input")
            if case["stage"] in ("S", "T", "C", "A"):
                verify_signature(c, canon, signed["signature"])
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


def main() -> int:
    if sys.version_info < (3, 11):
        print("Python 3.11 or later is required", file=sys.stderr)
        return 2
    try:
        pubs = check_keys(load("keys.json"))
        valid = load("valid.json")
        check_valid(valid, pubs)
        reject = load("reject.json")
        seen = check_reject(reject)
        payload = load("payload.json")
        seen |= check_payload_vectors(payload, valid)
        ids = [c["id"] for c in valid["cases"] + reject["cases"] + payload["cases"] + payload["reject"]]
        expect(len(ids) == len(set(ids)), "duplicate vector ids")
        expect("sig_torsion_r" in ids, "missing vector sig_torsion_r (cofactorless G1)")
        missing = set(STAGE_OF) - NOT_VECTORED - seen
        expect(not missing, f"sentinels without a must-reject vector: {sorted(missing)}")
    except (Failure, Reject) as e:
        print(f"FAIL: {e}", file=sys.stderr)
        return 1
    print(f"OK: {len(valid['cases'])} valid, {len(reject['cases'])} reject, "
          f"{len(payload['cases'])} payload, {len(payload['reject'])} payload reject")
    return 0


if __name__ == "__main__":
    sys.exit(main())
