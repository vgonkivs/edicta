#!/usr/bin/env python3
"""Frozen copy of the v0-draft.8 rules. It checks spec/vectors/v0, which the Go
code reads until it switches to the draft.9 vectors; delete this directory then.

Verifies every vector in spec/vectors/v0 against an independent implementation of the v0 rules.

da_blob.json share commitments are upstream go-square output and are checked
by Go only; this script checks their blob descriptions. payload_blob.json is
checked by check_payload_blob.py, which runs the RFC 9180 known-answer tests of
the hand-written HPKE first.

Usage: python3 spec/vectors/check/draft8/check_vectors.py [--dir DIR]
Exit status 0 when all vectors pass. Requires Python 3.11+ and 'cryptography'
(see requirements.txt next to this file).
"""

from __future__ import annotations

import sys

sys.dont_write_bytecode = True

from pathlib import Path as _Path
sys.path.append(str(_Path(__file__).resolve().parent.parent))  # shared, unchanged modules

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
from edicta_v0 import (ED25519_L, MAX_RECEIPT_SIZE, RECEIPT, TAG_RECEIPT_SIG, TAG_SIG, Params,
                      Reject, check_action, check_anchor_time, check_payload,
                      check_registry_epoch, client_order_id, commitment_hash,
                      decode_signed, decode_signed_receipt, plaintext_hash,
                      receipt_hash, retention_margin, retention_window, route,
                      signing_message, tagged, to_cbor, verify_for_gate,
                      verify_receipt, verify_signature, within_retention)
from vecjson import (commitment_from_json, gate_from_json, order_from_json,
                     params_from_json, receipt_from_json)
import check_payload_blob
import hpke_base

DIR = Path(__file__).resolve().parent.parent.parent / "v0"
if "--dir" in sys.argv:
    DIR = Path(sys.argv[sys.argv.index("--dir") + 1]).resolve()
FORMAT = "edicta-vectors/v0"

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
# Gate sentinels with stateless vectors; the stateful ones (allowlist, nonce,
# anchor lookup, availability) have none.
GATE_VECTORED = {"ErrIssuedBeforeAnchor", "ErrBeforeRegistryEpoch", "ErrArchiveRecomputeUnsupported",
                 "ErrRetentionUnavailable"}


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
        expect(len(msg) == 46 and msg.hex() == case["signed_message_hex"], f"{cid}: signed message mismatch")
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
    """sig_torsion_r must fail the signature equation for the right reason:
    the public key is valid, S < L, the cofactored equation holds, R has an
    order-8 component, and only the
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


def check_receipts(rf: dict, pubs: dict, valid: dict) -> set:
    hashes = {c["id"]: c["commitment_hash_hex"] for c in valid["cases"]}
    gate = gate_from_json(rf["gate"])
    for case in rf["cases"]:
        cid = case["id"]
        r = receipt_from_json(case["input"])
        expect(r["commitment_hash"].hex() == hashes[case["commitment_ref"]], f"{cid}: commitment_hash is not {case['commitment_ref']}")
        expect(r["gate_id"] == gate["gate_id"] and r["rail"] == gate["rail"], f"{cid}: gate_id or rail differs from the gate")
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


def check_client_order_ids(cf: dict, valid: dict) -> set:
    hashes = {c["id"]: c["commitment_hash_hex"] for c in valid["cases"]}
    expect(len(cf["cases"]) == len(valid["cases"]), "client_order_id.json: one case per valid commitment expected")
    for c in cf["cases"]:
        expect(c["commitment_hash_hex"] == hashes[c["commitment_ref"]], f"{c['id']}: hash is not {c['commitment_ref']}")
        got = client_order_id(int(c["rail"]), bytes.fromhex(c["commitment_hash_hex"]))
        expect(got == c["client_order_id"], f"{c['id']}: client order id mismatch")
        expect(len(got) == 64 and set(got) <= set("0123456789abcdef"), f"{c['id']}: not 64 lowercase hex characters")
    seen = set()
    for c in cf["reject"]:
        got = outcome(client_order_id, int(c["rail"]), bytes.fromhex(c["commitment_hash_hex"]))
        expect(got == c["expect_error"], f"{c['id']}: got {got}, want {c['expect_error']}")
        seen.add(got)
    return seen


def check_da_blob_inputs(df: dict):
    """The share commitments come from upstream go-square and are checked by Go
    only. Here only the blob descriptions are checked, so a pattern or hex
    mistake shows up in both languages."""
    for c in df["cases"] + df["reject"]:
        if "blob_hex" in c:
            blob = bytes.fromhex(c["blob_hex"])
        else:
            expect(c["blob_pattern"] in df["patterns"], f"{c['id']}: unknown pattern")
            blob = bytes((7 * i + 3) & 0xFF for i in range(int(c["size"])))
        expect(len(blob) == int(c["size"]), f"{c['id']}: size mismatch")
        expect(hashlib.sha256(blob).hexdigest() == c["blob_sha256_hex"], f"{c['id']}: blob sha256 mismatch")
        expect(len(bytes.fromhex(c["namespace_hex"])) == 29 and len(bytes.fromhex(c["signer_hex"])) == 20
               and len(bytes.fromhex(c["commitment_hex"])) == 32, f"{c['id']}: field size")


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
        receipts = load("receipt.json")
        seen |= check_receipts(receipts, pubs, valid)
        anchor = load("anchor.json")
        gate_seen = check_anchor(anchor)
        coids = load("client_order_id.json")
        seen |= check_client_order_ids(coids, valid)
        da_blob = load("da_blob.json")
        check_da_blob_inputs(da_blob)
        blob_summary, blob_ids = check_payload_blob.check(DIR)
        ids = [c["id"] for c in valid["cases"] + reject["cases"] + payload["cases"] + payload["reject"]
               + receipts["cases"] + receipts["reject"] + anchor["k1"] + anchor["k2"] + anchor["epoch"]
               + coids["cases"] + coids["reject"] + da_blob["cases"] + da_blob["reject"]] + blob_ids
        expect(len(ids) == len(set(ids)), "duplicate vector ids")
        expect("sig_torsion_r" in ids, "missing vector sig_torsion_r (cofactorless G1)")
        missing = set(STAGE_OF) - NOT_VECTORED - seen
        expect(not missing, f"sentinels without a must-reject vector: {sorted(missing)}")
        expect(gate_seen == GATE_VECTORED, f"anchor.json sentinels: {sorted(gate_seen)}")
    except (Failure, Reject, check_payload_blob.Failure, hpke_base.HPKEError) as e:
        print(f"FAIL: {e}", file=sys.stderr)
        return 1
    print(f"OK: {len(valid['cases'])} valid, {len(reject['cases'])} reject, "
          f"{len(payload['cases'])} payload, {len(payload['reject'])} payload reject, "
          f"{len(receipts['cases'])} receipt, {len(receipts['reject'])} receipt reject, "
          f"{len(anchor['k1'])} K1, {len(anchor['k2'])} K2, {len(anchor['epoch'])} epoch, "
          f"{len(coids['cases'])} client order id, {len(coids['reject'])} client order id reject, "
          f"{len(da_blob['cases'])} da_blob inputs, {len(da_blob['reject'])} da_blob reject inputs")
    print(f"OK: {blob_summary}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
