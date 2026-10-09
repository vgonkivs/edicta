#!/usr/bin/env python3
"""Verifies payload_blob.json of the core vector set (v1-draft.5, default spec/vectors/v1).

Runs the RFC 9180 known-answer tests of the hand-written HPKE first and
refuses to go on if they fail. Then re-derives every valid case in the seal
direction from its inputs (payload, salt, DEK, nonce, ephemeral keys), opens it
with every recipient key, verifies its signed envelope, and runs every
must-reject case through the opening procedure.

Usage: python3 spec/vectors/check/check_payload_blob.py [--dir DIR]
"""

from __future__ import annotations

import sys

sys.dont_write_bytecode = True

import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

import edicta_payload as pv
import hpke_base as hpke
from edicta import (Reject, action_hash, check_payload, commitment_hash, decode_signed, tagged,
                    verify_for_gate)
from vecjson import _conv, commitment_from_json, gate_from_json, params_from_json

DIR = Path(__file__).resolve().parent.parent / "v1"
if "--dir" in sys.argv:
    DIR = Path(sys.argv[sys.argv.index("--dir") + 1]).resolve()

SENTINELS = {
    "blob.ErrTooLarge", "blob.ErrMalformed", "blob.ErrVersion", "blob.ErrRecipients", "blob.ErrDuplicateKID",
    "blob.ErrNoRecipient", "blob.ErrUnwrap", "blob.ErrDecrypt",
    "payload.ErrMalformed", "payload.ErrVersion", "payload.ErrTooLarge",
    "sdk.ErrPlaintextHashMismatch", "sdk.ErrPayloadMismatch",
}
NOT_VECTORED = {"blob.ErrTooLarge", "payload.ErrTooLarge"}


class Failure(Exception):
    pass


def expect(cond: bool, msg: str):
    if not cond:
        raise Failure(msg)


def raises(fn, sentinel: str, where: str):
    try:
        fn()
    except Reject as e:
        expect(e.sentinel == sentinel, f"{where}: got {e.sentinel} ({e.detail}), want {sentinel}")
        return
    raise Failure(f"{where}: accepted, want {sentinel}")


def hx(s: str) -> bytes:
    return bytes.fromhex(s)


def openssl_unwrap(enc: bytes, wrapped: bytes, sk: bytes, kid: bytes):
    """Second opinion from the OpenSSL HPKE in 'cryptography', when the installed version has one."""
    try:
        from cryptography.hazmat.bindings._rust import openssl as rust_openssl
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        h = rust_openssl.hpke
        suite = h.Suite(h.KEM.X25519, h.KDF.HKDF_SHA256, h.AEAD.CHACHA20_POLY1305)
        dec = h._decrypt_with_aad
    except (ImportError, AttributeError):
        return None
    return dec(suite, enc + wrapped, X25519PrivateKey.from_private_bytes(sk), info=pv.hpke_info(),
               aad=pv.hpke_aad(kid))


def check_suite(v: dict):
    s = v["suite"]
    expect((s["hpke_mode"], s["kem_id"], s["kdf_id"], s["aead_id"]) == ("0", "32", "1", "3"), "suite ids")
    expect(hx(s["hpke_info_hex"]) == tagged(b"edicta/v1/payload-dek") == b"\x15edicta/v1/payload-dek", "hpke info")
    expect(hx(s["payload_aad_hex"]) == tagged(b"edicta/v1/payload") == b"\x11edicta/v1/payload", "payload aad")
    for name, k in v["recipient_keys"].items():
        sk, pk = hpke.derive_key_pair(hx(k["ikm_hex"]))
        expect(sk.hex() == k["sk_hex"] and pk.hex() == k["pk_hex"], f"recipient key {name}")
        expect(1 <= len(hx(k["kid_hex"])) <= pv.MAX_KID_SIZE, f"kid size {name}")


def check_valid(v: dict, keys: dict) -> int:
    gate, params = gate_from_json(v["gate"]), params_from_json(v["params"])
    openssl_checks = 0
    for c in v["cases"]:
        cid = c["id"]
        p = _conv(c["payload"], pv.PAYLOAD, False)
        pt = pv.payload_encode(p)
        expect(pt.hex() == c["plaintext_cbor_hex"], f"{cid}: payload encoding")
        expect(pv.payload_decode(pt) == p, f"{cid}: payload round trip")
        expect(pv.media_type_ok(p["context"]["media_type"]), f"{cid}: context media type")
        expect("context_dca" not in c, f"{cid}: context bodies are profile data, not core vectors")
        salt, dek, nonce = hx(c["salt_hex"]), hx(c["dek_hex"]), hx(c["aead_nonce_hex"])
        expect(salt == hashlib.sha256(f"edicta/v0 test payload salt|{cid}".encode()).digest(), f"{cid}: salt label")
        expect(dek == hashlib.sha256(f"edicta/v0 test dek|{cid}".encode()).digest(), f"{cid}: dek label")
        expect(nonce == hashlib.sha256(f"edicta/v0 test aead nonce|{cid}".encode()).digest()[:12], f"{cid}: nonce label")
        ph = hashlib.sha256(salt + pt).digest()
        expect(ph.hex() == c["plaintext_hash_hex"], f"{cid}: plaintext_hash")
        expect(1 <= len(c["recipients"]) <= 16, f"{cid}: recipient count")
        entries = []
        for i, r in enumerate(c["recipients"]):
            k = keys[r["key"]]
            kid = hx(r["kid_hex"])
            expect(kid == hx(k["kid_hex"]), f"{cid}: kid of {r['key']}")
            ikm_e = hashlib.sha256(f"edicta/v0 test ephemeral|{cid}|{i}".encode()).digest()
            expect(ikm_e.hex() == r["ikme_hex"], f"{cid}: ikmE {i}")
            sk_e = hpke.derive_key_pair(ikm_e)[0]
            expect(sk_e.hex() == r["ske_hex"], f"{cid}: skE {i}")
            enc, ctx = hpke.setup_base_s(hx(k["pk_hex"]), pv.hpke_info(), sk_e)
            wrapped = ctx.seal(pv.hpke_aad(kid), dek)
            expect(enc.hex() == r["enc_hex"], f"{cid}: enc {i}")
            expect(ctx.trace["shared_secret"].hex() == r["shared_secret_hex"], f"{cid}: shared_secret {i}")
            expect(ctx.key.hex() == r["hpke_key_hex"] and ctx.base_nonce.hex() == r["hpke_base_nonce_hex"],
                   f"{cid}: HPKE key schedule {i}")
            expect(wrapped.hex() == r["wrapped_dek_hex"] and len(wrapped) == 48, f"{cid}: wrapped_dek {i}")
            got = openssl_unwrap(enc, wrapped, hx(k["sk_hex"]), kid)
            if got is not None:
                expect(got == dek, f"{cid}: OpenSSL HPKE disagrees for recipient {i}")
                openssl_checks += 1
            entries.append(pv.Entry(kid, enc, wrapped))
        ct = ChaCha20Poly1305(dek).encrypt(nonce, salt + pt, pv.payload_aad())
        expect(ct.hex() == c["ciphertext_hex"], f"{cid}: ciphertext")
        blob = pv.blob_encode(pv.Blob(1, entries, nonce, ct))
        expect(blob.hex() == c["blob_hex"], f"{cid}: blob bytes")
        expect(pv.blob_encode(pv.blob_decode(blob)) == blob, f"{cid}: blob round trip")
        expect(str(len(blob)) == c["payload_size"], f"{cid}: payload_size")
        expect(hashlib.sha256(blob).hexdigest() == c["ciphertext_hash_hex"], f"{cid}: ciphertext_hash")
        at, ah = c["action_type"], hx(c["action_hash_hex"])
        expect(at == p["action"]["type"] and hx(c["action_hex"]) == p["action"]["data"], f"{cid}: action fields")
        expect(hx(c["action_salt_hex"]) == p["action"]["action_salt"]
               and action_hash(at, p["action"]["action_salt"], p["action"]["data"]) == ah, f"{cid}: action hash")
        for r in c["recipients"]:
            sk = hx(keys[r["key"]]["sk_hex"])
            expect(pv.open_payload(blob, sk, hx(r["kid_hex"]), ph, at, ah) == p, f"{cid}: open by {r['key']}")
            expect(pv.open_payload(blob, sk, None, ph, at, ah) == p, f"{cid}: open by {r['key']}, no kid")
        cm = c["commitment"]
        env = hx(cm["envelope_hex"])
        signed, canon = decode_signed(env)
        expect(canon.hex() == cm["commitment_cbor_hex"], f"{cid}: commitment bytes")
        expect(commitment_hash(canon).hex() == cm["commitment_hash_hex"], f"{cid}: commitment hash")
        com = signed["commitment"]
        expect(com == commitment_from_json(cm["input"]), f"{cid}: commitment input")
        verify_for_gate(env, int(cm["now"]), gate, params)
        check_payload(com, blob)
        expect(com["plaintext_hash"] == ph, f"{cid}: commitment plaintext_hash")
        expect(com["action"] == {"type": at, "hash": ah}, f"{cid}: commitment action")
    return openssl_checks


def check_rejects(v: dict, keys: dict) -> set:
    seen = set()
    expect(not {1, 2} & set(pv.PAYLOAD_ACTION) and 6 not in pv.PAYLOAD, "payload: an unassigned key is defined")
    for r in v["reject"]:
        rid, blob, want = r["id"], hx(r["blob_hex"]), r["expect_error"]
        expect(want in SENTINELS, f"{rid}: unknown sentinel {want}")
        seen.add(want)
        stage = r["stage"]
        if stage == "decode":
            raises(lambda: pv.blob_decode(blob), want, rid)
            continue
        pv.blob_decode(blob)
        sk = hx(keys[r["key"]]["sk_hex"])
        kid = hx(r["kid_hex"]) if "kid_hex" in r else None
        if stage == "open":
            raises(lambda: pv.open_blob(blob, sk, kid), want, rid)
            continue
        expect(stage == "plaintext", f"{rid}: unknown stage {stage}")
        ph, at, ah = hx(r["plaintext_hash_hex"]), r["action_type"], hx(r["action_hash_hex"])
        pv.open_blob(blob, sk, kid)
        raises(lambda: pv.open_payload(blob, sk, kid, ph, at, ah), want, rid)
        if "honest_key" in r:
            hsk = hx(keys[r["honest_key"]]["sk_hex"])
            honest = pv.open_blob(blob, hsk, hx(r["honest_kid_hex"]))
            expect(hashlib.sha256(honest).digest() == ph, f"{rid}: honest recipient must match plaintext_hash")
            pv.open_payload(blob, hsk, hx(r["honest_kid_hex"]), ph, at, ah)
            other = pv.open_blob(blob, sk, kid)
            expect(other.hex() == r["auditor_aead_plaintext_hex"] and other != honest, f"{rid}: second plaintext")
            b = pv.blob_decode(blob)
            for dk in (hx(r["dek1_hex"]), hx(r["dek2_hex"])):
                ChaCha20Poly1305(dk).decrypt(b.aead_nonce, b.ciphertext, pv.payload_aad())
            expect(r["dek1_hex"] != r["dek2_hex"], f"{rid}: DEKs must differ")
    missing = SENTINELS - NOT_VECTORED - seen
    expect(not missing, f"sentinels without a must-reject vector: {sorted(missing)}")
    return seen


def check_existing_blob(directory: Path):
    """The payload.json dummy blob is only hashed by stage P: a reader that decodes it stops at its version."""
    p = json.loads((directory / "payload.json").read_text())
    small = next(c for c in p["cases"] if c["id"] == "ciphertext_hash_small_blob")
    raises(lambda: pv.blob_decode(hx(small["blob_hex"])), "blob.ErrVersion", "payload.json small blob")


def check(directory: Path = DIR) -> tuple[str, list]:
    v = json.loads((directory / "payload_blob.json").read_text())
    expect(v["format"] == "edicta-vectors/v1" and v["revision"] == "v1-draft.5", "payload_blob.json format")
    kat = hpke.run_kat([v["hpke_kat"]])
    check_suite(v)
    keys = v["recipient_keys"]
    n_openssl = check_valid(v, keys)
    seen = check_rejects(v, keys)
    expect("dca" not in v, "payload_blob.json: the DCA body vectors belong to the dca-agent profile")
    check_existing_blob(directory)
    ids = [c["id"] for c in v["cases"] + v["reject"]]
    expect(len(ids) == len(set(ids)), "payload_blob.json: duplicate ids")
    by_stage = {}
    for r in v["reject"]:
        by_stage[r["stage"]] = by_stage.get(r["stage"], 0) + 1
    summary = (f"{kat}; payload_blob: {len(v['cases'])} valid, {len(v['reject'])} reject "
               f"({', '.join(f'{n} {s}' for s, n in by_stage.items())}), {len(seen)} sentinels; "
               + (f"{n_openssl} wrapped DEKs also opened by OpenSSL HPKE" if n_openssl
                  else "OpenSSL HPKE cross-check not available in this 'cryptography'"))
    return summary, ids


def main() -> int:
    try:
        summary, _ = check(DIR)
    except (Failure, Reject, hpke.HPKEError) as e:
        print(f"FAIL: {e}", file=sys.stderr)
        return 1
    print(f"OK: {summary}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
