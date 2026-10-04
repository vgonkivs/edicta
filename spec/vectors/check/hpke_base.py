"""HPKE (RFC 9180) base mode for one suite: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20Poly1305.

Hand-written on top of the 'cryptography' primitives (X25519, HMAC-SHA256,
HKDF-Expand, ChaCha20-Poly1305) so that the Python checker does not share an
HPKE implementation with the Go SDK. Only the base mode is implemented. The
sender takes the ephemeral private key as an argument, which is what makes
test vectors reproducible; production code must draw it at random.

Self-test: run this file directly, or call run_kat(), to check it against the
RFC 9180 known-answer vectors for this suite.
"""

from __future__ import annotations

import json
import struct
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

MODE_BASE = 0x00
KEM_ID = 0x0020
KDF_ID = 0x0001
AEAD_ID = 0x0003

N_SECRET = 32
N_ENC = 32
N_PK = 32
N_SK = 32
N_H = 32
N_K = 32
N_N = 12
N_T = 16

SUITE_ID_KEM = b"KEM" + struct.pack(">H", KEM_ID)
SUITE_ID = b"HPKE" + struct.pack(">HHH", KEM_ID, KDF_ID, AEAD_ID)


class HPKEError(Exception):
    pass


def _extract(salt: bytes, ikm: bytes) -> bytes:
    h = hmac.HMAC(salt if salt else bytes(N_H), hashes.SHA256())
    h.update(ikm)
    return h.finalize()


def _expand(prk: bytes, info: bytes, length: int) -> bytes:
    return HKDFExpand(hashes.SHA256(), length, info).derive(prk)


def labeled_extract(suite_id: bytes, salt: bytes, label: bytes, ikm: bytes) -> bytes:
    return _extract(salt, b"HPKE-v1" + suite_id + label + ikm)


def labeled_expand(suite_id: bytes, prk: bytes, label: bytes, info: bytes, length: int) -> bytes:
    if length > 0xFFFF:
        raise HPKEError("expand length too large")
    labeled_info = struct.pack(">H", length) + b"HPKE-v1" + suite_id + label + info
    return _expand(prk, labeled_info, length)


def _pk_bytes(sk: bytes) -> bytes:
    return X25519PrivateKey.from_private_bytes(sk).public_key().public_bytes_raw()


def _dh(sk: bytes, pk: bytes) -> bytes:
    try:
        out = X25519PrivateKey.from_private_bytes(sk).exchange(X25519PublicKey.from_public_bytes(pk))
    except ValueError as e:
        raise HPKEError(f"X25519 failed: {e}")
    if out == bytes(32):
        raise HPKEError("X25519 output is all zero")
    return out


def derive_key_pair(ikm: bytes) -> tuple[bytes, bytes]:
    """DeriveKeyPair for X25519. Returns (sk, pk), both 32 raw bytes."""
    dkp_prk = labeled_extract(SUITE_ID_KEM, b"", b"dkp_prk", ikm)
    sk = labeled_expand(SUITE_ID_KEM, dkp_prk, b"sk", b"", N_SK)
    return sk, _pk_bytes(sk)


def _extract_and_expand(dh: bytes, kem_context: bytes) -> bytes:
    eae_prk = labeled_extract(SUITE_ID_KEM, b"", b"eae_prk", dh)
    return labeled_expand(SUITE_ID_KEM, eae_prk, b"shared_secret", kem_context, N_SECRET)


def encap(pk_r: bytes, sk_e: bytes) -> tuple[bytes, bytes]:
    """Encap with a caller-supplied ephemeral private key. Returns (shared_secret, enc)."""
    if len(pk_r) != N_PK or len(sk_e) != N_SK:
        raise HPKEError("bad key size")
    enc = _pk_bytes(sk_e)
    dh = _dh(sk_e, pk_r)
    return _extract_and_expand(dh, enc + pk_r), enc


def decap(enc: bytes, sk_r: bytes) -> bytes:
    if len(enc) != N_ENC or len(sk_r) != N_SK:
        raise HPKEError("bad key size")
    dh = _dh(sk_r, enc)
    return _extract_and_expand(dh, enc + _pk_bytes(sk_r))


class Context:
    def __init__(self, key: bytes, base_nonce: bytes, exporter_secret: bytes, trace: dict):
        self.key = key
        self.base_nonce = base_nonce
        self.exporter_secret = exporter_secret
        self.seq = 0
        self.trace = trace
        self._aead = ChaCha20Poly1305(key)

    def _nonce(self) -> bytes:
        if self.seq >= (1 << (8 * N_N)) - 1:
            raise HPKEError("message limit reached")
        seq_bytes = self.seq.to_bytes(N_N, "big")
        return bytes(a ^ b for a, b in zip(self.base_nonce, seq_bytes))

    def seal(self, aad: bytes, pt: bytes) -> bytes:
        ct = self._aead.encrypt(self._nonce(), pt, aad)
        self.seq += 1
        return ct

    def open(self, aad: bytes, ct: bytes) -> bytes:
        try:
            pt = self._aead.decrypt(self._nonce(), ct, aad)
        except InvalidTag:
            raise HPKEError("AEAD open failed")
        self.seq += 1
        return pt

    def export(self, exporter_context: bytes, length: int) -> bytes:
        return labeled_expand(SUITE_ID, self.exporter_secret, b"sec", exporter_context, length)


def key_schedule_base(shared_secret: bytes, info: bytes) -> Context:
    psk_id_hash = labeled_extract(SUITE_ID, b"", b"psk_id_hash", b"")
    info_hash = labeled_extract(SUITE_ID, b"", b"info_hash", info)
    ks_context = bytes([MODE_BASE]) + psk_id_hash + info_hash
    secret = labeled_extract(SUITE_ID, shared_secret, b"secret", b"")
    key = labeled_expand(SUITE_ID, secret, b"key", ks_context, N_K)
    base_nonce = labeled_expand(SUITE_ID, secret, b"base_nonce", ks_context, N_N)
    exporter_secret = labeled_expand(SUITE_ID, secret, b"exp", ks_context, N_H)
    trace = {"key_schedule_context": ks_context, "secret": secret, "shared_secret": shared_secret}
    return Context(key, base_nonce, exporter_secret, trace)


def setup_base_s(pk_r: bytes, info: bytes, sk_e: bytes) -> tuple[bytes, Context]:
    shared_secret, enc = encap(pk_r, sk_e)
    return enc, key_schedule_base(shared_secret, info)


def setup_base_r(enc: bytes, sk_r: bytes, info: bytes) -> Context:
    return key_schedule_base(decap(enc, sk_r), info)


KAT_FILE = Path(__file__).resolve().parent / "hpke_rfc9180_a2_1.json"


def check_kat_entry(v: dict) -> int:
    """Checks one RFC 9180 base-mode vector of this suite. Returns the number of AEAD and export checks."""
    def b(name: str) -> bytes:
        return bytes.fromhex(v[name])

    if (int(v["mode"]), int(v["kem_id"]), int(v["kdf_id"]), int(v["aead_id"])) != (MODE_BASE, KEM_ID, KDF_ID, AEAD_ID):
        raise HPKEError("vector is not for base mode of this suite")
    sk_e, pk_e = derive_key_pair(b("ikmE"))
    sk_r, pk_r = derive_key_pair(b("ikmR"))
    if (sk_e, pk_e, sk_r, pk_r) != (b("skEm"), b("pkEm"), b("skRm"), b("pkRm")):
        raise HPKEError("DeriveKeyPair mismatch")
    enc, ctx_s = setup_base_s(pk_r, b("info"), sk_e)
    if enc != b("enc") or ctx_s.trace["shared_secret"] != b("shared_secret"):
        raise HPKEError("Encap mismatch")
    if ctx_s.trace["key_schedule_context"] != b("key_schedule_context") or ctx_s.trace["secret"] != b("secret"):
        raise HPKEError("key schedule mismatch")
    if (ctx_s.key, ctx_s.base_nonce, ctx_s.exporter_secret) != (b("key"), b("base_nonce"), b("exporter_secret")):
        raise HPKEError("key, base_nonce or exporter_secret mismatch")
    ctx_r = setup_base_r(b("enc"), sk_r, b("info"))
    if ctx_r.trace["shared_secret"] != b("shared_secret") or ctx_r.key != ctx_s.key:
        raise HPKEError("Decap mismatch")
    n = 0
    for e in v["encryptions"]:
        if "seq" in e:
            ctx_s.seq = ctx_r.seq = int(e["seq"])
        nonce = ctx_s._nonce()
        if "nonce" in e and nonce != bytes.fromhex(e["nonce"]):
            raise HPKEError(f"nonce mismatch at encryption {n}")
        pt, aad, ct = bytes.fromhex(e["pt"]), bytes.fromhex(e["aad"]), bytes.fromhex(e["ct"])
        if ctx_s.seal(aad, pt) != ct:
            raise HPKEError(f"seal mismatch at encryption {n}")
        if ctx_r.open(aad, ct) != pt:
            raise HPKEError(f"open mismatch at encryption {n}")
        n += 1
    for x in v["exports"]:
        if ctx_r.export(bytes.fromhex(x["exporter_context"]), int(x["L"])) != bytes.fromhex(x["exported_value"]):
            raise HPKEError("export mismatch")
        n += 1
    try:
        ctx_r.seq = 0
        ctx_r.open(b"wrong aad", bytes.fromhex(v["encryptions"][0]["ct"]))
    except HPKEError:
        pass
    else:
        raise HPKEError("open accepted a wrong aad")
    return n


def run_kat(extra: list | None = None) -> str:
    """Runs the vendored RFC 9180 vector set and any extra entries. Returns a summary line."""
    full = json.loads(KAT_FILE.read_text())
    n_full = check_kat_entry(full["vector"])
    n_extra = sum(check_kat_entry(v) for v in (extra or []))
    return (f"RFC 9180 A.2.1 base mode: {len(full['vector']['encryptions'])} encryptions and "
            f"{len(full['vector']['exports'])} exports from the CFRG set, plus {n_extra} RFC text checks, all match"
            if n_full else "no checks")


if __name__ == "__main__":
    print(run_kat())
