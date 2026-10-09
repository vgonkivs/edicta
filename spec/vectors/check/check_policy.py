#!/usr/bin/env python3
"""Verifies the policy v1 vectors (spec/policy-v1.md, policy-v1-draft.9).

Two independent paths:
- the generator (gen_policy.py over policy_v1.py) reproduces every file byte
  for byte;
- this file re-implements, from the spec text and without importing
  policy_v1, the canonical encodings (lenient parse, then canonical
  re-encode), the hashes from literal tag bytes, the Ed25519 checks, the
  schemas and value rules, rendering, the engine (per-hour dictionary, window
  sums by direct iteration), the archive record reader, the verifier outcome
  rules and the tia-transfer extractor, and checks every expectation.

Usage: python3 spec/vectors/check/check_policy.py
"""

from __future__ import annotations

import sys

sys.dont_write_bytecode = True

import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path

import principal_crypto as pc
import profile_bank_send as bs
from cbor_strict import encode
from ed25519_point import cofactorless_ok, public_key_problem

HERE = Path(__file__).resolve().parent
VECTORS = HERE.parent
L = 2**252 + 27742317777372353535851937790883648493
MAXI = (1 << 63) - 1
MAXA = (1 << 256) - 1

# Literal tag bytes: uint8(len) || ASCII.
T_MANDATE = bytes.fromhex("18") + b"edicta/policy/v1/mandate"
T_MANDATE_SIG = bytes.fromhex("1c") + b"edicta/policy/v1/mandate-sig"
T_VERDICT = bytes.fromhex("18") + b"edicta/policy/v1/verdict"
T_VERDICT_SIG = bytes.fromhex("1c") + b"edicta/policy/v1/verdict-sig"
T_BUCKET = bytes.fromhex("17") + b"edicta/policy/v1/bucket"
T_CLOSED = bytes.fromhex("17") + b"edicta/policy/v1/closed"
T_STATE = bytes.fromhex("16") + b"edicta/policy/v1/state"
T_COUNTER = bytes.fromhex("18") + b"edicta/policy/v1/counter"
T_SUCC = bytes.fromhex("1a") + b"edicta/policy/v1/successor"
T_PRIV_PART = bytes.fromhex("1d") + b"edicta/policy/v1/private-part"
T_PRIV_AEAD = bytes.fromhex("18") + b"edicta/policy/v1/private"
T_PRIV_DEK = bytes.fromhex("1c") + b"edicta/policy/v1/private-dek"
T_ACTION_V1 = bytes.fromhex("10") + b"edicta/v1/action"
T_STATE_BLIND = bytes.fromhex("1c") + b"edicta/policy/v1/state-blind"
T_BLIND_KEY = bytes.fromhex("1a") + b"edicta/policy/v1/blind-key"
T_AUDITOR_KID = bytes.fromhex("15") + b"edicta/v1/auditor-kid"
LABEL = set(chr(c) for c in range(0x20, 0x7F)) - {'"', "\\"}
for t in (T_MANDATE, T_MANDATE_SIG, T_VERDICT, T_VERDICT_SIG, T_BUCKET, T_CLOSED, T_STATE, T_COUNTER, T_SUCC):
    assert t[0] == len(t) - 1

ID = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._:/-")
PRINT = set(chr(c) for c in range(0x21, 0x7F))
KIND = re.compile(r"[a-z][a-z0-9-]{0,31}")
XID = re.compile(r"[a-z0-9][a-z0-9./-]{0,63}")
TEST_TYPE = "application/vnd.edicta.test-facts.v1+cbor"
TEST_X = "edicta/test-facts/v1"
DENY = ["ErrAgentNotCovered", "ErrFastModeNotAllowed", "ErrNoExtractor", "ErrFactsInvalid", "ErrOutsideMandate", "ErrKindNotAllowed",
        "ErrAssetNotAllowed", "ErrRecipientNotAllowed", "ErrAmountAboveMax", "ErrDecisionAge", "ErrMinSpacing",
        "ErrPeriodLimit", "ErrCountLimit", "ErrHistoryFull"]


class Bad(Exception):
    def __init__(self, sentinel):
        super().__init__(sentinel)
        self.sentinel = sentinel


class Failure(Exception):
    pass


def expect(c, msg):
    if not c:
        raise Failure(msg)


def H(*parts):
    return hashlib.sha256(b"".join(parts)).digest()


# Lenient parse into Python values (lists stay lists, maps become dicts with
# int keys), then canonical re-encode must give the input: that covers
# minimal heads, key order, duplicates, definite lengths in one comparison.

def lenient(b: bytes, sentinel: str, cap: int, max_depth=6):
    if len(b) > cap:
        raise Bad(sentinel)
    pos = [0]

    def rd(n):
        if pos[0] + n > len(b):
            raise Bad(sentinel)
        x = b[pos[0]:pos[0] + n]
        pos[0] += n
        return x

    def item(depth):
        ib = rd(1)[0]
        major, ai = ib >> 5, ib & 31
        if major in (6, 7) or ai > 27:
            raise Bad(sentinel)
        arg = ai if ai < 24 else int.from_bytes(rd(1 << (ai - 24)), "big")
        if major == 0:
            return arg
        if major == 1:
            return -1 - arg
        if major == 2:
            return bytes(rd(arg))
        if major == 3:
            try:
                return rd(arg).decode("utf-8")
            except UnicodeDecodeError:
                raise Bad(sentinel)
        if depth >= max_depth or arg > 1024:
            raise Bad(sentinel)
        if major == 4:
            return [item(depth + 1) for _ in range(arg)]
        out = {}
        for _ in range(arg):
            kk = item(depth + 1)
            if not isinstance(kk, int) or kk < 0:
                raise Bad(sentinel)
            out[kk] = item(depth + 1)
        return out

    v = item(0)
    if pos[0] != len(b):
        raise Bad(sentinel)
    try:
        if encode(v) != b:
            raise Bad(sentinel)
    except (TypeError, ValueError):
        raise Bad(sentinel)
    return v


def need(c, s):
    if not c:
        raise Bad(s)


def keys(m, s, req, opt=()):
    need(isinstance(m, dict), s)
    need(set(m) <= set(req) | set(opt) and set(req) <= set(m), s)


def u(x, s, lo=0, hi=MAXI):
    need(isinstance(x, int) and not isinstance(x, bool) and lo <= x <= hi, s)


def txt(x, s, lo, hi, chars):
    need(isinstance(x, str) and lo <= len(x.encode()) <= hi and all(c in chars for c in x), s)


def amount_ok(x, s, min_value=0):
    need(isinstance(x, bytes) and 1 <= len(x) <= 32 and (len(x) == 1 or x[0] != 0), s)
    need(int.from_bytes(x, "big") >= min_value, s)


def b32(x, s, n=32):
    need(isinstance(x, bytes) and len(x) == n, s)


def ascending(xs, s):
    need(all(a < b for a, b in zip(xs, xs[1:])), s)


def ival(b):
    return int.from_bytes(b, "big")


def ibytes(n):
    return n.to_bytes(max(1, (n.bit_length() + 7) // 8), "big")


# Structures (maps with int keys).

def v_facts(f, s="ErrFactsInvalid"):
    keys(f, s, (1, 2, 3, 4), (5,))
    txt(f[1], s, 1, 32, PRINT)
    need(KIND.fullmatch(f[1]) is not None, s)
    txt(f[2], s, 1, 128, PRINT)
    amount_ok(f[3], s)
    u(f[4], s, 0, 255)
    if 5 in f:
        txt(f[5], s, 1, 128, PRINT)


def facts_dec(b):
    f = lenient(b, "ErrFactsInvalid", 512, 1)
    v_facts(f)
    return f


def low_order_x25519(pub):
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
    try:
        out = X25519PrivateKey.from_private_bytes(bytes([1] * 32)).exchange(X25519PublicKey.from_public_bytes(pub))
    except ValueError:
        return True
    return out == bytes(32)


def v_mandate(m):
    s = "ErrMandateInvalid"
    keys(m, s, (1, 2, 3, 4, 5, 6, 7, 9, 10), (8, 11, 12, 13, 14, 15, 16, 17, 18))
    need(m[1] == 1, s)
    if 14 in m:
        u(m[14], s)
        need(m[14] in (2, 3), s)
    st = m.get(14)
    if st is None:
        b32(m[2], s)
        need(public_key_problem(m[2]) is None, s)
    elif st == 2:
        b32(m[2], s, 33)
        need(pc.decompress(m[2]) is not None, s)
    else:
        b32(m[2], s, 20)
    need((15 in m) == (st == 2), s)
    if 15 in m:
        txt(m[15], s, 1, 16, set("abcdefghijklmnopqrstuvwxyz0123456789"))
    if 16 in m:
        u(m[16], s, 1, 1000)
    if 17 in m:
        need(isinstance(m[17], list) and 1 <= len(m[17]) <= 16, s)
        for a in m[17]:
            keys(a, s, (1, 2, 3))
            b32(a[1], s, 16)
            b32(a[2], s)
            txt(a[3], s, 1, 64, LABEL)
            need(a[3] == a[3].strip(" "), s)
            need(a[1] == H(T_AUDITOR_KID, a[2])[:16], s)
            need(not low_order_x25519(a[2]), s)
        ascending([a[1] for a in m[17]], s)
        need(len({a[3] for a in m[17]}) == len(m[17]), s)
    need((18 in m) == (17 in m), s)
    if 18 in m:
        b32(m[18], s)
    txt(m[3], s, 1, 64, ID)
    need(isinstance(m[4], list) and 1 <= len(m[4]) <= 64, s)
    for a in m[4]:
        b32(a, s)
        need(public_key_problem(a) is None, s)
    ascending(m[4], s)
    need(m[2] not in m[4], s)
    u(m[5], s, 1)
    u(m[6], s, m[5] + 1, 253402300799)
    need(isinstance(m[7], list) and 1 <= len(m[7]) <= 16, s)
    for r in m[7]:
        keys(r, s, (1, 2), (3, 4, 5))
        txt(r[1], s, 1, 128, PRINT)
        u(r[2], s, 0, 255)
        need(3 in r or 4 in r, s)
        if 3 in r:
            amount_ok(r[3], s, 1)
        if 4 in r:
            need(isinstance(r[4], list) and 1 <= len(r[4]) <= 4, s)
            for p in r[4]:
                keys(p, s, (1, 2))
                u(p[1], s, 1, 744)
                amount_ok(p[2], s, 1)
            ascending([p[1] for p in r[4]], s)
        if 5 in r:
            need(isinstance(r[5], list) and 1 <= len(r[5]) <= 256, s)
            for x in r[5]:
                txt(x, s, 1, 128, PRINT)
            ascending([x.encode() for x in r[5]], s)
    ascending([r[1].encode() for r in m[7]], s)
    if 8 in m:
        need(isinstance(m[8], list) and 1 <= len(m[8]) <= 4, s)
        for c in m[8]:
            keys(c, s, (1, 2))
            u(c[1], s, 1, 744)
            u(c[2], s, 1, 1 << 32)
        ascending([c[1] for c in m[8]], s)
    b32(m[9], s, 16)
    u(m[10], s, 1)
    if 11 in m:
        u(m[11], s, 1, 86400)
    if 12 in m:
        u(m[12], s, 1, 2678400)
    if 13 in m:
        need(isinstance(m[13], list) and 1 <= len(m[13]) <= 8, s)
        for x in m[13]:
            need(isinstance(x, str) and KIND.fullmatch(x) is not None, s)
        ascending([x.encode() for x in m[13]], s)


def sig_ok(pub, tag, h, sig):
    if public_key_problem(pub) or len(sig) != 64 or int.from_bytes(sig[32:], "little") >= L:
        return False
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    msg = tag + h
    try:
        Ed25519PublicKey.from_public_bytes(pub).verify(sig, msg)
        lib = True
    except InvalidSignature:
        lib = False
    assert lib == cofactorless_ok(pub, msg, sig)
    return lib


def cosmos_signer(m):
    return pc.cosmos_address(m[2], m[15])


def adr036_doc(m, h, data=None):
    """Amino JSON of the ADR-036 sign document, written out key by key in sorted order."""
    import base64
    d = (render(m) + "\nmandate hash: " + h.hex()) if data is None else data
    value = {"data": base64.b64encode(d.encode()).decode(), "signer": cosmos_signer(m)}
    doc = {"account_number": "0", "chain_id": "", "fee": {"amount": [], "gas": "0"}, "memo": "",
           "msgs": [{"type": "sign/MsgSignData", "value": value}], "sequence": "0"}
    out = json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return out.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026").encode()


def eip712_digest(m, h):
    k = pc.keccak256
    dom = k(k(b"EIP712Domain(string name,string version)") + k(b"Edicta Mandate") + k(b"1"))
    th = k(b"Mandate(bytes32 mandateHash,bytes16 mandateId,uint64 version,string gateId)")
    hs = k(th + h + m[9] + bytes(16) + m[10].to_bytes(32, "big") + k(m[3].encode()))
    return k(bytes([0x19, 0x01]) + dom + hs)


def mandate_verify(b):
    sm = lenient(b, "ErrMandateInvalid", 16384)
    keys(sm, "ErrMandateInvalid", (1, 2))
    need(isinstance(sm[1], dict), "ErrMandateInvalid")
    b32(sm[2], "ErrMandateInvalid", 65 if sm[1].get(14) == 3 else 64)
    v_mandate(sm[1])
    m = sm[1]
    h = H(T_MANDATE, encode(m))
    st = m.get(14)
    if st is None:
        ok = sig_ok(m[2], T_MANDATE_SIG, h, sm[2])
    elif st == 2:
        ok = pc.verify_cosmos(m[2], adr036_doc(m, h), sm[2])
    else:
        ok = pc.verify_eth(m[2], eip712_digest(m, h), sm[2])
    if not ok:
        raise Bad("ErrMandateSignature")
    return m, h


def v_bucket(b, s="ErrStateInvalid"):
    keys(b, s, (1, 2, 3, 4))
    need(b[1] == 1, s)
    u(b[2], s)
    u(b[3], s, 1)
    need(isinstance(b[4], list) and 1 <= len(b[4]) <= 64, s)
    for x in b[4]:
        keys(x, s, (1, 2, 3))
        txt(x[1], s, 1, 128, PRINT)
        u(x[2], s, 0, 255)
        amount_ok(x[3], s)
    ascending([(x[1].encode(), x[2]) for x in b[4]], s)


def v_closed(c, s="ErrStateInvalid"):
    keys(c, s, (1, 2))
    need(c[1] == 1 and isinstance(c[2], list) and len(c[2]) <= 767, s)
    for r in c[2]:
        keys(r, s, (1, 2))
        u(r[1], s)
        b32(r[2], s)
    ascending([r[1] for r in c[2]], s)


EMPTY = {1: 1, 2: []}
EMPTY_ROOT = H(T_CLOSED, encode(EMPTY))
GEN = {1: 1, 2: 0, 5: EMPTY_ROOT}
GEN_HASH_CONST = H(T_STATE, encode(GEN))


def v_state(st, s="ErrStateInvalid"):
    keys(st, s, (1, 2, 5), (3, 4, 6))
    need(st[1] == 1, s)
    u(st[2], s)
    b32(st[5], s)
    if st[2] == 0:
        need(st == GEN, s)
    else:
        need({3, 4, 6} <= set(st), s)
        u(st[3], s)
        u(st[4], s, 0, st[3])
        v_bucket(st[6], s)
        need(st[6][2] == st[3] // 3600, s)


def dec_struct(b, cap, fn):
    v = lenient(b, "ErrStateInvalid", cap)
    fn(v)
    return v


def v_verdict(v):
    s = "ErrVerdictInvalid"
    keys(v, s, (1, 2, 3, 4, 5, 6, 7), (8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20))
    need(v[1] == 1, s)
    txt(v[2], s, 1, 64, ID)
    for kk in (3, 4, 5, 6):
        b32(v[kk], s)
    u(v[7], s, 1, 2)
    if 17 in v:
        u(v[17], s, 1)
    if 9 in v:
        need(isinstance(v[9], str) and XID.fullmatch(v[9]) is not None, s)
    if 10 in v:
        v_facts(v[10], s)
    if 13 in v:
        v_state(v[13], s)
    for kk in (11, 12):
        if kk in v:
            u(v[kk], s)
    for kk in (14, 15, 16, 19, 20):
        if kk in v:
            b32(v[kk], s)
    if 19 in v:
        # Private form: only the hashes, the links and the outcome bit are public.
        have = set(v) - {1, 2, 3, 4, 5, 6, 7, 19}
        if v[7] == 1:
            want = {14, 20} | ({15, 16} if v.get(20, GEN_HASH_CONST) != GEN_HASH_CONST else set())
        else:
            want = set()
        need(have == want, s)
        return
    need(17 in v and 20 not in v, s)
    have = set(v) - {1, 2, 3, 4, 5, 6, 7, 17}
    if v[7] == 1:
        later = 13 in v and v[13][2] >= 1
        want = {9, 10, 11, 12, 14, 13} | ({15, 16} if later else set())
    else:
        need(v.get(8) in DENY, s)
        r = v[8]
        stage = {"ErrAgentNotCovered": "a", "ErrFastModeNotAllowed": "a", "ErrNoExtractor": "a",
                 "ErrFactsInvalid": "x"}.get(r, "f")
        if r == "ErrDecisionAge":
            stage = "age"
        elif r in ("ErrMinSpacing", "ErrPeriodLimit", "ErrCountLimit", "ErrHistoryFull"):
            stage = "eval"
        elif r == "ErrOutsideMandate" and 11 in v:
            stage = "nb"
        want = {8}
        want |= {"a": set(), "x": {9}, "f": {9, 10}, "age": {9, 10, 11, 18}, "nb": {9, 10, 11, 13},
                 "eval": {9, 10, 11, 12, 13}}[stage]
    need(have == want, s)
    if 18 in v:
        need(v[18] == 1, s)


def v_private_part(pp):
    s = "ErrVerdictInvalid"
    keys(pp, s, (1, 2, 17), (8, 9, 10, 11, 12, 13, 18))
    need(pp[1] == 1, s)
    b32(pp[2], s)
    u(pp[17], s, 1)
    if 8 in pp:
        txt(pp[8], s, 4, 64, ID)
    if 9 in pp:
        need(isinstance(pp[9], str) and XID.fullmatch(pp[9]) is not None, s)
    if 10 in pp:
        v_facts(pp[10], s)
    for kk in (11, 12):
        if kk in pp:
            u(pp[kk], s)
    if 13 in pp:
        v_state(pp[13], s)
    if 18 in pp:
        need(pp[18] == 1, s)


def merge(pub, pp):
    out = {k: x for k, x in pub.items() if k not in (19, 20)}
    out.update({k: x for k, x in pp.items() if k not in (1, 2)})
    return dict(sorted(out.items()))


def blind_state(st, salt):
    return H(T_STATE, encode(st)) if salt is None or st == GEN else H(T_STATE_BLIND, salt, encode(st))


def verdict_verify(b, gate_pub):
    sv = lenient(b, "ErrVerdictInvalid", 16384)
    keys(sv, "ErrVerdictInvalid", (1, 2))
    b32(sv[2], "ErrVerdictInvalid", 64)
    v_verdict(sv[1])
    h = H(T_VERDICT, encode(sv[1]))
    if gate_pub is not None and not sig_ok(gate_pub, T_VERDICT_SIG, h, sv[2]):
        raise Bad("ErrVerdictSignature")
    return sv[1], h


def counter(principal, mid, sig_type=None):
    if sig_type is None:
        return H(T_COUNTER, principal, mid)
    return H(T_COUNTER, bytes([sig_type, len(principal)]), principal, mid)


def succ_key(gate_id, ck, sh):
    g = gate_id.encode()
    return H(T_SUCC, bytes([len(g)]), g, ck, sh)


# Archive reader (policy kinds).

PATH = {7: "mandate", 8: "policy-allow", 9: "policy-deny", 10: "policy-bucket", 11: "policy-closed",
        12: "policy-successor", 15: "private"}
RCAP = {7: 16448, 8: 16448, 9: 16448, 10: 16448, 11: 36928, 12: 256, 15: 69760}


def read_record(b):
    s = "archive.ErrCorrupt"
    r = lenient(b, s, 69760, 1)
    need(isinstance(r, dict) and 1 in r and 2 in r and r[1] == 1 and r[2] in PATH and len(b) <= RCAP[r[2]], s)
    kind = r[2]
    try:
        if kind == 15:
            keys(r, s, (1, 2, 3, 4, 5))
            u(r[3], s, 1, 5)
            b32(r[4], s)
            need(isinstance(r[5], bytes) and 1 <= len(r[5]) <= (69632 if r[3] == 5 else 65536), s)
            return {"kind": 15, "key": r[4], "pk": r[3], "path": f"private/{r[3]}/{r[4].hex()}", "envelope": r[5]}
        if kind == 12:
            keys(r, s, (1, 2, 3, 4, 5, 6))
            txt(r[3], s, 1, 64, ID)
            for kk in (4, 5, 6):
                b32(r[kk], s)
            key = succ_key(r[3], r[4], r[5])
            return {"kind": 12, "key": key, "path": f"policy-successor/{key.hex()}", "commitment": r[6]}
        keys(r, s, (1, 2, 3))
        need(isinstance(r[3], bytes) and 1 <= len(r[3]) <= (36864 if kind == 11 else 16384), s)
        body = r[3]
        if kind == 7:
            sm = lenient(body, s, 16384)
            keys(sm, s, (1, 2))
            v_mandate(sm[1])
            key = H(T_MANDATE, encode(sm[1]))
            return {"kind": 7, "key": key, "path": f"mandate/{key.hex()}", "body": body}
        if kind in (8, 9):
            v, _ = verdict_verify(body, None)
            need(v[7] == (1 if kind == 8 else 2), s)
            p = f"{PATH[kind]}/{v[4].hex()}" + ((f"/{v[8]}" if 19 not in v else "/private") if kind == 9 else "")
            return {"kind": kind, "key": v[4], "path": p, "body": body}
        if kind == 10:
            x = dec_struct(body, 16384, v_bucket)
            key = H(T_BUCKET, body)
            return {"kind": 10, "key": key, "path": f"policy-bucket/{key.hex()}", "bucket": x}
        x = dec_struct(body, 36864, v_closed)
        key = H(T_CLOSED, body)
        return {"kind": 11, "key": key, "path": f"policy-closed/{key.hex()}", "closed": x}
    except Bad:
        raise Bad(s)


# Private envelopes (section 9.5): the core blob layout under the policy tags.

def hpke_unwrap(enc, wrapped, sk, kid):
    """OpenSSL's HPKE (base mode, X25519, HKDF-SHA256, ChaCha20-Poly1305) through 'cryptography'; None when the
    entry does not unwrap."""
    from cryptography.hazmat.bindings._rust import openssl as rust_openssl
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    h = rust_openssl.hpke
    suite = h.Suite(h.KEM.X25519, h.KDF.HKDF_SHA256, h.AEAD.CHACHA20_POLY1305)
    try:
        return h._decrypt_with_aad(suite, enc + wrapped, X25519PrivateKey.from_private_bytes(sk), info=T_PRIV_DEK,
                                   aad=bytes([len(kid)]) + kid)
    except Exception:  # noqa: BLE001
        return None


def envelope_parts(env, cap=65536):
    s = "envelope"
    need(len(env) <= cap, s)
    e = lenient(env, s, cap, 3)
    keys(e, s, (1, 2, 3, 4))
    need(e[1] == 1 and isinstance(e[2], list) and 1 <= len(e[2]) <= 16, s)
    for x in e[2]:
        keys(x, s, (1, 2, 3))
        need(isinstance(x[1], bytes) and 1 <= len(x[1]) <= 32, s)
        b32(x[2], s)
        b32(x[3], s, 48)
    need(len({x[1] for x in e[2]}) == len(e[2]), s)
    b32(e[3], s, 12)
    need(isinstance(e[4], bytes) and len(e[4]) >= 49, s)
    # Fixed key order 1..4 and entry key order 1..3 is what the canonical re-encode of lenient() enforces.
    return e


def plain_hash(pk, pt, atype=None):
    if pk == 5:
        need(atype is not None and len(pt) >= 33, "action")
        return H(T_ACTION_V1, bytes([len(atype)]), atype.encode(), pt)
    if pk == 1:
        return mandate_verify_nosig(pt)
    if pk == 2:
        dec_struct(pt, 16384, v_bucket)
        return H(T_BUCKET, pt)
    if pk == 3:
        dec_struct(pt, 36864, v_closed)
        return H(T_CLOSED, pt)
    pp = lenient(pt, "ErrVerdictInvalid", 16384)
    v_private_part(pp)
    return H(T_PRIV_PART, pt)


def mandate_verify_nosig(b):
    sm = lenient(b, "ErrMandateInvalid", 16384)
    keys(sm, "ErrMandateInvalid", (1, 2))
    v_mandate(sm[1])
    return H(T_MANDATE, encode(sm[1]))


def open_private(env, sks, pk, want, atype=None):
    """('ok', plaintext, kid), ('corrupt', None, None) or ('private', None, None)."""
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    try:
        e = envelope_parts(env, 69632 if pk == 5 else 65536)
    except Bad:
        return "corrupt", None, None
    for sk in sks:
        for x in e[2]:
            dek = hpke_unwrap(x[2], x[3], sk, x[1])
            if dek is None:
                continue
            try:
                pt = ChaCha20Poly1305(dek).decrypt(e[3], e[4], T_PRIV_AEAD)[32:]
                ok = plain_hash(pk, pt, atype) == want
            except (InvalidTag, Bad, ValueError):
                return "corrupt", None, None
            return ("ok", pt, x[1]) if ok else ("corrupt", None, None)
    return "private", None, None


# Engine: the ledger as {"st": State map, "closed": {index: bucket map or None (hash only)}, "hashes": {index: hash}}.

def bucket_hash(b):
    return H(T_BUCKET, encode(b))


def ledger(st, closed_set, buckets):
    hashes = {r[1]: r[2] for r in closed_set[2]}
    return {"st": st, "hashes": hashes, "closed": {b[2]: b for b in buckets}}


def win(led, t, hours, open_b):
    lo = (t - 3600 * hours + 1) // 3600 if t >= 3600 * hours else 0
    hi = t // 3600
    out = []
    for i in range(lo, hi + 1):
        if open_b is not None and i == open_b[2]:
            out.append(open_b)
        elif i in led["hashes"]:
            out.append(led["closed"][i])
    return out


def transition(led, asset, scale, amount, th, check=None):
    st = led["st"]
    teff = th if st[2] == 0 else max(th, st[3])
    kk = teff // 3600
    hashes, closed = dict(led["hashes"]), dict(led["closed"])
    if st[2] == 0:
        ob = {1: 1, 2: kk, 3: 0, 4: []}
        rolled = None
    elif kk > st[6][2]:
        rolled = st[6]
        hashes[rolled[2]] = bucket_hash(rolled)
        closed[rolled[2]] = rolled
        hashes = {i: h for i, h in hashes.items() if i >= kk - 767}
        closed = {i: b for i, b in closed.items() if i >= kk - 767}
        ob = {1: 1, 2: kk, 3: 0, 4: []}
    else:
        rolled = None
        ob = {1: 1, 2: st[6][2], 3: st[6][3], 4: [dict(x) for x in st[6][4]]}
    tmp = {"st": st, "hashes": hashes, "closed": closed}
    if check:
        r = check(tmp, ob, teff)
        if r:
            return r
    cur = [x for x in ob[4] if x[1] == asset and x[2] == scale]
    if cur:
        cur[0][3] = ibytes(ival(cur[0][3]) + amount)
    else:
        ob[4] = sorted(ob[4] + [{1: asset, 2: scale, 3: ibytes(amount)}], key=lambda x: (x[1].encode(), x[2]))
    ob[3] += 1
    cs = {1: 1, 2: [{1: i, 2: hashes[i]} for i in sorted(hashes)]}
    nst = {1: 1, 2: st[2] + 1, 3: teff, 4: th, 5: H(T_CLOSED, encode(cs)), 6: ob}
    return {"st": nst, "hashes": hashes, "closed": closed, "teff": teff, "rolled": rolled, "cs": cs,
            "hash": H(T_STATE, encode(nst))}


def rule_of(m, asset):
    return next((r for r in m[7] if r[1] == asset), None)


def engine(m, led, f, th):
    if th < m[5]:
        return {"deny": "ErrOutsideMandate"}
    st = led["st"]
    if 12 in m and st[2] >= 1 and th < min(MAXI, st[4] + m[12]):
        return {"deny": "ErrMinSpacing"}
    a = ival(f[3])
    r = rule_of(m, f[2])

    def check(tmp, ob, teff):
        for p in r.get(4, []):
            tot = sum(ival(x[3]) for b in win(tmp, teff, p[1], ob) for x in b[4] if x[1] == f[2] and x[2] == f[4])
            if tot + a > ival(p[2]):
                return {"deny": "ErrPeriodLimit"}
        for c in m.get(8, []):
            if sum(b[3] for b in win(tmp, teff, c[1], ob)) >= c[2]:
                return {"deny": "ErrCountLimit"}
        cur = [x for x in ob[4] if x[1] == f[2] and x[2] == f[4]]
        if cur and ival(cur[0][3]) + a > MAXA:
            return {"deny": "ErrHistoryFull", "cause": "sum"}
        if ob[3] >= MAXI:
            return {"deny": "ErrHistoryFull", "cause": "count"}
        if not cur and len(ob[4]) >= 64:
            return {"deny": "ErrHistoryFull", "cause": "pairs"}
        if st[2] >= MAXI:
            return {"deny": "ErrHistoryFull", "cause": "seq"}
        return None

    return transition(led, f[2], f[4], a, th, check)


# JSON -> maps.

def hx(s):
    return bytes.fromhex(s)


def facts_in(j):
    out = {1: j["kind"], 2: j["asset"], 3: hx(j["amount"]), 4: int(j["scale"])}
    if "recipient" in j:
        out[5] = j["recipient"]
    return out


def mandate_in(j):
    m = {1: int(j["format"]), 2: hx(j["principal"]), 3: j["gate_id"], 4: [hx(a) for a in j["agents"]],
         5: int(j["not_before"]), 6: int(j["not_after"]), 9: hx(j["mandate_id"]), 10: int(j["version"])}
    assets = []
    for r in j["assets"]:
        x = {1: r["asset"], 2: int(r["scale"])}
        if "per_action_max" in r:
            x[3] = hx(r["per_action_max"])
        if "periods" in r:
            x[4] = [{1: int(p["hours"]), 2: hx(p["max"])} for p in r["periods"]]
        if "recipients" in r:
            x[5] = list(r["recipients"])
        assets.append(x)
    m[7] = assets
    if "count_limits" in j:
        m[8] = [{1: int(c["hours"]), 2: int(c["max_count"])} for c in j["count_limits"]]
    for kk, n in ((11, "max_decision_age"), (12, "min_spacing")):
        if n in j:
            m[kk] = int(j[n])
    if "kinds" in j:
        m[13] = list(j["kinds"])
    for kk, n in ((14, "sig_type"), (16, "fast_mode_max_delay")):
        if n in j:
            m[kk] = int(j[n])
    if "principal_hrp" in j:
        m[15] = j["principal_hrp"]
    if "auditors" in j:
        m[17] = [{1: hx(a["kid"]), 2: hx(a["pubkey"]), 3: a["label"]} for a in j["auditors"]]
    if "state_salt" in j:
        m[18] = hx(j["state_salt"])
    return m


def bucket_in(j):
    return {1: int(j["format"]), 2: int(j["index"]), 3: int(j["count"]),
            4: [{1: x["asset"], 2: int(x["scale"]), 3: hx(x["sum"])} for x in j["sums"]]}


def state_in(j):
    st = {1: int(j["format"]), 2: int(j["seq"]), 5: hx(j["closed_root"])}
    for kk, n in ((3, "last_t"), (4, "last_th")):
        if n in j:
            st[kk] = int(j[n])
    if "open" in j:
        st[6] = bucket_in(j["open"])
    return st


def amount_text(b, scale):
    d = str(ival(b))
    if scale == 0:
        return d
    while len(d) <= scale:
        d = "0" + d
    return d[:len(d) - scale] + "." + d[len(d) - scale:]


def render(m):
    t = lambda x: datetime.fromtimestamp(x, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")  # noqa: E731
    st = m.get(14)
    who = ("ed25519 " + m[2].hex() if st is None else
           "cosmos %s (adr-036)" % cosmos_signer(m) if st == 2 else "ethereum 0x%s (eip-712)" % m[2].hex())
    lines = ["Edicta mandate v1", "mandate_id: " + m[9].hex(), "version: %d" % m[10], "gate: " + m[3],
             "principal: " + who,
             ("fast mode: allowed, anchor at most %d blocks after the reference height" % m[16]) if 16 in m
             else "fast mode: not allowed"]
    if 17 in m:
        lines.append("auditors: %d (private mandate)" % len(m[17]))
        for a in m[17]:
            h = a[1].hex()
            fp = " ".join(h[i:i + 4] for i in range(0, 32, 4))
            lines.append('  - Auditor "%s" (label not verified) - key fingerprint: %s' % (a[3], fp))
    else:
        lines.append("auditors: none (public mandate)")
    lines.append("valid: reference time from %s ; decision valid_until up to %s" % (t(m[5]), t(m[6])))
    lines.append("max decision age: %ds" % m[11] if 11 in m else "max decision age: default (MaxTTL of the payload's DA)")
    lines.append("min spacing: %ds" % m[12] if 12 in m else "min spacing: none")
    lines.append("agents (%d, shared counter):" % len(m[4]))
    for a in m[4]:
        lines.append("  - " + a.hex())
    lines.append("kinds: " + (", ".join(m[13]) if 13 in m else "any"))
    for r in m[7]:
        lines.append("asset %s (scale %d):" % (r[1], r[2]))
        lines.append("  per action: max " + amount_text(r[3], r[2]) if 3 in r else "  per action: no limit")
        for p in r.get(4, []):
            lines.append("  period: max %s per rolling %dh (may count up to %dh)" % (amount_text(p[2], r[2]), p[1], p[1] + 1))
        if 4 not in r:
            lines.append("  period: no limit")
        if 5 in r:
            lines.append("  recipients:")
            lines += ["    - " + x for x in r[5]]
        else:
            lines.append("  recipients: any")
    for c in m.get(8, []):
        lines.append("count: max %d actions per rolling %dh (may count up to %dh)" % (c[2], c[1], c[1] + 1))
    if 8 not in m:
        lines.append("count: no limit")
    lines += ["notes:",
              "  - Limits are measured on the reference time of each decision (block time at its payload reference "
              "height), not on execution time.",
              "  - Limits use hourly buckets; a bucket partly inside a window counts fully, so a limit may cover up to "
              "one extra hour (a \"per 1h\" limit may span up to 2h): the gate may deny early, never allow extra.",
              "  - Limits count authorizations, not executions.",
              "  - Counters continue across versions of this mandate_id; a new mandate_id starts from zero.",
              "  - In fast mode the gate may authorize before the payload is anchored on L1; the anchor must land "
              "within the stated number of blocks or the decision is invalid."]
    if 17 in m:
        lines.append("  - Labels are not verified; check each key fingerprint or address out of band.")
    return "\n".join(lines) + "\n"


# Checks per file.

def check_facts(f):
    for c in f["cases"]:
        b = hx(c["cbor_hex"])
        expect(encode(facts_in(c["input"])) == b, c["id"])
        expect(facts_dec(b) == facts_in(c["input"]), c["id"])
    for r in f["reject"]:
        try:
            facts_dec(hx(r["cbor_hex"]))
            raise Failure(f"{r['id']} accepted")
        except Bad as e:
            expect(e.sentinel == r["expect_error"] == "ErrFactsInvalid", r["id"])
    return f"{len(f['cases'])} facts, {len(f['reject'])} reject"


def check_mandate(f):
    for n, k in f["keys"].items():
        if n.endswith("_secp"):
            expect(k["seed_hex"] == H(f"edicta/policy/v1 test principal secp|{n[:-5]}".encode()).hex(), n)
            pub = pc.pub_compressed(hx(k["seed_hex"]))
            expect(pub.hex() == k["public_key_compressed_hex"], n)
            expect(pc.eth_address(pc.decompress(pub)).hex() == k["eth_address_hex"], n)
            expect(pc.cosmos_address(pub, "celestia") == k["cosmos_address"], n)
            continue
        if n.startswith("auditor:"):
            import hpke_base
            name = n.split(":", 1)[1]
            sk_, pk_ = hpke_base.derive_key_pair(H(("edicta/policy/v1 test auditor|" + name).encode()))
            expect(k["kid_hex"] == H(T_AUDITOR_KID, pk_)[:16].hex() and k["sk_hex"] == sk_.hex()
                   and k["pk_hex"] == pk_.hex(), n)
            continue
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        pub = Ed25519PrivateKey.from_private_bytes(hx(k["seed_hex"])).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        expect(pub.hex() == k["public_key_hex"], n)
        if n in ("p1", "p2"):
            expect(k["seed_hex"] == H(f"edicta/policy/v1 test principal|{n}".encode()).hex(), n)
    for c in f["cases"]:
        m = mandate_in(c["input"])
        canon = encode(m)
        expect(canon.hex() == c["mandate_cbor_hex"], c["id"])
        h = H(T_MANDATE, canon)
        expect(h.hex() == c["mandate_hash_hex"] and (T_MANDATE_SIG + h).hex() == c["signed_message_hex"], c["id"])
        expect(len(T_MANDATE_SIG + h) == 61, "61 bytes")
        expect(encode({1: m, 2: hx(c["signature_hex"])}).hex() == c["signed_mandate_hex"], c["id"])
        m2, h2 = mandate_verify(hx(c["signed_mandate_hex"]))
        expect(m2 == m and h2 == h, c["id"])
        expect(counter(m[2], m[9], m.get(14)).hex() == c["counter_key_hex"], c["id"])
        if m.get(14) == 2:
            d = render(m) + "\nmandate hash: " + h.hex()
            expect(c["adr036_data"] == d and c["adr036_signer"] == cosmos_signer(m)
                   and c["signdoc"].encode() == adr036_doc(m, h), f"{c['id']}: ADR-036 document")
        if m.get(14) == 3:
            expect(c["eip712_digest_hex"] == eip712_digest(m, h).hex(), f"{c['id']}: EIP-712 digest")
    n_adopt = check_adoption(f["adoption"])
    ck = {c["id"]: c["counter_key_hex"] for c in f["cases"]}
    expect(ck["m_full"] == ck["m_full_v2"], "versions share a counter")
    need_ids = {"m_adr036", "m_eip712", "m_fast_mode", "m_private", "sig_type_1_present", "sig_type_4",
                "hrp_without_adr036", "adr036_without_hrp", "principal_32_for_adr036", "principal_not_on_curve",
                "principal_21_for_eip712", "signature_64_for_eip712", "fast_mode_max_delay_0",
                "fast_mode_max_delay_1001", "auditors_unsorted", "auditors_duplicate_kid", "auditor_low_order",
                "auditors_17", "sig_flipped", "sig_bad_adr036", "sig_bad_eip712", "auditor_kid_mismatch",
                "kid_15_bytes", "kid_17_bytes", "auditor_pubkey_31", "auditor_label_empty", "auditor_label_65",
                "auditor_label_quote", "auditor_label_backslash", "auditor_label_leading_space",
                "auditor_label_non_ascii", "auditors_duplicate_label", "auditors_empty_array", "sig_type_0",
                "principal_hrp_17", "hrp_with_eip712", "state_salt_missing_with_auditors",
                "state_salt_without_auditors", "state_salt_31"}
    have = {c["id"] for c in f["cases"]} | {r["id"] for r in f["reject"]}
    expect(need_ids <= have, f"mandate.json: missing {sorted(need_ids - have)}")
    for r in f["reject"]:
        try:
            mandate_verify(hx(r["signed_mandate_hex"]))
            raise Failure(f"{r['id']} accepted")
        except Bad as e:
            expect(e.sentinel == r["expect_error"], f"{r['id']}: {e.sentinel}")
    return f"{len(f['cases'])} mandates, {len(f['reject'])} reject, {n_adopt} adoption steps"


def check_adoption(cases):
    """Section 6.3 table, with the scale map held in the counter cell."""
    steps = 0
    causes = set()
    for c in cases:
        cell = None
        if "start" in c:
            s0 = c["start"]
            cell = (int(s0["version"]), hx(s0["mandate_hash_hex"]), {a: int(v) for a, v in s0["scales"].items()}, None)
        for st in c["steps"]:
            m, h = mandate_verify(hx(st["signed_mandate_hex"]))
            expect(h.hex() == st["mandate_hash_hex"], c["id"])
            if cell is None:
                got, nxt = "genesis", (m[10], h, {r[1]: r[2] for r in m[7]}, m.get(18))
            elif cell[0] > m[10]:
                got, nxt = "refuse:version", cell
            elif cell[0] == m[10]:
                got, nxt = ("use", cell) if cell[1] == h else ("refuse:same_version_other_hash", cell)
            elif cell[3] != m.get(18):
                got, nxt = "refuse:state_salt_changed", cell
            else:
                bad = [r[1] for r in m[7] if r[1] in cell[2] and cell[2][r[1]] != r[2]]
                union = {**cell[2], **{r[1]: r[2] for r in m[7]}}
                if bad:
                    got, nxt = "refuse:scale", cell
                elif len(union) > 1024:
                    got, nxt = "refuse:scales_full", cell
                else:
                    got, nxt = "switch", (m[10], h, union, m.get(18))
            want = st["expect"] + (":" + st["cause"] if "cause" in st else "")
            expect(got == want, f"{c['id']}: {got} != {want}")
            if st["expect"] == "refuse":
                expect(st["error"] == "gate.ErrInvalidConfig", c["id"])
                causes.add(st["cause"])
            cell = nxt
            expect({a: int(v) for a, v in st["scales_after"].items()} == cell[2], f"{c['id']}: scales")
            expect(st["version_after"] == str(cell[0]), c["id"])
            expect(st.get("state_salt_after_hex") == (cell[3].hex() if cell[3] else None), f"{c['id']}: salt")
            steps += 1
    expect({"version", "same_version_other_hash", "scale", "scales_full", "state_salt_changed"} <= causes,
           "adoption causes")
    expect(any(len(st["scales_after"]) == 1024 for c in cases for st in c["steps"]), "bound reached")
    return steps


def check_render(f, mand):
    by = {c["id"]: c for c in mand["cases"]}
    for c in f["cases"]:
        m = mandate_in(by[c["mandate_ref"]]["input"] if "mandate_ref" in c else c["input"])
        expect(render(m) == c["text"], c["id"])
        expect(c["text"].isascii() and not any(ln != ln.rstrip() for ln in c["text"].split("\n")), c["id"])
        if not any(5 in r for r in m[7]):
            expect("recipients: any" in c["text"], c["id"])
        if m.get(14) == 2:
            h = H(T_MANDATE, encode(m))
            d = c["text"] + "\nmandate hash: " + h.hex()
            expect(c["adr036_data"] == d and d.split("\n")[-2] == "" and not d.endswith("\n"), f"{c['id']}: D")
            if "signdoc" in c:
                expect(c["signdoc"].encode() == adr036_doc(m, h), f"{c['id']}: signdoc")
        else:
            expect("adr036_data" not in c, c["id"])
        expect(("kinds: any" in c["text"]) == (13 not in m), c["id"])
        expect("(may count up to" in c["text"] or all(4 not in r for r in m[7]) and 8 not in m, c["id"])
    text = "".join(c["text"] for c in f["cases"])
    for line in ("principal: ed25519 ", "principal: cosmos ", "principal: ethereum 0x", "fast mode: not allowed",
                 "fast mode: allowed, anchor at most ", "auditors: none (public mandate)", "(private mandate)",
                 "(label not verified) - key fingerprint: ", "Labels are not verified"):
        expect(line in text, f"render.json: no case shows {line!r}")
    expect(any("<" in c["text"] and "&" in c["text"] and ">" in c["text"] for c in f["cases"]), "render escape case")
    return f"{len(f['cases'])} texts"


def check_state(f):
    g = f["genesis"]
    expect(encode(GEN).hex() == g["state_cbor_hex"] and H(T_STATE, encode(GEN)).hex() == g["state_hash_hex"], "genesis")
    expect(encode(EMPTY).hex() == g["empty_closed_set_cbor_hex"] and EMPTY_ROOT.hex() == g["empty_closed_root_hex"], "empty")
    for c in f["buckets"]:
        b = bucket_in(c["input"])
        v_bucket(b)
        expect(encode(b).hex() == c["cbor_hex"] and bucket_hash(b).hex() == c["bucket_hash_hex"], c["id"])
    for c in f["closed_sets"]:
        if "input" in c:
            cs = {1: 1, 2: [{1: int(r["index"]), 2: hx(r["hash"])} for r in c["input"]["buckets"]]}
            expect(encode(cs).hex() == c["cbor_hex"], c["id"])
        else:
            cs = {1: 1, 2: [{1: (1 << 33) + i, 2: H(f"edicta/policy/v1 test ref|{i}".encode())} for i in range(767)]}
            expect(len(encode(cs)) == int(c["cbor_size"]) == 35289, c["id"])
            expect(hashlib.sha256(encode(cs)).hexdigest() == c["cbor_sha256_hex"], c["id"])
        v_closed(cs)
        expect(H(T_CLOSED, encode(cs)).hex() == c["closed_root_hex"], c["id"])
    hashes = {}
    for c in f["states"]:
        st = state_in(c["input"])
        v_state(st)
        expect(encode(st).hex() == c["cbor_hex"] and H(T_STATE, encode(st)).hex() == c["state_hash_hex"], c["id"])
        hashes[c["id"]] = c["state_hash_hex"]
    cov = f["coverage"]
    expect(hashes[cov["a"]] != hashes[cov["b"]], "coverage")
    for r in f["reject"]:
        fn = {"bucket": (16384, v_bucket), "closed_set": (36864, v_closed), "state": (16384, v_state)}[r["structure"]]
        try:
            dec_struct(hx(r["cbor_hex"]), *fn)
            raise Failure(f"{r['id']} accepted")
        except Bad as e:
            expect(e.sentinel == r["expect_error"] == "ErrStateInvalid", r["id"])
    return f"{len(f['buckets'])} buckets, {len(f['closed_sets'])} closed sets, {len(f['states'])} states, " \
           f"{len(f['reject'])} reject"


def check_engine(f):
    steps = 0
    for sc in f["scenarios"]:
        m = mandate_in(sc["mandate"])
        v_mandate(m)
        if "start" in sc:
            st = dec_struct(hx(sc["start"]["state_cbor_hex"]), 16384, v_state)
            cs = dec_struct(hx(sc["start"]["closed_set_cbor_hex"]), 36864, v_closed)
            bk = [dec_struct(hx(b), 16384, v_bucket) for b in sc["start"]["buckets_cbor_hex"]]
            led = ledger(st, cs, bk)
        else:
            led = ledger(GEN, EMPTY, [])
        for s in sc["steps"]:
            e = s["expect"]
            if "repeat" in s:
                f0 = facts_in(s["facts"])
                for j in range(int(s["repeat"])):
                    r = engine(m, led, f0, int(s["t_h_start"]) + j * int(s["t_h_step"]))
                    expect("deny" not in r, f"{sc['id']} repeat {j}")
                    led = r
                    steps += 1
                expect(H(T_STATE, encode(led["st"])).hex() == e["state_hash_hex"], sc["id"])
                expect(str(len(led["hashes"])) == e["closed"], sc["id"])
                if led["hashes"]:
                    expect(str(min(led["hashes"])) == e["oldest_closed_index"], sc["id"])
                    expect(min(led["hashes"]) == led["st"][6][2] - 767, sc["id"])
                continue
            steps += 1
            r = engine(m, led, facts_in(s["facts"]), int(s["t_h"]))
            if "deny" in r:
                expect(e.get("deny") == r["deny"] and e.get("cause") == r.get("cause"), f"{sc['id']}: {r} vs {e}")
                continue
            expect(e.get("allow") is True, f"{sc['id']}: allowed, expected {e}")
            expect(str(r["teff"]) == e["eval_time"] and r["hash"].hex() == e["new_state_hash_hex"], sc["id"])
            expect(encode(r["st"]).hex() == e["new_state_cbor_hex"] and str(len(r["hashes"])) == e["closed"], sc["id"])
            expect((r["rolled"] is not None) == e["rolled_over"], sc["id"])
            if r["rolled"] is not None:
                expect(bucket_hash(r["rolled"]).hex() == e["closed_bucket_hash_hex"], sc["id"])
                expect(encode(r["cs"]).hex() == e["closed_set_cbor_hex"], sc["id"])
            led = r
        expect(H(T_STATE, encode(led["st"])).hex() == sc["final"]["state_hash_hex"], sc["id"])
    seen = {s["expect"].get("deny") for sc in f["scenarios"] for s in sc["steps"]}
    causes = {s["expect"].get("cause") for sc in f["scenarios"] for s in sc["steps"]}
    expect({"ErrOutsideMandate", "ErrMinSpacing", "ErrPeriodLimit", "ErrCountLimit", "ErrHistoryFull"} <= seen, "coverage")
    expect({"sum", "count", "pairs", "seq"} <= causes, "history full causes")
    return f"{len(f['scenarios'])} scenarios, {steps} steps"


# Verifier outcome rules (section 13), independent of policy_v1.verify_policy.

def classify(c, records, gate_pub):
    d = c["decision"]
    cfg = c["config"]
    arch = {p: hx(records[p]) for p in c["archive"]}
    arch.update({p: hx(b) for p, b in c.get("corrupt", {}).items()})
    ch, action, atype = hx(d["commitment_hash_hex"]), hx(d["action_hex"]), d["action_type"]
    th = int(c["t_h"]) if "t_h" in c else None
    expect(d.get("version") == "1", "every decision is a v1 decision")
    v1 = True
    mode = int(d.get("mode", "1"))
    trusted = set()
    for x in cfg["principal_keys"]:
        if x.startswith("cosmos:"):
            trusted.add((2, x[7:]))
        elif x.startswith("eth:0x"):
            trusted.add((3, hx(x[6:])))
        else:
            trusted.add((None, hx(x)))
    schemes = {"ed25519": None, "cosmos": 2, "eth": 3}
    have_schemes = {schemes[x] for x in cfg.get("principal_schemes", schemes)}
    sks = [hx(x) for x in cfg.get("auditor_keys", [])]
    xreg = cfg["extractors"]
    cap = int(cfg["max_walk_steps"]) if cfg["max_walk_steps"] is not None else 10000
    expect(H(T_ACTION_V1, bytes([len(atype)]), atype.encode(), hx(d["action_salt_hex"]), action).hex()
           == d["action_hash_hex"], "salted action hash")
    GEN_HASH = H(T_STATE, encode(GEN))

    def get(kind, key):
        p = f"{PATH[kind]}/{key.hex()}"
        if p not in arch:
            return "absent", None
        try:
            r = read_record(arch[p])
        except Bad:
            return "corrupt", None
        return ("ok", r) if r["kind"] == kind and r["key"] == key else ("corrupt", None)

    def get_private(pk, key, want=None):
        p = f"private/{pk}/{key.hex()}"
        if p not in arch:
            return "absent", None, None
        try:
            r = read_record(arch[p])
        except Bad:
            return "corrupt", None, None
        if r["kind"] != 15 or r["pk"] != pk or r["key"] != key:
            return "corrupt", None, None
        return open_private(r["envelope"], sks, pk, key if want is None else want)

    def allow_of(key):
        s, r = get(8, key)
        if s != "ok":
            return s, None
        try:
            return "ok", verdict_verify(r["body"], gate_pub)[0]
        except Bad:
            return "corrupt", None

    mcache = {}

    def mandate_of(h):
        """(status, mandate, kid); status ok, absent, corrupt, private, scheme."""
        if h not in mcache:
            s, r = get(7, h)
            body, kid = (r["body"] if s == "ok" else None), None
            if s == "absent":
                s, body, kid = get_private(1, h)
            if s != "ok":
                mcache[h] = (s, None, None)
            else:
                try:
                    sm = lenient(body, "ErrMandateInvalid", 16384)
                    keys(sm, "ErrMandateInvalid", (1, 2))
                    need(isinstance(sm[1], dict), "ErrMandateInvalid")
                    v_mandate(sm[1])
                    if sm[1].get(14) not in have_schemes:
                        mcache[h] = ("scheme", None, None)
                    else:
                        mcache[h] = ("ok", mandate_verify(body)[0], kid)
                except Bad:
                    mcache[h] = ("corrupt", None, None)
        return mcache[h]

    def principal_ok(m):
        st = m.get(14)
        if st == 2:
            return (2, cosmos_signer(m)) in trusted
        return (st, m[2]) in trusted

    pcache = {}

    def logical(v):
        """(status, merged verdict): the verdict itself in public form; in private form merged with its opened
        PrivatePart. 'bad': the opened state does not hash to key 20 under the mandate's salt; 'pp': the PrivatePart
        hashes to key 19 but its presence does not fit the public outcome (a gate-signed contradiction)."""
        if 19 not in v:
            return "ok", v
        if v[19] not in pcache:
            s, pt, _ = get_private(4, v[19])
            if s != "ok":
                pcache[v[19]] = (s, None)
            else:
                pp = lenient(pt, "ErrVerdictInvalid", 16384)
                mg = merge(v, pp)
                sm, mm, _ = mandate_of(v[3])
                salt = mm.get(18) if sm == "ok" else None
                if v[7] == 1 and 13 in pp and blind_state(pp[13], salt) != v[20]:
                    pcache[v[19]] = ("bad", mg)
                else:
                    try:
                        v_verdict(mg)
                        pcache[v[19]] = ("ok", mg)
                    except Bad:
                        pcache[v[19]] = ("pp", mg)
        return pcache[v[19]]

    def state(v):
        """(status, State) of the state a verdict read."""
        s, mg = logical(v)
        return (s, mg[13]) if mg is not None else (s, None)

    def psh(v):
        return v[20] if 20 in v else H(T_STATE, encode(v[13]))

    def vh(v):
        return H(T_VERDICT, encode(v))

    def struct(kind, pk, h, salt):
        if salt is None:
            s, r = get(kind, h)
            if s == "ok":
                return "ok", r["closed" if kind == 11 else "bucket"]
            if s != "absent":
                return s, None
            key = h
        else:
            key = H(T_BLIND_KEY, salt, h)
        s, pt, _ = get_private(pk, key, h)
        if s == "ok":
            return "ok", lenient(pt, "ErrStateInvalid", 36864)
        return s, None

    def closed_for(v, st, m, contents):
        root = st[5]
        salt = m.get(18)
        if root == EMPTY_ROOT:
            cs = EMPTY
        else:
            s, cs = struct(11, 3, root, salt)
            if s != "ok":
                return s, None
        bks = []
        if contents:
            r0 = rule_of(m, v[10][2]) or {}
            w = max([p[1] for p in r0.get(4, [])] + [x[1] for x in m.get(8, [])] + [0])
            for ref in cs[2]:
                if ref[1] >= v[12] // 3600 - w:
                    s, b = struct(10, 2, ref[2], salt)
                    if s != "ok":
                        return s, None
                    bks.append(b)
        if st[2] >= 1:
            oi = st[6][2]
            if not all(max(0, oi - 767) <= ref[1] < oi for ref in cs[2]):
                return "inconsistent", None
        elif cs[2]:
            return "inconsistent", None
        for b in bks:
            if {r[1]: r[2] for r in cs[2]}.get(b[2]) != bucket_hash(b):
                return "inconsistent", None
        return "ok", ledger(st, cs, bks)

    hist = {"absent": "state_history_unavailable", "corrupt": "source_corrupt", "private": "policy_private",
            "scheme": "principal_scheme_unsupported"}
    viol = []
    pp_viol = []
    fail = fast_u = walk_u = None
    blocked = walked_ok = truncated = False
    walk_report = None
    report = {}

    s, V = allow_of(ch)
    if s != "ok":
        reason = "policy_verdict_unavailable" if s == "absent" else "source_corrupt"
        return {"policy": {"status": "unchecked", "reason": reason},
                "gate_integrity": {"status": "not_checked", "reason": None, "evidence": []},
                "verdict": "unchecked", "exit": "2"}
    if (V[5].hex(), V[6].hex(), V[2]) != (d["action_hash_hex"], d["agent_pubkey_hex"], d["gate_id"]):
        viol = [vh(V)]
    sV, mV0, _ = mandate_of(V[3])
    keyless = sV == "private"
    if v1:
        priv = keyless or (sV == "ok" and 17 in mV0) or (sV != "ok" and 19 in V)
        report["mode"] = "private" if priv else "public"

    def facts(VL):
        if xreg.get(atype) != VL[9] or VL[9] != TEST_X:
            return "u", "policy_no_extractor"
        try:
            fx = facts_dec(action)
        except Bad:
            return "f", "facts_mismatch"
        return ("f", "facts_mismatch") if fx != VL[10] else None

    def fast():
        nonlocal blocked, fast_u
        if v1:
            if "mandate_ref_hex" in d and d["mandate_ref_hex"] != V[3].hex():
                return "f", "mandate_ref_mismatch"
            report["mandate_ref"] = "match" if "mandate_ref_hex" in d else "absent"
        s, m, kid = mandate_of(V[3])
        if s == "private":
            return "u", "policy_private"
        if s != "ok":
            return "u", "policy_mandate_unavailable" if s == "absent" else hist[s]
        if kid is not None and v1:
            report["auditor_kid"] = " ".join(kid.hex()[i:i + 4] for i in range(0, 32, 4))
        if not principal_ok(m):
            return "u", "policy_principal_untrusted"
        if m[3] != V[2]:
            return "f", "mandate_gate_id"
        if (19 in V) != (17 in m):
            viol.append(vh(V))
            return None
        s, VL = logical(V)
        if s == "bad":
            viol.append(vh(V))
            return None
        if s == "pp":
            pp_viol.append(vh(V))
            if 10 not in VL:
                if xreg.get(atype) != TEST_X:
                    return "u", "policy_no_extractor"
                try:
                    VL = dict(VL)
                    VL[10], VL[9] = facts_dec(action), TEST_X
                except Bad:
                    return "u", "blocked"
            if not all(k in VL for k in (9, 11, 12, 13)):
                return "u", "blocked"
            s = "ok"
        if s != "ok":
            return "u", hist[s]
        r = facts(VL)
        if r:
            return r
        fx = VL[10]
        if hx(d["agent_pubkey_hex"]) not in m[4]:
            return "f", "ErrAgentNotCovered"
        if mode == 2:
            if 16 not in m:
                return "f", "ErrFastModeNotAllowed"
            if int(d["anchor_deadline"]) - int(d["h0"]) > m[16]:
                return "f", "fast_mode_delay"
        if int(d["valid_until"]) > m[6]:
            return "f", "ErrOutsideMandate"
        if 13 in m and fx[1] not in m[13]:
            return "f", "ErrKindNotAllowed"
        r = rule_of(m, fx[2])
        if r is None or r[2] != fx[4]:
            return "f", "ErrAssetNotAllowed"
        if 5 in r and fx.get(5) not in r[5]:
            return "f", "ErrRecipientNotAllowed"
        if 3 in r and ival(fx[3]) > ival(r[3]):
            return "f", "ErrAmountAboveMax"
        if th is None:
            blocked = True
        elif VL[11] != th:
            return "f", "anchor_time_mismatch"
        elif th < m[5]:
            return "f", "ErrOutsideMandate"
        st = VL[13]
        s, led = closed_for(VL, st, m, True)
        if s == "inconsistent":
            viol.append(vh(V))
            return None
        if s != "ok":
            return "u", hist[s]
        if VL[12] != (VL[11] if st[2] == 0 else max(VL[11], st[3])):
            return "f", "eval_time_mismatch"
        r2 = engine(m, led, VL[10], VL[11])
        if "deny" in r2:
            return "f", r2["deny"]
        if blind_state(r2["st"], m.get(18)) != V[14] and not viol:
            viol.append(vh(V))
        return None

    out = fast()
    if out and out[0] == "f":
        fail = out[1]
    elif out:
        fast_u = out[1]

    def seq(v):
        s, st = state(v)
        return st[2] if s in ("ok", "bad") else None

    def at_genesis(v):
        if keyless or 19 in v:
            return psh(v) == GEN_HASH
        return seq(v) == 0

    held = [V]
    if cfg["policy_full"] and not viol:
        walked_ok = True
        n, hops = V, 0
        chain = [V]
        seen = {}
        ended = "finding"
        while True:
            if at_genesis(n):
                ended = "genesis"
                break
            if hops == cap:
                truncated, ended = True, "max_steps"
                break
            s, p = allow_of(n[15])
            if s == "ok" and p[4] != n[15]:
                s = "corrupt"
            if s != "ok":
                walk_u = hist[s]
                break
            if vh(p) != n[16] or p[14] != psh(n):
                viol = [vh(p), vh(n)]
                break
            if not keyless:
                (sp_, stp), (sn_, stn) = state(p), state(n)
                if "bad" in (sp_, sn_):
                    viol = [vh(n if sn_ == "bad" else p)]
                    break
                if "pp" in (sp_, sn_):
                    pp_viol = pp_viol or [vh(n if sn_ == "pp" else p)]
                    break
                if sp_ != "ok" or sn_ != "ok":
                    walk_u = hist[sp_ if sp_ != "ok" else sn_]
                    break
                if stp[2] + 1 != stn[2]:
                    viol = [vh(p), vh(n)]
                    break
                sp, mp, _ = mandate_of(p[3])
                sn, mn, _ = mandate_of(n[3])
                if sp != "ok" or sn != "ok":
                    walk_u = hist[sp if sp != "ok" else sn]
                    break
                if (mp.get(14), mp[2], mp[9], mp[3]) != (mn.get(14), mn[2], mn[9], mn[3]) or mp[10] > mn[10]:
                    viol = [vh(p), vh(n)]
                    break
                # Every mandate reached so far must agree on the scale of each asset it lists.
                seen.update({r[1]: (r[2], n) for r in mn[7]})
                other = [seen[r[1]][1] for r in mp[7] if r[1] in seen and seen[r[1]][0] != r[2]]
                if other:
                    viol = [vh(p), vh(other[0])]
                    break
                lp = logical(p)[1]
                s, led = closed_for(lp, stp, mp, False)
                if s == "inconsistent":
                    viol = [vh(p)]
                    break
                if s != "ok":
                    walk_u = hist[s]
                    break
                nst = transition(led, lp[10][2], lp[10][4], ival(lp[10][3]), lp[11])["st"]
                if blind_state(nst, mp.get(18)) != p[14]:
                    viol = [vh(p)]
                    break
            chain.append(p)
            n, hops = p, hops + 1
        # Only a walk that read every link down to a seq-0 verdict, which read genesis, can be ok.
        walk_report = {"max_steps": str(cap), "steps": str(hops)}
        if not keyless:
            walk_report |= {"from_seq": str(seq(n)), "to_seq": str(seq(V)), "total": str(seq(V) + 1)}
            expect(hops == seq(V) - seq(n), "walk steps against the seq range")
        walk_report["end"] = ended
        if keyless and ended == "genesis" and not viol:
            walk_u = "policy_private"
        held = list(chain)
        if not viol and not keyless:
            for w in chain:
                s, mw, _ = mandate_of(w[3])
                if s != "ok":
                    continue
                s, r = get(12, succ_key(w[2], counter(mw[2], mw[9], mw.get(14)), psh(w)))
                if s == "ok" and r["commitment"] != w[4]:
                    s2, x = allow_of(r["commitment"])
                    if s2 == "ok":
                        held.append(x)
    for e in cfg["evidence"]:
        try:
            x = verdict_verify(hx(e), gate_pub)[0]
        except Bad:
            continue
        if x[7] == 1:
            held.append(x)
    if not viol:
        by_seq, by_hash = {}, {}
        for x in held:
            s, mx, _ = mandate_of(x[3])
            if s not in ("ok", "private") or x[2] != V[2]:
                continue
            # Fork: one counter, one seq, two commitments; without the key, one mandate and one prev_state_hash.
            k2 = (x[3], psh(x))
            other = by_hash.get(k2)
            if s == "ok" and seq(x) is not None:
                k1 = (counter(mx[2], mx[9], mx.get(14)), seq(x))
                if other is None or other[4] == x[4]:
                    other = by_seq.get(k1)
                by_seq.setdefault(k1, x)
            by_hash.setdefault(k2, x)
            if other is not None and other[4] != x[4]:
                viol = [vh(other), vh(x)]
                break
    if fail:
        pol = {"status": "fail", "rule": fail}
    elif viol or blocked:
        pol = {"status": "unchecked", "reason": "blocked"}
    elif fast_u or walk_u:
        pol = {"status": "unchecked", "reason": fast_u or walk_u}
    else:
        pol = {"status": "pass"}
    pol |= report
    if viol:
        gi = {"status": "violated", "reason": "gate_equivocation", "evidence": [h.hex() for h in viol]}
    elif pp_viol:
        gi = {"status": "violated", "reason": "gate_signed_inconsistent_private_part",
              "evidence": [h.hex() for h in pp_viol]}
    elif walked_ok and (walk_u or truncated):
        gi = {"status": "unchecked", "reason": walk_u or "policy_walk_truncated", "evidence": []}
    elif walked_ok:
        expect(walk_report["end"] == "genesis", "ok without genesis")
        gi = {"status": "ok", "reason": None, "evidence": []}
    else:
        gi = {"status": "not_checked", "reason": None, "evidence": []}
    if walk_report is not None:
        gi["walk"] = walk_report
    if fail:
        verdict, code = "invalid", 1
    elif viol or pp_viol:
        verdict, code = "unchecked", 5
    elif pol["status"] == "unchecked":
        verdict, code = "unchecked", 2
    else:
        verdict, code = "valid", 0
    return {"policy": pol, "gate_integrity": gi, "verdict": verdict, "exit": str(code)}


def check_verify(f):
    gate_pub = hx(f["gate"]["gate_pubkey_hex"])
    for p, b in f["records"].items():
        expect(read_record(hx(b))["path"] == p, p)
    seen = set()
    for c in f["cases"]:
        got = classify(c, f["records"], gate_pub)
        expect(got == c["expect"], f"{c['id']}: {got} != {c['expect']}")
        seen.add((c["expect"]["policy"]["status"], c["expect"]["gate_integrity"]["status"], c["expect"]["exit"]))
        if c["expect"]["gate_integrity"]["status"] == "violated":
            expect(c["expect"]["gate_integrity"]["evidence"], c["id"])
    reasons = {c["expect"]["policy"].get("reason") for c in f["cases"]}
    rules = {c["expect"]["policy"].get("rule") for c in f["cases"]}
    expect({"policy_verdict_unavailable", "policy_mandate_unavailable", "policy_principal_untrusted",
            "policy_no_extractor", "state_history_unavailable", "source_corrupt", "blocked"} <= reasons, "reasons")
    expect({"ErrKindNotAllowed", "ErrOutsideMandate", "ErrPeriodLimit", "ErrCountLimit", "ErrMinSpacing",
            "facts_mismatch", "eval_time_mismatch", "anchor_time_mismatch", "mandate_gate_id"} <= rules, "rules")
    expect({c["exit"] for c in (x["expect"] for x in f["cases"])} == {"0", "1", "2", "5"}, "exit codes")
    ids = {c["id"] for c in f["cases"]}
    trunc = [c for c in f["cases"] if c["expect"]["gate_integrity"]["reason"] == "policy_walk_truncated"]
    expect(trunc and all(c["expect"]["verdict"] == "valid" and c["expect"]["exit"] == "0"
                         and c["config"]["max_walk_steps"] is not None for c in trunc), "explicit cap truncates")
    for need_id in ("pass_depth_1", "walk_truncated_cap_2", "walk_cap_reaches_genesis", "equivocation_fork_evidence", "equivocation_fork_successor", "equivocation_unlinked",
                    "understated_open_bucket_full", "pass_hour_rollover", "pass_chain_continuity",
                    "equivocation_version_decrease", "walk_history_missing", "unchecked_bucket_corrupt",
                    "fail_not_before", "fail_kind", "mandate_ref_match", "mandate_ref_mismatch", "mandate_ref_absent",
                    "fast_mode_not_allowed", "fast_mode_delay_exceeded", "fast_mode_within_bound",
                    "principal_scheme_unsupported", "principal_cosmos_pinned", "principal_eth_pinned",
                    "anchor_time_t_ref_pending", "fast_mode_no_policy_record", "mandate_ref_without_verdict"):
        expect(need_id in ids, need_id)
    expect({"mandate_ref_mismatch", "ErrFastModeNotAllowed", "fast_mode_delay"} <= rules, "draft.5 rules")
    expect("principal_scheme_unsupported" in reasons, "draft.5 reasons")
    for c in f["cases"]:
        v1 = c["decision"].get("version") == "1"
        expect(v1, f"{c['id']}: every decision is a v1 decision")
        no_record = c["expect"]["policy"].get("reason") == "policy_verdict_unavailable"
        # The mode follows the decision's verdict, so a verdict that cannot be read reports none.
        unreadable = no_record or c["expect"]["policy"].get("reason") == "source_corrupt"
        expect(("mode" in c["expect"]["policy"]) or unreadable, c["id"])
        if v1 and c["decision"]["mode"] == "2" and no_record:
            expect(not c["config"]["require_policy"] and c["expect"]["verdict"] == "unchecked", c["id"])
        # mandate_ref, like mode 2, makes the check required whatever require_policy says.
        if "mandate_ref_hex" in c["decision"] and no_record:
            expect(c["expect"]["verdict"] == "unchecked" and c["expect"]["exit"] == "2", c["id"])
    mr = next(c for c in f["cases"] if c["id"] == "mandate_ref_without_verdict")
    expect(mr["decision"]["mode"] == "1" and "mandate_ref_hex" in mr["decision"] and not mr["config"]["require_policy"],
           "mandate_ref_without_verdict: strict mode, mandate_ref, require_policy off")
    return f"{len(f['records'])} records, {len(f['cases'])} cases"


def check_private(f, verify):
    gate_pub = hx(verify["gate"]["gate_pubkey_hex"])
    expect(f["tags"] == {"private-part": T_PRIV_PART[1:].decode(), "private": T_PRIV_AEAD[1:].decode(),
                         "private-dek": T_PRIV_DEK[1:].decode(), "state-blind": T_STATE_BLIND[1:].decode(),
                         "blind-key": T_BLIND_KEY[1:].decode(), "auditor-kid": T_AUDITOR_KID[1:].decode()}
           and f["cap"] == "65536" and f["action_cap"] == "69632", "tags and caps")
    sks, kids = {}, {}
    for n, k in f["auditor_keys"].items():
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        pk = X25519PrivateKey.from_private_bytes(hx(k["sk_hex"])).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        expect(pk.hex() == k["pk_hex"] and hx(k["kid_preimage_hex"]) == T_AUDITOR_KID + pk
               and H(T_AUDITOR_KID, pk)[:16].hex() == k["kid_hex"], n)
        expect(k["fingerprint"] == " ".join(k["kid_hex"][i:i + 4] for i in range(0, 32, 4)), n)
        expect(H(b"edicta/policy/v1 test auditor|" + n.encode()).hex() == k["ikm_hex"], n)
        sks[n] = hx(k["sk_hex"])
        kids[n] = hx(k["kid_hex"])
    kinds = set()
    for e in f["envelopes"]:
        env, pk, h = hx(e["envelope_hex"]), int(e["plaintext_kind"]), hx(e["hash_hex"])
        r = read_record(hx(e["record_cbor_hex"]))
        expect(r["kind"] == 15 and r["pk"] == pk and r["key"] == h and r["envelope"] == env and r["path"] == e["path"],
               e["id"])
        if pk != 5:
            expect(f["records"][e["path"]] == e["record_cbor_hex"], e["id"])
        parts = envelope_parts(env, 69632 if pk == 5 else 65536)
        expect(parts[3].hex() == e["aead_nonce_hex"] and [x[1].hex() for x in parts[2]] ==
               [x["kid_hex"] for x in e["recipients"]], e["id"])
        for i, x in enumerate(e["recipients"]):
            expect(parts[2][i][2].hex() == x["enc_hex"] and parts[2][i][3].hex() == x["wrapped_dek_hex"], e["id"])
        label = f"{pk}/{e['hash_hex']}"
        expect(H(f"edicta/policy/v1 test private salt|{label}".encode()).hex() == e["salt_hex"] and
               H(f"edicta/policy/v1 test private dek|{label}".encode()).hex() == e["dek_hex"], e["id"])
        want = h
        if pk in (2, 3):
            want = hx(e["plaintext_hash_hex"])
            expect(H(T_BLIND_KEY, hx(e["state_salt_hex"]), want) == h, f"{e['id']}: blinded key")
        for n in ("auditor-1", "auditor-2"):
            st, pt, kid = open_private(env, [sks[n]], pk, want, e.get("action_type"))
            expect(st == "ok" and pt.hex() == e["plaintext_cbor_hex"] and kid == kids[n], f"{e['id']} {n}")
        expect(open_private(env, [sks["auditor-3"]], pk, want, e.get("action_type"))[0] == "private", e["id"])
        if pk == 5:
            expect(hx(e["plaintext_cbor_hex"]) == hx(e["action_salt_hex"]) + hx(e["action_hex"]), e["id"])
        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
        ct = ChaCha20Poly1305(hx(e["dek_hex"])).encrypt(parts[3], hx(e["salt_hex"]) + hx(e["plaintext_cbor_hex"]),
                                                           T_PRIV_AEAD)
        expect(ct == parts[4], f"{e['id']}: ciphertext from salt, DEK and nonce")
        kinds.add(pk)
    expect(kinds == {1, 2, 3, 4, 5}, "one envelope per plaintext_kind")
    pv = f["private_verdict"]
    v, h = verdict_verify(hx(pv["signed_verdict_hex"]), gate_pub)
    ppb = hx(pv["private_part_cbor_hex"])
    pp = lenient(ppb, "x", 16384)
    v_private_part(pp)
    salt = hx(f["blinding"][0]["state_salt_hex"])
    expect(h.hex() == pv["verdict_hash_hex"] and 13 not in v and 17 not in v and v[19] == H(T_PRIV_PART, ppb) and
           v[20] == blind_state(pp[13], salt) and v[20].hex() == pv["prev_state_hash_hex"], "private verdict")
    expect(set(v) == {1, 2, 3, 4, 5, 6, 7, 14, 15, 16, 19, 20}, "private allow public keys")
    v_verdict(merge(v, pp))
    pd = f["private_deny"]
    dv, _ = verdict_verify(hx(pd["signed_verdict_hex"]), gate_pub)
    expect(set(dv) == {1, 2, 3, 4, 5, 6, 7, 19} and dv[7] == 2, "private deny public shape")
    r9 = read_record(hx(pd["kind9_record_cbor_hex"]))
    expect(r9["path"] == pd["kind9_path"] and pd["kind9_path"].endswith("/private"), "kind 9 private path")
    mk = lenient(hx(pd["marker_record_cbor_hex"]), "x", 512, 1)
    expect(mk[2] == 5 and mk[4] == "ErrDenied" and pd["marker_path"] == f"rejection/{mk[3].hex()}/ErrDenied", "marker")
    dpp = lenient(hx(pd["with_key"]["private_part_cbor_hex"]), "x", 16384)
    v_private_part(dpp)
    expect(dv[19] == H(T_PRIV_PART, hx(pd["with_key"]["private_part_cbor_hex"])) and dpp[8] == pd["with_key"]["reason"],
           "deny reason with key")
    v_verdict(merge(dv, dpp))
    for r in pv["reject"]:
        try:
            verdict_verify(hx(r["signed_verdict_hex"]), None)
            raise Failure(f"{r['id']} accepted")
        except Bad as e:
            expect(e.sentinel == r["expect_error"] == "ErrVerdictInvalid", r["id"])
    for r in f["reject"]:
        st, _, _ = open_private(hx(r["envelope_hex"]), [sks[n] for n in r["auditor_keys"]], int(r["plaintext_kind"]),
                                hx(r["hash_hex"]), "application/vnd.edicta.ibkr.order.v0+cbor")
        expect({"corrupt": "source_corrupt", "private": "policy_private"}[st] == r["expect"], r["id"])
        expect(len(hx(r["envelope_hex"])) == int(r["envelope_size"]), r["id"])
    expect({"envelope_cap_exceeded", "action_envelope_69633", "tampered_ciphertext", "wrong_tag_aad"}
           <= {r["id"] for r in f["reject"]}, "private rejects")
    b = {x["id"]: x for x in f["blinding"]}
    x = b["state_hash_blind_vs_public"]
    st = hx(x["state_cbor_hex"])
    expect(H(T_STATE, st).hex() == x["state_hash_hex"] and H(T_STATE_BLIND, salt, st).hex() == x["state_hash_p_hex"]
           and x["state_hash_p_preimage_hex"] == (T_STATE_BLIND + salt + st).hex(), "blind state hash")
    x = b["state_hash_blind_genesis"]
    expect(x["state_hash_p_hex"] == x["genesis_hash_hex"] == GEN_HASH_CONST.hex(), "genesis blinding")
    for n, field in (("blind_key_bucket", "bucket_hash_hex"), ("blind_key_closed", "closed_root_hex")):
        expect(H(T_BLIND_KEY, salt, hx(b[n][field])).hex() == b[n]["key_hex"], n)
    x = b["private_part_salt"]
    expect(H(T_PRIV_PART, hx(x["private_part_a_cbor_hex"])).hex() == x["private_hash_a_hex"] and
           H(T_PRIV_PART, hx(x["private_part_b_cbor_hex"])).hex() == x["private_hash_b_hex"] and
           x["private_hash_a_hex"] != x["private_hash_b_hex"], "private part salt")
    for p, bb in f["records"].items():
        expect(read_record(hx(bb))["path"] == p, p)
    for c in f["cases"]:
        got = classify(c, f["records"], gate_pub)
        expect(got == c["expect"], f"{c['id']}: {got} != {c['expect']}")
    ids = {c["id"] for c in f["cases"]}
    for need_id in ("private_with_key_pass", "private_without_key", "private_without_key_facts_mismatch",
                    "private_without_key_anchor_time_mismatch", "private_with_key_facts_mismatch",
                    "private_with_key_anchor_time_mismatch", "private_wrong_key", "private_part_hash_differs",
                    "private_state_not_key_20", "private_fork_without_key", "private_walk_without_key",
                    "verdict_form_mismatch", "private_part_row_mismatch", "private_part_allow_missing_facts",
                    "private_part_missing_facts_denies",
                    "state_salt_wrong", "chain_continuity_without_salt"):
        expect(need_id in ids, need_id)
    return (f"{len(f['envelopes'])} envelopes, {len(f['reject'])} reject, {len(pv['reject'])} verdict reject, "
            f"{len(f['blinding'])} blinding, {len(f['cases'])} private cases")


def check_archive(f, verify, private):
    for c in f["cases"]:
        r = read_record(hx(c["record_cbor_hex"]))
        expect(str(r["kind"]) == c["kind"] and r["key"].hex() == c["key_hex"] and r["path"] == c["path"], c["id"])
        if r["kind"] == 15 and r["pk"] == 5:
            expect(c["record_cbor_hex"] == next(e["record_cbor_hex"] for e in private["envelopes"]
                                                if e["plaintext_kind"] == "5"), c["id"])
            continue
        src = private if (r["kind"] == 15 or c["path"].endswith("/private")) else verify
        expect(src["records"][c["path"]] == c["record_cbor_hex"], c["id"])
    expect({c["plaintext_kind"] for c in f["cases"] if c["kind"] == "15"} == {"1", "2", "3", "4", "5"}, "kind 15 cases")
    expect(any(c["path"].endswith("/private") for c in f["cases"] if c["kind"] == "9"), "kind 9 private case")
    for x in f["reads"]:
        ok = read_record(hx(x["record_cbor_hex"]))["path"] == x["path"]
        expect(ok == (x["expect_error"] is None), x["id"])
    for r in f["reject"]:
        try:
            read_record(hx(r["record_cbor_hex"]))
            raise Failure(f"{r['id']} accepted")
        except Bad as e:
            expect(e.sentinel == r["expect_error"] == "archive.ErrCorrupt", r["id"])
    expect(f["reserved_kinds"] == ["6"] and f["marker_names"] == DENY + ["ErrDenied"]
           and f["marker_names_private_only"] == ["ErrDenied"], "kinds and markers")
    return f"{len(f['cases'])} records, {len(f['reject'])} reject"


def check_api(f, verify):
    gate_pub = hx(verify["gate"]["gate_pubkey_hex"])
    codes = [(m["status"], m["code"]) for m in f["mapping"]]
    expect([c for _, c in codes if c.startswith("policy.")] == ["policy." + n for n in DENY if n not in
                                                               ("ErrDecisionAge", "ErrFactsInvalid",
                                                                "ErrFastModeNotAllowed")] +
           ["policy.ErrFastModeNotAllowed", "policy.ErrDecisionAge", "policy.ErrFactsInvalid"], "mapping order")
    for x in f["examples"]:
        body = lenient(hx(x["response_cbor_hex"]), "api", 1 << 16, 2)
        if x["status"] == "200":
            expect(set(body) == {1, 5}, x["id"])
            a = lenient(body[1], "api", 256, 2)
            v, _ = verdict_verify(body[5], gate_pub)
            expect(v[7] == 1 and a[1][2] == v[4] and a[1][3] == v[5] and a[1][4] == v[2], x["id"])
            expect(a[1][1] == 1 and a[1].get(7) == 1 and "endpoint" not in x, x["id"])
            expect(sig_ok(gate_pub, bytes.fromhex("1b") + b"edicta/v1/authorization-sig",
                          H(bytes.fromhex("17") + b"edicta/v1/authorization", encode(a[1])), a[2]), x["id"])
            continue
        expect(set(body) <= {1, 2, 3, 4, 5}, x["id"])
        st = next(m for m in f["mapping"] if m["code"] == body[1]) if body[1] != "ErrNonceUsed" else None
        if st:
            expect(st["status"] == x["status"] and int(st["retryable"]) == body[3], x["id"])
        if 5 in body:
            v, _ = verdict_verify(body[5], gate_pub)
            if body[1].startswith("policy.") and 19 in v:
                # Private form: the sentinel is in the body, the verdict carries no reason.
                expect(v[7] == 2 and set(v) == {1, 2, 3, 4, 5, 6, 7, 19}, x["id"])
            elif body[1].startswith("policy."):
                expect(v[7] == 2 and "policy." + v[8] == body[1], x["id"])
            else:
                expect(4 in body and v[7] == 1, x["id"])
    return f"{len(f['mapping'])} codes, {len(f['examples'])} examples"


def tia(action):
    try:
        a = bs.action_decode(action)
        msg = bs.msg_decode(a["msg"], "celestia")
    except Exception:  # noqa: BLE001
        raise Bad("ErrFactsInvalid")
    if msg["denom"] != "utia":
        raise Bad("ErrFactsInvalid")
    f = {1: "transfer", 2: "cosmos:" + a["chain_id"] + "/utia", 3: ibytes(msg["amount"]), 4: 6,
         5: "cosmos:" + a["chain_id"] + ":" + msg["to_address"]}
    v_facts(f)
    return f


def check_tia(f):
    for c in f["cases"]:
        got = tia(hx(c["action_hex"]))
        expect(got == facts_in(c["facts"]) and encode(got).hex() == c["facts_cbor_hex"], c["id"])
    for r in f["reject"]:
        try:
            tia(hx(r["action_hex"]))
            raise Failure(f"{r['id']} accepted")
        except Bad as e:
            expect(e.sentinel == r["expect_error"], r["id"])
    return f"{len(f['cases'])} cases, {len(f['reject'])} reject"


# The revision that last changed each file's bytes; files not listed keep draft.1.
LAST_CHANGED = {"policy/mandate.json": "policy-v1-draft.7", "policy/render.json": "policy-v1-draft.7",
                "policy/verify.json": "policy-v1-draft.9", "policy/archive.json": "policy-v1-draft.8",
                "policy/api.json": "policy-v1-draft.8", "policy/private.json": "policy-v1-draft.8"}


def main() -> int:
    import gen_policy
    try:
        files = {}
        for rel, text in gen_policy.build().items():
            p = VECTORS / rel
            expect(p.exists() and p.read_text() == text, f"{rel}: generator output differs")
            files[rel] = json.loads(text)
        for rel, d in files.items():
            if rel.startswith("policy/"):
                want = LAST_CHANGED.get(rel, "policy-v1-draft.1")
                expect(d["format"] == "edicta-policy-vectors/v1" and d["revision"] == want, rel)
        P_ = lambda n: files[f"policy/{n}.json"]  # noqa: E731
        out = [check_facts(P_("facts")), check_mandate(P_("mandate")), check_render(P_("render"), P_("mandate")),
               check_state(P_("state")), check_engine(P_("engine")), check_verify(P_("verify")),
               check_private(P_("private"), P_("verify")),
               check_archive(P_("archive"), P_("verify"), P_("private")), check_api(P_("api"), P_("verify")),
               "tia-transfer " + check_tia(files["profiles/bank-send/tia_transfer_facts.json"])]
    except (Failure, Bad, KeyError, ValueError) as e:
        print(f"FAIL (policy v1): {type(e).__name__}: {e}", file=sys.stderr)
        return 1
    print("OK (policy v1, policy-v1-draft.9): " + "; ".join(out) + "; generator output identical")
    return 0


if __name__ == "__main__":
    sys.exit(main())
