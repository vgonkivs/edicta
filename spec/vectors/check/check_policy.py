#!/usr/bin/env python3
"""Verifies the policy v1 vectors (spec/policy-v1.md, policy-v1-draft.1).

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
T_ACTION = bytes.fromhex("10") + b"edicta/v0/action"
for t in (T_MANDATE, T_MANDATE_SIG, T_VERDICT, T_VERDICT_SIG, T_BUCKET, T_CLOSED, T_STATE, T_COUNTER, T_SUCC):
    assert t[0] == len(t) - 1

ID = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._:/-")
PRINT = set(chr(c) for c in range(0x21, 0x7F))
KIND = re.compile(r"[a-z][a-z0-9-]{0,31}")
XID = re.compile(r"[a-z0-9][a-z0-9./-]{0,63}")
TEST_TYPE = "application/vnd.edicta.test-facts.v1+cbor"
TEST_X = "edicta/test-facts/v1"
DENY = ["ErrAgentNotCovered", "ErrNoExtractor", "ErrFactsInvalid", "ErrOutsideMandate", "ErrKindNotAllowed",
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


def v_mandate(m):
    s = "ErrMandateInvalid"
    keys(m, s, (1, 2, 3, 4, 5, 6, 7, 9, 10), (8, 11, 12, 13))
    need(m[1] == 1, s)
    b32(m[2], s)
    need(public_key_problem(m[2]) is None, s)
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


def mandate_verify(b):
    sm = lenient(b, "ErrMandateInvalid", 16384)
    keys(sm, "ErrMandateInvalid", (1, 2))
    b32(sm[2], "ErrMandateInvalid", 64)
    v_mandate(sm[1])
    h = H(T_MANDATE, encode(sm[1]))
    if not sig_ok(sm[1][2], T_MANDATE_SIG, h, sm[2]):
        raise Bad("ErrMandateSignature")
    return sm[1], h


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
    keys(v, s, (1, 2, 3, 4, 5, 6, 7, 17), (8, 9, 10, 11, 12, 13, 14, 15, 16, 18))
    need(v[1] == 1, s)
    txt(v[2], s, 1, 64, ID)
    for kk in (3, 4, 5, 6):
        b32(v[kk], s)
    u(v[7], s, 1, 2)
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
    for kk in (14, 15, 16):
        if kk in v:
            b32(v[kk], s)
    have = set(v) - {1, 2, 3, 4, 5, 6, 7, 17}
    if v[7] == 1:
        want = {9, 10, 11, 12, 13, 14} | ({15, 16} if 13 in v and v[13][2] >= 1 else set())
    else:
        need(v.get(8) in DENY, s)
        r = v[8]
        stage = {"ErrAgentNotCovered": "a", "ErrNoExtractor": "a", "ErrFactsInvalid": "x"}.get(r, "f")
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


def verdict_verify(b, gate_pub):
    sv = lenient(b, "ErrVerdictInvalid", 16384)
    keys(sv, "ErrVerdictInvalid", (1, 2))
    b32(sv[2], "ErrVerdictInvalid", 64)
    v_verdict(sv[1])
    h = H(T_VERDICT, encode(sv[1]))
    if gate_pub is not None and not sig_ok(gate_pub, T_VERDICT_SIG, h, sv[2]):
        raise Bad("ErrVerdictSignature")
    return sv[1], h


def counter(principal, mid):
    return H(T_COUNTER, principal, mid)


def succ_key(gate_id, ck, sh):
    g = gate_id.encode()
    return H(T_SUCC, bytes([len(g)]), g, ck, sh)


# Archive reader (policy kinds).

PATH = {7: "mandate", 8: "policy-allow", 9: "policy-deny", 10: "policy-bucket", 11: "policy-closed",
        12: "policy-successor"}
RCAP = {7: 16448, 8: 16448, 9: 16448, 10: 16448, 11: 36928, 12: 256}


def read_record(b):
    s = "archive.ErrCorrupt"
    r = lenient(b, s, 36928, 1)
    need(isinstance(r, dict) and 1 in r and 2 in r and r[1] == 0 and r[2] in PATH and len(b) <= RCAP[r[2]], s)
    kind = r[2]
    try:
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
            p = f"{PATH[kind]}/{v[4].hex()}" + (f"/{v[8]}" if kind == 9 else "")
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
    lines = ["Edicta mandate v1", "principal: " + m[2].hex(), "mandate_id: " + m[9].hex(), "version: %d" % m[10],
             "gate: " + m[3], "valid: anchor time from %s ; decision valid_until up to %s" % (t(m[5]), t(m[6]))]
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
              "  - Limits are measured on the anchor time of each decision (block time of its payload), not on execution time.",
              "  - Limits use hourly buckets; a bucket partly inside a window counts fully, so a limit may cover up to "
              "one extra hour (a \"per 1h\" limit may span up to 2h): the gate may deny early, never allow extra.",
              "  - Limits count authorizations, not executions.",
              "  - Counters continue across versions of this mandate_id; a new mandate_id starts from zero."]
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
        expect(counter(m[2], m[9]).hex() == c["counter_key_hex"], c["id"])
    ck = {c["id"]: c["counter_key_hex"] for c in f["cases"]}
    expect(ck["m_full"] == ck["m_full_v2"], "versions share a counter")
    for r in f["reject"]:
        try:
            mandate_verify(hx(r["signed_mandate_hex"]))
            raise Failure(f"{r['id']} accepted")
        except Bad as e:
            expect(e.sentinel == r["expect_error"], f"{r['id']}: {e.sentinel}")
    return f"{len(f['cases'])} mandates, {len(f['reject'])} reject"


def check_render(f, mand):
    by = {c["id"]: c for c in mand["cases"]}
    for c in f["cases"]:
        m = mandate_in(by[c["mandate_ref"]]["input"] if "mandate_ref" in c else c["input"])
        expect(render(m) == c["text"], c["id"])
        expect(c["text"].isascii() and not any(ln != ln.rstrip() for ln in c["text"].split("\n")), c["id"])
        if not any(5 in r for r in m[7]):
            expect("recipients: any" in c["text"], c["id"])
        expect(("kinds: any" in c["text"]) == (13 not in m), c["id"])
        expect("(may count up to" in c["text"] or all(4 not in r for r in m[7]) and 8 not in m, c["id"])
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
    principals = {hx(x) for x in cfg["principal_keys"]}
    xreg = cfg["extractors"]
    depth = int(cfg["policy_depth"]) if cfg["policy_depth"] is not None else None
    expect(H(T_ACTION, bytes([len(atype)]), atype.encode(), action).hex() == d["action_hash_hex"], "action hash")

    def get(kind, key):
        p = f"{PATH[kind]}/{key.hex()}"
        if p not in arch:
            return "absent", None
        try:
            r = read_record(arch[p])
        except Bad:
            return "corrupt", None
        return ("ok", r) if r["kind"] == kind and r["key"] == key else ("corrupt", None)

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
        if h not in mcache:
            s, r = get(7, h)
            if s != "ok":
                mcache[h] = (s, None)
            else:
                try:
                    mcache[h] = ("ok", mandate_verify(r["body"])[0])
                except Bad:
                    mcache[h] = ("corrupt", None)
        return mcache[h]

    def vh(v):
        return H(T_VERDICT, encode(v))

    def closed_for(v, m, contents):
        root = v[13][5]
        if root == EMPTY_ROOT:
            cs = EMPTY
        else:
            s, r = get(11, root)
            if s != "ok":
                return s, None
            cs = r["closed"]
        bks = []
        if contents:
            r0 = rule_of(m, v[10][2]) or {}
            w = max([p[1] for p in r0.get(4, [])] + [x[1] for x in m.get(8, [])] + [0])
            for ref in cs[2]:
                if ref[1] >= v[12] // 3600 - w:
                    s, r = get(10, ref[2])
                    if s != "ok":
                        return s, None
                    bks.append(r["bucket"])
        st = v[13]
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

    hist = {"absent": "state_history_unavailable", "corrupt": "source_corrupt"}
    viol = []
    fail = fast_u = walk_u = None
    blocked = walked_ok = False

    s, V = allow_of(ch)
    if s != "ok":
        reason = "policy_verdict_unavailable" if s == "absent" else "source_corrupt"
        return {"policy": {"status": "unchecked", "reason": reason},
                "gate_integrity": {"status": "not_checked", "reason": None, "evidence": []},
                "verdict": "unchecked", "exit": "2"}
    if (V[5].hex(), V[6].hex(), V[2]) != (d["action_hash_hex"], d["agent_pubkey_hex"], d["gate_id"]):
        viol = [vh(V)]

    def fast():
        nonlocal blocked
        s, m = mandate_of(V[3])
        if s != "ok":
            return "u", "policy_mandate_unavailable" if s == "absent" else "source_corrupt"
        if m[2] not in principals:
            return "u", "policy_principal_untrusted"
        if m[3] != V[2]:
            return "f", "mandate_gate_id"
        if xreg.get(atype) != V[9] or V[9] != TEST_X:
            return "u", "policy_no_extractor"
        try:
            fx = facts_dec(action)
        except Bad:
            return "f", "facts_mismatch"
        if fx != V[10]:
            return "f", "facts_mismatch"
        if hx(d["agent_pubkey_hex"]) not in m[4]:
            return "f", "ErrAgentNotCovered"
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
        elif V[11] != th:
            return "f", "anchor_time_mismatch"
        elif th < m[5]:
            return "f", "ErrOutsideMandate"
        s, led = closed_for(V, m, True)
        if s == "inconsistent":
            viol.append(vh(V))
            return None
        if s != "ok":
            return "u", hist[s]
        if V[12] != (V[11] if V[13][2] == 0 else max(V[11], V[13][3])):
            return "f", "eval_time_mismatch"
        r2 = engine(m, led, V[10], V[11])
        if "deny" in r2:
            return "f", r2["deny"]
        if r2["hash"] != V[14] and not viol:
            viol.append(vh(V))
        return None

    out = fast()
    if out and out[0] == "f":
        fail = out[1]
    elif out:
        fast_u = out[1]
    held = [V]
    if cfg["policy_full"] and not viol:
        walked_ok = True
        n, hops, horizon = V, 0, V[12] - 32 * 86400
        chain = [V]
        while n[13][2] >= 1 and (depth is None or hops < depth) and n[13][3] >= horizon:
            s, p = allow_of(n[15])
            if s == "ok" and p[4] != n[15]:
                s = "corrupt"
            if s != "ok":
                walk_u = hist[s]
                break
            if vh(p) != n[16] or p[14] != H(T_STATE, encode(n[13])) or p[13][2] + 1 != n[13][2]:
                viol = [vh(p), vh(n)]
                break
            sp, mp = mandate_of(p[3])
            sn, mn = mandate_of(n[3])
            if sp != "ok" or sn != "ok":
                walk_u = hist[sp if sp != "ok" else sn]
                break
            scale_ok = all(rule_of(mn, r[1]) is None or rule_of(mn, r[1])[2] == r[2] for r in mp[7])
            if (mp[2], mp[9], mp[3]) != (mn[2], mn[9], mn[3]) or mp[10] > mn[10] or not scale_ok:
                viol = [vh(p), vh(n)]
                break
            s, led = closed_for(p, mp, False)
            if s == "inconsistent":
                viol = [vh(p)]
                break
            if s != "ok":
                walk_u = hist[s]
                break
            if transition(led, p[10][2], p[10][4], ival(p[10][3]), p[11])["hash"] != p[14]:
                viol = [vh(p)]
                break
            chain.append(p)
            n, hops = p, hops + 1
        held = list(chain)
        if not viol:
            for w in chain:
                s, mw = mandate_of(w[3])
                if s != "ok":
                    continue
                s, r = get(12, succ_key(w[2], counter(mw[2], mw[9]), H(T_STATE, encode(w[13]))))
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
        seen = {}
        for x in held:
            s, mx = mandate_of(x[3])
            if s != "ok" or x[2] != V[2]:
                continue
            key = (counter(mx[2], mx[9]), x[13][2])
            if key in seen and seen[key][4] != x[4]:
                viol = [vh(seen[key]), vh(x)]
                break
            seen.setdefault(key, x)
    if fail:
        pol = {"status": "fail", "rule": fail}
    elif viol or blocked:
        pol = {"status": "unchecked", "reason": "blocked"}
    elif fast_u or walk_u:
        pol = {"status": "unchecked", "reason": fast_u or walk_u}
    else:
        pol = {"status": "pass"}
    if viol:
        gi = {"status": "violated", "reason": "gate_equivocation", "evidence": [h.hex() for h in viol]}
    elif walked_ok:
        gi = {"status": "unchecked", "reason": walk_u, "evidence": []} if walk_u else \
            {"status": "ok", "reason": None, "evidence": []}
    else:
        gi = {"status": "not_checked", "reason": None, "evidence": []}
    if fail:
        verdict, code = "invalid", 1
    elif viol:
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
    for need_id in ("equivocation_fork_evidence", "equivocation_fork_successor", "equivocation_unlinked",
                    "understated_open_bucket_full", "pass_hour_rollover", "pass_chain_continuity",
                    "equivocation_version_decrease", "walk_history_missing", "unchecked_bucket_corrupt",
                    "fail_not_before", "fail_kind"):
        expect(need_id in ids, need_id)
    return f"{len(f['records'])} records, {len(f['cases'])} cases"


def check_archive(f, verify):
    for c in f["cases"]:
        r = read_record(hx(c["record_cbor_hex"]))
        expect(str(r["kind"]) == c["kind"] and r["key"].hex() == c["key_hex"] and r["path"] == c["path"], c["id"])
        expect(verify["records"][c["path"]] == c["record_cbor_hex"], c["id"])
    for r in f["reject"]:
        try:
            read_record(hx(r["record_cbor_hex"]))
            raise Failure(f"{r['id']} accepted")
        except Bad as e:
            expect(e.sentinel == r["expect_error"] == "archive.ErrCorrupt", r["id"])
    expect(f["reserved_kinds"] == ["6"] and f["marker_names"] == DENY, "kinds and markers")
    return f"{len(f['cases'])} records, {len(f['reject'])} reject"


def check_api(f, verify):
    gate_pub = hx(verify["gate"]["gate_pubkey_hex"])
    codes = [(m["status"], m["code"]) for m in f["mapping"]]
    expect([c for _, c in codes if c.startswith("policy.")] == ["policy." + n for n in DENY if n not in
                                                               ("ErrDecisionAge", "ErrFactsInvalid")] +
           ["policy.ErrDecisionAge", "policy.ErrFactsInvalid"], "mapping order")
    for x in f["examples"]:
        body = lenient(hx(x["response_cbor_hex"]), "api", 1 << 16, 2)
        if x["status"] == "200":
            expect(set(body) == {1, 5}, x["id"])
            a = lenient(body[1], "api", 256, 2)
            v, _ = verdict_verify(body[5], gate_pub)
            expect(v[7] == 1 and a[1][2] == v[4] and a[1][3] == v[5] and a[1][4] == v[2], x["id"])
            expect(sig_ok(gate_pub, bytes.fromhex("1b") + b"edicta/v0/authorization-sig",
                          H(bytes.fromhex("17") + b"edicta/v0/authorization", encode(a[1])), a[2]), x["id"])
            continue
        expect(set(body) <= {1, 2, 3, 4, 5}, x["id"])
        st = next(m for m in f["mapping"] if m["code"] == body[1]) if body[1] != "ErrNonceUsed" else None
        if st:
            expect(st["status"] == x["status"] and int(st["retryable"]) == body[3], x["id"])
        if 5 in body:
            v, _ = verdict_verify(body[5], gate_pub)
            if body[1].startswith("policy."):
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
                expect(d["format"] == "edicta-policy-vectors/v1" and d["revision"] == "policy-v1-draft.1", rel)
        P_ = lambda n: files[f"policy/{n}.json"]  # noqa: E731
        out = [check_facts(P_("facts")), check_mandate(P_("mandate")), check_render(P_("render"), P_("mandate")),
               check_state(P_("state")), check_engine(P_("engine")), check_verify(P_("verify")),
               check_archive(P_("archive"), P_("verify")), check_api(P_("api"), P_("verify")),
               "tia-transfer " + check_tia(files["profiles/bank-send/tia_transfer_facts.json"])]
    except (Failure, Bad, KeyError, ValueError) as e:
        print(f"FAIL (policy v1): {type(e).__name__}: {e}", file=sys.stderr)
        return 1
    print("OK (policy v1, policy-v1-draft.1): " + "; ".join(out) + "; generator output identical")
    return 0


if __name__ == "__main__":
    sys.exit(main())
