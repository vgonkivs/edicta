#!/usr/bin/env python3
"""Verifies spec/vectors/da/fibre_cert.json (v0-draft.21) without Go and
without the network.

The expected values come from upstream celestia-app, celestia-core and
cosmos-sdk code (spec/vectors/tools/fibrecert-gen). This script rebuilds them
from the raw bytes with its own code:
- protobuf decoding of the PFF tx, the x/staking HistoricalInfo, the CometBFT
  validator sets and headers;
- the promise sign bytes (section 10.6.1), the owner secp256k1 signature
  (low-S, over SHA-256 of the sign bytes) and every validator Ed25519
  signature (the Go crypto/ed25519 cofactorless equation);
- the network rule and the verifier report, stated as properties of the
  partition of the list into valid, invalid and empty entries rather than as
  a walk, and the list conditions under which CometBFT refuses to build a
  validator set;
- CometBFT header and validator-set hashes (RFC 6962 Merkle), the list's own
  CometBFT set (sorted and hashed here) against next_validators_hash of the
  promise header (CV7), and
  the backward last_block_id chain from the trusted header (HT2, HT3);
- every valset case (synthetic and live validator-set evidence);
- every mutation, re-evaluated after its byte flip; every boundary case and
  the threshold table;
- the live locator against fibre_commit.json.

Usage: python3 spec/vectors/check/check_fibre_cert.py [--file FILE] [--commit FILE]
"""

from __future__ import annotations

import sys

sys.dont_write_bytecode = True

import hashlib
import json
import re
from pathlib import Path

HERE = Path(__file__).resolve().parent
VECTORS = HERE.parent
FORMAT = "edicta-vectors/v0"
REVISION = "v0-draft.21"
PFF_URL = "/celestia.fibre.v1.MsgPayForFibre"
ED_URL = "/cosmos.crypto.ed25519.PubKey"
POWER_REDUCTION = 10**6
MAX_TOTAL = (2**63 - 1) // 8
GO_EPOCH_OFFSET = 62135596800
LIVE_PROMISE_HEIGHT = 1402813


class Failure(Exception):
    pass


def expect(cond: bool, msg: str):
    if not cond:
        raise Failure(msg)


def arg(name: str, default: Path) -> Path:
    if name in sys.argv:
        return Path(sys.argv[sys.argv.index(name) + 1]).resolve()
    return default


# ---- protobuf ----

def uvarint(b: bytes, i: int):
    v = shift = 0
    while True:
        expect(i < len(b), "truncated varint")
        c = b[i]
        i += 1
        v |= (c & 0x7F) << shift
        if c < 0x80:
            return v, i
        shift += 7
        expect(shift < 70, "varint too long")


def put_uvarint(v: int) -> bytes:
    out = bytearray()
    while v >= 0x80:
        out.append((v & 0x7F) | 0x80)
        v >>= 7
    out.append(v)
    return bytes(out)


def fields(b: bytes) -> list:
    """(field number, wire type, value): ints for varints, bytes otherwise."""
    out, i = [], 0
    while i < len(b):
        key, i = uvarint(b, i)
        num, wt = key >> 3, key & 7
        expect(num > 0, "field number 0")
        if wt == 0:
            v, i = uvarint(b, i)
        elif wt == 2:
            n, i = uvarint(b, i)
            expect(i + n <= len(b), "truncated length-delimited field")
            v, i = b[i:i + n], i + n
        elif wt == 1:
            expect(i + 8 <= len(b), "truncated fixed64")
            v, i = b[i:i + 8], i + 8
        elif wt == 5:
            expect(i + 4 <= len(b), "truncated fixed32")
            v, i = b[i:i + 4], i + 4
        else:
            raise Failure(f"wire type {wt}")
        out.append((num, wt, v))
    return out


def last(fs: list, num: int, wt: int, default=None):
    """Scalar and embedded fields: the last occurrence wins (protobuf merge
    for scalars; the decoders used here never meet a repeated embedded one)."""
    v = default
    for n, w, x in fs:
        if n == num:
            expect(w == wt, f"field {num}: wire type {w}")
            v = x
    return v


def every(fs: list, num: int) -> list:
    out = []
    for n, w, x in fs:
        if n == num:
            expect(w == 2, f"field {num}: wire type {w}")
            out.append(x)
    return out


def int64(v: int) -> int:
    return v - (1 << 64) if v >= 1 << 63 else v


# ---- hashes ----

def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def merkle(items: list) -> bytes:
    """RFC 6962 as CometBFT crypto/merkle.HashFromByteSlices."""
    if not items:
        return sha256(b"")
    if len(items) == 1:
        return sha256(b"\x00" + items[0])
    k = 1
    while k * 2 < len(items):
        k *= 2
    return sha256(b"\x01" + merkle(items[:k]) + merkle(items[k:]))


def wrap_bytes(v: bytes) -> bytes:
    """cdcEncode of a byte or string field: a BytesValue/StringValue, empty if
    the value is empty."""
    return b"\x0a" + put_uvarint(len(v)) + v if v else b""


def header_hash(hb: bytes) -> bytes:
    fs = fields(hb)
    height = int64(last(fs, 3, 0, 0))
    vals = last(fs, 8, 2, b"")
    expect(len(vals) > 0, "header without validators_hash")
    leaves = [
        last(fs, 1, 2, b""),
        wrap_bytes(last(fs, 2, 2, b"")),
        b"\x08" + put_uvarint(height & (2**64 - 1)) if height else b"",
        last(fs, 4, 2, b""),
        last(fs, 5, 2, b""),
    ] + [wrap_bytes(last(fs, n, 2, b"")) for n in range(6, 15)]
    return merkle(leaves)


def header_info(hb: bytes) -> dict:
    fs = fields(hb)
    lbid = fields(last(fs, 5, 2, b""))
    return {"height": int64(last(fs, 3, 0, 0)), "last_block_hash": last(lbid, 1, 2, b""),
            "validators_hash": last(fs, 8, 2, b""), "next_validators_hash": last(fs, 9, 2, b""),
            "chain_id": last(fs, 2, 2, b"").decode()}


def valset(vb: bytes) -> list:
    """CometBFT ValidatorSet proto: [(ed25519 key, voting power, SimpleValidator bytes)]."""
    out = []
    for v in every(fields(vb), 1):
        vf = fields(v)
        pkb = last(vf, 2, 2, b"")
        pk = last(fields(pkb), 1, 2, None)
        expect(pk is not None and len(pk) == 32, "valset: not an ed25519 key")
        power = int64(last(vf, 3, 0, 0))
        simple = b"\x0a" + put_uvarint(len(pkb)) + pkb + (b"\x10" + put_uvarint(power) if power else b"")
        out.append((pk, power, simple))
    expect(len(out) > 0, "empty valset")
    return out


def valset_hash(vs: list) -> bytes:
    return merkle([s for _, _, s in vs])


# ---- Ed25519 (Go crypto/ed25519.Verify: cofactorless, S < L) ----

EP = 2**255 - 19
EL = 2**252 + 27742317777372353535851937790883648493
ED = -121665 * pow(121666, EP - 2, EP) % EP
SQRT_M1 = pow(2, (EP - 1) // 4, EP)


def ed_add(p, q):
    x1, y1, z1, t1 = p
    x2, y2, z2, t2 = q
    a = (y1 - x1) * (y2 - x2) % EP
    b = (y1 + x1) * (y2 + x2) % EP
    c = 2 * t1 * t2 * ED % EP
    d = 2 * z1 * z2 % EP
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % EP, g * h % EP, f * g % EP, e * h % EP)


def ed_mul(k: int, p):
    acc = (0, 1, 1, 0)
    while k:
        if k & 1:
            acc = ed_add(acc, p)
        p = ed_add(p, p)
        k >>= 1
    return acc


def ed_decode(enc: bytes):
    if len(enc) != 32:
        return None
    n = int.from_bytes(enc, "little")
    sign, y = n >> 255, n & ((1 << 255) - 1)
    if y >= EP:
        return None
    u, v = (y * y - 1) % EP, (ED * y * y + 1) % EP
    x2 = u * pow(v, EP - 2, EP) % EP
    x = pow(x2, (EP + 3) // 8, EP)
    if (x * x - x2) % EP:
        x = x * SQRT_M1 % EP
    if (x * x - x2) % EP:
        return None
    if x == 0 and sign:
        return None
    if x & 1 != sign:
        x = EP - x
    return (x, y, 1, x * y % EP)


def ed_encode(p) -> bytes:
    x, y, z, _ = p
    zi = pow(z, EP - 2, EP)
    x, y = x * zi % EP, y * zi % EP
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


EB = ed_decode((4 * pow(5, EP - 2, EP) % EP).to_bytes(32, "little"))
_verified: dict = {}


def ed_verify(pub: bytes, msg: bytes, sig: bytes) -> bool:
    key = (pub, msg, sig)
    if key in _verified:
        return _verified[key]
    ok = False
    a = ed_decode(pub) if len(pub) == 32 else None
    if a is not None and len(sig) == 64:
        s = int.from_bytes(sig[32:], "little")
        if s < EL:
            k = int.from_bytes(hashlib.sha512(sig[:32] + pub + msg).digest(), "little") % EL
            na = (EP - a[0], a[1], a[2], EP - a[3])
            ok = ed_encode(ed_add(ed_mul(s, EB), ed_mul(k, na))) == sig[:32]
    _verified[key] = ok
    return ok


def ed_public(seed: bytes) -> bytes:
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return ed_encode(ed_mul(a, EB))


# ---- secp256k1 ECDSA (Cosmos SDK PubKey.VerifySignature: r || s, low S) ----

SP = 2**256 - 2**32 - 977
SN = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
SG = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
      0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


def sk_add(p, q):
    if p is None:
        return q
    if q is None:
        return p
    if p[0] == q[0] and (p[1] + q[1]) % SP == 0:
        return None
    if p == q:
        m = 3 * p[0] * p[0] * pow(2 * p[1], SP - 2, SP) % SP
    else:
        m = (q[1] - p[1]) * pow(q[0] - p[0], SP - 2, SP) % SP
    x = (m * m - p[0] - q[0]) % SP
    return (x, (m * (p[0] - x) - p[1]) % SP)


def sk_mul(k: int, p):
    acc = None
    while k:
        if k & 1:
            acc = sk_add(acc, p)
        p = sk_add(p, p)
        k >>= 1
    return acc


def sk_decode(pub: bytes):
    if len(pub) != 33 or pub[0] not in (2, 3):
        return None
    x = int.from_bytes(pub[1:], "big")
    if x >= SP:
        return None
    y = pow((x ** 3 + 7) % SP, (SP + 1) // 4, SP)
    if (y * y - x ** 3 - 7) % SP:
        return None
    if y & 1 != pub[0] & 1:
        y = SP - y
    return (x, y)


def sk_verify(pub: bytes, msg: bytes, sig: bytes) -> bool:
    q = sk_decode(pub)
    if q is None or len(sig) != 64:
        return False
    r, s = int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")
    if not (0 < r < SN and 0 < s <= SN // 2):
        return False
    z = int.from_bytes(sha256(msg), "big") % SN
    w = pow(s, SN - 2, SN)
    pt = sk_add(sk_mul(z * w % SN, SG), sk_mul(r * w % SN, q))
    return pt is not None and pt[0] % SN == r


# ---- PFF ----

def go_time_binary(sec: int, nanos: int) -> bytes:
    return b"\x01" + (sec + GO_EPOCH_OFFSET).to_bytes(8, "big") + nanos.to_bytes(4, "big") + b"\xff\xff"


def parse_pff(tx: bytes) -> dict:
    """The CV1 decode: TxRaw, TxBody with exactly one Any of the PFF type,
    MsgPayForFibre, PaymentPromise; and the promise sign bytes."""
    raw = fields(tx)
    body = fields(last(raw, 1, 2, b""))
    msgs = every(body, 1)
    expect(len(msgs) == 1, "CV1: not exactly one message")
    anyf = fields(msgs[0])
    expect(last(anyf, 1, 2, b"") == PFF_URL.encode(), "CV1: not a MsgPayForFibre")
    m = fields(last(anyf, 2, 2, b""))
    pf = fields(last(m, 2, 2, b""))
    ts = fields(last(pf, 7, 2, b""))
    sec, nanos = int64(last(ts, 1, 0, 0)), last(ts, 2, 0, 0)
    pk = last(fields(last(pf, 8, 2, b"")), 1, 2, b"")
    p = {
        "signer": last(m, 1, 2, b"").decode(),
        "chain_id": last(pf, 1, 2, b"").decode(),
        "height": int64(last(pf, 2, 0, 0)),
        "namespace": last(pf, 3, 2, b""),
        "blob_size": last(pf, 4, 0, 0),
        "blob_version": last(pf, 5, 0, 0),
        "commitment": last(pf, 6, 2, b""),
        "sec": sec, "nanos": nanos,
        "signer_key": pk,
        "owner_sig": last(pf, 9, 2, b""),
        "sigs": every(m, 3),
    }
    expect(len(p["namespace"]) == 29 and len(p["commitment"]) == 32, "CV1: namespace or commitment size")
    stripped = (pk + p["namespace"] + p["blob_size"].to_bytes(4, "big") + p["commitment"]
                + p["blob_version"].to_bytes(4, "big") + (p["height"] & (2**64 - 1)).to_bytes(8, "big")
                + go_time_binary(sec, nanos))
    cid = p["chain_id"].encode()
    uid = b"fibre/pp:v0"
    req = (b"\x0a" + put_uvarint(len(cid)) + cid + b"\x12" + put_uvarint(len(stripped)) + stripped
           + b"\x1a" + put_uvarint(len(uid)) + uid)
    p["stripped"] = stripped
    p["sign_bytes"] = b"COMET::RAW_BYTES::SIGN" + put_uvarint(len(req)) + req
    return p


def owner_ok(p: dict) -> bool:
    """CV3 as PaymentPromise.Validate."""
    return (len(p["signer_key"]) == 33 and 1 <= len(p["chain_id"]) <= 20 and p["blob_size"] > 0
            and (p["sec"], p["nanos"]) != (-GO_EPOCH_OFFSET, 0) and p["height"] > 0
            and len(p["owner_sig"]) == 64 and sk_verify(p["signer_key"], p["sign_bytes"], p["owner_sig"]))


def parse_hist(hb: bytes):
    fs = fields(hb)
    hdr = last(fs, 1, 2, b"")
    vals = []
    for v in every(fs, 2):
        vf = fields(v)
        anyf = fields(last(vf, 2, 2, b""))
        expect(last(anyf, 1, 2, b"") == ED_URL.encode(), "CV4: consensus key is not ed25519")
        # Key length and zero tokens are left to set_rejects: the chain
        # decodes them and refuses the list later.
        pk = last(fields(last(anyf, 2, 2, b"")), 1, 2, b"")
        tok = last(vf, 5, 2, b"").decode()
        expect(re.fullmatch(r"0|[1-9][0-9]*", tok) is not None, "CV4: tokens")
        t = int(tok)
        expect(t < 2**63, "CV4: tokens above int64")
        vals.append({"pk": pk, "addr": sha256(pk)[:20], "tokens": t, "power": t // POWER_REDUCTION})
    expect(len(vals) > 0, "CV4: empty set")
    return hdr, vals


def set_rejects(entries: list) -> bool:
    """True if CometBFT cannot build a validator set from [(key, power)]:
    a key that is not 32 bytes, two entries with one address, a power that is
    not positive or above MAX_TOTAL, or a total above MAX_TOTAL."""
    addrs = set()
    for pk, pw in entries:
        if len(pk) != 32 or not 0 < pw <= MAX_TOTAL:
            return True
        a = sha256(pk)[:20]
        if a in addrs:
            return True
        addrs.add(a)
    return not entries or sum(pw for _, pw in entries) > MAX_TOTAL


def classify(msg: bytes, vals: list, sigs: list):
    """Index sets of the signature list: (valid, invalid, empty). An entry with
    no validator at its index is invalid."""
    valid, invalid, empty = [], [], []
    for i, s in enumerate(sigs):
        if not s:
            empty.append(i)
        elif i < len(vals) and ed_verify(vals[i]["pk"], msg, s):
            valid.append(i)
        else:
            invalid.append(i)
    return valid, invalid, empty


def quorum_index(vals: list, valid: list, required: int):
    """The smallest valid index whose prefix of valid power reaches required."""
    acc = 0
    for i in valid:
        acc += vals[i]["tokens"]
        if acc >= required:
            return i
    return None


def keeper(msg: bytes, vals: list, sigs: list):
    """The network rule: the rule id that rejects, or None. Accept iff the
    list builds a set, is not longer than it, and either some valid prefix
    reaches the requirement with no invalid entry before that point, or there
    is no invalid entry at all and the requirement is met by every valid one."""
    if set_rejects([(v["pk"], v["tokens"]) for v in vals]):
        return "CV4"
    if len(sigs) > len(vals):
        return "CV5"
    required = sum(v["tokens"] for v in vals) * 2 // 3
    valid, invalid, _ = classify(msg, vals, sigs)
    q = quorum_index(vals, valid, required)
    if q is None:
        return None if not invalid and required <= 0 else "CV6"
    return "CV6" if any(i < q for i in invalid) else None


def report(msg: bytes, vals: list, sigs: list):
    if set_rejects([(v["pk"], v["tokens"]) for v in vals]):
        return None
    total = sum(v["tokens"] for v in vals)
    required = total * 2 // 3
    valid, invalid, empty = classify(msg, vals, sigs)
    q = quorum_index(vals, valid, required)
    signed = sum(vals[i]["tokens"] for i in valid)
    return {"signatures_len": len(sigs), "validators_len": len(vals), "valid": len(valid),
            "invalid": len(invalid), "empty": len(empty),
            "invalid_after_stop": 0 if q is None else sum(1 for i in invalid if i > q),
            "stop_index": "none" if q is None else str(q),
            "signed_power": str(signed), "total_power": str(total), "required": str(required),
            "signed_share": share(signed, total), "at_most_two_thirds": 3 * signed <= 2 * total}


def share(signed: int, total: int) -> str:
    if total == 0:
        return "undefined"
    q = signed * 10**6 // total
    rem = signed * 10**6 % total
    if 2 * rem >= total:
        q += 1
    return f"{q // 10**6}.{q % 10**6:06d}"


# ---- the live pipeline ----

def inputs_of(raw: dict) -> dict:
    return {"pff_tx": bytes.fromhex(raw["pff_tx_hex"]),
            "historical_info": bytes.fromhex(raw["historical_info"]["hex"]),
            "cometbft_valset": {int(v["height"]): bytes.fromhex(v["hex"]) for v in raw["cometbft_valsets"]},
            "header": {int(h["height"]): bytes.fromhex(h["header_hex"]) for h in raw["headers"]},
            "commit": {int(h["height"]): bytes.fromhex(h["commit_hex"]) for h in raw["headers"] if "commit_hex" in h},
            "trusted": (int(raw["trusted_header"]["height"]), bytes.fromhex(raw["trusted_header"]["hash_hex"]))}


def evaluate(inp: dict, binding: dict, full_report: bool) -> tuple:
    fails = []

    def fail(rule):
        if rule not in fails:
            fails.append(rule)

    p = None
    try:
        p = parse_pff(inp["pff_tx"])
    except Failure:
        fail("CV1")
    if p is not None:
        if (p["chain_id"] != binding["chain_id"] or p["namespace"].hex() != binding["namespace_hex"]
                or p["commitment"].hex() != binding["commitment_hex"] or str(p["blob_version"]) != binding["blob_version"]
                or str(p["blob_size"]) != binding["blob_size"]):
            fail("CV2")
        if not owner_ok(p):
            fail("CV3")
    ph = p["height"] if p is not None else LIVE_PROMISE_HEIGHT
    chain = p["chain_id"] if p is not None else "mocha-5"
    vf, vals, rep, via = eval_valset(inp["historical_info"], chain, ph,
                                     p["sign_bytes"] if p is not None else None,
                                     p["sigs"] if p is not None else [], inp["header"].get(ph))
    for r in vf:
        fail(r)
    if not full_report:
        rep = None
    th, thash = inp["trusted"]
    try:
        ok = header_hash(inp["header"][th]) == thash
    except (Failure, KeyError):
        ok = False
    if not ok:
        fail("HT2")
    try:
        for k in range(th, ph, -1):
            if header_hash(inp["header"][k - 1]) != header_info(inp["header"][k])["last_block_hash"]:
                raise Failure("break")
    except (Failure, KeyError):
        fail("HT3")
    return fails, p, vals, rep, via


def eval_valset(hist: bytes, chain: str, ph: int, msg, sigs: list, promise_header):
    """CV4 to CV7 over an archived HistoricalInfo and the header at the
    promise height."""
    fails = []
    try:
        hdr, vals = parse_hist(hist)
        expect(header_info(hdr)["height"] == ph, "CV4: HistoricalInfo for another height")
    except Failure:
        return ["CV4"], None, None, ""
    rep = None
    if msg is not None:
        rule = keeper(msg, vals, sigs)
        if rule:
            fails.append(rule)
        rep = report(msg, vals, sigs)
    via = cv7(chain, ph, vals, promise_header)
    if not via:
        fails.append("CV7")
    return fails, vals, rep, via


def list_set_hash(vals: list):
    """Hash of the CometBFT set the list stands for (consensus power
    tokens // 10^6, sorted by power descending then address), or None if
    CometBFT would refuse to build it."""
    entries = [(v["pk"], v["power"]) for v in vals]
    if set_rejects(entries):
        return None
    entries.sort(key=lambda e: (-e[1], sha256(e[0])[:20]))
    simple = []
    for pk, pw in entries:
        pkb = b"\x0a" + put_uvarint(len(pk)) + pk
        simple.append(b"\x0a" + put_uvarint(len(pkb)) + pkb + b"\x10" + put_uvarint(pw))
    return merkle(simple)


def cv7(chain: str, ph: int, vals: list, promise_header) -> str:
    """The list's own set hashes to next_validators_hash of a header with the
    promise's height and chain id. Nothing else is consulted."""
    want = list_set_hash(vals)
    try:
        pi = header_info(promise_header)
    except (Failure, TypeError, UnicodeDecodeError):
        return ""
    if want is not None and pi["height"] == ph and pi["chain_id"] == chain and pi["next_validators_hash"] == want:
        return f"next_validators_hash@{ph}"
    return ""


def flipped(inp: dict, m: dict) -> dict:
    out = {k: (dict(v) if isinstance(v, dict) else v) for k, v in inp.items()}
    t = m["target"]
    if t in ("pff_tx", "historical_info"):
        b = bytearray(out[t])
    else:
        b = bytearray(out[t][int(m["height"])])
    off = int(m["offset"])
    expect(0 <= off < len(b), f"{m['id']}: offset out of range")
    b[off] ^= int(m["xor"], 16)
    if t in ("pff_tx", "historical_info"):
        out[t] = bytes(b)
    else:
        out[t][int(m["height"])] = bytes(b)
    return out


def check_live(f: dict, commit_file: dict) -> tuple:
    live = f["live"]
    raw, d = live["raw"], live["derived"]
    inp = inputs_of(raw)
    expect(raw["chain_id"] == "mocha-5" and raw["pff_height"] == "1402819", "live locator")
    expect(sha256(inp["pff_tx"]).hex().upper() == raw["tx_hash"], "live: tx bytes do not hash to tx_hash")
    expect(raw["tx_result_code"] == "0", "live: result code")
    expect(raw["historical_info"]["height"] == "1402813", "live: HistoricalInfo height")
    for r in live["source"]["reads"]:
        if "at_height" in r:
            expect(r.get("echoed_height") == r["at_height"], f"live source: {r['what']} without an echoed height")

    fc = next(c for c in commit_file["cases"] if c["id"] == "fibre_live_mocha_popsmin1")
    lr = fc["live"]
    b = d["binding"]
    expect(lr["tx_hash"] == raw["tx_hash"] and lr["height"] == raw["pff_height"], "fibre_commit.json live locator")
    expect(lr["namespace_hex"] == b["namespace_hex"] and fc["commitment_hex"] == b["commitment_hex"]
           and fc["upload_size"] == b["blob_size"] and fc["size"] == b["payload_size"], "binding vs fibre_commit.json")

    fails, p, vals, rep, via = evaluate(inp, b, True)
    expect(fails == [], f"live fails {fails}")
    pr = d["promise"]
    expect(p["chain_id"] == pr["chain_id"] and str(p["height"]) == pr["height"] and p["namespace"].hex() == pr["namespace_hex"]
           and str(p["blob_size"]) == pr["blob_size"] and str(p["blob_version"]) == pr["blob_version"]
           and p["commitment"].hex() == pr["commitment_hex"] and str(p["sec"]) == pr["creation_unix_seconds"]
           and str(p["nanos"]) == pr["creation_nanos"] and p["signer_key"].hex() == pr["signer_public_key_hex"]
           and p["owner_sig"].hex() == pr["owner_signature_hex"] and p["signer"] == d["msg_signer"], "live promise fields")
    expect(p["stripped"].hex() == d["stripped_sign_bytes_hex"], "live stripped sign bytes")
    expect(p["sign_bytes"].hex() == d["sign_bytes_hex"], "live sign bytes")
    expect(d["owner_signature_valid"] is True, "owner_signature_valid")
    expect([s.hex() for s in p["sigs"]] == d["validator_signatures_hex"], "live signatures")
    expect(len(vals) == len(d["validators"]), "live validator count")
    for i, (v, dv) in enumerate(zip(vals, d["validators"])):
        state = "absent" if i >= len(p["sigs"]) else "empty" if not p["sigs"][i] else (
            "valid" if ed_verify(v["pk"], p["sign_bytes"], p["sigs"][i]) else "invalid")
        expect(dv == {"index": str(i), "pubkey_hex": v["pk"].hex(), "address_hex": v["addr"].hex(),
                      "tokens": str(v["tokens"]), "consensus_power": str(v["power"]), "signature": state},
               f"live validator {i}")
    order = [(-v["power"], v["addr"]) for v in vals]
    expect(order == sorted(order), "live: HistoricalInfo not in consensus-power, address order")
    tok = [(-v["tokens"], v["addr"]) for v in vals]
    expect(d["valset_order"]["consensus_power_then_address"] is True
           and d["valset_order"]["tokens_then_address"] == (tok == sorted(tok)), "valset_order")
    expect(d["power_reduction"] == str(POWER_REDUCTION), "power_reduction")
    expect(rep == d["certificate"], f"live certificate {rep} != {d['certificate']}")
    expect(rep["valid"] == 73 and rep["invalid"] == 0 and round(int(rep["signed_power"]) * 1000 / int(rep["total_power"])) == 762
           and rep["at_most_two_thirds"] is False and d["verdict"] == "accept", "live: 73 signatures, share 0.762")
    expect(via == d["cv7_matched"] == "next_validators_hash@1402813", f"cv7_matched {via}")
    hh = {int(x["height"]): x["hash_hex"] for x in d["header_hashes"]}
    for h, hb in inp["header"].items():
        expect(header_hash(hb).hex() == hh[h], f"header hash {h}")
        expect(header_info(hb)["height"] == h and header_info(hb)["chain_id"] == "mocha-5", f"header {h} height or chain")
    for h in raw["headers"]:
        expect(h["block_id_hash_hex"] == hh[int(h["height"])], f"block id {h['height']} != recomputed header hash")
    expect(set(hh) == set(range(1402813, 1402820)), "header heights")
    expect({int(h["height"]) for h in raw["headers"] if "commit_hex" in h} == {1402813, 1402814, 1402819}, "commit heights")
    hist_hdr, _ = parse_hist(inp["historical_info"])
    hf, rf = fields(hist_hdr), fields(inp["header"][1402813])
    for num, wt in ((2, 2), (3, 0), (4, 2), (9, 2), (11, 2), (14, 2)):
        expect(last(hf, num, wt) == last(rf, num, wt) is not None, f"HistoricalInfo header field {num}")
    expect(last(hf, 8, 2, b"") == b"", "HistoricalInfo header carries validators_hash")
    expect(d["historical_info_header"].startswith("partial:"), "historical_info_header note")
    vh = {int(x["height"]): x["hash_hex"] for x in d["cometbft_valset_hashes"]}
    for h, vb in inp["cometbft_valset"].items():
        expect(valset_hash(valset(vb)).hex() == vh[h], f"valset hash {h}")
    expect(bytes.fromhex(vh[1402813]) == header_info(inp["header"][1402813])["validators_hash"], "valset 1402813 vs header")
    expect(d["cv7_both_header_fields_match"] is True
           and header_info(inp["header"][1402813])["next_validators_hash"] == header_info(inp["header"][1402814])["validators_hash"]
           == bytes.fromhex(vh[1402814]), "CV7 header fields")
    return inp, b, p, rep


def check_mutations(f: dict, inp: dict, binding: dict, live_rep: dict) -> int:
    targets = {m["target"] for m in f["undetected_mutations"]}
    ids = set()
    for m in f["mutations"]:
        expect(m["id"] not in ids, f"duplicate id {m['id']}")
        ids.add(m["id"])
        fails, *_ = evaluate(flipped(inp, m), binding, False)
        expect(m["expect"]["verdict"] == "reject" and m["expect"]["fails"] == fails and fails,
               f"{m['id']}: recomputed {fails}, vector {m['expect']}")
        targets.add(m["target"])
    expect({"pff_tx", "historical_info", "cometbft_valset", "header"} <= targets, f"mutation targets {targets}")
    by = {m["id"]: m for m in f["mutations"]}
    expect("CV6" in by["sig_first_signature"]["expect"]["fails"], "signature mutation")
    expect("CV3" in by["promise_owner_signature"]["expect"]["fails"], "owner mutation")
    for m in f["undetected_mutations"]:
        expect(m["id"] not in ids, f"duplicate id {m['id']}")
        ids.add(m["id"])
        fails, p, vals, rep, _ = evaluate(flipped(inp, m), binding, True)
        expect(fails == [] and m["expect"]["verdict"] == "accept" and m["expect"]["fails"] == [],
               f"{m['id']}: recomputed {fails}")
        expect(rep == m["expect"]["certificate"], f"{m['id']}: report {rep}")
    und = {m["id"]: m for m in f["undetected_mutations"]}
    a = und["sig_after_quorum"]["expect"]["certificate"]
    expect(a["invalid_after_stop"] == 1 and a["valid"] == live_rep["valid"] - 1, "sig_after_quorum report")
    t = und["valset_tokens_low_digit"]["expect"]["certificate"]
    expect(t["total_power"] != live_rep["total_power"], "valset_tokens_low_digit does not change the total")
    return len(f["mutations"]) + len(f["undetected_mutations"])


def check_boundary(f: dict, msg: bytes) -> int:
    bd = f["boundary"]
    expect(bd["message"].startswith("live.derived.sign_bytes_hex"), "boundary message")
    prefix = b"edicta/v0/vectors/fibre_cert/validator/"
    expect("SHA-256" in bd["key_seed_rule"] and prefix.decode() in bd["key_seed_rule"], "key seed rule")
    seen = set()
    for c in bd["cases"]:
        vals = [{"pk": test_key(v, prefix, c["id"]), "tokens": int(v["power"])} for v in c["validators"]]
        for v in vals:
            v["addr"], v["power"] = sha256(v["pk"])[:20], v["tokens"] // POWER_REDUCTION
        sigs = [bytes.fromhex(s) for s in c["signatures_hex"]]
        rule = keeper(msg, vals, sigs)
        e = c["expect"]
        expect(e["verdict"] == ("reject" if rule else "accept") and e.get("rule") == rule,
               f"{c['id']}: recomputed {rule}, vector {e['verdict']} {e.get('rule')}")
        expect(report(msg, vals, sigs) == e.get("certificate"), f"{c['id']}: report")
        seen.add(c["id"])
    for need in ("exactly_two_thirds_small", "just_above_two_thirds", "just_below_two_thirds",
                 "floor_admits_below_two_thirds", "floor_just_below", "more_signatures_than_validators",
                 "fewer_signatures_quorum", "all_entries_empty", "empty_entries_interleaved",
                 "total_one_invalid_first", "duplicate_signer", "zero_power", "total_above_max",
                 "total_at_max", "bad_key_length"):
        expect(need in seen, f"missing boundary case {need}")
    by = {c["id"]: c for c in bd["cases"]}
    expect(by["exactly_two_thirds_small"]["expect"]["certificate"]["at_most_two_thirds"] is True
           and by["exactly_two_thirds_small"]["expect"]["verdict"] == "accept", "exact 2/3 sets the flag")
    expect(by["more_signatures_than_validators"]["expect"]["rule"] == "CV5", "more signatures than validators")
    return len(bd["cases"])


def test_key(v: dict, prefix: bytes, cid: str) -> bytes:
    pk = ed_public(sha256(prefix + v["key_index"].encode()))
    if "truncated_to" in v:
        pk = pk[:int(v["truncated_to"])]
    expect(pk.hex() == v["pubkey_hex"], f"{cid}: key {v['key_index']}")
    return pk


def check_valset(f: dict, p: dict, inp: dict) -> int:
    vd = f["valset"]
    expect(vd["message"] == "live.derived.sign_bytes_hex", "valset message")
    prefix = b"edicta/v0/vectors/fibre_cert/validator/"
    need = {"valset_synthetic_ok", "valset_honest_insufficient", "valset_duplicate_signer", "valset_zero_power",
            "valset_total_above_max", "valset_bad_key_length", "promise_header_other_set", "promise_header_wrong_height",
            "promise_header_other_chain", "valset_duplicate_signer_live"}
    seen = set()
    for c in vd["cases"]:
        cid = c["id"]
        expect(cid not in seen, f"duplicate id {cid}")
        seen.add(cid)
        hist = bytes.fromhex(c["historical_info_hex"])
        if "validators" in c:
            _, vals = parse_hist(hist)
            expect([v["pk"] for v in vals] == [test_key(v, prefix, cid) for v in c["validators"]]
                   and [str(v["tokens"]) for v in vals] == [v["tokens"] for v in c["validators"]],
                   f"{cid}: validators vs historical_info_hex")
        else:
            expect(cid.endswith("_live"), f"{cid}: no validators")
            expect(bytes.fromhex(c["promise_header_hex"]) == inp["header"][p["height"]], f"{cid}: live header")
        sigs = [bytes.fromhex(s) for s in c["signatures_hex"]]
        expect(set(c) == {"id", "description", "validators", "historical_info_hex", "promise_header_hex", "signatures_hex", "expect"}
               - ({"validators"} if cid.endswith("_live") else set()), f"{cid}: fields")
        fails, vals, rep, via = eval_valset(hist, p["chain_id"], p["height"], p["sign_bytes"], sigs,
                                            bytes.fromhex(c["promise_header_hex"]))
        e = c["expect"]
        expect(e["fails"] == fails and e["verdict"] == ("reject" if fails else "accept"),
               f"{cid}: recomputed {fails}, vector {e['verdict']} {e['fails']}")
        net = keeper(p["sign_bytes"], vals, sigs) if vals is not None else "CV4"
        expect(e["network"]["verdict"] == ("reject" if net else "accept") and e["network"].get("rule") == net,
               f"{cid}: network {net}, vector {e['network']}")
        expect(e["cv7_matched"] == via, f"{cid}: cv7 {via}")
        expect(e.get("certificate") == rep, f"{cid}: report {rep}")
    expect(need <= seen, f"missing valset cases {need - seen}")
    return len(vd["cases"])


def check_threshold(f: dict, live_rep: dict) -> int:
    for t in f["threshold"]:
        s, n = int(t["signed"]), int(t["total"])
        expect(0 <= s <= n <= MAX_TOTAL, f"{t['id']}: range")
        req = n * 2 // 3
        expect(t["required"] == str(req) and t["accept"] == (s >= req) and t["at_most_two_thirds"] == (3 * s <= 2 * n),
               f"threshold {t['id']}")
    by = {t["id"]: t for t in f["threshold"]}
    expect(by["live"]["signed"] == live_rep["signed_power"] and by["live"]["total"] == live_rep["total_power"], "threshold live")
    expect(by["t3_s2"]["accept"] and by["t3_s2"]["at_most_two_thirds"], "threshold exact 2/3")
    expect(by["t100_s66"]["accept"] and not by["t100_s65"]["accept"], "threshold floor")
    return len(f["threshold"])


def check(path: Path, commit_path: Path) -> str:
    f = json.loads(path.read_text())
    expect(f.get("format") == FORMAT, "format")
    expect(f.get("revision") == REVISION, "revision")
    expect(f.get("generator") == "spec/vectors/tools/fibrecert-gen", "generator")
    expect("v10.4.0-mocha" in f["upstream"]["celestia-app"] and "celestia-node v0.34.2-mocha" in f["upstream"]["replace_set"],
           "upstream pin")
    inp, binding, p, rep = check_live(f, json.loads(commit_path.read_text()))
    nm = check_mutations(f, inp, binding, rep)
    nb = check_boundary(f, p["sign_bytes"])
    nt = check_threshold(f, rep)
    nv = check_valset(f, p, inp)
    return (f"live {rep['valid']} of {rep['validators_len']} signatures, share {rep['signed_share']}; "
            f"{nm} mutations, {nb} boundary, {nt} threshold, {nv} valset")


def main() -> int:
    path = arg("--file", VECTORS / "da" / "fibre_cert.json")
    commit = arg("--commit", VECTORS / "da" / "fibre_commit.json")
    try:
        summary = check(path, commit)
    except (Failure, KeyError, StopIteration, ValueError, UnicodeDecodeError) as e:
        print(f"FAIL (fibre_cert.json): {e!r}", file=sys.stderr)
        return 1
    print(f"OK (fibre_cert.json, {REVISION}): {summary}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
