"""Rules of the bank-send profile (Cosmos MsgSend action, TxBody rule, timeout height, price-trigger context).

Python side of the cross-language check for examples/tia-transfer. The
protobuf here is hand-written over the wire format on purpose: the expected
bytes in msg_send.json and tx.json come from gogoproto (banksend-gen), so
agreement is between two independent encoders. The core (edicta_v0.py) never
imports this module.

Sentinel names carry the Go package that owns them: bankmsg.ErrX,
bankaction.ErrX, transfer.ErrX and pricetrigger.ErrX.
"""

from __future__ import annotations

import hashlib
import re

from cbor_strict import CBORError, decode_strict, encode
from edicta_v0 import ID_CHARS, MAX_INT, Reject, _schema_decode, to_cbor

ACTION_TYPE = "application/vnd.edicta.cosmos.bank-send.v0+cbor"
MEDIA_TYPE_PRICE_TRIGGER = "application/vnd.edicta.price-trigger.v0+cbor"
MSG_SEND_TYPE_URL = "/cosmos.bank.v1beta1.MsgSend"
PUBKEY_TYPE_URL = "/cosmos.crypto.secp256k1.PubKey"
SIGN_MODE_DIRECT = 1

MAX_MSG = 1024
MAX_CHAIN_ID = 50
CHAIN_ID_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-")
DENOM_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9/:._-]{2,127}$")
AMOUNT_RE = re.compile(r"^[1-9][0-9]*$")
MAX_TIMEOUT_BLOCKS_LIMIT = 10_000


# bech32 (BIP-173). bech32m and mixed case are refused.

_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_GEN = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)


def _polymod(values) -> int:
    chk = 1
    for v in values:
        top = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ v
        for i in range(5):
            if (top >> i) & 1:
                chk ^= _GEN[i]
    return chk


def _hrp_expand(hrp: str) -> list:
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def _convertbits(data, frm: int, to: int, pad: bool):
    acc, bits, out, maxv = 0, 0, [], (1 << to) - 1
    for v in data:
        acc = (acc << frm) | v
        bits += frm
        while bits >= to:
            bits -= to
            out.append((acc >> bits) & maxv)
    if pad:
        if bits:
            out.append((acc << (to - bits)) & maxv)
    elif bits >= frm or ((acc << (to - bits)) & maxv):
        return None
    return out


def bech32_encode(hrp: str, data: bytes) -> str:
    d = _convertbits(data, 8, 5, True)
    values = _hrp_expand(hrp) + d
    mod = _polymod(values + [0] * 6) ^ 1
    return hrp + "1" + "".join(_CHARSET[x] for x in d) + "".join(_CHARSET[(mod >> 5 * (5 - i)) & 31] for i in range(6))


def bech32_decode_address(s: str, hrp: str) -> bytes | None:
    """Lower-case bech32 with exactly this prefix and a 20-byte payload, else None."""
    if not s or len(s) > 90 or s != s.lower() or any(not 33 <= ord(c) <= 126 for c in s):
        return None
    pos = s.rfind("1")
    if pos < 1 or pos + 7 > len(s) or s[:pos] != hrp:
        return None
    try:
        data = [_CHARSET.index(c) for c in s[pos + 1:]]
    except ValueError:
        return None
    if _polymod(_hrp_expand(hrp) + data) != 1:
        return None
    raw = _convertbits(data[:-6], 5, 8, False)
    if raw is None or len(raw) != 20:
        return None
    return bytes(raw)


# Protobuf wire format, the subset this profile needs.

def pb_varint(v: int) -> bytes:
    if v < 0:
        raise ValueError("negative varint")
    out = bytearray()
    while v >= 0x80:
        out.append((v & 0x7F) | 0x80)
        v >>= 7
    out.append(v)
    return bytes(out)


def pb_bytes(num: int, b: bytes) -> bytes:
    return pb_varint(num << 3 | 2) + pb_varint(len(b)) + b


def pb_uint(num: int, v: int) -> bytes:
    """proto3 scalar: absent when zero."""
    return b"" if v == 0 else pb_varint(num << 3) + pb_varint(v)


def _read_varint(b: bytes, i: int):
    """Minimal-form varint at b[i:]; returns (value, next index) or raises ValueError."""
    v, shift, start = 0, 0, i
    while True:
        if i >= len(b) or i - start >= 10:
            raise ValueError("truncated or overlong varint")
        c = b[i]
        i += 1
        v |= (c & 0x7F) << shift
        shift += 7
        if not c & 0x80:
            break
    if i - start > 1 and b[i - 1] == 0:
        raise ValueError("non-minimal varint")
    if v >= 1 << 64:
        raise ValueError("varint above 64 bits")
    return v, i


def _read_fields(b: bytes) -> list:
    """(field number, wire type, value) in wire order; only wire types 0 and 2."""
    out, i = [], 0
    while i < len(b):
        key, i = _read_varint(b, i)
        num, wt = key >> 3, key & 7
        if num == 0:
            raise ValueError("field number 0")
        if wt == 0:
            v, i = _read_varint(b, i)
        elif wt == 2:
            n, i = _read_varint(b, i)
            if n > len(b) - i:
                raise ValueError("length exceeds input")
            v = b[i:i + n]
            i += n
        else:
            raise ValueError(f"wire type {wt}")
        out.append((num, wt, v))
    return out


# cosmos.bank.v1beta1.MsgSend

def msg_encode(from_address: str, to_address: str, denom: str, amount: str) -> bytes:
    coin = pb_bytes(1, denom.encode()) + pb_bytes(2, amount.encode())
    return pb_bytes(1, from_address.encode()) + pb_bytes(2, to_address.encode()) + pb_bytes(3, coin)


def _ascii(b: bytes) -> str:
    s = b.decode("ascii")
    if any(not 0x21 <= ord(c) <= 0x7E for c in s):
        raise ValueError("not printable ASCII")
    return s


def msg_decode(b: bytes, hrp: str) -> dict:
    """Strict MsgSend decoding. Every failure is bankmsg.ErrMalformed."""
    def bad(detail: str):
        raise Reject("bankmsg.ErrMalformed", detail)

    if not 1 <= len(b) <= MAX_MSG:
        bad(f"{len(b)} bytes")
    try:
        fields = _read_fields(b)
        if [(n, wt) for n, wt, _ in fields] != [(1, 2), (2, 2), (3, 2)]:
            bad(f"fields {[(n, wt) for n, wt, _ in fields]}, want 1, 2, 3 once each, length-delimited")
        coin = _read_fields(fields[2][2])
        if [(n, wt) for n, wt, _ in coin] != [(1, 2), (2, 2)]:
            bad("coin must be exactly denom then amount")
        from_a, to_a = _ascii(fields[0][2]), _ascii(fields[1][2])
        denom, amount = _ascii(coin[0][2]), _ascii(coin[1][2])
    except (ValueError, UnicodeDecodeError) as e:
        bad(str(e))
    if not DENOM_RE.match(denom):
        bad(f"denom {denom!r}")
    if not AMOUNT_RE.match(amount) or int(amount) > MAX_INT:
        bad(f"amount {amount!r}")
    fb, tb = bech32_decode_address(from_a, hrp), bech32_decode_address(to_a, hrp)
    if fb is None or tb is None:
        bad("address is not lower-case bech32 of 20 bytes with the chain's prefix")
    if fb == tb:
        bad("from_address equals to_address")
    if msg_encode(from_a, to_a, denom, amount) != b:
        bad("re-encoding differs")
    return {"from_address": from_a, "to_address": to_a, "denom": denom, "amount": int(amount),
            "from": fb, "to": tb}


# Action bytes {1: chain_id, 2: msg}

ACTION = {
    1: ("chain_id", "tstr", True, (1, MAX_CHAIN_ID, CHAIN_ID_CHARS)),
    2: ("msg", "bstr", True, (1, MAX_MSG)),
}


def action_encode(chain_id: str, msg: bytes) -> bytes:
    return encode(to_cbor({"chain_id": chain_id, "msg": msg}, ACTION))


def action_decode(b: bytes) -> dict:
    """Strict decoding of the action bytes. Every failure is bankaction.ErrMalformed.
    The msg is not parsed here (it needs the chain's prefix)."""
    try:
        it = decode_strict(b)
        a = _schema_decode(it, ACTION, "action")
    except (CBORError, Reject) as e:
        raise Reject("bankaction.ErrMalformed", str(e))
    if encode(to_cbor(a, ACTION)) != b:
        raise Reject("bankaction.ErrMalformed", "re-encoding differs")
    return a


# TxBody rule

def memo(commitment_hash: bytes) -> str:
    assert len(commitment_hash) == 32
    return commitment_hash.hex()


def body(msg: bytes, commitment_hash: bytes, timeout_height: int) -> bytes:
    if not 1 <= timeout_height <= MAX_INT:
        raise ValueError("timeout_height out of range")
    any_ = pb_bytes(1, MSG_SEND_TYPE_URL.encode()) + pb_bytes(2, msg)
    return pb_bytes(1, any_) + pb_bytes(2, memo(commitment_hash).encode()) + b"\x18" + pb_varint(timeout_height)


def check_body(body_bytes: bytes, msg: bytes, commitment_hash: bytes) -> int:
    """For a transaction found on chain: body_bytes == Body(msg, commitment_hash, th)
    for the th it carries. Returns th, or bankaction.ErrBodyMismatch."""
    prefix = body(msg, commitment_hash, 1)[:-2]
    if not body_bytes.startswith(prefix + b"\x18"):
        raise Reject("bankaction.ErrBodyMismatch", "prefix differs")
    try:
        th, end = _read_varint(body_bytes, len(prefix) + 1)
    except ValueError as e:
        raise Reject("bankaction.ErrBodyMismatch", str(e))
    if end != len(body_bytes) or not 1 <= th <= MAX_INT or body(msg, commitment_hash, th) != body_bytes:
        raise Reject("bankaction.ErrBodyMismatch", "timeout_height or trailing bytes")
    return th


# Timeout height

def block_interval_ms(headers: list) -> int:
    """tau_ms from recent headers [(height, time_ns)] with consecutive heights:
    the largest interval, rounded up to whole milliseconds, at least 1."""
    if len(headers) < 2:
        raise ValueError("need at least two headers")
    tau = 1
    for (h0, t0), (h1, t1) in zip(headers, headers[1:]):
        if h1 != h0 + 1 or t1 <= t0:
            raise ValueError("headers must have consecutive heights and increasing times")
        tau = max(tau, -(-(t1 - t0) // 1_000_000))
    return tau


def timeout_height(head_height: int, head_time: int, tau_ms: int, expires: int, skew_s: int,
                   max_timeout_blocks: int, now: int) -> int:
    """th = H0 + min(floor((expires - skew - T0) * 1000 / tau_ms), max_timeout_blocks), all exact.
    transfer.ErrExpired when the send may not start (I6) or no block fits."""
    if not 1 <= tau_ms or not 1 <= max_timeout_blocks <= MAX_TIMEOUT_BLOCKS_LIMIT:
        raise ValueError("configuration out of range")
    if now + skew_s >= expires:
        raise Reject("transfer.ErrExpired", "now + skew_s >= expires")
    end = expires - skew_s
    n = 0 if end <= head_time else (end - head_time) * 1000 // tau_ms
    n = min(n, max_timeout_blocks)
    if n == 0:
        raise Reject("transfer.ErrExpired", "no block fits before expires - skew_s")
    th = head_height + n
    if th > MAX_INT:
        raise ValueError("timeout_height above 2^63-1")
    return th


# Executor static checks (after VerifyAuthorization), in the profile's order.

def executor_static_check(action_bytes: bytes, domain: dict, destinations: list, max_amount: int) -> dict:
    a = action_decode(action_bytes)
    if a["chain_id"] != domain["chain_id"]:
        raise Reject("transfer.ErrChainMismatch", f"{a['chain_id']} != {domain['chain_id']}")
    m = msg_decode(a["msg"], domain["hrp"])
    if m["from_address"] != domain["sender"]:
        raise Reject("transfer.ErrSenderMismatch")
    if m["denom"] != domain["denom"]:
        raise Reject("transfer.ErrDenomMismatch")
    if destinations and m["to_address"] not in destinations:
        raise Reject("transfer.ErrDestination")
    if max_amount and m["amount"] > max_amount:
        raise Reject("transfer.ErrRiskLimit")
    return {"chain_id": a["chain_id"], "msg": a["msg"], **m}


# Illustrative transaction assembly (the executor's own AuthInfo).

def auth_info(pubkey33: bytes, sequence: int, fee_denom: str, fee_amount: str, gas_limit: int) -> bytes:
    pk_any = pb_bytes(1, PUBKEY_TYPE_URL.encode()) + pb_bytes(2, pb_bytes(1, pubkey33))
    mode = pb_bytes(1, pb_uint(1, SIGN_MODE_DIRECT))
    signer = pb_bytes(1, pk_any) + pb_bytes(2, mode) + pb_uint(3, sequence)
    fee = pb_bytes(1, pb_bytes(1, fee_denom.encode()) + pb_bytes(2, fee_amount.encode())) + pb_uint(2, gas_limit)
    return pb_bytes(1, signer) + pb_bytes(2, fee)


def sign_doc(body_bytes: bytes, auth_info_bytes: bytes, chain_id: str, account_number: int) -> bytes:
    return pb_bytes(1, body_bytes) + pb_bytes(2, auth_info_bytes) + pb_bytes(3, chain_id.encode()) + pb_uint(4, account_number)


def tx_raw(body_bytes: bytes, auth_info_bytes: bytes, signature: bytes) -> bytes:
    return pb_bytes(1, body_bytes) + pb_bytes(2, auth_info_bytes) + pb_bytes(3, signature)


SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


def secp256k1_pub_and_address(priv: bytes) -> tuple:
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    k = ec.derive_private_key(int.from_bytes(priv, "big"), ec.SECP256K1())
    pub = k.public_key().public_bytes(Encoding.X962, PublicFormat.CompressedPoint)
    try:
        rip = hashlib.new("ripemd160", hashlib.sha256(pub).digest()).digest()
    except ValueError:
        raise RuntimeError("this Python's OpenSSL has no RIPEMD-160; address derivation cannot be checked")
    return pub, rip


def secp256k1_verify(pub: bytes, msg: bytes, sig: bytes) -> bool:
    """Cosmos form: 64-byte r || s over SHA-256(msg), s in the lower half."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

    if len(sig) != 64:
        return False
    r, s = int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")
    if not (1 <= r < SECP256K1_N and 1 <= s <= SECP256K1_N // 2):
        return False
    key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), pub)
    try:
        key.verify(encode_dss_signature(r, s), msg, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False


# application/vnd.edicta.price-trigger.v0+cbor

QUOTE_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
DENOM_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789/:._-")
ADDRESS_CHARS = frozenset("abcdefghijklmnopqrstuvwxyz0123456789")
REASON_MAX = 1024
MAX_OBSERVATIONS = 8
DIRECTION_UP, DIRECTION_DOWN = 1, 2

PT_ASSET = {
    1: ("feed", "tstr", True, (1, 64, ID_CHARS)),
    2: ("asset_id", "tstr", True, (1, 64, ID_CHARS)),
    3: ("quote", "tstr", True, (3, 3, QUOTE_CHARS)),
}
PT_OBSERVATION = {
    1: ("source", "tstr", True, (1, 64, ID_CHARS)),
    2: ("price", "uint", True, None),
    3: ("observed_at", "uint", True, None),
    4: ("fetched_at", "uint", True, None),
}
PT_BASELINE = {
    1: ("price", "uint", True, None),
    2: ("set_at", "uint", True, None),
}
PT_BRANCH = {
    1: ("name", "tstr", True, (1, 64, ID_CHARS)),
    2: ("to_address", "tstr", True, (1, 90, ADDRESS_CHARS)),
    3: ("amount", "uint", True, None),
    4: ("denom", "tstr", True, (3, 128, DENOM_CHARS)),
}
PRICE_TRIGGER = {
    1: ("strategy_id", "tstr", True, (1, 64, ID_CHARS)),
    2: ("asset", PT_ASSET, True, None),
    3: ("observations", "array", True, None),
    4: ("baseline", PT_BASELINE, True, None),
    5: ("threshold_bp", "uint", True, None),
    6: ("direction", "uint", True, None),
    7: ("move_bp", "uint", True, None),
    8: ("branch", PT_BRANCH, True, None),
    9: ("reason", "utf8", False, (1, REASON_MAX)),
}


def pt_cbor_map(p: dict) -> dict:
    m = {}
    for k, (name, typ, _, _) in PRICE_TRIGGER.items():
        if name not in p:
            continue
        v = p[name]
        if typ == "array":
            m[k] = [to_cbor(o, PT_OBSERVATION) for o in v]
        elif isinstance(typ, dict):
            m[k] = to_cbor(v, typ)
        else:
            m[k] = v
    return m


def pt_encode(p: dict) -> bytes:
    return encode(pt_cbor_map(p))


def pt_decode(b: bytes) -> dict:
    """Strict decoding of a price-trigger body. Every failure is pricetrigger.ErrMalformed."""
    def bad(detail: str):
        raise Reject("pricetrigger.ErrMalformed", detail)

    try:
        it = decode_strict(b)
    except CBORError as e:
        bad(str(e))
    if it.major != 5:
        bad("top level is not a map")
    out = {}
    try:
        for k, v in it.value:
            if k.value not in PRICE_TRIGGER:
                bad(f"unknown key {k.value}")
            name, typ, _, limit = PRICE_TRIGGER[k.value]
            if typ == "array":
                if v.major != 4 or not 1 <= len(v.value) <= MAX_OBSERVATIONS:
                    bad("observations must be an array of 1..8")
                out[name] = [_schema_decode(o, PT_OBSERVATION, "observation") for o in v.value]
            elif isinstance(typ, dict):
                out[name] = _schema_decode(v, typ, name)
            elif typ == "uint":
                if v.major != 0:
                    bad(f"{name}: not a uint")
                out[name] = v.value
            elif typ == "tstr":
                lo, hi, chars = limit
                if v.major != 3 or not lo <= len(v.value.encode()) <= hi or any(c not in chars for c in v.value):
                    bad(f"{name}: length or charset")
                out[name] = v.value
            else:
                lo, hi = limit
                if v.major != 3 or not lo <= len(v.value.encode("utf-8")) <= hi:
                    bad(f"{name}: not 1..{hi} bytes of UTF-8")
                out[name] = v.value
    except Reject as e:
        if e.sentinel == "pricetrigger.ErrMalformed":
            raise
        bad(str(e))
    for name, typ, req, _ in PRICE_TRIGGER.values():
        if req and name not in out:
            bad(f"missing {name}")
    uints = [out["threshold_bp"], out["direction"], out["move_bp"], out["baseline"]["price"], out["baseline"]["set_at"],
             out["branch"]["amount"]]
    for o in out["observations"]:
        uints += [o["price"], o["observed_at"], o["fetched_at"]]
    if any(x > MAX_INT for x in uints):
        bad("uint above 2^63-1")
    if any(o[f] == 0 for o in out["observations"] for f in ("price", "observed_at", "fetched_at")):
        bad("zero observation field")
    if any(a["observed_at"] < b["observed_at"] for a, b in zip(out["observations"], out["observations"][1:])):
        bad("observations not newest first")
    if out["baseline"]["price"] == 0 or out["baseline"]["set_at"] == 0 or out["branch"]["amount"] == 0:
        bad("zero baseline or amount")
    if not 1 <= out["threshold_bp"] <= 10_000:
        bad("threshold_bp")
    if out["direction"] not in (DIRECTION_UP, DIRECTION_DOWN):
        bad("direction")
    if not DENOM_RE.match(out["branch"]["denom"]):
        bad("denom grammar")
    if pt_encode(out) != b:
        bad("re-encoding differs")
    return out


def pt_consistency(p: dict, msg: dict, issued_at: int) -> list:
    """Replay checks PT1..PT5 against the authorized MsgSend; returns the ids that fail.
    They test the agent's statements against each other, never whether the inputs were true."""
    failed = []
    price, base = p["observations"][0]["price"], p["baseline"]["price"]
    if p["move_bp"] != abs(price - base) * 10_000 // base:
        failed.append("PT1")
    want = DIRECTION_UP if price > base else DIRECTION_DOWN if price < base else None
    if p["direction"] != want:
        failed.append("PT2")
    if p["move_bp"] < p["threshold_bp"]:
        failed.append("PT3")
    br = p["branch"]
    if (br["to_address"], br["amount"], br["denom"]) != (msg["to_address"], msg["amount"], msg["denom"]):
        failed.append("PT4")
    if p["observations"][0]["fetched_at"] > issued_at:
        failed.append("PT5")
    return failed
