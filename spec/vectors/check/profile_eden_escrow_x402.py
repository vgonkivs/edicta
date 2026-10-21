# SPDX-License-Identifier: Apache-2.0
"""eden-escrow profile, x402 escrow-upto flow (spec/profiles/eden-escrow-v1.md 2.2a, 5.1 S4 and S11, 5.5).

The /deposit/build conversion (BJ1 to BJ7), the PaymentRequirements checks (S4a to S4f), the
Payment-Signature message (S11) and the multi-source outcome rules. Written independently of the Go
generator, which labels the reject vectors; this module re-derives each label.
"""

from __future__ import annotations

import json
import re

import principal_crypto as pc
import profile_eden_escrow as ee
from profile_eden_escrow import Refused, _bad


class JInt:
    """A JSON number written as an integer literal, kept as written."""

    def __init__(self, raw: str):
        self.raw = raw


class JFloat:
    def __init__(self, raw: str):
        self.raw = raw


class JSONError(Exception):
    pass


def _no_dups(pairs):
    d = {}
    for k, v in pairs:
        if k in d:
            raise JSONError(f"repeated member {k}")
        d[k] = v
    return d


def _no_surrogates(v):
    if isinstance(v, str):
        v.encode("utf-8")
    elif isinstance(v, list):
        for x in v:
            _no_surrogates(x)
    elif isinstance(v, dict):
        for k, x in v.items():
            _no_surrogates(k)
            _no_surrogates(x)


def _constant(c):
    raise JSONError(c)


MAX_DEPTH = 16


def _depth_ok(text: str) -> bool:
    """Nesting of arrays and objects at most MAX_DEPTH, counted without recursion before parsing, so
    a deep document never reaches the recursive parser."""
    depth, in_str, esc = 0, False, False
    for ch in text:
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
        elif ch == '"':
            in_str = True
        elif ch in "[{":
            depth += 1
            if depth > MAX_DEPTH:
                return False
        elif ch in "]}":
            depth -= 1
    return True


def strict_json(raw: bytes):
    """Core JT3 document rules: UTF-8 without a byte order mark, JSON whitespace only, one value and
    nothing after it, no repeated member name at any depth, no NaN or Infinity; strings are taken
    after unescaping under the JT4 text rules (no unpaired surrogate, no raw control character); and
    the profile's nesting limit. Numbers come back as written (JInt, JFloat)."""
    try:
        text = raw.decode("utf-8")
        if text.startswith(chr(0xFEFF)):
            raise JSONError("byte order mark")
        if not _depth_ok(text):
            raise JSONError(f"nested deeper than {MAX_DEPTH}")
        v = json.loads(text, object_pairs_hook=_no_dups, parse_int=JInt, parse_float=JFloat,
                       parse_constant=_constant)
        _no_surrogates(v)
        return v
    except (ValueError, UnicodeError, JSONError) as e:
        raise JSONError(str(e)) from None


_DEC = re.compile(r"(0|[1-9][0-9]{0,77})")
_HEX_ANY = re.compile(r"0x(?:[0-9a-fA-F]{2})*")
MAX_SAFE = (1 << 53) - 1
REQUIREMENTS_MAX = 16384
BUILD_MAX = 16384


def json_uint(v):
    """JT4 uint: an integer literal of digits only (no sign), at most 2^53 - 1."""
    if not isinstance(v, JInt) or not v.raw.isdigit() or int(v.raw) > MAX_SAFE:
        return None
    return int(v.raw)


def dec_str(v):
    """A decimal string: 1 to 78 digits, no sign, no leading zero other than "0" itself."""
    if not isinstance(v, str) or _DEC.fullmatch(v) is None:
        return None
    return int(v)


def hex_n(v, n: int):
    """"0x" and exactly 2n hex digits of either case."""
    if not isinstance(v, str) or re.fullmatch(r"0x[0-9a-fA-F]{%d}" % (2 * n), v) is None:
        return None
    return bytes.fromhex(v[2:])


TXDATA_REQUIRED = ("to", "data", "value", "nonce", "gasLimit", "maxFeePerGas", "maxPriorityFeePerGas", "chainId")
TXDATA_OPTIONAL = ("type", "accessList")


def _cbor_head(major: int, n: int) -> bytes:
    if n < 24:
        return bytes([major << 5 | n])
    for ai, size in ((24, 1), (25, 2), (26, 4), (27, 8)):
        if n < 1 << (8 * size):
            return bytes([major << 5 | ai]) + n.to_bytes(size, "big")
    raise ValueError(n)


def encode_action(tx: bytes, resource: str, req_hash: bytes) -> bytes:
    r = resource.encode()
    return (_cbor_head(5, 4) + _cbor_head(0, 1) + _cbor_head(0, 1) + _cbor_head(0, 2) + _cbor_head(2, len(tx)) + tx
            + _cbor_head(0, 3) + _cbor_head(3, len(r)) + r + _cbor_head(0, 4) + _cbor_head(2, 32) + req_hash)


def action_from_build(raw: bytes, resource: str, req_hash: bytes, build: str = "production") -> tuple:
    """Section 2.2a: the /deposit/build answer to form T action bytes, then 2.4 on them.
    Returns (action bytes, decoded action)."""
    if not 1 <= len(raw) <= BUILD_MAX:
        _bad("BJ0", f"{len(raw)} bytes")
    try:
        doc = strict_json(raw)
    except JSONError as e:
        _bad("BJ1", str(e))
    if not isinstance(doc, dict) or not isinstance(doc.get("txData"), dict) or not isinstance(doc.get("paymentId"), str):
        _bad("BJ1", "shape")
    t = doc["txData"]
    if not set(TXDATA_REQUIRED) <= set(t) or not set(t) <= set(TXDATA_REQUIRED + TXDATA_OPTIONAL):
        _bad("BJ2", f"members {sorted(t)}")
    ints = {}
    for k in ("value", "gasLimit", "maxFeePerGas", "maxPriorityFeePerGas"):
        ints[k] = dec_str(t[k])
    for k in ("nonce", "chainId"):
        ints[k] = json_uint(t[k])
    if None in ints.values():
        _bad("BJ3", str([k for k, v in ints.items() if v is None]))
    to, pid = hex_n(t["to"], 20), hex_n(doc["paymentId"], 32)
    data = bytes.fromhex(t["data"][2:]) if isinstance(t["data"], str) and _HEX_ANY.fullmatch(t["data"]) else None
    if to is None or data is None or pid is None:
        _bad("BJ4", "hex form")
    if "type" in t and not (isinstance(t["type"], JInt) and t["type"].raw == "2"):
        _bad("BJ5", "type")
    if "accessList" in t and t["accessList"] != []:
        _bad("BJ5", "accessList")
    tx = b"\x02" + ee.rlp_enc_list([
        ee.rlp_enc_int(ints["chainId"]), ee.rlp_enc_int(ints["nonce"]), ee.rlp_enc_int(ints["maxPriorityFeePerGas"]),
        ee.rlp_enc_int(ints["maxFeePerGas"]), ee.rlp_enc_int(ints["gasLimit"]), ee.rlp_enc_bytes(to),
        ee.rlp_enc_int(ints["value"]), ee.rlp_enc_bytes(data), ee.rlp_enc_list([])])
    action = encode_action(tx, resource, req_hash)
    a = ee.decode_action(action, build)
    if a["call"]["payment_id"] != pid:
        _bad("BJ7", "paymentId differs from w0")
    return action, a


def eip191_digest(m: bytes) -> bytes:
    if len(m) != 32:
        raise ValueError("message must be 32 bytes")
    return pc.keccak256(b"\x19Ethereum Signed Message:\n32" + m)


def recover_eip191(m: bytes, sig: bytes):
    """The address that signed personal_sign(m), or None. v in {0, 1, 27, 28}; r and s in 1..n-1: this
    is another party's signature, so malleability does not matter, only who signed."""
    if len(sig) != 65 or sig[64] not in (0, 1, 27, 28):
        return None
    r, s = int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:64], "big")
    if not (1 <= r < pc.N and 1 <= s < pc.N):
        return None
    q = pc.recover(eip191_digest(m), r, s, sig[64] & 1 if sig[64] < 27 else sig[64] - 27)
    return None if q is None else pc.eth_address(q)


HEADER_MAX = 4 * ((REQUIREMENTS_MAX + 2) // 3)
_HEADER = re.compile(r"[A-Za-z0-9+/]*")
_B64 = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


def decode_header(value: str) -> bytes:
    """RH: the PAYMENT-REQUIRED header value (after HTTP removed the surrounding whitespace) to R."""
    if len(value) > HEADER_MAX:
        _bad("S4a", f"{len(value)} characters")
    body = value.rstrip("=")
    pad = len(value) - len(body)
    if not _HEADER.fullmatch(body) or len(body) % 4 == 1 or pad > 2 or (pad and len(value) % 4):
        _bad("RH", "header")
    # Unused low bits of the last character are ignored, as WHATWG forgiving-base64 does.
    r = bytearray()
    bits = acc = 0
    for ch in body.encode():
        acc = (acc << 6) | _B64.index(ch)
        bits += 6
        if bits >= 8:
            bits -= 8
            r.append((acc >> bits) & 0xFF)
    if not 1 <= len(r) <= REQUIREMENTS_MAX:
        _bad("S4a", f"{len(r)} bytes")
    return bytes(r)


def check_requirements(raw: bytes, a: dict, check_server_signature: bool = True) -> dict:
    """S4a to S4f against the decoded action a; returns the matching accepts entry."""
    if not 1 <= len(raw) <= REQUIREMENTS_MAX:
        _bad("S4a", f"{len(raw)} bytes")
    if ee.requirements_hash(raw) != a["requirements_hash"]:
        _bad("S4b", "requirements_hash")
    try:
        doc = strict_json(raw)
    except JSONError as e:
        _bad("S4c", str(e))
    if (not isinstance(doc, dict) or not isinstance(doc.get("x402Version"), JInt)
            or doc["x402Version"].raw != "2" or not isinstance(doc.get("accepts"), list)):
        _bad("S4c", "shape")
    c = a["call"]
    hits = [e for e in doc["accepts"] if isinstance(e, dict) and e.get("scheme") == "escrow-upto"
            and isinstance(e.get("extra"), dict) and hex_n(e["extra"].get("paymentId"), 32) == c["payment_id"]]
    if len(hits) != 1:
        _bad("S4d", f"{len(hits)} entries")
    e = hits[0]
    x = e["extra"]
    checks = [
        e.get("network") == f"eip155:{a['chain_id']}",
        e.get("asset") == "native",
        dec_str(e.get("amount")) == a["value"],
        hex_n(e.get("payTo"), 20) == c["pay_to"],
        hex_n(x.get("escrowContract"), 20) == a["to"],
        hex_n(x.get("facilitator"), 20) == c["facilitator"],
        json_uint(x.get("expiresAt")) == c["expires_at"],
        json_uint(x.get("refundAfter")) == c["refund_after"],
        dec_str(x.get("tiaPriceUsd")) == int.from_bytes(c["tia_price_usd"], "big"),
        json_uint(x.get("chainId")) == a["chain_id"],
        "nonce" not in x or hex_n(x["nonce"], 32) is not None,
    ]
    if not all(checks):
        _bad("S4e", f"check {checks.index(False)}")
    if check_server_signature:
        sig = hex_n(x.get("serverSignature"), 65)
        if sig is None or recover_eip191(c["payment_id"], sig) != c["facilitator"]:
            _bad("S4f", "serverSignature")
    return e


def payment_signature_message(field: str, check_server_signature: bool, action: bytes, r):
    """The stateless steps of S11 (a, c, d, f): the 32 bytes the payer key signs, or the refusal.
    Only field paymentId is offered, only with the serverSignature check on; the committed resource
    is https; R (stored or presented) passes S4 a to f with S4f enforced against the action's
    requirements_hash; the message is w0. Returns (message, None) or (None, (rule, error, s4 rule))."""
    if field != "paymentId" or not check_server_signature:
        return None, ("S11a", "ErrPinMismatch", None)
    a = ee.decode_action(action)
    if not a["resource"].startswith("https://"):
        return None, ("S11c", "ErrRequirements", None)
    if r is None:
        return None, ("S11d", "ErrRequirements", "absent")
    try:
        check_requirements(r, a, True)
    except Refused as e:
        return None, ("S11d", "ErrRequirements", e.rule)
    return a["call"]["payment_id"], None


_SOURCE_REASON = {"not_found": "settlement_not_found", "unavailable": "settlement_source_unavailable",
                  "unconfirmed": "settlement_unconfirmed"}

# Set-aside reasons that a source can only give after it served a transaction for the hash: EE5 (chain,
# code) runs before the lookup, everything after it means the source showed the transaction.
_SEEN_ASIDE = {"settlement_hash_mismatch", "settlement_tx_type", "settlement_disagree", "settlement_log_mismatch",
               "settlement_source_unavailable"}


def seen(s: dict) -> bool:
    return s["result"] in ("pass", "unconfirmed") or (s["result"] == "set_aside" and s["reason"] in _SEEN_ASIDE)


def multi_source(sources: list, min_sources: int, min_level: str, phase: str, seen_before: bool = False) -> dict:
    """Section 5.5: per-source results to the report, the Await state and what it allows. seen_before: a
    source was seen in an earlier poll of the same Await."""
    passing = [s for s in sources if s["result"] == "pass"]
    if len({s["binding"] for s in passing}) > 1:
        return {"verify": {"status": "unchecked", "reason": "settlement_disagree"}, "await": "disputed",
                "record": False, "payment_signature": False, "release": False}
    explicit = all(s["operator_label"] == "explicit" for s in sources)

    def operators(result):
        return {s["operator"] for s in sources if s["result"] == result}

    k = len(operators("pass"))
    level = "L1" if k >= min_sources else ("L0" if k else None)
    if level and (level == "L1" or min_level == "L0"):
        o = passing[0]["outcome"]
        return {"verify": {"status": "pass", "level": level, "outcome": o}, "await": o, "record": True,
                "payment_signature": o == "executed" and level == "L1" and explicit, "release": False}
    waiting = any(s["result"] == "unconfirmed" for s in sources)
    if waiting:
        reason = "settlement_unconfirmed"
    elif k:
        reason = "settlement_below_level"
    else:
        first = sources[0]
        reason = first["reason"] if first["result"] == "set_aside" else _SOURCE_REASON[first["result"]]
    if phase == "polling":
        state = "pending"
    elif not seen_before and not any(seen(s) for s in sources) and len(operators("not_found")) >= min_sources:
        state = "not_executed"
    else:
        state = "unknown"
    return {"verify": {"status": "unchecked", "reason": reason}, "await": state, "record": False,
            "payment_signature": False, "release": state == "not_executed"}
