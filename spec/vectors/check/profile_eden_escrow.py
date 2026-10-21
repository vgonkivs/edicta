# SPDX-License-Identifier: Apache-2.0
"""eden-escrow profile (spec/profiles/eden-escrow-v1.md): strict decoders and pure checks.

Written independently of the Go generator (spec/vectors/tools/edenescrow-gen), which builds the
vectors with go-ethereum; the checker compares both. Nothing here reads the network.
"""

from __future__ import annotations

import hashlib
import hmac
import re

import principal_crypto as pc
from cbor_strict import CBORError, decode_strict

ACTION_TYPE = "application/vnd.edicta.eden.escrow-deposit-tx.v1+cbor"
EXTRACTOR_ID = "eden/escrow-deposit-tx/v1"
EXTRACTOR_DEV_ID = "eden/escrow-deposit-tx-dev/v1"
REQUIREMENTS_TAG = b"edicta/eden-escrow/v1/requirements"
ERR_MALFORMED = "edenescrow.ErrMalformed"
ERR_DOMAIN = "edenescrow.ErrUnknownDomain"
ACTION_MAX = 4096
TX_MAX = 512
RESOURCE_MAX = 2048
INT63 = (1 << 63) - 1
N = pc.N

SELECTOR_DEPOSIT = pc.keccak256(b"deposit(bytes32,address,address,uint256,uint256,uint256)")[:4]
TOPIC_DEPOSITED = pc.keccak256(
    b"NativeEscrowDeposited(bytes32,address,address,address,uint256,uint256,uint256,uint256)")

ESCROW_714 = bytes.fromhex("65d77c98e73dfbea91ecb72b27c9753e186a94c8")
ESCROW_COPY = bytes.fromhex("e851a9b22d949ae005f65e1ba97c9b0c18354e5d")
CODE_HASH = bytes.fromhex("281a5ec0494b3c25ba7d7e36648a4f00f9f910d3889cc09d706755bd894300e5")
DEPLOYER = bytes.fromhex("4e59b44847b379578588920ca78fbf26c0b4956c")
ROWS = {
    "production": {714: ESCROW_714, 3735928814: ESCROW_COPY},
    "edictadev": {714: ESCROW_714, 3735928814: ESCROW_COPY, 31337: ESCROW_COPY},
}

RAIL_REF_RE = re.compile(r"[0-9a-f]{64}")


class Refused(Exception):
    def __init__(self, sentinel: str, rule: str, detail: str = ""):
        super().__init__(f"{sentinel} ({rule}): {detail}")
        self.sentinel = sentinel
        self.rule = rule


def _bad(rule: str, detail: str, sentinel: str = ERR_MALFORMED):
    raise Refused(sentinel, rule, detail)


# --- RLP, canonical only ---

def rlp_item(b: bytes, i: int, end: int, rule: str):
    """One canonical item at b[i:end]: (is_list, payload_start, payload_end, next)."""
    if i >= end:
        _bad(rule, "item past the end")
    c = b[i]
    if c < 0x80:
        return False, i, i + 1, i + 1
    if c < 0xc0:
        is_list, short, base = False, c <= 0xb7, 0x80 if c <= 0xb7 else 0xb7
    else:
        is_list, short, base = True, c <= 0xf7, 0xc0 if c <= 0xf7 else 0xf7
    if short:
        n, s = c - base, i + 1
        if not is_list and n == 1 and (s >= end or b[s] < 0x80):
            _bad(rule, "single byte below 0x80 wrapped in a string header")
    else:
        ll = c - base
        if i + 1 + ll > end:
            _bad(rule, "length of length past the end")
        if b[i + 1] == 0:
            _bad(rule, "length with a leading zero byte")
        n = int.from_bytes(b[i + 1:i + 1 + ll], "big")
        if n <= 55:
            _bad(rule, "long form for a short payload")
        s = i + 1 + ll
    if s + n > end:
        _bad(rule, "payload past the end")
    return is_list, s, s + n, s + n


def rlp_list_items(b: bytes, start: int, rule: str):
    """b[start:] is exactly one canonical list; returns its items as (is_list, ps, pe, enc_start, enc_end)."""
    is_list, s, e, nxt = rlp_item(b, start, len(b), rule)
    if not is_list:
        _bad(rule, "not a list")
    if nxt != len(b):
        _bad(rule, "bytes after the list")
    items, i = [], s
    while i < e:
        il, ps, pe, nx = rlp_item(b, i, e, rule)
        items.append((il, ps, pe, i, nx))
        i = nx
    return s, items


def rlp_enc_bytes(x: bytes) -> bytes:
    if len(x) == 1 and x[0] < 0x80:
        return x
    return _rlp_head(0x80, 0xb7, len(x)) + x


def rlp_enc_int(v: int) -> bytes:
    return rlp_enc_bytes(v.to_bytes((v.bit_length() + 7) // 8, "big"))


def rlp_enc_list(items: list) -> bytes:
    p = b"".join(items)
    return _rlp_head(0xc0, 0xf7, len(p)) + p


def _rlp_head(short: int, long: int, n: int) -> bytes:
    if n <= 55:
        return bytes([short + n])
    ln = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([long + len(ln)]) + ln


# --- deposit calldata (DC1 to DC5) ---

def decode_deposit_call(d: bytes) -> dict:
    if len(d) != 196:
        _bad("DC1", f"{len(d)} bytes")
    if d[:4] != SELECTOR_DEPOSIT:
        _bad("DC2", d[:4].hex())
    w = [d[4 + 32 * i:4 + 32 * (i + 1)] for i in range(6)]
    for i in (1, 2):
        if any(w[i][:12]) or not any(w[i][12:]):
            _bad("DC3", f"word {i}")
    times = []
    for i in (3, 4):
        if any(w[i][:24]):
            _bad("DC4", f"word {i} above 64 bits")
        v = int.from_bytes(w[i], "big")
        if not 1 <= v <= INT63:
            _bad("DC4", f"word {i} = {v}")
        times.append(v)
    if times[1] <= times[0]:
        _bad("DC4", "refundAfter <= expiresAt")
    if not any(w[5]):
        _bad("DC5", "tiaPriceUsd 0")
    return {"payment_id": w[0], "pay_to": w[1][12:], "facilitator": w[2][12:], "expires_at": times[0],
            "refund_after": times[1], "tia_price_usd": w[5], "words": w}


# --- action (EA1 to EA3) and transaction (ET1 to ET8, ED1) ---

def _printable(s: str) -> bool:
    return all(0x21 <= ord(ch) <= 0x7e for ch in s)


def decode_action(b: bytes, build: str = "production") -> dict:
    if not 1 <= len(b) <= ACTION_MAX:
        _bad("EA1", f"{len(b)} bytes")
    try:
        it = decode_strict(b)
    except CBORError as e:
        _bad("EA2", e.sentinel)
    if it.major != 5:
        _bad("EA3", "not a map")
    want = {1: 0, 2: 2, 3: 3, 4: 2}
    out = {}
    for k, v in it.value:
        if k.value not in want:
            _bad("EA3", f"unknown key {k.value}")
        if v.major != want[k.value]:
            _bad("EA3", f"key {k.value} major {v.major}")
        if k.value == 1 and v.value != 1:
            _bad("EA3", "version")
        if k.value == 2 and not 1 <= len(v.value) <= TX_MAX:
            _bad("EA3", "tx length")
        if k.value == 3:
            raw = v.value.encode("utf-8")
            if not 1 <= len(raw) <= RESOURCE_MAX or not _printable(v.value):
                _bad("EA3", "resource")
        if k.value == 4 and len(v.value) != 32:
            _bad("EA3", "requirements_hash length")
        out[k.value] = v.value
    if set(out) != set(want):
        _bad("EA3", f"missing {sorted(set(want) - set(out))}")
    tx = decode_tx(out[2], build)
    return {"tx": out[2], "resource": out[3], "requirements_hash": out[4], **tx}


def decode_tx(tx: bytes, build: str = "production") -> dict:
    if not tx or tx[0] != 0x02:
        _bad("ET1", "type byte")
    list_start, items = rlp_list_items(tx, 1, "ET2")
    if len(items) != 9:
        _bad("ET2", f"{len(items)} items")
    if any(items[i][0] for i in range(8)) or not items[8][0]:
        _bad("ET2", "item kinds")
    p = [tx[ps:pe] for _, ps, pe, _, _ in items]
    ints = {}
    for i, name, hi in ((0, "chain_id", 8), (1, "nonce", 8), (2, "tip", 32), (3, "fee", 32), (4, "gas", 8),
                        (6, "value", 32)):
        if p[i][:1] == b"\x00":
            _bad("ET3", f"{name} leading zero")
        if len(p[i]) > hi:
            _bad("ET3", f"{name} length")
        v = int.from_bytes(p[i], "big")
        if hi == 8 and v > INT63:
            _bad("ET3", f"{name} range")
        ints[name] = v
    if ints["tip"] > ints["fee"]:
        _bad("ET4", "tip above fee")
    if len(p[5]) != 20:
        _bad("ET5", "to length")
    if ints["value"] < 1:
        _bad("ET6", "value 0")
    if p[8]:
        _bad("ET7", "access list")
    try:
        call = decode_deposit_call(p[7])
    except Refused as e:
        _bad("ET8", f"{e.rule}")
    rows = ROWS[build]
    if ints["chain_id"] not in rows or rows[ints["chain_id"]] != p[5]:
        _bad("ED1", f"chain {ints['chain_id']} to {p[5].hex()}", ERR_DOMAIN)
    enc = [tx[es:ee] for _, _, _, es, ee in items]
    return {**ints, "to": p[5], "data": p[7], "call": call, "item_encodings": enc,
            "list_payload": tx[list_start:]}


def facts(a: dict) -> dict:
    cid = a["chain_id"]
    return {"kind": "x402-payment", "asset": f"eip155:{cid}/native",
            "amount": a["value"].to_bytes((a["value"].bit_length() + 7) // 8, "big"), "scale": 18,
            "recipient": f"eip155:{cid}:0x{a['call']['pay_to'].hex()}"}


def requirements_hash(raw: bytes) -> bytes:
    return hashlib.sha256(bytes([len(REQUIREMENTS_TAG)]) + REQUIREMENTS_TAG + raw).digest()


def sighash(tx: bytes) -> bytes:
    return pc.keccak256(tx)


# --- signed transaction (signer output) and the settlement rules ---

def address_of(d: int) -> bytes:
    return pc.eth_address(pc._mul(d, (pc.GX, pc.GY)))


def sign_rfc6979(d: int, digest: bytes) -> tuple:
    """(y_parity, r, s) with the RFC 6979 HMAC-SHA-256 nonce and low s, in pure Python (no OpenSSL)."""
    mac = lambda k, m: hmac.new(k, m, hashlib.sha256).digest()  # noqa: E731
    x, z = d.to_bytes(32, "big"), int.from_bytes(digest, "big") % N
    h = z.to_bytes(32, "big")
    v, k = b"\x01" * 32, b"\x00" * 32
    k = mac(k, v + b"\x00" + x + h)
    v = mac(k, v)
    k = mac(k, v + b"\x01" + x + h)
    v = mac(k, v)
    while True:
        v = mac(k, v)
        t = int.from_bytes(v, "big")
        if 1 <= t < N:
            rp = pc._mul(t, (pc.GX, pc.GY))
            r = rp[0] % N
            s = pow(t, N - 2, N) * (z + r * d) % N
            if r and s:
                y = rp[1] & 1
                if s > N // 2:
                    s, y = N - s, y ^ 1
                return y, r, s
        k = mac(k, v + b"\x00")
        v = mac(k, v)


def splice(action_tx: bytes, y: int, r: int, s: int) -> bytes:
    _, items = rlp_list_items(action_tx, 1, "ET2")
    enc = [action_tx[es:ee] for _, _, _, es, ee in items]
    return b"\x02" + rlp_enc_list(enc + [rlp_enc_int(y), rlp_enc_int(r), rlp_enc_int(s)])


def rail_ref(signed: bytes) -> str:
    return pc.keccak256(signed).hex()


def check_rail_ref(ref: str) -> bytes:
    """EE1: exactly 64 lower-case hex characters; a failure is unchecked, never violated."""
    if RAIL_REF_RE.fullmatch(ref) is None:
        raise Refused("malformed_rail_ref", "EE1", ref)
    return bytes.fromhex(ref)


def exact_tx(signed: bytes, action_tx: bytes) -> bytes:
    """EE3, then EE4: returns the payer address, or raises Refused('wrong_tx')."""
    def wrong(detail):
        raise Refused("wrong_tx", "EE3", detail)
    if not signed or signed[0] != 0x02:
        wrong("type byte")
    try:
        _, items = rlp_list_items(signed, 1, "EE3")
    except Refused as e:
        wrong(str(e))
    if len(items) != 12:
        wrong(f"{len(items)} items")
    _, want = rlp_list_items(action_tx, 1, "ET2")
    for i in range(9):
        if signed[items[i][3]:items[i][4]] != action_tx[want[i][3]:want[i][4]]:
            wrong(f"item {i}")
    if any(items[i][0] for i in (9, 10, 11)):
        wrong("signature item is a list")
    y_enc = signed[items[9][3]:items[9][4]]
    if y_enc not in (b"\x80", b"\x01"):
        wrong("y_parity")
    rs = []
    for i in (10, 11):
        p = signed[items[i][1]:items[i][2]]
        if not 1 <= len(p) <= 32 or p[0] == 0:
            wrong(f"item {i} encoding")
        rs.append(int.from_bytes(p, "big"))
    r, s = rs
    if not (1 <= r < N and 1 <= s <= N // 2):
        wrong("r or s out of range")
    q = pc.recover(sighash(action_tx), r, s, 0 if y_enc == b"\x80" else 1)
    if q is None:
        wrong("no public key recovers")
    return pc.eth_address(q)


def rebuild_type2(rpc: dict) -> bytes:
    """EE2 for a type 2 answer: the EIP-2718 bytes from the served fields."""
    if rpc["type"] != "0x2":
        raise ValueError("only type 2 is rebuilt here")
    q = lambda k: int(rpc[k], 16)  # noqa: E731
    items = [rlp_enc_int(q("chainId")), rlp_enc_int(q("nonce")), rlp_enc_int(q("maxPriorityFeePerGas")),
             rlp_enc_int(q("maxFeePerGas")), rlp_enc_int(q("gas")), rlp_enc_bytes(bytes.fromhex(rpc["to"][2:])),
             rlp_enc_int(q("value")), rlp_enc_bytes(bytes.fromhex(rpc["input"][2:])),
             rlp_enc_list([rlp_enc_list([rlp_enc_bytes(bytes.fromhex(e["address"][2:])),
                                         rlp_enc_list([rlp_enc_bytes(bytes.fromhex(k[2:])) for k in e["storageKeys"]])])
                           for e in rpc["accessList"]]),
             rlp_enc_int(q("yParity")), rlp_enc_int(q("r")), rlp_enc_int(q("s"))]
    return b"\x02" + rlp_enc_list(items)


def bloom(logs: list) -> bytes:
    f = 0
    for lg in logs:
        for x in [bytes.fromhex(lg["address"][2:])] + [bytes.fromhex(t[2:]) for t in lg["topics"]]:
            h = pc.keccak256(x)
            for j in (0, 2, 4):
                f |= 1 << (int.from_bytes(h[j:j + 2], "big") & 2047)
    return f.to_bytes(256, "big")


def receipt_consensus(rc: dict) -> bytes:
    logs = [rlp_enc_list([rlp_enc_bytes(bytes.fromhex(lg["address"][2:])),
                          rlp_enc_list([rlp_enc_bytes(bytes.fromhex(t[2:])) for t in lg["topics"]]),
                          rlp_enc_bytes(bytes.fromhex(lg["data"][2:]))]) for lg in rc["logs"]]
    body = rlp_enc_list([rlp_enc_int(int(rc["status"], 16)), rlp_enc_int(int(rc["cumulativeGasUsed"], 16)),
                         rlp_enc_bytes(bytes.fromhex(rc["logsBloom"][2:])), rlp_enc_list(logs)])
    return bytes([int(rc["type"], 16)]) + body


def deposit_event(status: int, logs: list, action: dict, sender: bytes, escrow: bytes, tx_hash: str,
                  block_hash: str, index: str) -> str:
    """EE7 and EE8: 'executed', 'reverted' or the reason 'settlement_log_mismatch'."""
    if status == 0:
        return "reverted" if not logs else "settlement_log_mismatch"
    if len(logs) != 1:
        return "settlement_log_mismatch"
    lg = logs[0]
    w = action["call"]["words"]
    want_topics = [TOPIC_DEPOSITED, w[0], bytes(12) + sender, w[1]]
    want_data = w[2] + action["value"].to_bytes(32, "big") + w[3] + w[4] + w[5]
    ok = (bytes.fromhex(lg["address"][2:]) == escrow and lg["removed"] is False and len(lg["topics"]) == 4
          and lg["transactionHash"] == tx_hash and lg["blockHash"] == block_hash and lg["transactionIndex"] == index
          and [bytes.fromhex(t[2:]) for t in lg["topics"]] == want_topics
          and bytes.fromhex(lg["data"][2:]) == want_data)
    return "executed" if ok else "settlement_log_mismatch"


HEADER_FIELDS = [
    ("parentHash", "b"), ("sha3Uncles", "b"), ("miner", "b"), ("stateRoot", "b"), ("transactionsRoot", "b"),
    ("receiptsRoot", "b"), ("logsBloom", "b"), ("difficulty", "i"), ("number", "i"), ("gasLimit", "i"),
    ("gasUsed", "i"), ("timestamp", "i"), ("extraData", "b"), ("mixHash", "b"), ("nonce", "b"),
    ("baseFeePerGas", "i"), ("withdrawalsRoot", "b"), ("blobGasUsed", "i"), ("excessBlobGas", "i"),
    ("parentBeaconBlockRoot", "b"), ("requestsHash", "b"),
]


def header_rlp(blk: dict) -> bytes:
    """Prague header as Eden's RPC serves it; every field present on the recorded block."""
    items = []
    for name, kind in HEADER_FIELDS:
        v = blk[name]
        items.append(rlp_enc_int(int(v, 16)) if kind == "i" else rlp_enc_bytes(bytes.fromhex(v[2:])))
    return rlp_enc_list(items)
