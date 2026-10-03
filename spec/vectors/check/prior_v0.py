"""DecisionCommitment v0 rules.

This module is the Python side of the cross-language check. It must not be
ported from, or to, the Go implementation: agreement between two independent
implementations of the same rules is the point.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from cbor_strict import CBORError, Item, decode_strict, encode
from ed25519_point import cofactorless_ok, public_key_problem

TAG_COMMITMENT = b"prior/v0/decision-commitment"
TAG_SIG = b"prior/v0/sig"
TAG_RECEIPT = b"prior/v0/receipt"
TAG_RECEIPT_SIG = b"prior/v0/receipt-sig"

MAX_SIGNED_SIZE = 2176
MAX_COMMITMENT_SIZE = 2048
MAX_PAYLOAD_SIZE = 1 << 27
MAX_INT = (1 << 63) - 1
QTY_SCALE = 10_000
MONEY_SCALE = 100_000_000
MAX_TTL_CAP = 3600
ED25519_L = 2**252 + 27742317777372353535851937790883648493

KIND_IBKR_ORDER_V0 = "ibkr.order.v0"

ID_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._:/-")
PRINTABLE = frozenset(chr(c) for c in range(0x20, 0x7F))
UPPER = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZ")


class Reject(Exception):
    def __init__(self, sentinel: str, detail: str = ""):
        super().__init__(f"{sentinel}: {detail}" if detail else sentinel)
        self.sentinel = sentinel
        self.detail = detail


def tagged(tag: bytes) -> bytes:
    if not 1 <= len(tag) <= 255:
        raise ValueError("tag length out of range")
    return bytes([len(tag)]) + tag


# Field schema: key -> (name, type, required, limit)
# type: "uint" | "bstr" | "tstr" | map schema dict | "params"
# required: True, False, or DA_BLOB_ONLY (payload_ref.signer: required when
# da == 2, not defined when da == 1, optional for any other da, which the enum check rejects).
# limit for bstr/tstr: (min_len, max_len); tstr also carries a charset.

DA_FIBRE = 1
DA_CELESTIA_BLOB = 2
DA_BLOB_ONLY = "da=celestia_blob"
SIGNER_SIZE = 20

SCOPE = {
    1: ("gate_id", "tstr", True, (1, 64, ID_CHARS)),
    2: ("rail", "uint", True, None),
    3: ("account", "tstr", True, (1, 32, ID_CHARS)),
    4: ("chain_id", "tstr", False, (1, 64, ID_CHARS)),
}

IBKR_ORDER_V0 = {
    1: ("account", "tstr", True, (1, 32, ID_CHARS)),
    2: ("conid", "uint", True, None),
    3: ("symbol", "tstr", False, (1, 32, PRINTABLE)),
    4: ("side", "uint", True, None),
    5: ("qty", "uint", True, None),
    6: ("order_type", "uint", True, None),
    7: ("limit_price", "uint", False, None),
    8: ("currency", "tstr", True, (3, 3, UPPER)),
    9: ("tif", "uint", True, None),
}

ACTION = {
    1: ("kind", "tstr", True, (1, 64, ID_CHARS)),
    2: ("params", "params", True, None),
}

CONSTRAINTS = {
    1: ("max_notional", "uint", True, None),
    2: ("price_bound", "uint", False, None),
    3: ("deadline", "uint", False, None),
}

PAYLOAD_REF = {
    1: ("da", "uint", True, None),
    2: ("namespace", "bstr", True, (29, 29)),
    3: ("commitment", "bstr", True, (32, 32)),
    4: ("height", "uint", True, None),
    5: ("signer", "bstr", DA_BLOB_ONLY, (SIGNER_SIZE, SIGNER_SIZE)),
}

COMMITMENT = {
    1: ("version", "uint", True, None),
    2: ("agent_id", "tstr", True, (1, 64, ID_CHARS)),
    3: ("agent_pubkey", "bstr", True, (32, 32)),
    4: ("nonce", "bstr", True, (16, 16)),
    5: ("issued_at", "uint", True, None),
    6: ("valid_until", "uint", True, None),
    7: ("scope", SCOPE, True, None),
    8: ("action", ACTION, True, None),
    9: ("constraints", CONSTRAINTS, True, None),
    10: ("payload_ref", PAYLOAD_REF, True, None),
    11: ("ciphertext_hash", "bstr", True, (32, 32)),
    12: ("plaintext_hash", "bstr", True, (32, 32)),
    13: ("payload_size", "uint", True, None),
}

ENVELOPE = {
    1: ("commitment", COMMITMENT, True, None),
    2: ("signature", "bstr", True, (64, 64)),
}

PARAMS_BY_KIND = {KIND_IBKR_ORDER_V0: IBKR_ORDER_V0}

MAJOR = {"uint": 0, "bstr": 2, "tstr": 3, "params": 5}


def _schema_decode(it: Item, schema: dict, where: str) -> dict:
    if it.major != 5:
        raise Reject("ErrWrongType", f"{where}: expected map")
    out: dict = {}
    for k, v in it.value:
        key = k.value
        if key not in schema:
            raise Reject("ErrUnknownKey", f"{where}: key {key}")
        name, typ, req, limit = schema[key]
        path = f"{where}.{name}"
        if req == DA_BLOB_ONLY and out.get("da") == DA_FIBRE:
            raise Reject("ErrUnknownKey", f"{path}: not defined for da=fibre")
        expect = 5 if isinstance(typ, dict) else MAJOR[typ]
        if v.major != expect:
            raise Reject("ErrWrongType", f"{path}: major {v.major}, want {expect}")
        if typ == "bstr":
            lo, hi = limit
            if not lo <= len(v.value) <= hi:
                raise Reject("ErrFieldSize", f"{path}: {len(v.value)} bytes")
            out[name] = v.value
        elif typ == "tstr":
            lo, hi, chars = limit
            if not lo <= len(v.value.encode("utf-8")) <= hi:
                raise Reject("ErrFieldSize", f"{path}: {len(v.value)} chars")
            if any(c not in chars for c in v.value):
                raise Reject("ErrInvalidString", f"{path}: character outside charset")
            out[name] = v.value
        elif typ == "uint":
            out[name] = v.value
        elif typ == "params":
            kind = out.get("kind")
            if kind is None:
                raise Reject("ErrMissingField", f"{where}.kind")
            if kind not in PARAMS_BY_KIND:
                raise Reject("ErrUnsupportedActionKind", kind)
            out[name] = _schema_decode(v, PARAMS_BY_KIND[kind], path)
        else:
            if typ is COMMITMENT and v.end - v.start > MAX_COMMITMENT_SIZE:
                raise Reject("ErrTooLarge", f"commitment is {v.end - v.start} bytes")
            out[name] = _schema_decode(v, typ, path)
    for key, (name, _, required, _) in schema.items():
        if required == DA_BLOB_ONLY:
            required = out.get("da") == DA_CELESTIA_BLOB
        if required and name not in out:
            raise Reject("ErrMissingField", f"{where}.{name}")
    return out


def decode_signed(envelope: bytes):
    """Decode and schema-check a signed envelope. Returns (signed dict, canonical commitment bytes)."""
    if len(envelope) > MAX_SIGNED_SIZE:
        raise Reject("ErrTooLarge", f"{len(envelope)} bytes")
    try:
        it = decode_strict(envelope)
    except CBORError as e:
        raise Reject(e.sentinel, e.detail)
    signed = _schema_decode(it, ENVELOPE, "envelope")
    inner = next(v for k, v in it.value if k.value == 1)
    canon = envelope[inner.start:inner.end]
    if encode(to_cbor(signed["commitment"])) != canon:
        raise Reject("ErrNonCanonical", "re-encoding differs")
    return signed, canon


def to_cbor(c: dict, schema: dict = COMMITMENT) -> dict:
    """Named dict -> integer-keyed dict, following the schema."""
    by_name = {f[0]: (k, f) for k, f in schema.items()}
    out = {}
    for name, val in c.items():
        key, (_, typ, _, _) = by_name[name]
        if isinstance(typ, dict):
            out[key] = to_cbor(val, typ)
        elif typ == "params":
            out[key] = to_cbor(val, PARAMS_BY_KIND.get(c.get("kind"), IBKR_ORDER_V0))
        else:
            out[key] = val
    return out


def commitment_hash(canon: bytes) -> bytes:
    return hashlib.sha256(tagged(TAG_COMMITMENT) + canon).digest()


def signing_message(h: bytes, tag: bytes = TAG_SIG) -> bytes:
    assert len(h) == 32
    return tagged(tag) + h


@dataclass(frozen=True)
class Params:
    fibre_retention_s: int = 14400
    blob_retention_s: int = 14400
    skew_s: int = 30

    def validate(self):
        for v in (self.fibre_retention_s, self.blob_retention_s):
            if not 1 <= v <= MAX_INT:
                raise Reject("ErrInvalidParams", "retention out of range")
        if not 0 <= self.skew_s <= 300:
            raise Reject("ErrInvalidParams", "skew out of range")

    def max_ttl(self, da: int) -> int:
        retention = self.fibre_retention_s if da == 1 else self.blob_retention_s
        return min(MAX_TTL_CAP, retention // 4)


def _ints(c: dict):
    p, k, r = c["action"]["params"], c["constraints"], c["payload_ref"]
    yield from (c["version"], c["issued_at"], c["valid_until"], c["scope"]["rail"], c["payload_size"])
    for name in ("conid", "side", "qty", "order_type", "limit_price", "tif"):
        if name in p:
            yield p[name]
    for name in ("max_notional", "price_bound", "deadline"):
        if name in k:
            yield k[name]
    yield from (r["da"], r["height"])


def namespace_ok(ns: bytes) -> bool:
    # Celestia v0 user namespace: version 0, 18 zero bytes, and the first 9
    # sub-id bytes not all zero, which excludes the primary reserved range.
    return ns[0] == 0 and not any(ns[1:19]) and any(ns[19:28])


def validate_static(c: dict, p: Params):
    """Static checks in this fixed order, so that every implementation
    reports the same error for an input with several defects."""
    a = c["action"]["params"]
    k = c["constraints"]
    r = c["payload_ref"]
    if c["version"] != 0:
        raise Reject("ErrUnsupportedVersion", str(c["version"]))
    if any(v > MAX_INT for v in _ints(c)):
        raise Reject("ErrIntRange")
    for name, val, allowed in (
        ("side", a["side"], {1, 2}),
        ("order_type", a["order_type"], {1, 2}),
        ("tif", a["tif"], {1, 2, 3}),
        ("da", r["da"], {1, 2}),
    ):
        if val not in allowed:
            raise Reject("ErrInvalidEnum", f"{name}={val}")
    if c["scope"]["rail"] == 0:
        raise Reject("ErrInvalidEnum", "rail=0")
    if c["scope"]["rail"] != 1:
        raise Reject("ErrUnsupportedRail", str(c["scope"]["rail"]))
    if a["order_type"] == 2:
        raise Reject("ErrUnsupportedOrderType", "MKT")
    for name, val in (
        ("issued_at", c["issued_at"]), ("conid", a["conid"]), ("qty", a["qty"]),
        ("limit_price", a.get("limit_price")), ("max_notional", k["max_notional"]),
        ("price_bound", k.get("price_bound")), ("height", r["height"]),
        ("payload_size", c["payload_size"]),
    ):
        if val == 0:
            raise Reject("ErrZeroValue", name)
    if c["payload_size"] > MAX_PAYLOAD_SIZE:
        raise Reject("ErrPayloadTooLarge")
    if not namespace_ok(r["namespace"]):
        raise Reject("ErrInvalidNamespace")
    if ("limit_price" in a) != (a["order_type"] == 1):
        raise Reject("ErrLimitPrice")
    if c["scope"]["account"] != a["account"]:
        raise Reject("ErrAccountMismatch")
    if "chain_id" in c["scope"]:
        raise Reject("ErrChainIDRule")
    if c["valid_until"] <= c["issued_at"]:
        raise Reject("ErrTimeOrder")
    if "deadline" in k and not c["issued_at"] < k["deadline"] <= c["valid_until"]:
        raise Reject("ErrDeadlineRange")
    if c["valid_until"] - c["issued_at"] > p.max_ttl(r["da"]):
        raise Reject("ErrTTLTooLong")
    if "price_bound" in k:
        lp, b = a["limit_price"], k["price_bound"]
        if (a["side"] == 1 and lp > b) or (a["side"] == 2 and lp < b):
            raise Reject("ErrPriceBound")
    if a["qty"] * a["limit_price"] > k["max_notional"] * QTY_SCALE:
        raise Reject("ErrNotionalExceeded")


def verify_signature(c: dict, canon: bytes, sig: bytes) -> bytes:
    """Public-key validity, then S < L, then the signature equation.
    Returns commitment_hash."""
    h = commitment_hash(canon)
    _verify_tagged_hash(c["agent_pubkey"], h, sig)
    return h


def _verify_tagged_hash(pub: bytes, h: bytes, sig: bytes, tag: bytes = TAG_SIG):
    """Signature checks for a public key and an already domain-separated hash."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    # Public-key validity is checked here, not left to the library: OpenSSL (via 'cryptography')
    # accepts small-order and non-canonical public keys, so (A = identity,
    # R = identity, S = 0) verifies for every message without this check.
    problem = public_key_problem(pub)
    if problem:
        raise Reject("ErrInvalidPublicKey", problem)
    if int.from_bytes(sig[32:], "little") >= ED25519_L:
        raise Reject("ErrSignatureInvalid", "S >= L")
    # The signature equation is checked with our own cofactorless equation; OpenSSL (also
    # cofactorless) must agree, so a disagreement is a checker bug, not a verdict.
    msg = signing_message(h, tag)
    ours = cofactorless_ok(pub, msg, sig)
    try:
        Ed25519PublicKey.from_public_bytes(pub).verify(sig, msg)
        lib = True
    except (InvalidSignature, ValueError):
        lib = False
    if ours != lib:
        raise RuntimeError(f"G1 disagreement: cofactorless={ours}, OpenSSL={lib}")
    if not ours:
        raise Reject("ErrSignatureInvalid", "cofactorless equation fails")


def check_time(c: dict, now: int, p: Params):
    if c["issued_at"] > now + p.skew_s:
        raise Reject("ErrNotYetValid")
    expiry = c["constraints"].get("deadline", c["valid_until"])
    if now + p.skew_s >= expiry:
        raise Reject("ErrExpired")


def check_scope(c: dict, gate: dict):
    s = c["scope"]
    for name in ("gate_id", "rail", "account", "chain_id"):
        if s.get(name) != gate.get(name):
            raise Reject("ErrScopeMismatch", name)


def check_action(c: dict, req: dict):
    a = c["action"]["params"]
    for name in ("account", "conid", "side", "qty", "order_type", "limit_price", "currency", "tif"):
        if a.get(name) != req.get(name):
            raise Reject("ErrActionMismatch", name)


def check_payload(c: dict, blob: bytes):
    if len(blob) != c["payload_size"]:
        raise Reject("ErrPayloadSizeMismatch")
    if hashlib.sha256(blob).digest() != c["ciphertext_hash"]:
        raise Reject("ErrPayloadHashMismatch")


def plaintext_hash(salt: bytes, plaintext: bytes) -> bytes:
    if len(salt) != 32:
        raise ValueError("salt must be 32 bytes")
    return hashlib.sha256(salt + plaintext).digest()


def verify_for_gate(envelope: bytes, now: int, gate: dict, p: Params):
    """Runs decoding, static checks, signature, time, then scope in this fixed
    order, so that every implementation reports the same error for an input with several defects."""
    p.validate()
    signed, canon = decode_signed(envelope)
    c = signed["commitment"]
    validate_static(c, p)
    h = verify_signature(c, canon, signed["signature"])
    check_time(c, now, p)
    check_scope(c, gate)
    return signed, h


# Receipt (gate output). Same CBOR profile as the commitment.

MAX_RECEIPT_SIZE = 512
RAIL_IBKR = 1
PATH_DA = 1
PATH_ARCHIVE = 2

RECEIPT = {
    1: ("version", "uint", True, None),
    2: ("commitment_hash", "bstr", True, (32, 32)),
    3: ("gate_id", "tstr", True, (1, 64, ID_CHARS)),
    4: ("gate_pubkey", "bstr", True, (32, 32)),
    5: ("rail", "uint", True, None),
    6: ("rail_ref", "tstr", True, (1, 128, ID_CHARS)),
    7: ("path", "uint", True, None),
    8: ("executed_at", "uint", True, None),
}

SIGNED_RECEIPT = {
    1: ("receipt", RECEIPT, True, None),
    2: ("signature", "bstr", True, (64, 64)),
}


def receipt_hash(canon: bytes) -> bytes:
    return hashlib.sha256(tagged(TAG_RECEIPT) + canon).digest()


def decode_signed_receipt(data: bytes):
    """Decode and schema-check a signed receipt. Returns (signed dict, canonical receipt bytes)."""
    if len(data) > MAX_RECEIPT_SIZE:
        raise Reject("ErrTooLarge", f"{len(data)} bytes")
    try:
        it = decode_strict(data)
    except CBORError as e:
        raise Reject(e.sentinel, e.detail)
    signed = _schema_decode(it, SIGNED_RECEIPT, "signed_receipt")
    inner = next(v for k, v in it.value if k.value == 1)
    canon = data[inner.start:inner.end]
    if encode(to_cbor(signed["receipt"], RECEIPT)) != canon:
        raise Reject("ErrNonCanonical", "re-encoding differs")
    return signed, canon


def validate_receipt_static(r: dict):
    """Static receipt checks in this fixed order."""
    if r["version"] != 0:
        raise Reject("ErrUnsupportedVersion", str(r["version"]))
    if any(r[n] > MAX_INT for n in ("version", "rail", "path", "executed_at")):
        raise Reject("ErrIntRange")
    if r["rail"] == 0:
        raise Reject("ErrInvalidEnum", "rail=0")
    if r["path"] not in (PATH_DA, PATH_ARCHIVE):
        raise Reject("ErrInvalidEnum", f"path={r['path']}")
    if r["rail"] != RAIL_IBKR:
        raise Reject("ErrUnsupportedRail", str(r["rail"]))
    if r["executed_at"] == 0:
        raise Reject("ErrZeroValue", "executed_at")


def verify_receipt(data: bytes):
    """Decoding, static checks, then signature checks under gate_pubkey.
    Returns (signed, receipt_hash)."""
    signed, canon = decode_signed_receipt(data)
    validate_receipt_static(signed["receipt"])
    h = receipt_hash(canon)
    _verify_tagged_hash(signed["receipt"]["gate_pubkey"], h, signed["signature"], TAG_RECEIPT_SIG)
    return signed, h


# Anchor-relative rules. Exact integers; a uint64 implementation that
# saturates reaches the same verdicts because every left-hand side stays
# below 2^63 + 600.

U64_MAX = (1 << 64) - 1
MARGIN_CAP = 600


def sat_add(a: int, b: int) -> int:
    return min(a + b, U64_MAX)


def check_anchor_time(issued_at: int, block_time: int, skew: int):
    """The agent signed no earlier than the anchor block, up to skew."""
    if sat_add(issued_at, skew) < block_time:
        raise Reject("ErrIssuedBeforeAnchor")


def retention_margin(r: int) -> int:
    return min(MARGIN_CAP, r // 8)


def retention_window(da: int, block_time: int, p: Params, fibre_latest: int | None = None,
                     fibre_at_height: int | None = None, creation_ts: int = 0):
    """Returns (r, start) for the retention check, or None when the creation
    timestamp is unknown (the check then fails). An unreadable at-height retention is a rejection: falling
    back to the latest value could overstate the window if retention was
    lowered after the upload."""
    if da == DA_CELESTIA_BLOB:
        return p.blob_retention_s, block_time
    if fibre_at_height is None:
        raise Reject("ErrRetentionUnavailable")
    if fibre_latest is None or creation_ts == 0:
        return None
    return min(fibre_latest, fibre_at_height), min(block_time, creation_ts)


def within_retention(valid_until: int, start: int, r: int) -> bool:
    """valid_until plus a safety margin must end before the payload leaves retention."""
    return sat_add(valid_until, retention_margin(r)) <= sat_add(start, r)


def route(da: int, within: bool) -> str:
    """Where the payload may come from once the retention check is known. Raises for da = 1 off the DA path."""
    if within:
        return "da"
    if da == DA_FIBRE:
        raise Reject("ErrArchiveRecomputeUnsupported")
    return "archive"


def check_registry_epoch(issued_at: int, epoch: int, skew: int):
    """Nothing signed before the registry existed (plus skew) is admitted."""
    if issued_at <= sat_add(epoch, skew):
        raise Reject("ErrBeforeRegistryEpoch")


# Client order id per rail.

def client_order_id(rail: int, h: bytes) -> str:
    if len(h) != 32:
        raise ValueError("commitment_hash must be 32 bytes")
    if rail == 0:
        raise Reject("ErrInvalidEnum", "rail=0")
    if rail != RAIL_IBKR:
        raise Reject("ErrUnsupportedRail", str(rail))
    return h.hex()
