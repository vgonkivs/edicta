"""DecisionCommitment v0 rules (v0-draft.9).

This module is the Python side of the cross-language check. It must not be
ported from, or to, the Go implementation: agreement between two independent
implementations of the same rules is the point.

The core is platform-agnostic: an action is an opaque byte string bound to the
commitment by its type and a tagged hash. Nothing here knows any rail.
"""

from __future__ import annotations

import hashlib
import hmac
import re
from dataclasses import dataclass

from cbor_strict import CBORError, Item, decode_strict, encode
from ed25519_point import cofactorless_ok, public_key_problem

TAG_COMMITMENT = b"edicta/v0/decision-commitment"
TAG_SIG = b"edicta/v0/sig"
TAG_RECEIPT = b"edicta/v0/receipt"
TAG_RECEIPT_SIG = b"edicta/v0/receipt-sig"
TAG_ACTION = b"edicta/v0/action"
TAG_AUTHORIZATION = b"edicta/v0/authorization"
TAG_AUTHORIZATION_SIG = b"edicta/v0/authorization-sig"
TAG_RECORD_REQUEST = b"edicta/v0/record-request"

MAX_SIGNED_SIZE = 2176
MAX_COMMITMENT_SIZE = 2048
MAX_PAYLOAD_SIZE = 1 << 27
MAX_ACTION_SIZE = 1 << 16
MAX_ACTION_TYPE_SIZE = 128
MIN_ACTION_TYPE_SIZE = 3
MAX_AUTHORIZATION_SIZE = 256
MAX_RECEIPT_SIZE = 512
MAX_INT = (1 << 63) - 1
MAX_TTL_CAP = 3600
ED25519_L = 2**252 + 27742317777372353535851937790883648493

ID_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._:/-")
PRINTABLE = frozenset(chr(c) for c in range(0x20, 0x7F))
MEDIA_CHARS = frozenset("abcdefghijklmnopqrstuvwxyz0123456789!#$&^_.+-/")
_MEDIA_PART = r"[a-z0-9][a-z0-9!#$&^_.+-]*"
_MEDIA_RE = re.compile(rf"^{_MEDIA_PART}/{_MEDIA_PART}$")


class Reject(Exception):
    def __init__(self, sentinel: str, detail: str = ""):
        super().__init__(f"{sentinel}: {detail}" if detail else sentinel)
        self.sentinel = sentinel
        self.detail = detail


def tagged(tag: bytes) -> bytes:
    if not 1 <= len(tag) <= 255:
        raise ValueError("tag length out of range")
    return bytes([len(tag)]) + tag


def media_type_ok(s: str, lo: int, hi: int) -> bool:
    """Lower-case type/subtype, one slash, no parameters, no whitespace."""
    return lo <= len(s) <= hi and all(c in MEDIA_CHARS for c in s) and _MEDIA_RE.match(s) is not None


# Field schema: key -> (name, type, required, limit)
# type: "uint" | "bstr" | "tstr" | "media" | map schema dict
# required: True, False, or DA_BLOB_ONLY (payload_ref.signer: required when
# da == 2, not defined when da == 1, optional for any other da, which the enum check rejects).
# limit for bstr/tstr/media: (min_len, max_len[, charset]). A "media" string is
# a tstr checked for length first, then for the media-type grammar.

DA_FIBRE = 1
DA_CELESTIA_BLOB = 2
DA_BLOB_ONLY = "da=celestia_blob"
SIGNER_SIZE = 20

# Retired keys are left out of the schemas, so they decode as ErrUnknownKey:
# commitment 9 (constraints), action 1 (kind), 2 (params), scope 2 (rail),
# 3 (account), 4 (chain_id),
# receipt 5 (rail), 7 (path), payload 6 (constraints).
SCOPE = {
    1: ("gate_id", "tstr", True, (1, 64, ID_CHARS)),
}

ACTION = {
    3: ("type", "media", True, (MIN_ACTION_TYPE_SIZE, MAX_ACTION_TYPE_SIZE)),
    4: ("hash", "bstr", True, (32, 32)),
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
    10: ("payload_ref", PAYLOAD_REF, True, None),
    11: ("ciphertext_hash", "bstr", True, (32, 32)),
    12: ("plaintext_hash", "bstr", True, (32, 32)),
    13: ("payload_size", "uint", True, None),
}

ENVELOPE = {
    1: ("commitment", COMMITMENT, True, None),
    2: ("signature", "bstr", True, (64, 64)),
}

MAJOR = {"uint": 0, "bstr": 2, "tstr": 3, "media": 3}


def _schema_decode(it: Item, schema: dict, where: str, size_limits: dict | None = None) -> dict:
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
        elif typ == "media":
            lo, hi = limit
            if not lo <= len(v.value.encode("utf-8")) <= hi:
                raise Reject("ErrFieldSize", f"{path}: {len(v.value.encode('utf-8'))} bytes")
            if not media_type_ok(v.value, lo, hi):
                raise Reject("ErrInvalidString", f"{path}: not a lower-case type/subtype")
            out[name] = v.value
        elif typ == "uint":
            out[name] = v.value
        else:
            if size_limits and typ is not None and id(typ) in size_limits:
                limit_bytes, what = size_limits[id(typ)]
                if v.end - v.start > limit_bytes:
                    raise Reject("ErrTooLarge", f"{what} is {v.end - v.start} bytes")
            out[name] = _schema_decode(v, typ, path, size_limits)
    for key, (name, _, required, _) in schema.items():
        if required == DA_BLOB_ONLY:
            required = out.get("da") == DA_CELESTIA_BLOB
        if required and name not in out:
            raise Reject("ErrMissingField", f"{where}.{name}")
    return out


def _decode_signed(data: bytes, limit: int, schema: dict, inner_schema: dict, where: str,
                   size_limits: dict | None = None):
    if len(data) > limit:
        raise Reject("ErrTooLarge", f"{len(data)} bytes")
    try:
        it = decode_strict(data)
    except CBORError as e:
        raise Reject(e.sentinel, e.detail)
    signed = _schema_decode(it, schema, where, size_limits)
    inner = next(v for k, v in it.value if k.value == 1)
    canon = data[inner.start:inner.end]
    inner_name = schema[1][0]
    if encode(to_cbor(signed[inner_name], inner_schema)) != canon:
        raise Reject("ErrNonCanonical", "re-encoding differs")
    return signed, canon


def decode_signed(envelope: bytes):
    """Decode and schema-check a signed envelope. Returns (signed dict, canonical commitment bytes)."""
    return _decode_signed(envelope, MAX_SIGNED_SIZE, ENVELOPE, COMMITMENT, "envelope",
                          {id(COMMITMENT): (MAX_COMMITMENT_SIZE, "commitment")})


def to_cbor(c: dict, schema: dict = COMMITMENT) -> dict:
    """Named dict -> integer-keyed dict, following the schema."""
    by_name = {f[0]: (k, f) for k, f in schema.items()}
    out = {}
    for name, val in c.items():
        key, (_, typ, _, _) = by_name[name]
        out[key] = to_cbor(val, typ) if isinstance(typ, dict) else val
    return out


def commitment_hash(canon: bytes) -> bytes:
    return hashlib.sha256(tagged(TAG_COMMITMENT) + canon).digest()


def signing_message(h: bytes, tag: bytes = TAG_SIG) -> bytes:
    assert len(h) == 32
    return tagged(tag) + h


# Action hash. The type is inside the preimage with a one-byte length prefix,
# so bytes committed under one type never match under another, and
# type || bytes splits one way only.

def action_type_ok(t: str) -> bool:
    return media_type_ok(t, MIN_ACTION_TYPE_SIZE, MAX_ACTION_TYPE_SIZE)


def action_preimage_prefix(action_type: str) -> bytes:
    t = action_type.encode("ascii")
    return tagged(TAG_ACTION) + bytes([len(t)]) + t


def action_hash(action_type: str, action: bytes) -> bytes:
    if not 1 <= len(action) <= MAX_ACTION_SIZE:
        raise Reject("ErrActionSize", f"{len(action)} bytes")
    if not action_type_ok(action_type):
        raise Reject("ErrInvalidString", f"action type {action_type!r}")
    return hashlib.sha256(action_preimage_prefix(action_type) + action).digest()


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


def namespace_ok(ns: bytes) -> bool:
    # Celestia v0 user namespace: version 0, 18 zero bytes, and the first 9
    # sub-id bytes not all zero, which excludes the primary reserved range.
    return ns[0] == 0 and not any(ns[1:19]) and any(ns[19:28])


def validate_static(c: dict, p: Params):
    """Static checks in this fixed order, so that every implementation
    reports the same error for an input with several defects."""
    r = c["payload_ref"]
    if c["version"] != 0:
        raise Reject("ErrUnsupportedVersion", str(c["version"]))
    if any(v > MAX_INT for v in (c["version"], c["issued_at"], c["valid_until"], c["payload_size"],
                                 r["da"], r["height"])):
        raise Reject("ErrIntRange")
    if r["da"] not in (DA_FIBRE, DA_CELESTIA_BLOB):
        raise Reject("ErrInvalidEnum", f"da={r['da']}")
    for name, val in (("issued_at", c["issued_at"]), ("height", r["height"]), ("payload_size", c["payload_size"])):
        if val == 0:
            raise Reject("ErrZeroValue", name)
    if c["payload_size"] > MAX_PAYLOAD_SIZE:
        raise Reject("ErrPayloadTooLarge")
    if not namespace_ok(r["namespace"]):
        raise Reject("ErrInvalidNamespace")
    if c["valid_until"] <= c["issued_at"]:
        raise Reject("ErrTimeOrder")
    if c["valid_until"] - c["issued_at"] > p.max_ttl(r["da"]):
        raise Reject("ErrTTLTooLong")


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
    if now + p.skew_s >= c["valid_until"]:
        raise Reject("ErrExpired")


def check_scope(c: dict, gate: dict):
    """gate: {"gate_id": str, "action_types": [str, ...]}."""
    if c["scope"]["gate_id"] != gate["gate_id"]:
        raise Reject("ErrScopeMismatch", "gate_id")
    if c["action"]["type"] not in gate["action_types"]:
        raise Reject("ErrActionTypeNotAllowed", c["action"]["type"])


def check_action(c: dict, action: bytes):
    """Exact match: the supplied bytes hash, under the committed type, to the committed hash."""
    if not 1 <= len(action) <= MAX_ACTION_SIZE:
        raise Reject("ErrActionSize", f"{len(action)} bytes")
    got = action_hash(c["action"]["type"], action)
    if not hmac.compare_digest(got, c["action"]["hash"]):
        raise Reject("ErrActionMismatch")


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


# Authorization (gate output, checked by the integrator's executor).

PATH_DA = 1
PATH_ARCHIVE = 2

AUTHORIZATION = {
    1: ("version", "uint", True, None),
    2: ("commitment_hash", "bstr", True, (32, 32)),
    3: ("action_hash", "bstr", True, (32, 32)),
    4: ("gate_id", "tstr", True, (1, 64, ID_CHARS)),
    5: ("expires", "uint", True, None),
    6: ("path", "uint", True, None),
}

SIGNED_AUTHORIZATION = {
    1: ("authorization", AUTHORIZATION, True, None),
    2: ("signature", "bstr", True, (64, 64)),
}


def authorization_hash(canon: bytes) -> bytes:
    return hashlib.sha256(tagged(TAG_AUTHORIZATION) + canon).digest()


def decode_signed_authorization(data: bytes):
    """Decode and schema-check a signed Authorization. Returns (signed dict, canonical Authorization bytes)."""
    return _decode_signed(data, MAX_AUTHORIZATION_SIZE, SIGNED_AUTHORIZATION, AUTHORIZATION,
                          "signed_authorization")


def validate_authorization_static(a: dict):
    if a["version"] != 0:
        raise Reject("ErrUnsupportedVersion", str(a["version"]))
    if any(a[n] > MAX_INT for n in ("version", "expires", "path")):
        raise Reject("ErrIntRange")
    if a["path"] not in (PATH_DA, PATH_ARCHIVE):
        raise Reject("ErrInvalidEnum", f"path={a['path']}")
    if a["expires"] == 0:
        raise Reject("ErrZeroValue", "expires")


@dataclass(frozen=True)
class AuthorizationCheck:
    """What an executor knows on its own: the pinned gate key and id, the
    action type it executes, the exact bytes it is about to execute, its clock."""
    gate_pubkey: bytes
    gate_id: str
    action_type: str
    action: bytes
    now: int
    skew_s: int


def verify_authorization(data: bytes, chk: AuthorizationCheck):
    """Decoding, static checks, signature under the pinned gate key, then the
    executor checks in this fixed order. Returns (signed, authorization_hash)."""
    signed, canon = decode_signed_authorization(data)
    a = signed["authorization"]
    validate_authorization_static(a)
    h = authorization_hash(canon)
    _verify_tagged_hash(chk.gate_pubkey, h, signed["signature"], TAG_AUTHORIZATION_SIG)
    if a["gate_id"] != chk.gate_id:
        raise Reject("ErrScopeMismatch", "gate_id")
    if not 1 <= len(chk.action) <= MAX_ACTION_SIZE:
        raise Reject("ErrActionSize", f"{len(chk.action)} bytes")
    if not hmac.compare_digest(action_hash(chk.action_type, chk.action), a["action_hash"]):
        raise Reject("ErrActionMismatch")
    if chk.now + chk.skew_s >= a["expires"]:
        raise Reject("ErrExpired")
    return signed, h


def authorization_expires(valid_until: int, authorized_at: int, max_ttl: int) -> int:
    return min(valid_until, authorized_at + max_ttl)


# Record request: an allowlisted executor's signed claim of a rail reference
# for one decision at one gate. Both variable fields carry a length byte, so
# gate_id || rail_ref splits one way only.

RAIL_REF_CHARS = ID_CHARS
MAX_RAIL_REF = 128


def check_rail_ref(rail_ref: str):
    if not 1 <= len(rail_ref.encode("utf-8")) <= MAX_RAIL_REF:
        raise Reject("ErrFieldSize", f"rail_ref of {len(rail_ref.encode('utf-8'))} bytes")
    if any(c not in RAIL_REF_CHARS for c in rail_ref):
        raise Reject("ErrInvalidString", "rail_ref character outside the ID charset")


def record_message(commitment_hash_: bytes, gate_id: str, rail_ref: str) -> bytes:
    assert len(commitment_hash_) == 32
    g = gate_id.encode("ascii")
    r = rail_ref.encode("ascii")
    assert 1 <= len(g) <= 64 and 1 <= len(r) <= MAX_RAIL_REF
    return tagged(TAG_RECORD_REQUEST) + commitment_hash_ + bytes([len(g)]) + g + bytes([len(r)]) + r


def verify_record_signature(executor_pubkey: bytes, msg: bytes, sig: bytes):
    """Key validity, S < L, then the cofactorless equation, over the record message itself."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    problem = public_key_problem(executor_pubkey)
    if problem:
        raise Reject("ErrInvalidPublicKey", problem)
    if len(sig) != 64 or int.from_bytes(sig[32:], "little") >= ED25519_L:
        raise Reject("ErrSignatureInvalid", "S >= L")
    ours = cofactorless_ok(executor_pubkey, msg, sig)
    try:
        Ed25519PublicKey.from_public_bytes(executor_pubkey).verify(sig, msg)
        lib = True
    except (InvalidSignature, ValueError):
        lib = False
    if ours != lib:
        raise RuntimeError(f"G1 disagreement: cofactorless={ours}, OpenSSL={lib}")
    if not ours:
        raise Reject("ErrSignatureInvalid", "cofactorless equation fails")


def verify_record_request(commitment_hash_: bytes, agent_pubkey: bytes, gate_id: str, rail_ref: str,
                          executor_pubkey: bytes, sig: bytes, executor_keys: list, gate_keys: list):
    """The stateless part of the gate's Record, in this fixed order: rail_ref,
    signature under the presented executor key, allowlist, key roles."""
    check_rail_ref(rail_ref)
    verify_record_signature(executor_pubkey, record_message(commitment_hash_, gate_id, rail_ref), sig)
    if executor_pubkey not in executor_keys:
        raise Reject("ErrExecutorNotAllowed")
    if executor_pubkey == agent_pubkey or executor_pubkey in gate_keys:
        raise Reject("ErrKeyRole", "executor key is also an agent or gate key")


# Receipt (gate notarization of an allowlisted executor's claim).

RECEIPT = {
    1: ("version", "uint", True, None),
    2: ("commitment_hash", "bstr", True, (32, 32)),
    3: ("gate_id", "tstr", True, (1, 64, ID_CHARS)),
    4: ("gate_pubkey", "bstr", True, (32, 32)),
    6: ("rail_ref", "tstr", True, (1, 128, ID_CHARS)),
    8: ("recorded_at", "uint", True, None),
    9: ("executor_pubkey", "bstr", True, (32, 32)),
    10: ("executor_signature", "bstr", True, (64, 64)),
}

SIGNED_RECEIPT = {
    1: ("receipt", RECEIPT, True, None),
    2: ("signature", "bstr", True, (64, 64)),
}


def receipt_hash(canon: bytes) -> bytes:
    return hashlib.sha256(tagged(TAG_RECEIPT) + canon).digest()


def decode_signed_receipt(data: bytes):
    """Decode and schema-check a signed receipt. Returns (signed dict, canonical receipt bytes)."""
    return _decode_signed(data, MAX_RECEIPT_SIZE, SIGNED_RECEIPT, RECEIPT, "signed_receipt")


def validate_receipt_static(r: dict):
    """Static receipt checks in this fixed order."""
    if r["version"] != 0:
        raise Reject("ErrUnsupportedVersion", str(r["version"]))
    if any(r[n] > MAX_INT for n in ("version", "recorded_at")):
        raise Reject("ErrIntRange")
    if r["recorded_at"] == 0:
        raise Reject("ErrZeroValue", "recorded_at")
    if r["executor_pubkey"] == r["gate_pubkey"]:
        raise Reject("ErrKeyRole", "executor key equals the gate key")


def verify_receipt(data: bytes):
    """Decoding, static checks, then signature checks under gate_pubkey.
    Returns (signed, receipt_hash)."""
    signed, canon = decode_signed_receipt(data)
    validate_receipt_static(signed["receipt"])
    h = receipt_hash(canon)
    r = signed["receipt"]
    _verify_tagged_hash(r["gate_pubkey"], h, signed["signature"], TAG_RECEIPT_SIG)
    verify_record_signature(r["executor_pubkey"], record_message(r["commitment_hash"], r["gate_id"], r["rail_ref"]),
                            r["executor_signature"])
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
