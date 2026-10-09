"""DecisionCommitment v1 core rules (spec/decision-commitment-v1.md, v1-draft.5).

This module is the Python side of the cross-language check. It must not be
ported from, or to, the Go implementation: agreement between two independent
implementations of the same rules is the point.

The core is platform-agnostic: an action is an opaque byte string bound to the
commitment by its type, a salt and a tagged hash. Nothing here knows any rail.
"""

from __future__ import annotations

import hashlib
import hmac
import re
from dataclasses import dataclass

from cbor_strict import CBORError, Item, decode_strict, encode
from ed25519_point import cofactorless_ok, public_key_problem

TAG_COMMITMENT = b"edicta/v1/decision-commitment"
TAG_SIG = b"edicta/v1/sig"
TAG_ACTION = b"edicta/v1/action"
TAG_AUTHORIZATION = b"edicta/v1/authorization"
TAG_AUTHORIZATION_SIG = b"edicta/v1/authorization-sig"
TAG_RECEIPT = b"edicta/v1/receipt"
TAG_RECEIPT_SIG = b"edicta/v1/receipt-sig"
TAG_RECORD_REQUEST = b"edicta/v1/record-request"
TAG_AUDITOR_KID = b"edicta/v1/auditor-kid"
TAG_BATCH_LEAF = b"edicta/v1/batch-leaf"

VERSION = 1
MAX_SIGNED_SIZE = 2176
MAX_COMMITMENT_SIZE = 2048
MAX_PAYLOAD_SIZE = 1 << 27
MAX_ACTION_SIZE = 1 << 16
MAX_ACTION_TYPE_SIZE = 128
MIN_ACTION_TYPE_SIZE = 3
ACTION_SALT_SIZE = 32
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

DA_FIBRE = 1
DA_CELESTIA_BLOB = 2
SIGNER_SIZE = 20
ANCHOR_PENDING = 2
MODE_STRICT = 1
MODE_FAST = 2
MAX_FAST_WINDOW = 1000
PATH_DA = 1
PATH_ARCHIVE = 2


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


# Field schema: key -> (name, type, presence, limit).
# type: "uint" | "bstr" | "tstr" | "media" | map schema dict.
# presence: True (required), False (optional), or a function of the fields decoded so far
# that returns "required", "optional" or "undefined". Every key of a map precedes the keys
# whose presence it decides, so one pass in ascending key order suffices.
# limit for bstr/tstr/media: (min_len, max_len[, charset]).


def signer_presence(out: dict) -> str:
    """payload_ref key 5: required for da = 2, not defined for da = 1, optional for any other da
    (which S3 then refuses)."""
    if out.get("da") == DA_FIBRE:
        return "undefined"
    return "required" if out.get("da") == DA_CELESTIA_BLOB else "optional"


def deadline_presence(out: dict) -> str:
    if out.get("mode") == MODE_STRICT:
        return "undefined"
    return "required" if out.get("mode") == MODE_FAST else "optional"


# Unassigned keys are left out of the schemas, so a present one is ErrUnknownKey:
# commitment 9 and 15 (reserved), scope 2..4, action 1, 2, payload_ref 7, 8 (reserved),
# receipt 5, 7.
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
    5: ("signer", "bstr", signer_presence, (SIGNER_SIZE, SIGNER_SIZE)),
    6: ("anchor", "uint", False, None),
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
    14: ("mandate_ref", "bstr", False, (32, 32)),
}

ENVELOPE = {
    1: ("commitment", COMMITMENT, True, None),
    2: ("signature", "bstr", True, (64, 64)),
}

MAJOR = {"uint": 0, "bstr": 2, "tstr": 3, "media": 3}


def _presence(req, out: dict) -> str:
    if callable(req):
        return req(out)
    return "required" if req else "optional"


def _schema_decode(it: Item, schema: dict, where: str) -> dict:
    """Stage D for one map: per key in ascending order D15, D16, D18, D19; D17 after the map."""
    if it.major != 5:
        raise Reject("ErrWrongType", f"{where}: expected map")
    out: dict = {}
    for k, v in it.value:
        key = k.value
        if key not in schema:
            raise Reject("ErrUnknownKey", f"{where}: key {key}")
        name, typ, req, limit = schema[key]
        path = f"{where}.{name}"
        if _presence(req, out) == "undefined":
            raise Reject("ErrUnknownKey", f"{path}: not defined here")
        want = 5 if isinstance(typ, dict) else MAJOR[typ]
        if v.major != want:
            raise Reject("ErrWrongType", f"{path}: major {v.major}, want {want}")
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
            if typ is COMMITMENT and v.end - v.start > MAX_COMMITMENT_SIZE:
                raise Reject("ErrTooLarge", f"commitment is {v.end - v.start} bytes")
            out[name] = _schema_decode(v, typ, path)
    for key, (name, _, req, _) in schema.items():
        if _presence(req, out) == "required" and name not in out:
            raise Reject("ErrMissingField", f"{where}.{name}")
    return out


def to_cbor(c: dict, schema: dict = COMMITMENT) -> dict:
    """Named dict -> integer-keyed dict, following the schema."""
    by_name = {f[0]: (k, f) for k, f in schema.items()}
    out = {}
    for name, val in c.items():
        key, (_, typ, _, _) = by_name[name]
        out[key] = to_cbor(val, typ) if isinstance(typ, dict) else val
    return out


def _parse(data: bytes, limit: int) -> Item:
    if len(data) > limit:
        raise Reject("ErrTooLarge", f"{len(data)} bytes")
    try:
        return decode_strict(data)
    except CBORError as e:
        raise Reject(e.sentinel, e.detail)


def _decode_signed(data: bytes, limit: int, schema: dict, where: str):
    it = _parse(data, limit)
    signed = _schema_decode(it, schema, where)
    inner = next(v for k, v in it.value if k.value == 1)
    canon = data[inner.start:inner.end]
    if encode(to_cbor(signed[schema[1][0]], schema[1][1])) != canon:
        raise Reject("ErrNonCanonical", "re-encoding differs")
    return signed, canon


def decode_signed(envelope: bytes):
    """Decode and schema-check a signed envelope. Returns (signed dict, canonical commitment bytes)."""
    return _decode_signed(envelope, MAX_SIGNED_SIZE, ENVELOPE, "envelope")


def commitment_hash(canon: bytes) -> bytes:
    return hashlib.sha256(tagged(TAG_COMMITMENT) + canon).digest()


def signing_message(h: bytes, tag: bytes = TAG_SIG) -> bytes:
    assert len(h) == 32
    return tagged(tag) + h


def is_pending(c: dict) -> bool:
    return c["payload_ref"].get("anchor") == ANCHOR_PENDING


# Action hash. The type is inside the preimage with a one-byte length prefix and the salt has a
# fixed 32 bytes between the type and the bytes, so tag || type || salt || bytes splits one way only.

def action_type_ok(t: str) -> bool:
    return media_type_ok(t, MIN_ACTION_TYPE_SIZE, MAX_ACTION_TYPE_SIZE)


def action_preimage_prefix(action_type: str) -> bytes:
    t = action_type.encode("ascii")
    return tagged(TAG_ACTION) + bytes([len(t)]) + t


def action_hash(action_type: str, salt: bytes, action: bytes) -> bytes:
    if len(salt) != ACTION_SALT_SIZE:
        raise ValueError("action salt must be 32 bytes")
    if not 1 <= len(action) <= MAX_ACTION_SIZE:
        raise Reject("ErrActionSize", f"{len(action)} bytes")
    if not action_type_ok(action_type):
        raise Reject("ErrInvalidString", f"action type {action_type!r}")
    return hashlib.sha256(action_preimage_prefix(action_type) + salt + action).digest()


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
    # Celestia user namespace: version 0, 18 zero bytes, and the first 9 sub-id bytes not
    # all zero, which excludes the primary reserved range.
    return ns[0] == 0 and not any(ns[1:19]) and any(ns[19:28])


def validate_static(c: dict, p: Params):
    """Stage S in this fixed order, so that every implementation reports the same error for an
    input with several defects: S1, S2, S3, S4 (anchor), S6, S7, S8, S12, S14."""
    r = c["payload_ref"]
    if c["version"] != VERSION:
        raise Reject("ErrUnsupportedVersion", str(c["version"]))
    if any(x > MAX_INT for x in (c["version"], c["issued_at"], c["valid_until"], c["payload_size"],
                                 r["da"], r["height"], r.get("anchor", 0))):
        raise Reject("ErrIntRange")
    if r["da"] not in (DA_FIBRE, DA_CELESTIA_BLOB):
        raise Reject("ErrInvalidEnum", f"da={r['da']}")
    if "anchor" in r and r["anchor"] != ANCHOR_PENDING:
        raise Reject("ErrInvalidEnum", f"anchor={r['anchor']}")
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


def _verify_tagged_hash(pub: bytes, h: bytes, sig: bytes, tag: bytes = TAG_SIG):
    """Signature checks for a public key and an already domain-separated hash."""
    _verify_message(pub, signing_message(h, tag), sig)


def _verify_message(pub: bytes, msg: bytes, sig: bytes):
    """Public-key validity, then S < L, then the cofactorless equation over msg."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    # Public-key validity is checked here, not left to the library: OpenSSL (via 'cryptography')
    # accepts small-order and non-canonical public keys, so (A = identity,
    # R = identity, S = 0) verifies for every message without this check.
    problem = public_key_problem(pub)
    if problem:
        raise Reject("ErrInvalidPublicKey", problem)
    if len(sig) != 64 or int.from_bytes(sig[32:], "little") >= ED25519_L:
        raise Reject("ErrSignatureInvalid", "S >= L")
    # The signature equation is checked with our own cofactorless equation; OpenSSL (also
    # cofactorless) must agree, so a disagreement is a checker bug, not a verdict.
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


def verify_signature(c: dict, canon: bytes, sig: bytes) -> bytes:
    """Public-key validity, then S < L, then the signature equation. Returns commitment_hash."""
    h = commitment_hash(canon)
    _verify_tagged_hash(c["agent_pubkey"], h, sig)
    return h


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


def check_salt(salt: bytes | None):
    """Gate A0s and executor X2s: the salt presented with the action bytes is exactly 32 bytes."""
    if salt is None or len(salt) == 0:
        raise Reject("ErrMissingField", "action_salt")
    if len(salt) != ACTION_SALT_SIZE:
        raise Reject("ErrFieldSize", f"action_salt {len(salt)} bytes")


def action_matches(action_type: str, salt: bytes, action: bytes, committed: bytes) -> bool:
    return hmac.compare_digest(action_hash(action_type, salt, action), committed)


def check_action(c: dict, action: bytes, salt: bytes | None):
    """Stage A: A0 size, A0s salt, A1 exact match of the salted hash under the committed type."""
    if not 1 <= len(action) <= MAX_ACTION_SIZE:
        raise Reject("ErrActionSize", f"{len(action)} bytes")
    check_salt(salt)
    if not action_matches(c["action"]["type"], salt, action, c["action"]["hash"]):
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
    """D, S, G, T, then C in this fixed order, so that every implementation reports the same error
    for an input with several defects. Returns (signed, commitment_hash)."""
    p.validate()
    signed, canon = decode_signed(envelope)
    c = signed["commitment"]
    validate_static(c, p)
    h = verify_signature(c, canon, signed["signature"])
    check_time(c, now, p)
    check_scope(c, gate)
    return signed, h


# Authorization (gate output, checked by the integrator's executor).

AUTHORIZATION = {
    1: ("version", "uint", True, None),
    2: ("commitment_hash", "bstr", True, (32, 32)),
    3: ("action_hash", "bstr", True, (32, 32)),
    4: ("gate_id", "tstr", True, (1, 64, ID_CHARS)),
    5: ("expires", "uint", True, None),
    6: ("path", "uint", True, None),
    7: ("mode", "uint", True, None),
    8: ("anchor_deadline", "uint", deadline_presence, None),
}

SIGNED_AUTHORIZATION = {
    1: ("authorization", AUTHORIZATION, True, None),
    2: ("signature", "bstr", True, (64, 64)),
}


def authorization_hash(canon: bytes) -> bytes:
    return hashlib.sha256(tagged(TAG_AUTHORIZATION) + canon).digest()


def authorization_message(h: bytes) -> bytes:
    return tagged(TAG_AUTHORIZATION_SIG) + h


def decode_signed_authorization(data: bytes):
    """Decode and schema-check a signed Authorization. Returns (signed dict, canonical Authorization bytes)."""
    return _decode_signed(data, MAX_AUTHORIZATION_SIZE, SIGNED_AUTHORIZATION, "signed_authorization")


def validate_authorization_static(a: dict):
    """Q1, Q2, Q3, Q5, Q4, Q6 in this order."""
    if a["version"] != VERSION:
        raise Reject("ErrUnsupportedVersion", str(a["version"]))
    if any(a[n] > MAX_INT for n in ("version", "expires", "path", "mode", "anchor_deadline") if n in a):
        raise Reject("ErrIntRange")
    if a["path"] not in (PATH_DA, PATH_ARCHIVE):
        raise Reject("ErrInvalidEnum", f"path={a['path']}")
    if a["mode"] not in (MODE_STRICT, MODE_FAST):
        raise Reject("ErrInvalidEnum", f"mode={a['mode']}")
    if a["expires"] == 0:
        raise Reject("ErrZeroValue", "expires")
    if a.get("anchor_deadline") == 0:
        raise Reject("ErrZeroValue", "anchor_deadline")


@dataclass(frozen=True)
class AuthorizationCheck:
    """What an executor knows on its own: the pinned gate key and id, the action type it executes,
    the exact bytes it is about to execute with the salt presented alongside (None: absent), its clock."""
    gate_pubkey: bytes
    gate_id: str
    action_type: str
    action: bytes
    now: int
    skew_s: int
    action_salt: bytes | None = None


def verify_authorization(data: bytes, chk: AuthorizationCheck):
    """Decoding, static checks, signature under the pinned gate key, then the executor checks
    X1, X2, X2s, X3, X4 in this fixed order. Returns (signed, authorization_hash)."""
    signed, canon = decode_signed_authorization(data)
    a = signed["authorization"]
    validate_authorization_static(a)
    h = authorization_hash(canon)
    _verify_tagged_hash(chk.gate_pubkey, h, signed["signature"], TAG_AUTHORIZATION_SIG)
    if a["gate_id"] != chk.gate_id:
        raise Reject("ErrScopeMismatch", "gate_id")
    if not 1 <= len(chk.action) <= MAX_ACTION_SIZE:
        raise Reject("ErrActionSize", f"{len(chk.action)} bytes")
    check_salt(chk.action_salt)
    if not action_matches(chk.action_type, chk.action_salt, chk.action, a["action_hash"]):
        raise Reject("ErrActionMismatch")
    if chk.now + chk.skew_s >= a["expires"]:
        raise Reject("ErrExpired")
    return signed, h


def authorization_expires(valid_until: int, authorized_at: int, max_ttl: int) -> int:
    return min(valid_until, authorized_at + max_ttl)


# Record request: an allowlisted executor's signed claim of a rail reference for one decision at
# one gate. Both variable fields carry a length byte, so gate_id || rail_ref splits one way only.

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
    _verify_message(executor_pubkey, msg, sig)


def verify_record_request(commitment_hash_: bytes, agent_pubkey: bytes, gate_id: str, rail_ref: str,
                          executor_pubkey: bytes, sig: bytes, executor_keys: list, gate_keys: list):
    """The stateless part of the gate's Record, in this fixed order: rail_ref, signature under the
    presented executor key, allowlist, key roles."""
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
    return _decode_signed(data, MAX_RECEIPT_SIZE, SIGNED_RECEIPT, "signed_receipt")


def validate_receipt_static(r: dict):
    """Static receipt checks in this fixed order."""
    if r["version"] != VERSION:
        raise Reject("ErrUnsupportedVersion", str(r["version"]))
    if any(r[n] > MAX_INT for n in ("version", "recorded_at")):
        raise Reject("ErrIntRange")
    if r["recorded_at"] == 0:
        raise Reject("ErrZeroValue", "recorded_at")
    if r["executor_pubkey"] == r["gate_pubkey"]:
        raise Reject("ErrKeyRole", "executor key equals the gate key")


def verify_receipt(data: bytes):
    """Decoding, static checks, then signature checks under gate_pubkey. Returns (signed, receipt_hash)."""
    signed, canon = decode_signed_receipt(data)
    validate_receipt_static(signed["receipt"])
    h = receipt_hash(canon)
    r = signed["receipt"]
    _verify_tagged_hash(r["gate_pubkey"], h, signed["signature"], TAG_RECEIPT_SIG)
    verify_record_signature(r["executor_pubkey"], record_message(r["commitment_hash"], r["gate_id"], r["rail_ref"]),
                            r["executor_signature"])
    return signed, h


# Anchor-relative rules. Exact integers; a uint64 implementation that saturates reaches the same
# verdicts because every left-hand side stays below 2^63 + 600.

U64_MAX = (1 << 64) - 1
MARGIN_CAP = 600


def sat_add(a: int, b: int) -> int:
    return min(a + b, U64_MAX)


def check_anchor_time(issued_at: int, t_ref: int, skew: int):
    """K1: the agent signed no earlier than the reference time, up to skew."""
    if sat_add(issued_at, skew) < t_ref:
        raise Reject("ErrIssuedBeforeAnchor")


def retention_margin(r: int) -> int:
    return min(MARGIN_CAP, r // 8)


def retention_window(da: int, block_time: int, p: Params, fibre_latest: int | None = None,
                     fibre_at_height: int | None = None, creation_ts: int = 0):
    """Returns (r, start) for the retention check of an included reference, or None when the
    creation timestamp is unknown (the check then fails). An unreadable at-height retention is a
    rejection: falling back to the latest value could overstate the window if retention was lowered
    after the upload."""
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
    """Where the payload may come from once the retention check is known. Raises for da = 1 off the
    DA path at a gate without a Fibre committer."""
    if within:
        return "da"
    if da == DA_FIBRE:
        raise Reject("ErrArchiveRecomputeUnsupported")
    return "archive"


def check_registry_epoch(issued_at: int, epoch: int, skew: int):
    """Nothing signed before the registry existed (plus skew) is admitted."""
    if issued_at <= sat_add(epoch, skew):
        raise Reject("ErrBeforeRegistryEpoch")


def retention_start(da: int, pending: bool, t_ref: int, creation_ts: int = 0, created_at: int = 0) -> int:
    """K2 start: min(T_ref, promise creation) for an included Fibre reference, min(T_ref, intent
    created_at) for a pending one, T_ref for da = 2."""
    if da == DA_CELESTIA_BLOB:
        return t_ref
    return min(t_ref, created_at if pending else creation_ts)


# Gate configuration, stage K-fast window and slack.

GATE_CONFIG_DEFAULTS = {"fast_mode": False, "fast_window_blocks": 100, "max_h0_age_blocks": 10,
                        "min_fast_slack_blocks": 3, "min_promise_slack_seconds": 15, "rebroadcast_intent": True}


# Compiled profile registry: action type -> public_execution (the profile documents, section "Public execution").
PROFILE_REGISTRY = {"application/vnd.edicta.ibkr.order.v0+cbor": False,
                    "application/vnd.edicta.cosmos.bank-send.v0+cbor": True}


def validate_gate_config(cfg: dict, mandate: bool, allowlist: list, registry: dict | None = None,
                         mandate_fast_mode_max_delay: int | None = None):
    """ValidateBasic in table order, then the cross-field rule, then the constructor's mandate checks.
    Raises Reject("ErrInvalidConfig", cause)."""
    registry = PROFILE_REGISTRY if registry is None else registry
    c = dict(GATE_CONFIG_DEFAULTS, **cfg)
    bad = lambda cause: Reject("ErrInvalidConfig", cause)
    if c["fast_mode"] and not c.get("pending_namespaces"):
        raise bad("pending_namespaces")
    if c["fast_mode"] and not c.get("archive", True):
        raise bad("archive")
    if not 1 <= c["fast_window_blocks"] <= MAX_FAST_WINDOW:
        raise bad("fast_window_blocks")
    if not 1 <= c["max_h0_age_blocks"] <= c["fast_window_blocks"] - 1:
        raise bad("max_h0_age_blocks")
    if not 1 <= c["min_fast_slack_blocks"] <= 100:
        raise bad("min_fast_slack_blocks")
    if not 1 <= c["min_promise_slack_seconds"] <= 600:
        raise bad("min_promise_slack_seconds")
    for ns in c.get("pending_namespaces", []):
        if len(ns) != 29 or not namespace_ok(ns):
            raise bad("pending_namespaces")
    for t in c.get("reveal_on_execution", []):
        if t not in allowlist:
            raise bad("reveal_on_execution")
        # Revealing the salt of an action whose bytes are not public makes it testable against action_hash.
        if registry.get(t) is not True:
            raise bad("reveal_not_public_execution")
    if c["max_h0_age_blocks"] + c["min_fast_slack_blocks"] > c["fast_window_blocks"]:
        raise bad("age_plus_slack")
    if c["fast_mode"] and not mandate:
        raise bad("fast_mode_without_mandate")
    # A deadline at most fast_mode_max_delay above h0 must leave the slack above a head one block past h0.
    if (c["fast_mode"] and mandate_fast_mode_max_delay is not None
            and mandate_fast_mode_max_delay < c["min_fast_slack_blocks"] + 1):
        raise bad("fast_delay_below_slack")


def fast_window(da: int, h0: int, head: int, fast_window_blocks: int, max_h0_age: int,
                fast_mode_max_delay: int, chain_window: int | None = None, timeout_height: int = 0,
                min_fast_slack: int = 3, included: tuple | None = None, promise: dict | None = None) -> int:
    """F3/B3 head bound, then F5/B4 in order, then the F6/B5 lookup that may waive a provisional failure.
    included = (H, code) when the lookup finds the tx; promise = {t_head, creation, timeout, min_slack}
    for da = 1. Returns anchor_deadline."""
    if head < h0:
        raise Reject("ErrChainUnavailable", "head below h0")
    if head - h0 > max_h0_age:
        raise Reject("ErrH0TooOld")
    window = min(fast_window_blocks, fast_mode_max_delay)
    if da == DA_FIBRE:
        if chain_window is None:
            raise ValueError("da = 1 needs the chain window")
        window = min(window, chain_window)
    if window < 1:
        raise Reject("ErrAnchorWindowClosed", "window 0")
    deadline = h0 + window
    if da == DA_CELESTIA_BLOB and 0 < timeout_height < deadline:
        deadline = timeout_height
    provisional = deadline < head + min_fast_slack
    if da == DA_FIBRE and promise is not None:
        if promise["t_head"] + promise["min_slack"] >= promise["creation"] + promise["timeout"]:
            provisional = True
    if included is not None:
        H, code = included
        if code == 0 and h0 <= H <= deadline:
            return deadline
        raise Reject("ErrAnchorWindowClosed", "included outside the window or with a nonzero code")
    if provisional:
        raise Reject("ErrAnchorWindowClosed", "slack")
    return deadline
