"""DecisionCommitment v1 and Authorization v1 rules (v1-draft.4).

Python side of the cross-language check for format v1. Everything v1 does not
change is taken from edicta_v0 (the frozen v0 rules), including the whole v0
path of the version dispatch, so a v1 reader gives exactly the v0 outcome for
v0 bytes.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass, field

import edicta_v0 as v0
from cbor_strict import CBORError, Item, decode_strict, encode
from edicta_v0 import ID_CHARS, MAX_INT, Params, Reject, tagged

TAG_COMMITMENT_V1 = b"edicta/v1/decision-commitment"
TAG_SIG_V1 = b"edicta/v1/sig"
TAG_AUTHORIZATION_V1 = b"edicta/v1/authorization"
TAG_AUTHORIZATION_SIG_V1 = b"edicta/v1/authorization-sig"
TAG_BATCH_LEAF = b"edicta/v1/batch-leaf"
TAG_ACTION_V1 = b"edicta/v1/action"
TAG_AUDITOR_KID = b"edicta/v1/auditor-kid"
ACTION_SALT_SIZE = 32

ANCHOR_PENDING = 2
MODE_STRICT = 1
MODE_FAST = 2
MAX_FAST_WINDOW = 1000

# Schema entries: key -> (name, type, presence, limit), as edicta_v0, where
# presence is True, False, or a function of the fields decoded so far that
# returns "required", "optional" or "undefined". Every key of a map precedes the
# keys whose presence it decides, so one pass in ascending key order suffices.


def _signer_presence(out: dict) -> str:
    if out.get("da") == v0.DA_FIBRE:
        return "undefined"
    return "required" if out.get("da") == v0.DA_CELESTIA_BLOB else "optional"


def _deadline_presence(out: dict) -> str:
    if out.get("mode") == MODE_STRICT:
        return "undefined"
    return "required" if out.get("mode") == MODE_FAST else "optional"


# Commitment key 15 and payload_ref keys 7, 8 are reserved and left out, so
# they decode as ErrUnknownKey, as do the retired keys of v0.
PAYLOAD_REF_V1 = {
    1: ("da", "uint", True, None),
    2: ("namespace", "bstr", True, (29, 29)),
    3: ("commitment", "bstr", True, (32, 32)),
    4: ("height", "uint", True, None),
    5: ("signer", "bstr", _signer_presence, (20, 20)),
    6: ("anchor", "uint", False, None),
}

COMMITMENT_V1 = {
    1: ("version", "uint", True, None),
    2: ("agent_id", "tstr", True, (1, 64, ID_CHARS)),
    3: ("agent_pubkey", "bstr", True, (32, 32)),
    4: ("nonce", "bstr", True, (16, 16)),
    5: ("issued_at", "uint", True, None),
    6: ("valid_until", "uint", True, None),
    7: ("scope", v0.SCOPE, True, None),
    8: ("action", v0.ACTION, True, None),
    10: ("payload_ref", PAYLOAD_REF_V1, True, None),
    11: ("ciphertext_hash", "bstr", True, (32, 32)),
    12: ("plaintext_hash", "bstr", True, (32, 32)),
    13: ("payload_size", "uint", True, None),
    14: ("mandate_ref", "bstr", False, (32, 32)),
}

ENVELOPE_V1 = {
    1: ("commitment", COMMITMENT_V1, True, None),
    2: ("signature", "bstr", True, (64, 64)),
}

AUTHORIZATION_V1 = {
    1: ("version", "uint", True, None),
    2: ("commitment_hash", "bstr", True, (32, 32)),
    3: ("action_hash", "bstr", True, (32, 32)),
    4: ("gate_id", "tstr", True, (1, 64, ID_CHARS)),
    5: ("expires", "uint", True, None),
    6: ("path", "uint", True, None),
    7: ("mode", "uint", True, None),
    8: ("anchor_deadline", "uint", _deadline_presence, None),
}

SIGNED_AUTHORIZATION_V1 = {
    1: ("authorization", AUTHORIZATION_V1, True, None),
    2: ("signature", "bstr", True, (64, 64)),
}

_MAJOR = {"uint": 0, "bstr": 2, "tstr": 3, "media": 3}


def _presence(req, out: dict) -> str:
    if callable(req):
        return req(out)
    return "required" if req else "optional"


def _decode_map(it: Item, schema: dict, where: str) -> dict:
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
        want = 5 if isinstance(typ, dict) else _MAJOR[typ]
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
            if not v0.media_type_ok(v.value, lo, hi):
                raise Reject("ErrInvalidString", f"{path}: not a lower-case type/subtype")
            out[name] = v.value
        elif typ == "uint":
            out[name] = v.value
        else:
            if typ is COMMITMENT_V1 and v.end - v.start > v0.MAX_COMMITMENT_SIZE:
                raise Reject("ErrTooLarge", f"commitment is {v.end - v.start} bytes")
            out[name] = _decode_map(v, typ, path)
    for key, (name, _, req, _) in schema.items():
        if _presence(req, out) == "required" and name not in out:
            raise Reject("ErrMissingField", f"{where}.{name}")
    return out


def to_cbor(c: dict, schema: dict) -> dict:
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


def _inner_version(it: Item):
    """Key 1 of the key-1 map, if both exist and the inner value is a uint; else None.
    Only reads bytes pass 1 accepted, so it cannot fail."""
    if it.major != 5:
        return None
    inner = next((v for k, v in it.value if k.value == 1), None)
    if inner is None or inner.major != 5:
        return None
    ver = next((v for k, v in inner.value if k.value == 1), None)
    return ver.value if ver is not None and ver.major == 0 else None


def _decode_signed(data: bytes, limit: int, schema: dict, it: Item, where: str):
    signed = _decode_map(it, schema, where)
    inner = next(v for k, v in it.value if k.value == 1)
    canon = data[inner.start:inner.end]
    if encode(to_cbor(signed[schema[1][0]], schema[1][1])) != canon:
        raise Reject("ErrNonCanonical", "re-encoding differs")
    return signed, canon


# Commitment.

def commitment_hash_v1(canon: bytes) -> bytes:
    return hashlib.sha256(tagged(TAG_COMMITMENT_V1) + canon).digest()


def signing_message_v1(h: bytes) -> bytes:
    return tagged(TAG_SIG_V1) + h


def decode_signed_v1(envelope: bytes):
    it = _parse(envelope, v0.MAX_SIGNED_SIZE)
    return _decode_signed(envelope, v0.MAX_SIGNED_SIZE, ENVELOPE_V1, it, "envelope")


def envelope_version(envelope: bytes) -> int:
    """Section 3.1: 1 for the v1 path, 0 for the frozen v0 path (whatever key 1 holds)."""
    it = _parse(envelope, v0.MAX_SIGNED_SIZE)
    return 1 if _inner_version(it) == 1 else 0


def validate_static_v1(c: dict, p: Params):
    """Stage S for v1: V1-1, S2, S3, V1-3, S6, S7, S8, S12, S14."""
    r = c["payload_ref"]
    if c["version"] != 1:
        raise Reject("ErrUnsupportedVersion", str(c["version"]))
    if any(x > MAX_INT for x in (c["version"], c["issued_at"], c["valid_until"], c["payload_size"],
                                 r["da"], r["height"], r.get("anchor", 0))):
        raise Reject("ErrIntRange")
    if r["da"] not in (v0.DA_FIBRE, v0.DA_CELESTIA_BLOB):
        raise Reject("ErrInvalidEnum", f"da={r['da']}")
    if "anchor" in r and r["anchor"] != ANCHOR_PENDING:
        raise Reject("ErrInvalidEnum", f"anchor={r['anchor']}")
    for name, val in (("issued_at", c["issued_at"]), ("height", r["height"]), ("payload_size", c["payload_size"])):
        if val == 0:
            raise Reject("ErrZeroValue", name)
    if c["payload_size"] > v0.MAX_PAYLOAD_SIZE:
        raise Reject("ErrPayloadTooLarge")
    if not v0.namespace_ok(r["namespace"]):
        raise Reject("ErrInvalidNamespace")
    if c["valid_until"] <= c["issued_at"]:
        raise Reject("ErrTimeOrder")
    if c["valid_until"] - c["issued_at"] > p.max_ttl(r["da"]):
        raise Reject("ErrTTLTooLong")


def verify_signature_v1(c: dict, canon: bytes, sig: bytes) -> bytes:
    h = commitment_hash_v1(canon)
    v0._verify_tagged_hash(c["agent_pubkey"], h, sig, TAG_SIG_V1)
    return h


def verify_for_gate_any(envelope: bytes, now: int, gate: dict, p: Params):
    """Dispatch (3.1), then D, S, G, T, C of the selected version. Returns (version, signed, commitment_hash)."""
    p.validate()
    if envelope_version(envelope) == 0:
        signed, h = v0.verify_for_gate(envelope, now, gate, p)
        return 0, signed, h
    signed, canon = decode_signed_v1(envelope)
    c = signed["commitment"]
    validate_static_v1(c, p)
    h = verify_signature_v1(c, canon, signed["signature"])
    v0.check_time(c, now, p)
    v0.check_scope(c, gate)
    return 1, signed, h


def is_pending(c: dict) -> bool:
    return c["payload_ref"].get("anchor") == ANCHOR_PENDING


# Authorization v1.

def authorization_hash_v1(canon: bytes) -> bytes:
    return hashlib.sha256(tagged(TAG_AUTHORIZATION_V1) + canon).digest()


def authorization_message_v1(h: bytes) -> bytes:
    return tagged(TAG_AUTHORIZATION_SIG_V1) + h


@dataclass(frozen=True)
class CheckV1:
    """The executor's own knowledge, as core AuthorizationCheck, plus the versions it accepts and the salt
    presented with the action bytes (None: absent)."""
    gate_pubkey: bytes
    gate_id: str
    action_type: str
    action: bytes
    now: int
    skew_s: int
    accept_versions: frozenset = field(default=frozenset({0, 1}))
    action_salt: bytes | None = None


def validate_authorization_v1(a: dict, accept: frozenset):
    """Q1, Q2, Q3, Q5, Q4, Q6."""
    if a["version"] != 1 or 1 not in accept:
        raise Reject("ErrUnsupportedVersion", str(a["version"]))
    if any(a[n] > MAX_INT for n in ("version", "expires", "path", "mode", "anchor_deadline") if n in a):
        raise Reject("ErrIntRange")
    if a["path"] not in (v0.PATH_DA, v0.PATH_ARCHIVE):
        raise Reject("ErrInvalidEnum", f"path={a['path']}")
    if a["mode"] not in (MODE_STRICT, MODE_FAST):
        raise Reject("ErrInvalidEnum", f"mode={a['mode']}")
    if a["expires"] == 0:
        raise Reject("ErrZeroValue", "expires")
    if a.get("anchor_deadline") == 0:
        raise Reject("ErrZeroValue", "anchor_deadline")


def action_hash_v1(action_type: str, salt: bytes, action: bytes) -> bytes:
    """Section 4.7: the salted action hash of a v1 commitment."""
    if len(salt) != ACTION_SALT_SIZE:
        raise ValueError("action salt must be 32 bytes")
    t = action_type.encode("ascii")
    return hashlib.sha256(tagged(TAG_ACTION_V1) + bytes([len(t)]) + t + salt + action).digest()


def check_salt_presence(version: int, salt: bytes | None):
    """Gate A0s / executor X2s: v1 needs a 32-byte salt, v0 refuses any salt."""
    if version == 1:
        if salt is None:
            raise Reject("ErrMissingField", "action_salt")
        if len(salt) != ACTION_SALT_SIZE:
            raise Reject("ErrFieldSize", f"action_salt {len(salt)} bytes")
    elif salt is not None:
        raise Reject("ErrUnknownKey", "action_salt with a v0 commitment")


def action_matches(version: int, action_type: str, salt: bytes | None, action: bytes, committed: bytes) -> bool:
    got = action_hash_v1(action_type, salt, action) if version == 1 else v0.action_hash(action_type, action)
    return hmac.compare_digest(got, committed)


def gate_stage_a(version: int, c: dict, action: bytes, salt: bytes | None):
    """Section 7.1 stage A: A0, A0s, A1."""
    if not 1 <= len(action) <= v0.MAX_ACTION_SIZE:
        raise Reject("ErrActionSize", f"{len(action)} bytes")
    check_salt_presence(version, salt)
    if not action_matches(version, c["action"]["type"], salt, action, c["action"]["hash"]):
        raise Reject("ErrActionMismatch")


def _executor_checks(a: dict, chk, version: int):
    """X1, X2, X2s, X3, X4."""
    if a["gate_id"] != chk.gate_id:
        raise Reject("ErrScopeMismatch", "gate_id")
    if not 1 <= len(chk.action) <= v0.MAX_ACTION_SIZE:
        raise Reject("ErrActionSize", f"{len(chk.action)} bytes")
    check_salt_presence(version, chk.action_salt)
    if not action_matches(version, chk.action_type, chk.action_salt, chk.action, a["action_hash"]):
        raise Reject("ErrActionMismatch")
    if chk.now + chk.skew_s >= a["expires"]:
        raise Reject("ErrExpired")


def verify_authorization_any(data: bytes, chk: CheckV1):
    """Section 6.3. Returns (version, signed, authorization_hash)."""
    it = _parse(data, v0.MAX_AUTHORIZATION_SIZE)
    if _inner_version(it) != 1:
        signed, canon = v0.decode_signed_authorization(data)
        a = signed["authorization"]
        if a["version"] == 0 and 0 not in chk.accept_versions:
            raise Reject("ErrUnsupportedVersion", "0 not accepted")
        v0.validate_authorization_static(a)
        h = v0.authorization_hash(canon)
        v0._verify_tagged_hash(chk.gate_pubkey, h, signed["signature"], v0.TAG_AUTHORIZATION_SIG)
        _executor_checks(a, chk, 0)
        return 0, signed, h
    signed, canon = _decode_signed(data, v0.MAX_AUTHORIZATION_SIZE, SIGNED_AUTHORIZATION_V1, it,
                                   "signed_authorization")
    a = signed["authorization"]
    validate_authorization_v1(a, chk.accept_versions)
    h = authorization_hash_v1(canon)
    v0._verify_tagged_hash(chk.gate_pubkey, h, signed["signature"], TAG_AUTHORIZATION_SIG_V1)
    _executor_checks(a, chk, 1)
    return 1, signed, h


# Gate configuration (7.4), stage K-fast window and slack (8), and the reference-time rules (9).

GATE_CONFIG_DEFAULTS = {"fast_mode": False, "fast_window_blocks": 100, "max_h0_age_blocks": 10,
                        "min_fast_slack_blocks": 3, "min_promise_slack_seconds": 15, "rebroadcast_intent": True}


def validate_gate_config(cfg: dict, mandate: bool, allowlist: list):
    """ValidateBasic in table order, then the cross-field rule, then the constructor's mandate check.
    Raises Reject("ErrInvalidConfig", cause)."""
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
        if len(ns) != 29 or not v0.namespace_ok(ns):
            raise bad("pending_namespaces")
    for t in c.get("reveal_on_execution", []):
        if t not in allowlist:
            raise bad("reveal_on_execution")
    if c["max_h0_age_blocks"] + c["min_fast_slack_blocks"] > c["fast_window_blocks"]:
        raise bad("age_plus_slack")
    if c["fast_mode"] and not mandate:
        raise bad("fast_mode_without_mandate")


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
    if da == v0.DA_FIBRE:
        if chain_window is None:
            raise ValueError("da = 1 needs the chain window")
        window = min(window, chain_window)
    if window < 1:
        raise Reject("ErrAnchorWindowClosed", "window 0")
    deadline = h0 + window
    if da == v0.DA_CELESTIA_BLOB and 0 < timeout_height < deadline:
        deadline = timeout_height
    provisional = deadline < head + min_fast_slack
    if da == v0.DA_FIBRE and promise is not None:
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


def retention_start(da: int, pending: bool, t_ref: int, creation_ts: int = 0, created_at: int = 0) -> int:
    """K2 start: min(T_ref, promise creation) for an included Fibre reference, min(T_ref, intent created_at)
    for a pending one, T_ref for da = 2."""
    if da == v0.DA_CELESTIA_BLOB:
        return t_ref
    return min(t_ref, created_at if pending else creation_ts)


# Payload plaintext v1 (4.8).

def _payload_schemas():
    import edicta_payload_v0 as pv0
    action_v1 = dict(pv0.PAYLOAD_ACTION)
    action_v1[5] = ("action_salt", "bstr", True, (ACTION_SALT_SIZE, ACTION_SALT_SIZE))
    payload_v1 = dict(pv0.PAYLOAD)
    payload_v1[5] = ("action", action_v1, True, None)
    return pv0, payload_v1


def payload_encode_v1(p: dict) -> bytes:
    _, schema = _payload_schemas()
    return encode(v0.to_cbor(p, schema))


def payload_decode_v1(b: bytes) -> dict:
    """PV2, PV3: strict decoding of a payload v1. Structural failures are payload.ErrMalformed."""
    pv0, schema = _payload_schemas()
    try:
        p = v0._schema_decode(decode_strict(b), schema, "payload")
    except (CBORError, Reject) as e:
        raise Reject("payload.ErrMalformed", str(e))
    for k in ("context", "metadata"):
        if k in p and not pv0.media_type_ok(p[k]["media_type"]):
            raise Reject("payload.ErrMalformed", f"{k}.media_type")
    if payload_encode_v1(p) != b:
        raise Reject("payload.ErrMalformed", "re-encoding differs")
    if p["version"] != 1:
        raise Reject("payload.ErrVersion", f"version {p['version']}")
    return p


def o8(commitment_version: int, aead_plaintext: bytes, action_type: str, committed_hash: bytes) -> dict:
    """PV1 then O8 (v0: core O8; v1: O8 v1), on the AEAD plaintext that passed O7."""
    import edicta_payload_v0 as pv0
    body = aead_plaintext[pv0.SALT_SIZE:]
    p = payload_decode_v1(body) if commitment_version == 1 else pv0.payload_decode(body)
    a = p["action"]
    if a["type"] != action_type:
        raise Reject("sdk.ErrPayloadMismatch", "action type")
    if not action_matches(commitment_version, a["type"], a.get("action_salt"), a["data"], committed_hash):
        raise Reject("sdk.ErrPayloadMismatch", "action hash")
    return p
