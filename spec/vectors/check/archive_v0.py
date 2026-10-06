"""Archive record format 0 (spec section 19, v0-draft.20).

Encoding, strict decoding, keys, identities and the reference write rules of
the archive. Independent of the Go implementation on purpose, like
edicta_v0.py.
"""

from __future__ import annotations

import hashlib

from cbor_strict import CBORError, Item, encode
from edicta_v0 import (
    ID_CHARS, MAX_INT, Reject, decode_signed, decode_signed_authorization, namespace_ok,
    validate_authorization_static,
)

FORMAT = 0

KIND_PAYLOAD = 1
KIND_EVIDENCE = 2
KIND_DECISION = 3
KIND_AUTHORIZATION = 4
KIND_REJECTION = 5
KIND_NAMES = {KIND_PAYLOAD: "payload", KIND_EVIDENCE: "evidence", KIND_DECISION: "decision",
              KIND_AUTHORIZATION: "authorization", KIND_REJECTION: "rejection"}
KIND_BY_NAME = {v: k for k, v in KIND_NAMES.items()}

MAX_RECORD_SIZE = (1 << 27) + 4096
MAX_KIND_SIZE = {
    KIND_PAYLOAD: MAX_RECORD_SIZE,
    KIND_EVIDENCE: 1 << 25,
    KIND_DECISION: 69632,
    KIND_AUTHORIZATION: 512,
    KIND_REJECTION: 256,
}
MAX_DEPTH = 2
MAX_PAIRS = 24
MAX_OPAQUE = 1 << 22
MAX_BLOB = 1 << 27

SOURCE_DIRECT = 1
SOURCE_OBSERVED = 2
SOURCE_BOTH = 3

# Verdict sentinels of section 8.7 stages 5 to 12, the only names a
# rejection record may carry (AR5).
VERDICTS = (
    "ErrActionMismatch", "ErrAnchorNotFound", "ErrAnchorTooOld", "ErrArchiveRecomputeUnsupported",
    "ErrDACommitmentMismatch", "ErrExpired", "ErrIssuedBeforeAnchor", "ErrNonceUsed", "ErrNotYetValid",
    "ErrPayloadHashMismatch", "ErrPayloadSizeMismatch", "ErrPayloadUnavailable", "ErrRetentionUnavailable",
)
NAME_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")

# Presence conditions. R: required. O: optional. R1/R2: required when da is
# 1/2 and undefined for the other da. O1: optional for da = 1 only. R1O2:
# required for da = 1, optional for da = 2. TX: allowed only next to
# anchor_tx (index required with it, proof optional).
R, O, R1, R2, O1, R1O2, TXI, TXP = "R", "O", "R1", "R2", "O1", "R1O2", "TXI", "TXP"

K2 = {
    1: ("da", "uint", R, None),
    2: ("checked_at", "uint", R, None),
    3: ("block_time", "uint", R, None),
    4: ("blob_retention_s", "uint", R2, None),
    5: ("retention_latest_s", "uint", R1, None),
    6: ("retention_at_height_s", "uint", R1, None),
    7: ("retention_source", "uint", R1, None),
    8: ("promise_created", "uint", O1, None),
}

COMMON = {
    1: ("format", "uint", R, None),
    2: ("kind", "uint", R, None),
}

SCHEMAS = {
    KIND_PAYLOAD: {
        3: ("da", "uint", R, None),
        4: ("commitment", "bstr", R, (32, 32)),
        5: ("namespace", "bstr", R2, (29, 29)),
        6: ("signer", "bstr", R2, (20, 20)),
        7: ("blob", "bstr", R, (1, MAX_BLOB)),
        8: ("intent_height", "uint", R, None),
    },
    KIND_EVIDENCE: {
        3: ("da", "uint", R, None),
        4: ("commitment", "bstr", R, (32, 32)),
        5: ("namespace", "bstr", R, (29, 29)),
        6: ("height", "uint", R, None),
        7: ("header", "bstr", R, (1, MAX_OPAQUE)),
        8: ("anchor_tx", "bstr", R1O2, (1, MAX_OPAQUE)),
        9: ("anchor_tx_index", "uint", TXI, None),
        10: ("anchor_tx_proof", "bstr", TXP, (1, MAX_OPAQUE)),
        11: ("blob_proof", "bstr", R2, (1, MAX_OPAQUE)),
        12: ("tx_code", "uint", R1, None),
        13: ("system_blob", "bstr", R1, (1, MAX_OPAQUE)),
        14: ("system_blob_proof", "bstr", R1, (1, MAX_OPAQUE)),
        15: ("promise_height", "uint", R1, None),
        16: ("promise_header", "bstr", R1, (1, MAX_OPAQUE)),
        17: ("historical_info", "bstr", R1, (1, MAX_OPAQUE)),
        18: ("promise_valset", "bstr", R1, (1, MAX_OPAQUE)),
    },
    KIND_DECISION: {
        3: ("envelope", "bstr", R, (1, 2176)),
        4: ("action", "bstr", R, (1, 1 << 16)),
    },
    KIND_AUTHORIZATION: {
        3: ("signed_authorization", "bstr", R, (1, 256)),
        4: ("authorized_at", "uint", R, None),
        5: ("k2", K2, O, None),
    },
    KIND_REJECTION: {
        3: ("commitment_hash", "bstr", R, (32, 32)),
        4: ("error", "errname", R, (4, 64)),
        5: ("gate_id", "tstr", R, (1, 64)),
        6: ("rejected_at", "uint", R, None),
    },
}

NONZERO = {"intent_height", "height", "promise_height", "authorized_at", "rejected_at", "checked_at",
           "block_time", "blob_retention_s", "retention_latest_s", "retention_at_height_s", "promise_created"}

# Fields that decide whether a second write of the same key is the same
# record (section 19.4). Everything else is first-write-wins.
IDENTITY = {
    KIND_PAYLOAD: ("da", "commitment", "namespace", "signer", "blob"),
    KIND_EVIDENCE: ("da", "commitment", "namespace", "height"),
    KIND_DECISION: ("envelope", "action"),
    KIND_AUTHORIZATION: ("signed_authorization",),
    KIND_REJECTION: ("commitment_hash", "error"),
}


# ---------------------------------------------------------------- encoding

def _to_int_keys(rec: dict, schema: dict) -> dict:
    by_name = {f[0]: (k, f) for k, f in schema.items()}
    out = {}
    for name, val in rec.items():
        k, f = by_name[name]
        out[k] = _to_int_keys(val, f[1]) if isinstance(f[1], dict) else val
    return out


def schema_of(kind: int) -> dict:
    return {**COMMON, **SCHEMAS[kind]}


def to_cbor(rec: dict) -> dict:
    """Named record (with 'kind' as an int) -> integer-keyed map."""
    return _to_int_keys({"format": FORMAT, **rec}, schema_of(rec["kind"]))


def encode_record(rec: dict) -> bytes:
    return encode(to_cbor(rec))


# ---------------------------------------------------------------- decoding

class _Decoder:
    """Generic pass with the archive limits: depth 2, 24 entries per map."""

    def __init__(self, data: bytes):
        self.d = data
        self.i = 0

    def _need(self, n: int):
        if self.i + n > len(self.d):
            raise CBORError("ErrMalformed", f"truncated at offset {self.i}")

    def _head(self):
        self._need(1)
        ib = self.d[self.i]
        self.i += 1
        major, ai = ib >> 5, ib & 0x1F
        if 28 <= ai <= 30:
            raise CBORError("ErrMalformed", f"reserved additional info {ai}")
        if ai == 31:
            if major in (2, 3, 4, 5):
                raise CBORError("ErrIndefiniteLength", f"major {major}")
            raise CBORError("ErrMalformed", f"additional info 31 on major {major}")
        if major == 7:
            if ai in (25, 26, 27):
                raise CBORError("ErrFloat", f"offset {self.i - 1}")
            raise CBORError("ErrSimpleValue", f"simple value ai={ai}")
        if major == 6:
            raise CBORError("ErrTag", f"offset {self.i - 1}")
        if ai < 24:
            return major, ai
        n = 1 << (ai - 24)
        self._need(n)
        arg = int.from_bytes(self.d[self.i:self.i + n], "big")
        self.i += n
        if arg < {1: 24, 2: 1 << 8, 4: 1 << 16, 8: 1 << 32}[n]:
            raise CBORError("ErrNonMinimalInt", f"argument {arg} encoded in {n} bytes")
        return major, arg

    def item(self, depth: int) -> Item:
        start = self.i
        major, arg = self._head()
        if major in (0, 1):
            return Item(major, arg if major == 0 else -1 - arg, start, self.i)
        if major in (2, 3):
            if arg > len(self.d) - self.i:
                raise CBORError("ErrMalformed", "string length exceeds input")
            raw = self.d[self.i:self.i + arg]
            self.i += arg
            if major == 3:
                try:
                    return Item(3, raw.decode("utf-8", errors="strict"), start, self.i)
                except UnicodeDecodeError:
                    raise CBORError("ErrInvalidString", "invalid UTF-8")
            return Item(2, bytes(raw), start, self.i)
        if depth + 1 > MAX_DEPTH:
            raise CBORError("ErrNestingTooDeep", f"container at depth {depth + 1}")
        if arg > MAX_PAIRS:
            raise CBORError("ErrTooLarge", f"{arg} entries exceed {MAX_PAIRS}")
        if major == 4:
            if arg > len(self.d) - self.i:
                raise CBORError("ErrMalformed", "array length exceeds input")
            return Item(4, [self.item(depth + 1) for _ in range(arg)], start, self.i)
        if 2 * arg > len(self.d) - self.i:
            raise CBORError("ErrMalformed", "map length exceeds input")
        pairs, prev = [], None
        for _ in range(arg):
            k = self.item(depth + 1)
            if k.major != 0:
                raise CBORError("ErrKeyType", f"map key of major type {k.major}")
            if prev is not None:
                if k.value == prev:
                    raise CBORError("ErrDuplicateKey", f"key {k.value}")
                if k.value < prev:
                    raise CBORError("ErrUnsortedMap", f"key {k.value} after {prev}")
            prev = k.value
            pairs.append((k, self.item(depth + 1)))
        return Item(5, pairs, start, self.i)


def _generic(data: bytes) -> Item:
    dec = _Decoder(data)
    it = dec.item(0)
    if dec.i != len(data):
        raise CBORError("ErrTrailingData", f"{len(data) - dec.i} bytes after the record")
    return it


def _cond(cond: str, da, have: dict, where: str):
    """Raise ErrUnknownKey if a present field is not defined here."""
    if cond in (R1, O1) and da == 2:
        raise Reject("ErrUnknownKey", f"{where}: not defined for da = 2")
    if cond == R2 and da == 1:
        raise Reject("ErrUnknownKey", f"{where}: not defined for da = 1")
    if cond in (TXI, TXP) and "anchor_tx" not in have:
        raise Reject("ErrUnknownKey", f"{where}: only allowed next to anchor_tx")


def _required(cond: str, da, have: dict) -> bool:
    if cond == R:
        return True
    if cond in (R1, R1O2):
        return da == 1
    if cond == R2:
        return da == 2
    if cond == TXI:
        return "anchor_tx" in have
    return False


def _schema(it: Item, schema: dict, where: str) -> dict:
    if it.major != 5:
        raise Reject("ErrWrongType", f"{where}: expected map")
    out: dict = {}
    for k, v in it.value:
        key = k.value
        if key not in schema:
            raise Reject("ErrUnknownKey", f"{where}: key {key}")
        name, typ, cond, limit = schema[key]
        path = f"{where}.{name}"
        _cond(cond, out.get("da"), out, path)
        if isinstance(typ, dict):
            want = 5
        else:
            want = {"uint": 0, "bstr": 2, "tstr": 3, "errname": 3}[typ]
        if v.major != want:
            raise Reject("ErrWrongType", f"{path}: major {v.major}, want {want}")
        if typ == "bstr":
            lo, hi = limit
            if not lo <= len(v.value) <= hi:
                raise Reject("ErrFieldSize", f"{path}: {len(v.value)} bytes")
        elif typ in ("tstr", "errname"):
            lo, hi = limit
            n = len(v.value.encode("utf-8"))
            if not lo <= n <= hi:
                raise Reject("ErrFieldSize", f"{path}: {n} bytes")
            chars = ID_CHARS if typ == "tstr" else NAME_CHARS
            if any(c not in chars for c in v.value) or (typ == "errname" and not v.value.startswith("Err")):
                raise Reject("ErrInvalidString", f"{path}: outside the grammar")
        if isinstance(typ, dict):
            out[name] = _schema(v, typ, path)
        else:
            out[name] = v.value
    for key, (name, _, cond, _) in schema.items():
        if name not in out and _required(cond, out.get("da"), out):
            raise Reject("ErrMissingField", f"{where}.{name}")
    return out


def _uints(rec: dict, schema: dict):
    for key in sorted(schema):
        name, typ, _, _ = schema[key]
        if name not in rec:
            continue
        if isinstance(typ, dict):
            yield from _uints(rec[name], typ)
        elif typ == "uint":
            yield name, rec[name]


def _values(rec: dict, kind: int):
    schema = schema_of(kind)
    uints = list(_uints(rec, schema))
    for name, val in uints:
        if val > MAX_INT:
            raise Reject("ErrIntRange", f"{name} = {val}")
        if name == "tx_code" and val != 0:
            raise Reject("ErrIntRange", f"tx_code = {val}, only 0 is archived")
    for d in ([rec] + ([rec["k2"]] if "k2" in rec else [])):
        if "da" in d and d["da"] not in (1, 2):
            raise Reject("ErrInvalidEnum", f"da = {d['da']}")
    k2 = rec.get("k2", {})
    if "retention_source" in k2 and k2["retention_source"] not in (SOURCE_DIRECT, SOURCE_OBSERVED, SOURCE_BOTH):
        raise Reject("ErrInvalidEnum", f"retention_source = {k2['retention_source']}")
    if kind == KIND_REJECTION and rec["error"] not in VERDICTS:
        raise Reject("ErrInvalidEnum", f"error {rec['error']} is not a verdict sentinel")
    for name, val in uints:
        if name in NONZERO and val == 0:
            raise Reject("ErrZeroValue", name)
    if "namespace" in rec and not namespace_ok(rec["namespace"]):
        raise Reject("ErrInvalidNamespace", rec["namespace"].hex())
    if kind == KIND_DECISION:
        decode_signed(rec["envelope"])
    if kind == KIND_AUTHORIZATION:
        sa, _ = decode_signed_authorization(rec["signed_authorization"])
        validate_authorization_static(sa["authorization"])


def decode_record(data: bytes) -> dict:
    """Strict decoding of one archive record. Raises Reject with the cause;
    an implementation reports every such failure as archive.ErrCorrupt."""
    if len(data) > MAX_RECORD_SIZE:
        raise Reject("ErrTooLarge", f"{len(data)} bytes")
    try:
        it = _generic(data)
    except CBORError as e:
        raise Reject(e.sentinel, e.detail)
    if it.major != 5:
        raise Reject("ErrWrongType", "record: expected map")
    top = {k.value: v for k, v in it.value}
    for key, name in ((1, "format"), (2, "kind")):
        if key not in top:
            raise Reject("ErrMissingField", f"record.{name}")
        if top[key].major != 0:
            raise Reject("ErrWrongType", f"record.{name}")
    if top[1].value != FORMAT:
        raise Reject("ErrUnsupportedVersion", f"format {top[1].value}")
    kind = top[2].value
    if kind not in SCHEMAS:
        raise Reject("ErrInvalidEnum", f"kind {kind}")
    if len(data) > MAX_KIND_SIZE[kind]:
        raise Reject("ErrTooLarge", f"{KIND_NAMES[kind]} record of {len(data)} bytes")
    rec = _schema(it, schema_of(kind), KIND_NAMES[kind])
    _values(rec, kind)
    rec.pop("format")
    if encode_record(rec) != data:
        raise Reject("ErrNonCanonical", "re-encoding differs")
    return rec


# ---------------------------------------------------------------- keys

def commitment_hash_of_envelope(envelope: bytes) -> bytes:
    from edicta_v0 import commitment_hash
    _, canon = decode_signed(envelope)
    return commitment_hash(canon)


def record_key(rec: dict) -> tuple:
    kind = rec["kind"]
    if kind in (KIND_PAYLOAD, KIND_EVIDENCE):
        return (kind, rec["da"], rec["commitment"])
    if kind == KIND_DECISION:
        return (kind, commitment_hash_of_envelope(rec["envelope"]))
    if kind == KIND_AUTHORIZATION:
        sa, _ = decode_signed_authorization(rec["signed_authorization"])
        return (kind, sa["authorization"]["commitment_hash"])
    return (kind, rec["commitment_hash"], rec["error"])


def key_path(key: tuple) -> str:
    kind = key[0]
    if kind in (KIND_PAYLOAD, KIND_EVIDENCE):
        return f"{KIND_NAMES[kind]}/{key[1]}/{key[2].hex()}"
    if kind == KIND_REJECTION:
        return f"rejection/{key[1].hex()}/{key[2]}"
    return f"{KIND_NAMES[kind]}/{key[1].hex()}"


def identity(rec: dict) -> tuple:
    return tuple(rec.get(n) for n in IDENTITY[rec["kind"]])


# ---------------------------------------------------------------- reference store

class Conflict(Exception):
    sentinel = "archive.ErrConflict"


class NotFound(Exception):
    sentinel = "archive.ErrNotFound"


class DAMismatch(Exception):
    sentinel = "gate.ErrDACommitmentMismatch"


class Store:
    """Reference semantics of section 19.4 and 19.5, in memory."""

    def __init__(self, da_check):
        self.records: dict = {}
        self.da_check = da_check

    def _put(self, rec: dict) -> bool:
        key = record_key(rec)
        old = self.records.get(key)
        if old is None:
            self.records[key] = encode_record(rec)
            return True
        if identity(decode_record(old)) == identity(rec):
            return False
        raise Conflict(key_path(key))

    def put(self, rec: dict) -> bool:
        """Returns True if the record was written, False if it was a no-op."""
        kind = rec["kind"]
        if kind == KIND_PAYLOAD and not self.da_check(rec):
            raise DAMismatch(rec["commitment"].hex())
        if kind == KIND_EVIDENCE and (KIND_PAYLOAD, rec["da"], rec["commitment"]) not in self.records:
            raise NotFound("evidence without payload")
        if kind in (KIND_AUTHORIZATION, KIND_REJECTION):
            h = record_key(rec)[1]
            if (KIND_DECISION, h) not in self.records:
                raise NotFound("no decision record")
            if kind == KIND_REJECTION and (KIND_AUTHORIZATION, h) in self.records:
                return False
        return self._put(rec)

    def state(self, h: bytes):
        if (KIND_DECISION, h) not in self.records:
            return {"state": "absent", "rejections": []}
        marks = sorted((decode_record(v) for k, v in self.records.items()
                        if k[0] == KIND_REJECTION and k[1] == h),
                       key=lambda r: (r["rejected_at"], r["error"]))
        names = [m["error"] for m in marks]
        if (KIND_AUTHORIZATION, h) in self.records:
            return {"state": "authorized", "rejections": names}
        return {"state": "rejected" if names else "pending", "rejections": names}


def k2_holds(env: dict, k2: dict) -> bool:
    """Rule K2 of section 11.2 recomputed from archived inputs."""
    c = env["commitment"]
    if k2["da"] == 2:
        r, start = k2["blob_retention_s"], k2["block_time"]
    else:
        if "promise_created" not in k2:
            return False
        r = min(k2["retention_latest_s"], k2["retention_at_height_s"])
        start = min(k2["block_time"], k2["promise_created"])
    margin = min(600, r // 8)
    return c["valid_until"] + margin <= start + r


def placeholder(label: str, size: int) -> bytes:
    """Deterministic stand-in for an upstream object the Python side cannot build."""
    out = b""
    i = 0
    while len(out) < size:
        out += hashlib.sha256(f"edicta/v0 test archive placeholder|{label}|{i}".encode()).digest()
        i += 1
    return out[:size]

