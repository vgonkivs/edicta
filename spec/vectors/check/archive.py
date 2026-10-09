"""Archive records, format 1 (spec/decision-commitment-v1.md section 19, v1-draft.5).

Encoding, strict decoding, keys, identities, the reference write rules and the verifier rules of the
archive records. Kind numbers are scoped per archive format; in format 1 kind 3 is unassigned and the
decision record is kind 17. Independent of the Go implementation on purpose, like edicta.py.
"""

from __future__ import annotations

import hashlib

import edicta as E
from cbor_strict import CBORError, Item, encode
from edicta import (
    ID_CHARS, MAX_INT, Reject, decode_signed, decode_signed_authorization, decode_signed_receipt, namespace_ok,
    validate_authorization_static, validate_receipt_static,
)

FORMAT = 1

KIND_PAYLOAD = 1
KIND_EVIDENCE = 2
KIND_AUTHORIZATION = 4
KIND_REJECTION = 5
KIND_INTENT = 13
KIND_ABSENCE = 14
KIND_PRIVATE = 15
KIND_DECISION = 17
KIND_REVEAL = 18
# Never assigned (6), reserved (16), or unassigned in format 1 (3): refused like any undefined kind.
UNASSIGNED_KINDS = (3, 6, 16)
KIND_NAMES = {KIND_PAYLOAD: "payload", KIND_EVIDENCE: "evidence", KIND_AUTHORIZATION: "authorization",
              KIND_REJECTION: "rejection", KIND_INTENT: "anchor_intent", KIND_ABSENCE: "absence_proof",
              KIND_PRIVATE: "private_blob", KIND_DECISION: "decision", KIND_REVEAL: "execution_reveal"}
KIND_BY_NAME = {v: k for k, v in KIND_NAMES.items()}
FORM_PUBLIC = 1
FORM_PRIVATE = 2
PLAINTEXT_ACTION = 5
MAX_PRIVATE_ENVELOPE = 1 << 16
MAX_ACTION_ENVELOPE = 69632
MAX_TX = 1 << 16
MAX_PROOF_PART = 1 << 22
MAX_NAMESPACE_DATA = 1 << 24

MAX_RECORD_SIZE = (1 << 27) + 4096
MAX_KIND_SIZE = {
    KIND_PAYLOAD: MAX_RECORD_SIZE,
    KIND_EVIDENCE: 1 << 25,
    KIND_AUTHORIZATION: 512,
    KIND_REJECTION: 256,
    KIND_INTENT: 65600,
    KIND_ABSENCE: 1 << 24,
    KIND_PRIVATE: 69760,
    KIND_DECISION: 69632,
    KIND_REVEAL: 640,
}
MAX_DEPTH = 2
MAX_PAIRS = 24
MAX_OPAQUE = 1 << 22
MAX_BLOB = 1 << 27

SOURCE_DIRECT = 1
SOURCE_OBSERVED = 2
SOURCE_BOTH = 3

# Verdict sentinels of the gate's refusal stages, the only names a rejection record may carry.
VERDICTS = (
    "ErrActionMismatch", "ErrAnchorNotFound", "ErrAnchorTooOld", "ErrArchiveRecomputeUnsupported",
    "ErrDACommitmentMismatch", "ErrExpired", "ErrIssuedBeforeAnchor", "ErrNonceUsed", "ErrNotYetValid",
    "ErrPayloadHashMismatch", "ErrPayloadSizeMismatch", "ErrPayloadUnavailable", "ErrRetentionUnavailable",
    "ErrMandateRefMissing", "ErrMandateMismatch", "ErrAnchorIntentInvalid", "ErrCertInvalid", "ErrH0TooOld",
    "ErrAnchorWindowClosed", "ErrFastModeNotAllowed", "ErrDenied",
)
NAME_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")

# Presence conditions. R: required. O: optional. R1/R2: required when da is 1/2 and undefined for the
# other da. O1: optional for da = 1 only. R1O2: required for da = 1, optional for da = 2. TXI/TXP: allowed
# only next to anchor_tx (index required with it, proof optional).
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
    9: ("fast_window", "uint", O, None),
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
    # Key 18 is unassigned: the CometBFT validator set at the promise height is not archived, because the
    # certificate check builds that set from historical_info and binds it to promise_header.
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
    KIND_INTENT: {
        3: ("da", "uint", R, None),
        4: ("commitment", "bstr", R, (32, 32)),
        5: ("namespace", "bstr", R, (29, 29)),
        6: ("ref_height", "uint", R, None),
        7: ("tx", "bstr", R, (1, MAX_TX)),
        8: ("signer", "bstr", R2, (20, 20)),
        9: ("created_at", "uint", R, None),
    },
    KIND_ABSENCE: {
        3: ("da", "uint", R, None),
        4: ("commitment", "bstr", R, (32, 32)),
        5: ("namespace", "bstr", R, (29, 29)),
        6: ("height", "uint", R, None),
        7: ("header", "bstr", R, (1, MAX_PROOF_PART)),
        8: ("dah", "bstr", R, (1, MAX_PROOF_PART)),
        9: ("namespace_data", "bstr", R, (0, MAX_NAMESPACE_DATA)),
        10: ("results", "bstr", O1, (1, MAX_PROOF_PART)),
        11: ("next_header", "bstr", O1, (1, MAX_PROOF_PART)),
    },
    KIND_PRIVATE: {
        3: ("plaintext_kind", "uint", R, None),
        4: ("hash", "bstr", R, (32, 32)),
        5: ("envelope", "bstr", R, (1, MAX_ACTION_ENVELOPE)),
    },
    KIND_DECISION: {
        3: ("envelope", "bstr", R, (1, E.MAX_SIGNED_SIZE)),
        4: ("form", "uint", R, None),
        5: ("action", "bstr", O, (1, E.MAX_ACTION_SIZE)),
        6: ("action_salt", "bstr", O, (E.ACTION_SALT_SIZE, E.ACTION_SALT_SIZE)),
    },
    KIND_REVEAL: {
        3: ("signed_receipt", "bstr", R, (1, E.MAX_RECEIPT_SIZE)),
        4: ("action_salt", "bstr", R, (E.ACTION_SALT_SIZE, E.ACTION_SALT_SIZE)),
    },
}

NONZERO = {"intent_height", "height", "promise_height", "authorized_at", "rejected_at", "checked_at",
           "block_time", "blob_retention_s", "retention_latest_s", "retention_at_height_s", "promise_created",
           "ref_height", "created_at", "fast_window"}

# Fields that decide whether a second write of the same key is the same record. None: the whole record.
# Kinds 14 and 15 keep the first write (identity is the key).
IDENTITY = {
    KIND_PAYLOAD: ("da", "commitment", "namespace", "signer", "blob"),
    KIND_EVIDENCE: ("da", "commitment", "namespace", "height"),
    KIND_AUTHORIZATION: ("signed_authorization",),
    KIND_REJECTION: ("commitment_hash", "error"),
    KIND_INTENT: None,
    KIND_DECISION: None,
    KIND_REVEAL: None,
    KIND_ABSENCE: (),
    KIND_PRIVATE: (),
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


def decode_authorization(sa: bytes) -> dict:
    """Kind 4 field 3: a SignedAuthorization that decodes and passes stage S."""
    signed, _ = decode_signed_authorization(sa)
    validate_authorization_static(signed["authorization"])
    return signed["authorization"]


def decode_envelope(env: bytes) -> tuple:
    """An archived envelope: stage D, then version 1. Returns (commitment, commitment_hash)."""
    signed, canon = decode_signed(env)
    if signed["commitment"]["version"] != E.VERSION:
        raise Reject("ErrUnsupportedVersion", f"envelope version {signed['commitment']['version']}")
    return signed["commitment"], E.commitment_hash(canon)


def _values(rec: dict, kind: int):
    uints = list(_uints(rec, schema_of(kind)))
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
    if kind == KIND_PRIVATE and rec["plaintext_kind"] not in (1, 2, 3, 4, PLAINTEXT_ACTION):
        raise Reject("ErrInvalidEnum", f"plaintext_kind = {rec['plaintext_kind']}")
    if kind == KIND_PRIVATE and rec["plaintext_kind"] != PLAINTEXT_ACTION and len(rec["envelope"]) > MAX_PRIVATE_ENVELOPE:
        raise Reject("ErrFieldSize", f"private_blob.envelope: {len(rec['envelope'])} bytes for plaintext kind "
                                     f"{rec['plaintext_kind']}")
    if kind == KIND_DECISION:
        if rec["form"] not in (FORM_PUBLIC, FORM_PRIVATE):
            raise Reject("ErrInvalidEnum", f"form = {rec['form']}")
        for name in ("action", "action_salt"):
            if rec["form"] == FORM_PRIVATE and name in rec:
                raise Reject("ErrUnknownKey", f"decision.{name}: not defined for form 2")
            if rec["form"] == FORM_PUBLIC and name not in rec:
                raise Reject("ErrMissingField", f"decision.{name}")
    if kind == KIND_REJECTION and rec["error"] not in VERDICTS:
        raise Reject("ErrInvalidEnum", f"error {rec['error']} is not a verdict sentinel")
    for name, val in uints:
        if name in NONZERO and val == 0:
            raise Reject("ErrZeroValue", name)
    if "fast_window" in k2 and k2["fast_window"] > E.MAX_FAST_WINDOW:
        raise Reject("ErrIntRange", f"fast_window = {k2['fast_window']}")
    if "namespace" in rec and not namespace_ok(rec["namespace"]):
        raise Reject("ErrInvalidNamespace", rec["namespace"].hex())
    if kind == KIND_DECISION:
        decode_envelope(rec["envelope"])
    if kind == KIND_REVEAL:
        signed, _ = decode_signed_receipt(rec["signed_receipt"])
        validate_receipt_static(signed["receipt"])
    if kind == KIND_AUTHORIZATION:
        a = decode_authorization(rec["signed_authorization"])
        fast = a["mode"] == E.MODE_FAST
        if "k2" in rec and fast and "fast_window" not in k2:
            raise Reject("ErrMissingField", "authorization.k2.fast_window")
        if "fast_window" in k2 and not fast:
            raise Reject("ErrUnknownKey", "authorization.k2.fast_window: only with a mode 2 Authorization")
    if kind == KIND_ABSENCE and ("results" in rec) != ("next_header" in rec):
        raise Reject("ErrMissingField" if "results" in rec else "ErrUnknownKey",
                     "absence_proof.next_header: present iff results")


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
    return decode_envelope(envelope)[1]


def record_key(rec: dict) -> tuple:
    kind = rec["kind"]
    if kind in (KIND_PAYLOAD, KIND_EVIDENCE):
        return (kind, rec["da"], rec["commitment"])
    if kind == KIND_DECISION:
        return (kind, commitment_hash_of_envelope(rec["envelope"]))
    if kind == KIND_REVEAL:
        return (kind, decode_signed_receipt(rec["signed_receipt"])[0]["receipt"]["commitment_hash"])
    if kind == KIND_AUTHORIZATION:
        return (kind, decode_authorization(rec["signed_authorization"])["commitment_hash"])
    if kind == KIND_INTENT:
        return (kind, rec["da"], rec["commitment"], rec["ref_height"])
    if kind == KIND_ABSENCE:
        return (kind, rec["da"], rec["commitment"], rec["height"])
    if kind == KIND_PRIVATE:
        return (kind, rec["plaintext_kind"], rec["hash"])
    return (kind, rec["commitment_hash"], rec["error"])


def key_path(key: tuple) -> str:
    kind = key[0]
    if kind in (KIND_PAYLOAD, KIND_EVIDENCE):
        return f"{KIND_NAMES[kind]}/{key[1]}/{key[2].hex()}"
    if kind == KIND_REJECTION:
        return f"rejection/{key[1].hex()}/{key[2]}"
    if kind == KIND_INTENT:
        return f"intent/{key[1]}/{key[2].hex()}/{key[3]}"
    if kind == KIND_ABSENCE:
        return f"absence/{key[1]}/{key[2].hex()}/{key[3]}"
    if kind == KIND_PRIVATE:
        return f"private/{key[1]}/{key[2].hex()}"
    if kind == KIND_REVEAL:
        return f"reveal/{key[1].hex()}"
    return f"{KIND_NAMES[kind]}/{key[1].hex()}"


def identity(rec: dict) -> tuple:
    fields = IDENTITY[rec["kind"]]
    if fields is None:
        return tuple(sorted((k, v) for k, v in rec.items() if not isinstance(v, dict)))
    return tuple(rec.get(n) for n in fields)


def same_identity(old: dict, new: dict) -> bool:
    if IDENTITY[new["kind"]] is None:
        return old == new
    return identity(old) == identity(new)


# ---------------------------------------------------------------- reference store

class Conflict(Exception):
    sentinel = "archive.ErrConflict"


class NotFound(Exception):
    sentinel = "archive.ErrNotFound"


class DAMismatch(Exception):
    sentinel = "gate.ErrDACommitmentMismatch"


class Corrupt(Exception):
    sentinel = "archive.ErrCorrupt"


def k2_da_matches(auth: dict, decision_rec: dict) -> bool:
    """The da of the K2 inputs is the decision's payload_ref.da."""
    if "k2" not in auth:
        return True
    c, _ = decode_envelope(decision_rec["envelope"])
    return auth["k2"]["da"] == c["payload_ref"]["da"]


class Store:
    """Reference write and read semantics of the archive, in memory."""

    def __init__(self, da_check):
        self.records: dict = {}
        self.da_check = da_check

    def _put(self, rec: dict) -> bool:
        key = record_key(rec)
        old = self.records.get(key)
        if old is None:
            self.records[key] = encode_record(rec)
            return True
        if same_identity(decode_record(old), rec):
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
            if kind == KIND_AUTHORIZATION and not k2_da_matches(rec, decode_record(self.records[(KIND_DECISION, h)])):
                raise Corrupt("k2 da differs from the decision's da")
        return self._put(rec)

    def authorization(self, h: bytes) -> dict:
        """Reads the Authorization record of h with the reader checks. Raises NotFound or Corrupt."""
        data = self.records.get((KIND_AUTHORIZATION, h))
        if data is None:
            raise NotFound("no Authorization record")
        try:
            rec = decode_record(data)
        except Reject as e:
            raise Corrupt(e.sentinel)
        if record_key(rec) != (KIND_AUTHORIZATION, h):
            raise Corrupt("stored under another key")
        dec = self.records.get((KIND_DECISION, h))
        if dec is not None and not k2_da_matches(rec, decode_record(dec)):
            raise Corrupt("k2 da differs from the decision's da")
        return rec

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
    """Rule K2 recomputed from archived inputs."""
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


# Verifier rules on decoded inputs.

def authorization_rules(c: dict, a: dict) -> str | None:
    """A1, A2 on the decision's commitment and the archived Authorization. Returns the failing rule or None."""
    pending = E.is_pending(c)
    if a["mode"] != (E.MODE_FAST if pending else E.MODE_STRICT):
        return "A1"
    if pending:
        h0 = c["payload_ref"]["height"]
        if not h0 < a["anchor_deadline"] <= h0 + E.MAX_FAST_WINDOW:
            return "A2"
    return None


def first_unproven(h0: int, d: int, absence: dict, want: str = "absent") -> int | None:
    return next((h for h in range(h0, d + 1) if absence.get(h) != want), None)


def anchor_pending_rules(h0: int, d: int, evidence: dict | None, head: int, absence: dict,
                         needs_results: bool) -> dict:
    """The anchor check of a pending reference. evidence: None or {height, verifies}; absence: height ->
    'absent' | 'present' | 'unproven' (a missing height is unproven). Returns status, reason or rule, and report."""
    if evidence is not None and evidence["verifies"]:
        hh = evidence["height"]
        if hh < h0:
            return {"status": "unchecked", "reason": "source_corrupt"}
        if hh <= d:
            return {"status": "pass", "anchor_height": hh, "publication": "anchored"}
        miss = first_unproven(h0, d, absence)
        if miss is None:
            return {"status": "fail", "rule": "anchor_absent", "anchor_height": hh, "publication": "failed"}
        return {"status": "unchecked", "reason": "absence_unproven", "first_unproven": miss, "anchor_height": hh,
                "publication": "unknown"}
    if head < (d + 1 if needs_results else d):
        return {"status": "unchecked", "reason": "anchor_pending", "publication": "unknown"}
    present = next((h for h in range(h0, d + 1) if absence.get(h) == "present"), None)
    if present is not None:
        return {"status": "unchecked", "reason": "evidence_unavailable", "anchor_height": present,
                "publication": "unknown"}
    miss = first_unproven(h0, d, absence)
    if miss is None:
        return {"status": "fail", "rule": "anchor_absent", "publication": "failed"}
    return {"status": "unchecked", "reason": "absence_unproven", "first_unproven": miss, "publication": "unknown"}


def replay_rules(c: dict, a: dict, k2: dict | None) -> dict:
    """retention_replay: K2 on the archived inputs, and the fast window."""
    if k2 is None:
        return {"status": "unchecked", "reason": "replay_inputs_missing"}
    if "fast_window" in k2 and a["anchor_deadline"] - c["payload_ref"]["height"] > k2["fast_window"]:
        return {"status": "unchecked", "reason": "replay_inconsistent"}
    if not k2_holds({"commitment": c}, k2) and a["path"] == E.PATH_DA:
        return {"status": "unchecked", "reason": "replay_inconsistent"}
    return {"status": "pass"}


def action_rules(c: dict, decision: dict | None, opened_plaintext: bytes | None, private_absent: bool,
                 reveal: dict | None, payload_salt: bytes | None = None) -> dict:
    """The action check of a decision, on decoded inputs.

    decision: the kind 17 decision record; opened_plaintext: kind 15 (5, ...) opened with a key (salt || bytes), or None;
    private_absent: that record is absent in every copy; reveal: None or {"salt", "action"} where action is A' from
    the profile's ActionFromTx (None when the reveal path does not apply); payload_salt: the salt of a payload that
    passed O8. Returns status, reason, action_source and the salt used."""
    t, want = c["action"]["type"], c["action"]["hash"]
    salt = None
    if decision["form"] == FORM_PUBLIC:
        if not E.action_matches(t, decision["action_salt"], decision["action"], want):
            return {"status": "unchecked", "reason": "source_corrupt"}
        out, salt = {"status": "pass", "action_source": "decision_record"}, decision["action_salt"]
    elif opened_plaintext is not None:
        if len(opened_plaintext) < 33 or not E.action_matches(t, opened_plaintext[:32], opened_plaintext[32:], want):
            return {"status": "unchecked", "reason": "source_corrupt"}
        out, salt = {"status": "pass", "action_source": "private_blob"}, opened_plaintext[:32]
    elif private_absent:
        return {"status": "unchecked", "reason": "decision_unavailable"}
    elif reveal is not None and reveal.get("action") is not None:
        if not E.action_matches(t, reveal["salt"], reveal["action"], want):
            return {"status": "unchecked", "reason": "source_corrupt", "record": "reveal"}
        out, salt = {"status": "pass", "action_source": "reveal"}, reveal["salt"]
    else:
        return {"status": "unchecked", "reason": "policy_private"}
    if payload_salt is not None and payload_salt != salt:
        return {"status": "unchecked", "reason": "source_corrupt", "record": out["action_source"]}
    return out


def placeholder(label: str, size: int) -> bytes:
    """Deterministic stand-in for an upstream object the Python side cannot build."""
    n = (size + 31) // 32
    return b"".join(hashlib.sha256(f"edicta/v0 test archive placeholder|{label}|{i}".encode()).digest()
                    for i in range(n))[:size]
