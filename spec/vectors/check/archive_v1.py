"""Archive record format 0, v1 additions (spec/decision-commitment-v1.md section 11, v1-draft.2).

Kinds 13 (anchor intent), 14 (absence proof) and 15 (private blob), version
dispatch for the envelope of kind 3 and the Authorization of kind 4, and K2
input key 9. Reuses the generic decoder of archive_v0; the v0 kinds keep
their rules there.
"""

from __future__ import annotations

import archive_v0 as a0
import edicta_v0 as v0
import edicta_v1 as v1
from archive_v0 import O, O1, R, R2, Reject
from cbor_strict import CBORError, encode

KIND_INTENT = 13
KIND_ABSENCE = 14
KIND_PRIVATE = 15
RESERVED_KINDS = (6, 16)
MAX_TX = 1 << 16
MAX_PROOF_PART = 1 << 22
MAX_NAMESPACE_DATA = 1 << 24

KIND_NAMES = {**a0.KIND_NAMES, KIND_INTENT: "anchor_intent", KIND_ABSENCE: "absence_proof",
              KIND_PRIVATE: "private_blob"}
MAX_KIND_SIZE = {**a0.MAX_KIND_SIZE, KIND_INTENT: 65600, KIND_ABSENCE: 1 << 24, KIND_PRIVATE: 65600}

# Present iff results (key 10) is present.
NEXT = "NEXT"

K2_V1 = {**a0.K2, 9: ("fast_window", "uint", O, None)}
SCHEMAS = {
    **a0.SCHEMAS,
    a0.KIND_AUTHORIZATION: {**a0.SCHEMAS[a0.KIND_AUTHORIZATION], 5: ("k2", K2_V1, O, None)},
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
        5: ("envelope", "bstr", R, (1, 65536)),
    },
}

VERDICTS_V1 = a0.VERDICTS + ("ErrMandateRefMissing", "ErrMandateMismatch", "ErrAnchorIntentInvalid", "ErrCertInvalid",
                             "ErrH0TooOld", "ErrAnchorWindowClosed", "ErrFastModeNotAllowed")
NONZERO = a0.NONZERO | {"ref_height", "created_at", "fast_window"}


def schema_of(kind: int) -> dict:
    return {**a0.COMMON, **SCHEMAS[kind]}


def encode_record(rec: dict) -> bytes:
    return encode(a0._to_int_keys({"format": a0.FORMAT, **rec}, schema_of(rec["kind"])))


def decode_authorization(sa: bytes) -> dict:
    """Kind 4 field 3 by its own version (core v1 11.2): core 15 rules for 0, section 6 for 1."""
    it = v1._parse(sa, v0.MAX_AUTHORIZATION_SIZE)
    if v1._inner_version(it) != 1:
        signed, _ = v0.decode_signed_authorization(sa)
        v0.validate_authorization_static(signed["authorization"])
        return signed["authorization"]
    signed, _ = v1._decode_signed(sa, v0.MAX_AUTHORIZATION_SIZE, v1.SIGNED_AUTHORIZATION_V1, it,
                                  "signed_authorization")
    v1.validate_authorization_v1(signed["authorization"], frozenset({1}))
    return signed["authorization"]


def decode_envelope(env: bytes) -> tuple:
    """Kind 3 field 3 by its own version. Returns (commitment, commitment_hash)."""
    if v1.envelope_version(env) == 1:
        signed, canon = v1.decode_signed_v1(env)
        return signed["commitment"], v1.commitment_hash_v1(canon)
    signed, canon = v0.decode_signed(env)
    return signed["commitment"], v0.commitment_hash(canon)


def _values(rec: dict, kind: int):
    uints = list(a0._uints(rec, schema_of(kind)))
    for name, val in uints:
        if val > a0.MAX_INT:
            raise Reject("ErrIntRange", f"{name} = {val}")
        if name == "tx_code" and val != 0:
            raise Reject("ErrIntRange", f"tx_code = {val}, only 0 is archived")
    for d in ([rec] + ([rec["k2"]] if "k2" in rec else [])):
        if "da" in d and d["da"] not in (1, 2):
            raise Reject("ErrInvalidEnum", f"da = {d['da']}")
    k2 = rec.get("k2", {})
    if "retention_source" in k2 and k2["retention_source"] not in (a0.SOURCE_DIRECT, a0.SOURCE_OBSERVED,
                                                                   a0.SOURCE_BOTH):
        raise Reject("ErrInvalidEnum", f"retention_source = {k2['retention_source']}")
    if kind == KIND_PRIVATE and rec["plaintext_kind"] not in (1, 2, 3, 4):
        raise Reject("ErrInvalidEnum", f"plaintext_kind = {rec['plaintext_kind']}")
    if kind == a0.KIND_REJECTION and rec["error"] not in VERDICTS_V1:
        raise Reject("ErrInvalidEnum", f"error {rec['error']} is not a verdict sentinel")
    for name, val in uints:
        if name in NONZERO and val == 0:
            raise Reject("ErrZeroValue", name)
    if "fast_window" in k2 and k2["fast_window"] > v1.MAX_FAST_WINDOW:
        raise Reject("ErrIntRange", f"fast_window = {k2['fast_window']}")
    if "namespace" in rec and not a0.namespace_ok(rec["namespace"]):
        raise Reject("ErrInvalidNamespace", rec["namespace"].hex())
    if kind == a0.KIND_DECISION:
        decode_envelope(rec["envelope"])
    if kind == a0.KIND_AUTHORIZATION:
        a = decode_authorization(rec["signed_authorization"])
        fast = a["version"] == 1 and a["mode"] == v1.MODE_FAST
        if "k2" in rec and fast and "fast_window" not in k2:
            raise Reject("ErrMissingField", "authorization.k2.fast_window")
        if "fast_window" in k2 and not fast:
            raise Reject("ErrUnknownKey", "authorization.k2.fast_window: only with an Authorization v1 in mode 2")
    if kind == KIND_ABSENCE and ("results" in rec) != ("next_header" in rec):
        raise Reject("ErrMissingField" if "results" in rec else "ErrUnknownKey",
                     "absence_proof.next_header: present iff results")


def decode_record(data: bytes) -> dict:
    """Strict decoding with the v1 kinds. Raises Reject with the cause (reported as archive.ErrCorrupt)."""
    if len(data) > a0.MAX_RECORD_SIZE:
        raise Reject("ErrTooLarge", f"{len(data)} bytes")
    try:
        it = a0._generic(data)
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
    if top[1].value != a0.FORMAT:
        raise Reject("ErrUnsupportedVersion", f"format {top[1].value}")
    kind = top[2].value
    if kind not in SCHEMAS:
        raise Reject("ErrInvalidEnum", f"kind {kind}")
    if len(data) > MAX_KIND_SIZE[kind]:
        raise Reject("ErrTooLarge", f"{KIND_NAMES[kind]} record of {len(data)} bytes")
    rec = a0._schema(it, schema_of(kind), KIND_NAMES[kind])
    _values(rec, kind)
    rec.pop("format")
    if encode_record(rec) != data:
        raise Reject("ErrNonCanonical", "re-encoding differs")
    return rec


def record_key(rec: dict) -> tuple:
    kind = rec["kind"]
    if kind == a0.KIND_DECISION:
        return (kind, decode_envelope(rec["envelope"])[1])
    if kind == a0.KIND_AUTHORIZATION:
        return (kind, decode_authorization(rec["signed_authorization"])["commitment_hash"])
    if kind == KIND_INTENT:
        return (kind, rec["da"], rec["commitment"], rec["ref_height"])
    if kind == KIND_ABSENCE:
        return (kind, rec["da"], rec["commitment"], rec["height"])
    if kind == KIND_PRIVATE:
        return (kind, rec["plaintext_kind"], rec["hash"])
    return a0.record_key(rec)


def key_path(key: tuple) -> str:
    kind = key[0]
    if kind == KIND_INTENT:
        return f"intent/{key[1]}/{key[2].hex()}/{key[3]}"
    if kind == KIND_ABSENCE:
        return f"absence/{key[1]}/{key[2].hex()}/{key[3]}"
    if kind == KIND_PRIVATE:
        return f"private/{key[1]}/{key[2].hex()}"
    return a0.key_path(key)


# Identity (core AW2): the whole record for 13, the key for 14 and 15 (first write stays).
def same_identity(old: dict, new: dict) -> bool:
    if new["kind"] in (KIND_ABSENCE, KIND_PRIVATE):
        return True
    if new["kind"] == KIND_INTENT:
        return old == new
    return a0.identity(old) == a0.identity(new)


# Verifier rules for a v1 decision (section 10.1 to 10.3), on decoded inputs.

def authorization_rules(c: dict, a: dict) -> str | None:
    """A1 to A3 on the decision's commitment and the archived Authorization. Returns the failing rule or None."""
    if a["version"] != c["version"]:
        return "A1"
    pending = v1.is_pending(c)
    if a["mode"] != (v1.MODE_FAST if pending else v1.MODE_STRICT):
        return "A2"
    if pending:
        h0 = c["payload_ref"]["height"]
        if not h0 < a["anchor_deadline"] <= h0 + v1.MAX_FAST_WINDOW:
            return "A3"
    return None


def first_unproven(h0: int, d: int, absence: dict, want: str = "absent") -> int | None:
    return next((h for h in range(h0, d + 1) if absence.get(h) != want), None)


def anchor_pending_rules(h0: int, d: int, evidence: dict | None, head: int, absence: dict,
                         needs_results: bool) -> dict:
    """The anchor check of a pending reference (10.2). evidence: None or {height, verifies}; absence: height ->
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
    """retention_replay (core 20.1 with 10.3): K2 on the archived inputs, and the fast window."""
    if k2 is None:
        return {"status": "unchecked", "reason": "replay_inputs_missing"}
    if "fast_window" in k2 and a["anchor_deadline"] - c["payload_ref"]["height"] > k2["fast_window"]:
        return {"status": "unchecked", "reason": "replay_inconsistent"}
    if not a0.k2_holds({"commitment": c}, k2) and a["path"] == v0.PATH_DA:
        return {"status": "unchecked", "reason": "replay_inconsistent"}
    return {"status": "pass"}
