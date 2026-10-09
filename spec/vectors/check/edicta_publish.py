"""Publish request rules (spec/decision-commitment-v1.md, v1-draft.5): the agent-signed
request a Recorder accepts before it spends fees on a blob.

Python side of the cross-language check for the publish endpoint. Reuses the
core CBOR profile, sentinels and signature rules; the message itself is new
and signed directly, like a record request.
"""

from __future__ import annotations

import hashlib
import struct

from cbor_strict import CBORError, decode_strict, encode
from ed25519_point import cofactorless_ok, public_key_problem
from edicta import (ED25519_L, ID_CHARS, MAX_INT, PAYLOAD_REF, Reject, _schema_decode, tagged,
                    to_cbor)

TAG_PUBLISH_REQUEST = b"edicta/v1/publish-request"
PUBLISH_WINDOW_S = 300
REQUEST_OVERHEAD = 256

PUBLISH_REQUEST = {
    1: ("blob", "bstr", True, (1, 1 << 27)),
    2: ("agent_id", "tstr", True, (1, 64, ID_CHARS)),
    3: ("requested_at", "uint", True, None),
    4: ("signature", "bstr", True, (64, 64)),
}

PUBLISH_RESPONSE = {
    1: ("payload_ref", "bstr", True, (1, 128)),
    2: ("block_time", "uint", True, None),
    3: ("retention_start", "uint", True, None),
}


def publish_message(gate_id: str, agent_id: str, requested_at: int, blob: bytes) -> bytes:
    g = gate_id.encode("ascii")
    a = agent_id.encode("ascii")
    assert 1 <= len(g) <= 64 and 1 <= len(a) <= 64 and 1 <= requested_at <= MAX_INT
    return (tagged(TAG_PUBLISH_REQUEST) + bytes([len(g)]) + g + bytes([len(a)]) + a + struct.pack(">Q", requested_at)
            + hashlib.sha256(blob).digest())


def encode_request(blob: bytes, agent_id: str, requested_at: int, signature: bytes) -> bytes:
    return encode({1: blob, 2: agent_id, 3: requested_at, 4: signature})


def decode_request(data: bytes, max_blob_bytes: int) -> dict:
    if len(data) > max_blob_bytes + REQUEST_OVERHEAD:
        raise Reject("ErrTooLarge", f"{len(data)} bytes")
    try:
        it = decode_strict(data)
    except CBORError as e:
        raise Reject(e.sentinel, e.detail)
    r = _schema_decode(it, PUBLISH_REQUEST, "publish_request")
    if len(r["blob"]) > max_blob_bytes:
        raise Reject("ErrTooLarge", f"blob of {len(r['blob'])} bytes")
    if encode(to_cbor(r, PUBLISH_REQUEST)) != data:
        raise Reject("ErrNonCanonical", "re-encoding differs")
    return r


def _signature_ok(pub: bytes | None, msg: bytes, sig: bytes) -> bool:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    if pub is None or public_key_problem(pub) or int.from_bytes(sig[32:], "little") >= ED25519_L:
        return False
    ours = cofactorless_ok(pub, msg, sig)
    try:
        Ed25519PublicKey.from_public_bytes(pub).verify(sig, msg)
        lib = True
    except (InvalidSignature, ValueError):
        lib = False
    if ours != lib:
        raise RuntimeError(f"G1 disagreement: cofactorless={ours}, OpenSSL={lib}")
    return ours


def verify_request(data: bytes, gate_id: str, now: int, skew_s: int, max_blob_bytes: int, allowlist: dict,
                   gate_keys: list) -> dict:
    """The stateless publish checks PR1..PR5 in this fixed order, with the server's own gate_id.
    Dedupe (PR6) and quotas (PR7) are stateful."""
    r = decode_request(data, max_blob_bytes)
    if r["requested_at"] > MAX_INT:
        raise Reject("ErrIntRange", "requested_at")
    if r["requested_at"] == 0:
        raise Reject("ErrZeroValue", "requested_at")
    pub = allowlist.get(r["agent_id"])
    msg = publish_message(gate_id, r["agent_id"], r["requested_at"], r["blob"])
    if not _signature_ok(pub, msg, r["signature"]):
        raise Reject("edictaapi.ErrPublishSignature")
    if pub in gate_keys:
        raise Reject("ErrAgentKeyIsGateKey")
    if abs(now - r["requested_at"]) > skew_s + PUBLISH_WINDOW_S:
        raise Reject("edictaapi.ErrPublishStale")
    return r


def payload_ref_cbor(ref: dict) -> bytes:
    """The canonical PayloadRef map, the same bytes as commitment key 10."""
    return encode(to_cbor(ref, PAYLOAD_REF))


def decode_payload_ref(b: bytes) -> dict:
    try:
        ref = _schema_decode(decode_strict(b), PAYLOAD_REF, "payload_ref")
    except CBORError as e:
        raise Reject(e.sentinel, e.detail)
    if payload_ref_cbor(ref) != b:
        raise Reject("ErrNonCanonical", "re-encoding differs")
    return ref


def encode_response(payload_ref: bytes, block_time: int, retention_start: int) -> bytes:
    return encode({1: payload_ref, 2: block_time, 3: retention_start})
