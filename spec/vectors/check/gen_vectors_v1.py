#!/usr/bin/env python3
"""Generates the format v1 vectors (v1-draft.3) under spec/vectors/v1. Deterministic.

Usage: python3 spec/vectors/check/gen_vectors_v1.py [--out DIR]
Keys are core keys.json by reference (agent1, agent2, gate1); no copy is written.
Writes valid.json, reject.json, authorization.json, limits.json and anchor.json;
archive.json and verify.json are written by gen_archive_v1.py.
"""

from __future__ import annotations

import sys

sys.dont_write_bytecode = True

import copy
import hashlib
import json
from pathlib import Path

import edicta_v0 as v0
import edicta_v1 as v1
import gen_vectors as g
from cbor_strict import Raw, encode
from edicta_v0 import Reject
from vecjson import PATTERNS, _conv, gate_to_json, params_to_json

OUT = Path(__file__).resolve().parent.parent / "v1"
if "--out" in sys.argv:
    OUT = Path(sys.argv[sys.argv.index("--out") + 1]).resolve()
FORMAT = "edicta-vectors/v1"
REVISION = "v1-draft.2"
# A file carries the revision of its last content change; reject.json changed at v1-draft.3 (anchor_2pow63).
REJECT_REVISION = "v1-draft.3"
MANDATE_FILE = Path(__file__).resolve().parent.parent / "policy" / "mandate.json"

T0, NOW, GATE, IBKR, ACTION = g.T0, g.NOW, g.GATE, g.IBKR, g.ACTION_MINIMAL
H0_FIBRE = 4200123
H0_BLOB = 4200000
MAX_AUTH_TTL = 300
PLACEHOLDER = ("Placeholder: SHA-256 of a fixed label, not the DA commitment of any blob. The bytes and hashes "
               "of this vector are normative; the value is not a real anchor.")


def mandate_ref() -> bytes:
    """mandate_hash of policy mandate.json case m_full (gate gate-paper-1)."""
    cases = json.loads(MANDATE_FILE.read_text())["cases"]
    return bytes.fromhex(next(c for c in cases if c["id"] == "m_full")["mandate_hash_hex"])


def cj(c: dict) -> dict:
    return _conv(c, v1.COMMITMENT_V1, True)


def aj(a: dict) -> dict:
    return _conv(a, v1.AUTHORIZATION_V1, True)


def blob_v1() -> dict:
    c = g.base()
    c["version"] = 1
    c["nonce"] = g.h("v1 nonce blob")[:16]
    return c


def fibre_v1() -> dict:
    c = g.fibre()
    c["version"] = 1
    c["nonce"] = g.h("v1 nonce fibre")[:16]
    c["payload_size"] = 1024
    return c


def pending(c: dict, h0: int, label: str) -> dict:
    c = copy.deepcopy(c)
    c["nonce"] = g.h(f"v1 nonce {label}")[:16]
    c["payload_ref"]["height"] = h0
    c["payload_ref"]["anchor"] = v1.ANCHOR_PENDING
    return c


def maximal() -> dict:
    """Every field at its longest encoding: 596-byte commitment, 665-byte envelope."""
    c = blob_v1()
    c["agent_id"] = "a" * 64
    c["nonce"] = g.h("v1 nonce maximal")[:16]
    c["issued_at"] = v0.MAX_INT - 3600
    c["valid_until"] = v0.MAX_INT
    c["scope"] = {"gate_id": "g" * 64}
    c["action"] = {"type": g.TYPE_128, "hash": v0.action_hash(g.TYPE_128, b"edicta v1 maximal")}
    c["payload_ref"]["height"] = v0.MAX_INT
    c["payload_ref"]["anchor"] = v1.ANCHOR_PENDING
    c["payload_size"] = 1 << 27
    c["mandate_ref"] = mandate_ref()
    return c


def canon_of(c: dict) -> bytes:
    return encode(v1.to_cbor(c, v1.COMMITMENT_V1))


def sign_v1(canon: bytes, signer: str = "agent1"):
    hh = v1.commitment_hash_v1(canon)
    msg = v1.signing_message_v1(hh)
    return hh, msg, g.sk(signer).sign(msg)


def sign_v0(canon: bytes, signer: str = "agent1"):
    hh = v0.commitment_hash(canon)
    msg = v0.signing_message(hh)
    return hh, msg, g.sk(signer).sign(msg)


def env(canon: bytes, sig: bytes) -> bytes:
    return encode({1: Raw(canon), 2: sig})


def signed_fields(c: dict | None, canon: bytes, signer: str = "agent1", tags: str = "v1") -> dict:
    hh, msg, sig = (sign_v1 if tags == "v1" else sign_v0)(canon, signer)
    out = {}
    if c is not None:
        out["input"] = cj(c) if c.get("version") == 1 else _conv(c, v0.COMMITMENT, True)
    out.update({"commitment_cbor_hex": canon.hex(), "commitment_hash_hex": hh.hex(), "signer": signer,
                "signed_tags": tags, "signed_message_hex": msg.hex(), "signature_hex": sig.hex(),
                "envelope_hex": env(canon, sig).hex()})
    return out


# valid.json

VALID: dict = {}


def valid_cases() -> list:
    out = []

    def add(cid, desc, c, action_type=IBKR, action=ACTION):
        if action_type != IBKR or action != ACTION:
            c = g.with_action(c, action_type, action)
        canon = canon_of(c)
        case = {"id": cid, "description": desc}
        case.update(signed_fields(c, canon))
        case["now"] = str(NOW)
        case["pending"] = v1.is_pending(c)
        case.update(g.action_fields(action_type, action))
        case["placeholders"] = {"payload_ref.commitment": PLACEHOLDER}
        if "mandate_ref" in c:
            case["placeholders"]["mandate_ref"] = "mandate_hash of spec/vectors/policy/mandate.json case m_full."
        VALID[cid] = (c, canon, action_type, action)
        out.append(case)

    add("v1_minimal_included_fibre", "version 1, da = 1, included reference (anchor key absent): every field as v0.",
        fibre_v1())
    add("v1_minimal_included_blob", "version 1, da = 2, included reference.", blob_v1())
    add("v1_pending_fibre", f"da = 1, anchor = 2: payload_ref.height is the reference height h0 = {H0_FIBRE} "
        "(PaymentPromise.height of the upload).", pending(fibre_v1(), H0_FIBRE, "pending fibre"))
    add("v1_pending_blob", f"da = 2, anchor = 2: h0 = {H0_BLOB} is the head the Recorder read before building the PFB.",
        pending(blob_v1(), H0_BLOB, "pending blob"))
    c = blob_v1()
    c["nonce"] = g.h("v1 nonce mandate ref")[:16]
    c["mandate_ref"] = mandate_ref()
    add("v1_mandate_ref", "Included blob reference with mandate_ref (key 14).", c)
    c = pending(fibre_v1(), H0_FIBRE, "pending fibre mandate ref")
    c["mandate_ref"] = mandate_ref()
    add("v1_pending_fibre_mandate_ref", "Pending Fibre reference with mandate_ref: the fast-mode decision under a mandate.", c)
    c = maximal()
    add("v1_maximal", "Largest schema-valid v1 commitment: agent_id and gate_id 64 chars, action type 128, "
        "9-byte heads for issued_at, valid_until and height, payload_size 2^27, da = 2 with signer, anchor = 2, "
        "mandate_ref. 596-byte commitment, 665-byte envelope. Valid at its own issued_at (now = issued_at).", c,
        action_type=g.TYPE_128, action=b"edicta v1 maximal")
    out[-1]["now"] = str(c["issued_at"])
    out[-1]["gate"] = gate_to_json({"gate_id": "g" * 64, "action_types": [g.TYPE_128]})
    assert len(VALID["v1_maximal"][1]) == 596, len(VALID["v1_maximal"][1])
    assert len(bytes.fromhex(out[-1]["envelope_hex"])) == 665
    return out


# reject.json

def ikeyed(c: dict) -> dict:
    return v1.to_cbor(c, v1.COMMITMENT_V1)


def reject_cases() -> list:
    out = []
    b = blob_v1()
    f = fibre_v1()

    def raw_case(cid, stage, rule, desc, m: dict, expect, reader="v1", tags="v1", signer="agent1", src=None):
        canon = encode(m)
        case = {"id": cid, "stage": stage, "rule": rule, "reader": reader, "description": desc}
        case.update(signed_fields(src, canon, signer, tags))
        case["now"] = str(NOW)
        case["expect_error"] = expect
        out.append(case)

    def s_case(cid, stage, rule, desc, c, expect, reader="v1", tags="v1"):
        raw_case(cid, stage, rule, desc, ikeyed(c) if c.get("version") == 1 else v0.to_cbor(c), expect, reader,
                 tags, src=c)

    def mutate_pr(c, kv: dict):
        m = ikeyed(c)
        m[10].update(kv)
        return m

    raw_case("da_3_reserved", "S", "S3", "da = 3 is reserved for a batch leaf (4.4).",
             mutate_pr(b, {1: 3}), "ErrInvalidEnum")
    raw_case("da_3_with_anchor_2", "S", "S3", "da = 3 with anchor = 2 and a signer: S3 runs before V1-3.",
             mutate_pr(b, {1: 3, 6: 2}), "ErrInvalidEnum")
    raw_case("payload_ref_key_7_reserved", "D", "D15", "payload_ref key 7 (reserved leaf_hash, 32 bytes).",
             mutate_pr(b, {7: g.h("v1 leaf hash")}), "ErrUnknownKey")
    raw_case("payload_ref_key_8_reserved", "D", "D15", "payload_ref key 8 (reserved leaf_index = 0).",
             mutate_pr(b, {8: 0}), "ErrUnknownKey")
    m = ikeyed(b)
    m[15] = g.h("v1 attestation ref")
    raw_case("commitment_key_15_reserved", "D", "D15", "Commitment key 15 (reserved TEE attestation reference).",
             m, "ErrUnknownKey")
    for val, cid, desc in ((1, "anchor_1", "anchor = 1: included has one encoding, the absent key."),
                           (3, "anchor_3", "anchor = 3."),
                           (0, "anchor_0", "anchor = 0.")):
        raw_case(cid, "S", "V1-3", desc, mutate_pr(b, {6: val}), "ErrInvalidEnum")
    raw_case("anchor_2pow63", "S", "S2", "anchor = 2^63: S2 precedes V1-3.", mutate_pr(b, {6: 1 << 63}),
             "ErrIntRange")
    raw_case("anchor_tstr", "D", "D16", "anchor as the text \"2\".", mutate_pr(b, {6: "2"}), "ErrWrongType")
    for n, cid in ((31, "mandate_ref_31_bytes"), (33, "mandate_ref_33_bytes")):
        m = ikeyed(b)
        m[14] = (g.h("v1 mandate ref short") * 2)[:n]
        raw_case(cid, "D", "V1-2", f"mandate_ref of {n} bytes.", m, "ErrFieldSize")
    m = ikeyed(b)
    m[14] = mandate_ref().hex()
    raw_case("mandate_ref_tstr", "D", "D16", "mandate_ref as lower-case hex text.", m, "ErrWrongType")
    m = ikeyed(b)
    m[1] = 2
    raw_case("version_2", "S", "S1", "version = 2 with only v0-defined keys: the dispatch takes the v0 path, "
             "which refuses the version.", m, "ErrUnsupportedVersion")
    m = ikeyed(b)
    del m[1]
    raw_case("version_absent", "D", "D17", "version absent: the dispatch takes the v0 path.", m, "ErrMissingField")
    s_case("v1_signed_under_v0_tags", "G", "G1", "A v1 commitment hashed under edicta/v0/decision-commitment and "
           "signed under edicta/v0/sig.", b, "ErrSignatureInvalid", tags="v0")
    c0 = copy.deepcopy(g.base())
    s_case("v0_signed_under_v1_tags", "G", "G1", "The v0 minimal_lmt commitment hashed and signed under the v1 "
           "tags: the dispatch takes the v0 path, which verifies under the v0 tags.", c0, "ErrSignatureInvalid")
    s_case("v1_bytes_v0_reader_minimal", "S", "S1", "A frozen v0 reader given v1_minimal_included_blob: every key "
           "is v0-defined, so S1 refuses.", b, "ErrUnsupportedVersion", reader="v0")
    c = copy.deepcopy(b)
    c["mandate_ref"] = mandate_ref()
    s_case("v1_bytes_v0_reader_key_14", "D", "D15", "A frozen v0 reader given a v1 commitment with mandate_ref: "
           "key 14 is unknown to v0, and D15 precedes S1.", c, "ErrUnknownKey", reader="v0")
    s_case("v1_bytes_v0_reader_pending", "D", "D15", "A frozen v0 reader given v1_pending_blob: payload_ref key 6 "
           "is unknown to v0.", pending(b, H0_BLOB, "pending blob"), "ErrUnknownKey", reader="v0")
    m = ikeyed(b)
    m[9] = {1: 1}
    raw_case("retired_key_9", "D", "D15", "Retired constraints key 9 stays undefined in v1.", m, "ErrUnknownKey")
    m = ikeyed(pending(f, H0_FIBRE, "pending fibre"))
    m[10][5] = g.SIGNER
    raw_case("signer_on_fibre_pending", "D", "D15", "da = 1, anchor = 2, with a signer: key 5 is not defined for "
             "da = 1.", m, "ErrUnknownKey")
    m = ikeyed(pending(b, H0_BLOB, "pending blob"))
    del m[10][5]
    raw_case("missing_signer_blob_pending", "D", "D17", "da = 2, anchor = 2, without a signer.", m, "ErrMissingField")
    raw_case("height_0_pending", "S", "S6", "Pending reference with h0 = 0.",
             ikeyed(pending(b, 0, "pending zero")), "ErrZeroValue")
    return out


# authorization.json

def check_block(action_type: str, action: bytes, now: int, accept=None, skew: int = 30) -> dict:
    blk = {"gate_pubkey_hex": g.KEYS["gate1"]["public_key_hex"], "gate_id": g.GID, "action_type": action_type}
    blk.update({k: v for k, v in g.action_fields(action_type, action, with_hash=False).items() if k != "action_type"})
    blk["now"] = str(now)
    blk["skew_s"] = str(skew)
    if accept is not None:
        blk["accept_versions"] = [str(x) for x in sorted(accept)]
    return blk


def auth_canon(a: dict) -> bytes:
    return encode(v1.to_cbor(a, v1.AUTHORIZATION_V1))


def sign_auth(canon: bytes, tags: str = "v1", signer: str = "gate1"):
    if tags == "v1":
        ah = v1.authorization_hash_v1(canon)
        msg = v1.authorization_message_v1(ah)
    else:
        ah = v0.authorization_hash(canon)
        msg = v0.tagged(v0.TAG_AUTHORIZATION_SIG) + ah
    return ah, msg, g.sk(signer).sign(msg)


def auth_fields(a: dict | None, canon: bytes, tags: str = "v1", signer: str = "gate1") -> dict:
    ah, msg, sig = sign_auth(canon, tags, signer)
    out = {}
    if a is not None:
        out["input"] = aj(a)
    out.update({"authorization_cbor_hex": canon.hex(), "authorization_hash_hex": ah.hex(), "signer": signer,
                "signed_tags": tags, "signed_message_hex": msg.hex(), "signature_hex": sig.hex(),
                "signed_authorization_hex": encode({1: Raw(canon), 2: sig}).hex()})
    return out


def base_auth(ref: str, path: int, mode: int, deadline: int | None, authorized_at: int = NOW) -> dict:
    c, canon, _, _ = VALID[ref]
    a = {"version": 1, "commitment_hash": v1.commitment_hash_v1(canon), "action_hash": c["action"]["hash"],
         "gate_id": c["scope"]["gate_id"], "expires": v0.authorization_expires(c["valid_until"], authorized_at,
                                                                                MAX_AUTH_TTL),
         "path": path, "mode": mode}
    if deadline is not None:
        a["anchor_deadline"] = deadline
    return a


def authorization_vectors() -> dict:
    cases, reject = [], []

    def add(cid, desc, ref, a, extra=None):
        _, _, at, act = VALID[ref]
        case = {"id": cid, "description": desc, "commitment_ref": ref, "authorized_at": str(NOW)}
        if extra:
            case.update(extra)
        case.update(auth_fields(a, auth_canon(a)))
        case["check"] = check_block(at, act, NOW)
        cases.append(case)
        return case

    add("auth_v1_strict_da", "v1_minimal_included_blob, payload from DA (path 1), mode 1, no deadline.",
        "v1_minimal_included_blob", base_auth("v1_minimal_included_blob", 1, 1, None))
    add("auth_v1_strict_archive", "v1_mandate_ref, payload from the archive (path 2), mode 1.",
        "v1_mandate_ref", base_auth("v1_mandate_ref", 2, 1, None))
    w = v1.fast_window(1, H0_FIBRE, H0_FIBRE + 2, 100, 10, fast_mode_max_delay=200, chain_window=1000)
    add("auth_v1_fast_fibre", f"v1_pending_fibre_mandate_ref in fast mode: head = h0 + 2, FastWindowBlocks 100, "
        f"mandate bound 200, chain window 1000, so anchor_deadline = h0 + 100 = {w}.",
        "v1_pending_fibre_mandate_ref", base_auth("v1_pending_fibre_mandate_ref", 1, 2, w),
        {"window_inputs": {"da": "1", "h0": str(H0_FIBRE), "head": str(H0_FIBRE + 2), "fast_window_blocks": "100",
                           "max_h0_age": "10", "fast_mode_max_delay": "200", "chain_window": "1000"}})
    w = v1.fast_window(2, H0_BLOB, H0_BLOB + 1, 100, 10, timeout_height=H0_BLOB + 40)
    add("auth_v1_fast_blob_timeout_lowered", f"v1_pending_blob in fast mode without a mandate: the PFB's "
        f"timeout_height h0 + 40 is below h0 + 100, so anchor_deadline = {w}.",
        "v1_pending_blob", base_auth("v1_pending_blob", 2, 2, w),
        {"window_inputs": {"da": "2", "h0": str(H0_BLOB), "head": str(H0_BLOB + 1), "fast_window_blocks": "100",
                           "max_h0_age": "10", "timeout_height": str(H0_BLOB + 40)}})
    big = {"version": 1, "commitment_hash": g.h("v1 auth max commitment"), "action_hash": g.h("v1 auth max action"),
           "gate_id": "g" * 64, "expires": v0.MAX_INT, "path": 2, "mode": 2, "anchor_deadline": v0.MAX_INT}
    canon = auth_canon(big)
    case = {"id": "auth_v1_max_size", "description": "Largest v1 SignedAuthorization: gate_id 64 chars, expires and "
            "anchor_deadline 2^63-1 (9-byte heads), 233 bytes. Encoding and signature only (stand-in hashes)."}
    case.update(auth_fields(big, canon))
    assert len(bytes.fromhex(case["signed_authorization_hex"])) == 233
    cases.append(case)

    def rej(cid, stage, rule, desc, canon_or_map, expect, ref="v1_pending_blob", tags="v1", signer="gate1",
            accept=None, executor="v1", a=None, data=None):
        _, _, at, act = VALID[ref]
        canon = canon_or_map if isinstance(canon_or_map, bytes) else encode(canon_or_map)
        case = {"id": cid, "stage": stage, "rule": rule, "executor": executor, "description": desc,
                "commitment_ref": ref}
        case.update(auth_fields(a, canon, tags, signer))
        if data is not None:
            case["signed_authorization_hex"] = data.hex()
        case["check"] = check_block(at, act, NOW, accept)
        case["expect_error"] = expect
        reject.append(case)

    fast = base_auth("v1_pending_blob", 2, 2, H0_BLOB + 40)
    strict = base_auth("v1_minimal_included_blob", 1, 1, None)
    m = v1.to_cbor(fast, v1.AUTHORIZATION_V1)
    del m[8]
    rej("auth_v1_fast_without_deadline", "D", "D17", "mode = 2 without anchor_deadline.", m, "ErrMissingField")
    m = v1.to_cbor(strict, v1.AUTHORIZATION_V1)
    m[8] = H0_BLOB + 100
    rej("auth_v1_strict_with_deadline", "D", "D15", "mode = 1 with anchor_deadline: key 8 is not defined for mode 1.",
        m, "ErrUnknownKey", ref="v1_minimal_included_blob")
    m = v1.to_cbor(fast, v1.AUTHORIZATION_V1)
    m[7] = 3
    rej("auth_v1_mode_3", "S", "Q5", "mode = 3 with a deadline: key 8 is optional at stage D for an unknown mode, "
        "Q5 refuses.", m, "ErrInvalidEnum")
    m = v1.to_cbor(strict, v1.AUTHORIZATION_V1)
    m[7] = 0
    rej("auth_v1_mode_0", "S", "Q5", "mode = 0 without a deadline.", m, "ErrInvalidEnum", ref="v1_minimal_included_blob")
    m = v1.to_cbor(strict, v1.AUTHORIZATION_V1)
    del m[7]
    rej("auth_v1_missing_mode", "D", "D17", "version 1 without mode.", m, "ErrMissingField",
        ref="v1_minimal_included_blob")
    m = v1.to_cbor(fast, v1.AUTHORIZATION_V1)
    del m[7]
    rej("auth_v1_missing_mode_with_deadline", "D", "D17", "version 1 with anchor_deadline and without mode: key 8 "
        "is optional while mode is unknown, then mode is missing.", m, "ErrMissingField")
    m = v1.to_cbor(fast, v1.AUTHORIZATION_V1)
    m[8] = 0
    rej("auth_v1_deadline_0", "S", "Q6", "mode = 2, anchor_deadline = 0.", m, "ErrZeroValue")
    m = v1.to_cbor(fast, v1.AUTHORIZATION_V1)
    m[8] = 1 << 63
    rej("auth_v1_deadline_2pow63", "S", "Q2", "anchor_deadline = 2^63.", m, "ErrIntRange")
    m = v1.to_cbor(strict, v1.AUTHORIZATION_V1)
    m[7] = 1 << 63
    rej("auth_v1_mode_2pow63", "S", "Q2", "mode = 2^63: Q2 precedes Q5.", m, "ErrIntRange",
        ref="v1_minimal_included_blob")
    m = v1.to_cbor(strict, v1.AUTHORIZATION_V1)
    m[7] = "1"
    rej("auth_v1_mode_tstr", "D", "D16", "mode as text.", m, "ErrWrongType", ref="v1_minimal_included_blob")
    rej("auth_v1_under_v0_tags", "G", "G1", "auth_v1_fast_blob_timeout_lowered signed under the v0 Authorization tags.",
        auth_canon(fast), "ErrSignatureInvalid", tags="v0", a=fast)
    a0 = {"version": 0, "commitment_hash": v0.commitment_hash(encode(v0.to_cbor(g.base()))),
          "action_hash": g.base()["action"]["hash"], "gate_id": g.GID,
          "expires": v0.authorization_expires(g.base()["valid_until"], NOW, MAX_AUTH_TTL), "path": 1}
    case_ref = "v1_minimal_included_blob"
    rej("auth_v0_under_v1_tags", "G", "G1", "A v0 Authorization (v0 minimal_lmt, path 1) signed under the v1 "
        "Authorization tags; the dispatch takes the v0 path.", encode(v0.to_cbor(a0, v0.AUTHORIZATION)),
        "ErrSignatureInvalid", ref=case_ref)
    reject[-1]["input"] = _conv(a0, v0.AUTHORIZATION, True)
    rej("v0_executor_refuses_v1", "D", "D15", "A frozen v0 executor (core 15.3 verbatim) given "
        "auth_v1_strict_da: key 7 is not in the v0 schema, and D15 precedes Q1.", auth_canon(strict),
        "ErrUnknownKey", ref="v1_minimal_included_blob", executor="v0", a=strict)
    rej("executor_accept_v0_only", "S", "Q1", "A v1 executor with check.accept_versions = {0} given auth_v1_strict_da.",
        auth_canon(strict), "ErrUnsupportedVersion", ref="v1_minimal_included_blob", accept={0}, a=strict)
    a0b = dict(a0)
    rej("executor_accept_v1_only_v0_auth", "S", "Q1", "A v1 executor with check.accept_versions = {1} given a v0 "
        "Authorization signed under the v0 tags.", encode(v0.to_cbor(a0b, v0.AUTHORIZATION)), "ErrUnsupportedVersion",
        ref=case_ref, tags="v0", accept={1})
    reject[-1]["input"] = _conv(a0b, v0.AUTHORIZATION, True)
    m = v0.to_cbor(dict(a0, version=1), v0.AUTHORIZATION)
    rej("v0_shape_version_1", "D", "D17", "A v0-shaped Authorization with version 1 (core vector "
        "authorization_version_1): a v1 executor takes the v1 path and finds mode missing.", m, "ErrMissingField",
        ref=case_ref)
    rej("auth_v1_signed_by_agent", "G", "G1", "auth_v1_strict_da signed by agent1 instead of the pinned gate1.",
        auth_canon(strict), "ErrSignatureInvalid", ref="v1_minimal_included_blob", signer="agent1", a=strict)
    exp = dict(strict)
    rej("auth_v1_expired", "X", "X4", "auth_v1_strict_da checked at now = expires - skew.", auth_canon(exp),
        "ErrExpired", ref="v1_minimal_included_blob", a=exp)
    reject[-1]["check"]["now"] = str(exp["expires"] - 30)
    ab = dict(strict)
    rej("auth_v1_action_mismatch", "X", "X3", "auth_v1_strict_da with the action's last byte flipped.",
        auth_canon(ab), "ErrActionMismatch", ref="v1_minimal_included_blob", a=ab)
    flipped = ACTION[:-1] + bytes([ACTION[-1] ^ 1])
    reject[-1]["check"]["action_hex"] = flipped.hex()
    padded = bytes.fromhex(cases[-1]["signed_authorization_hex"]) + bytes(256 - 233 + 1)
    rej("auth_v1_too_large", "D", "D0", "auth_v1_max_size followed by 24 zero bytes: 257 bytes.", auth_canon(big),
        "ErrTooLarge", data=padded, a=big)
    return {"format": FORMAT, "revision": REVISION, "max_authorization_ttl_s": str(MAX_AUTH_TTL),
            "gate": gate_to_json(GATE), "patterns": PATTERNS, "cases": cases, "reject": reject}


# limits.json

def limits_vectors() -> dict:
    c, canon, at, act = VALID["v1_maximal"]
    _, _, sig = sign_v1(canon)
    envb = env(canon, sig)
    over = envb + bytes(v0.MAX_SIGNED_SIZE + 1 - len(envb))
    # A commitment over 2048 bytes inside an envelope within 2176: agent_id cannot grow, so a long
    # mandate_ref-sized key cannot either; the over-size map carries an unknown key, and D14 (size)
    # is checked before the keys of the commitment are read.
    m = v1.to_cbor(c, v1.COMMITMENT_V1)
    m[16] = bytes(2048 - len(canon) - 4 + 1)
    big = encode(m)
    assert len(big) == 2049, len(big)
    _, _, bsig = sign_v1(big)
    big_env = env(big, bsig)
    assert len(big_env) <= v0.MAX_SIGNED_SIZE
    auth = json.loads(json.dumps(AUTH_CACHE["auth_v1_max_size"]))
    return {"format": FORMAT, "revision": REVISION,
            "limits": {"max_signed_size": str(v0.MAX_SIGNED_SIZE), "max_commitment_size": str(v0.MAX_COMMITMENT_SIZE),
                       "max_authorization_size": str(v0.MAX_AUTHORIZATION_SIZE),
                       "max_v1_commitment": "596", "max_v1_envelope": "665", "max_v1_signed_authorization": "233"},
            "cases": [
                {"id": "v1_envelope_maximal", "description": "valid.json v1_maximal: 665 bytes, accepted.",
                 "envelope_hex": envb.hex(), "size": str(len(envb)), "now": str(c["issued_at"]),
                 "gate": gate_to_json({"gate_id": "g" * 64, "action_types": [g.TYPE_128]}), "expect": "accept"},
                {"id": "v1_envelope_2177", "description": "v1_maximal padded with zero bytes to 2177: D0.",
                 "envelope_hex": over.hex(), "size": str(len(over)), "now": str(c["issued_at"]),
                 "expect_error": "ErrTooLarge"},
                {"id": "v1_commitment_2049", "description": "A 2049-byte commitment (v1_maximal plus key 16 padding) "
                 "in a 2120-byte envelope: the commitment size check precedes the unknown key.",
                 "envelope_hex": big_env.hex(), "size": str(len(big_env)), "now": str(c["issued_at"]),
                 "expect_error": "ErrTooLarge"},
                {"id": "v1_signed_authorization_maximal", "description": "authorization.json auth_v1_max_size: "
                 "233 bytes, decodes and passes stage S.", "signed_authorization_hex": auth["signed_authorization_hex"],
                 "size": "233", "expect": "accept"},
            ]}


# anchor.json

def anchor_vectors() -> dict:
    t_ref = T0 - 3000
    k1 = [
        {"id": "k1_pending_fibre_at_limit", "description": "Pending Fibre reference: issued_at + skew == T_ref "
         "(header time at h0).", "da": "1", "form": "pending", "issued_at": str(t_ref - 30), "t_ref": str(t_ref),
         "skew_s": "30"},
        {"id": "k1_pending_blob_one_second_early", "description": "Pending blob reference: issued_at + skew == "
         "T_ref - 1.", "da": "2", "form": "pending", "issued_at": str(t_ref - 31), "t_ref": str(t_ref),
         "skew_s": "30", "expect_error": "ErrIssuedBeforeAnchor"},
        {"id": "k1_included_blob", "description": "Included reference: T_ref = T_H, core K1 verbatim.", "da": "2",
         "form": "included", "issued_at": str(t_ref), "t_ref": str(t_ref), "skew_s": "30"},
    ]
    for c in k1:
        try:
            v0.check_anchor_time(int(c["issued_at"]), int(c["t_ref"]), int(c["skew_s"]))
            assert "expect_error" not in c
        except Reject as e:
            assert e.sentinel == c["expect_error"]

    def k2(cid, desc, da, form, valid_until, r, creation=None, created_at=None):
        start = v1.retention_start(da, form == "pending", t_ref, creation or 0, created_at or 0)
        within = v0.within_retention(valid_until, start, r)
        case = {"id": cid, "description": desc, "da": str(da), "form": form, "t_ref": str(t_ref),
                "valid_until": str(valid_until), "retention_s": str(r)}
        if creation is not None:
            case["creation_timestamp"] = str(creation)
        if created_at is not None:
            case["intent_created_at"] = str(created_at)
        case["expect"] = {"start": str(start), "margin": str(v0.retention_margin(r)), "within": within}
        return case

    k2s = [
        k2("k2_pending_fibre_created_before", "Pending Fibre: intent created_at = floor(promise.creation_timestamp) "
           "= T_ref - 20, so start = created_at; valid_until + 600 == start + 14400.", 1, "pending",
           t_ref - 20 + 14400 - 600, 14400, created_at=t_ref - 20),
        k2("k2_pending_fibre_one_over", "Same, one second over.", 1, "pending", t_ref - 20 + 14400 - 600 + 1, 14400,
           created_at=t_ref - 20),
        k2("k2_pending_fibre_created_after", "created_at after T_ref (clock skew of the promise): start = T_ref.",
           1, "pending", t_ref + 14400 - 600, 14400, created_at=t_ref + 5),
        k2("k2_included_fibre", "Included Fibre reference: start = min(T_ref, promise creation), core K2.", 1,
           "included", t_ref - 7 + 14400 - 600, 14400, creation=t_ref - 7),
        k2("k2_pending_blob", "Pending blob: start = T_ref (header time at h0).", 2, "pending", t_ref + 14400 - 600,
           14400),
        k2("k2_pending_blob_one_over", "Pending blob, one second over.", 2, "pending", t_ref + 14400 - 600 + 1, 14400),
    ]

    def win(cid, desc, da, h0, head, fwb, age, delay=None, chain=None, timeout=0):
        inp = {"da": str(da), "fast_window_blocks": str(fwb), "h0": str(h0), "head": str(head), "max_h0_age": str(age)}
        if delay is not None:
            inp["fast_mode_max_delay"] = str(delay)
        if chain is not None:
            inp["chain_window"] = str(chain)
        if da == 2:
            inp["timeout_height"] = str(timeout)
        try:
            e = {"anchor_deadline": str(v1.fast_window(da, h0, head, fwb, age, delay, chain, timeout))}
        except Reject as err:
            e = {"expect_error": err.sentinel}
        return {"id": cid, "description": desc, "input": inp, "expect": e}

    h0 = H0_FIBRE
    window = [
        win("window_gate_min", "FastWindowBlocks 100 is the smallest bound.", 1, h0, h0 + 3, 100, 10, 500, 1000),
        win("window_mandate_min", "The mandate's fast_mode_max_delay 40 is the smallest bound.", 1, h0, h0 + 3, 100,
            10, 40, 1000),
        win("window_chain_min", "The chain's payment_promise_height_window 30 is the smallest bound.", 1, h0, h0 + 3,
            100, 10, 500, 30),
        win("window_no_mandate_blob", "da = 2 at a gate without a mandate: window = FastWindowBlocks.", 2, H0_BLOB,
            H0_BLOB, 100, 10),
        win("timeout_lowers_deadline", "da = 2: timeout_height h0 + 25 < h0 + 100 lowers the deadline.", 2, H0_BLOB,
            H0_BLOB + 1, 100, 10, timeout=H0_BLOB + 25),
        win("timeout_above_window", "da = 2: timeout_height above h0 + window does not raise it.", 2, H0_BLOB,
            H0_BLOB + 1, 100, 10, timeout=H0_BLOB + 500),
        win("timeout_zero_ignored", "da = 2: timeout_height 0 means none.", 2, H0_BLOB, H0_BLOB + 1, 100, 10,
            timeout=0),
        win("h0_age_at_bound", "head - h0 == MaxH0AgeBlocks: accepted.", 1, h0, h0 + 10, 100, 10, 500, 1000),
        win("h0_too_old", "head - h0 == MaxH0AgeBlocks + 1.", 1, h0, h0 + 11, 100, 10, 500, 1000),
        win("window_closed", "head - h0 = 6 within the age bound 10 but above the window 5 (mandate bound).", 1, h0,
            h0 + 6, 100, 10, 5, 1000),
        win("window_at_bound", "head - h0 == window: accepted, deadline = h0 + window.", 1, h0, h0 + 5, 100, 10, 5,
            1000),
        win("window_chain_zero", "Chain payment_promise_height_window 0: window 0 is refused (window >= 1), even "
            "at head = h0.", 1, h0, h0, 100, 10, 500, 0),
        win("head_below_h0", "Head below h0: the consensus endpoint is behind.", 1, h0, h0 - 1, 100, 10, 500, 1000),
    ]
    return {"format": FORMAT, "revision": REVISION, "margin_cap": "600", "k1": k1, "k2": k2s, "window": window}


AUTH_CACHE: dict = {}


def write(name: str, obj: dict):
    path = OUT / name
    path.write_text(json.dumps(obj, indent=2, ensure_ascii=True) + "\n")
    print(f"wrote {path}")


def build() -> dict:
    VALID.clear()
    AUTH_CACHE.clear()
    head_ = {"format": FORMAT, "revision": REVISION, "params": params_to_json(g.PARAMS), "gate": gate_to_json(GATE),
             "patterns": PATTERNS, "keys": "spec/vectors/v0/keys.json"}
    valid = valid_cases()
    reject = reject_cases()
    auth = authorization_vectors()
    AUTH_CACHE.update({c["id"]: c for c in auth["cases"]})
    return {"valid.json": dict(head_, cases=valid), "reject.json": dict(head_, revision=REJECT_REVISION, cases=reject),
            "authorization.json": auth, "limits.json": limits_vectors(), "anchor.json": anchor_vectors()}


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    for name, obj in build().items():
        write(name, obj)


if __name__ == "__main__":
    main()
