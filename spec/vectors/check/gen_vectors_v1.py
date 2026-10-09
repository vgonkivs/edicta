#!/usr/bin/env python3
"""Generates the format v1 vectors (v1-draft.4) under spec/vectors/v1. Deterministic.

Usage: python3 spec/vectors/check/gen_vectors_v1.py [--out DIR]
Keys are core keys.json by reference (agent1, agent2, gate1); no copy is written.
Writes valid.json, reject.json, authorization.json, limits.json, anchor.json, action.json, gate.json and
payload.json;
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
# Every file changed at v1-draft.4: each v1 action hash is salted, so every v1 commitment hash changes.
REVISION = "v1-draft.4"
REJECT_REVISION = REVISION
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


def salt_of(label: str) -> bytes:
    """Fixed action salt of a vector, from a label (core 13 derivation): SHA-256("action-salt/" + label)."""
    return g.h("action-salt/" + label)


def salted(c: dict, label: str, action_type: str = IBKR, action: bytes = ACTION) -> dict:
    c = copy.deepcopy(c)
    c["action"] = {"type": action_type, "hash": v1.action_hash_v1(action_type, salt_of(label), action)}
    c["_salt_label"] = label
    return c


def strip(c: dict) -> dict:
    return {k: v for k, v in c.items() if not k.startswith("_")}


def preimage_prefix_v1(action_type: str) -> bytes:
    t = action_type.encode()
    return v0.tagged(v1.TAG_ACTION_V1) + bytes([len(t)]) + t


def action_fields_v1(action_type: str, action: bytes, salt: bytes, with_hash: bool = True) -> dict:
    out = g.action_fields(action_type, action, with_hash=False)
    out["action_salt_hex"] = salt.hex()
    if with_hash:
        out["action_preimage_prefix_hex"] = preimage_prefix_v1(action_type).hex()
        out["action_hash_hex"] = v1.action_hash_v1(action_type, salt, action).hex()
    return out


def blob_v1() -> dict:
    c = g.base()
    c["version"] = 1
    c["nonce"] = g.h("v1 nonce blob")[:16]
    return salted(c, "v1 blob")


def fibre_v1() -> dict:
    c = g.fibre()
    c["version"] = 1
    c["nonce"] = g.h("v1 nonce fibre")[:16]
    c["payload_size"] = 1024
    return salted(c, "v1 fibre")


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
    c = salted(c, "v1 maximal", g.TYPE_128, b"edicta v1 maximal")
    c["payload_ref"]["height"] = v0.MAX_INT
    c["payload_ref"]["anchor"] = v1.ANCHOR_PENDING
    c["payload_size"] = 1 << 27
    c["mandate_ref"] = mandate_ref()
    return c


def canon_of(c: dict) -> bytes:
    return encode(v1.to_cbor(strip(c), v1.COMMITMENT_V1))


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
        c = strip(c)
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
        c = salted(c, cid, action_type, action)
        salt = salt_of(cid)
        canon = canon_of(c)
        case = {"id": cid, "description": desc}
        case.update(signed_fields(c, canon))
        case["now"] = str(NOW)
        case["pending"] = v1.is_pending(c)
        case.update(action_fields_v1(action_type, action, salt))
        case["placeholders"] = {"payload_ref.commitment": PLACEHOLDER}
        if "mandate_ref" in c:
            case["placeholders"]["mandate_ref"] = "mandate_hash of spec/vectors/policy/mandate.json case m_full."
        VALID[cid] = (strip(c), canon, action_type, action, salt)
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
    c = pending(blob_v1(), H0_BLOB, "pending blob mandate ref")
    c["mandate_ref"] = mandate_ref()
    add("v1_pending_blob_mandate_ref", "Pending blob reference with mandate_ref: fast mode needs a mandate (7.4), so "
        "every fast-mode Authorization is for a decision that names one.", c)
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
    return v1.to_cbor(strip(c), v1.COMMITMENT_V1)


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
        raw_case(cid, stage, rule, desc, ikeyed(c) if c.get("version") == 1 else v0.to_cbor(strip(c)), expect, reader,
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

def check_block(action_type: str, action: bytes, now: int, accept=None, skew: int = 30,
                salt: bytes | None = None) -> dict:
    blk = {"gate_pubkey_hex": g.KEYS["gate1"]["public_key_hex"], "gate_id": g.GID, "action_type": action_type}
    blk.update({k: v for k, v in g.action_fields(action_type, action, with_hash=False).items() if k != "action_type"})
    if salt is not None:
        blk["action_salt_hex"] = salt.hex()
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
    c, canon, _, _, _ = VALID[ref]
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
        _, _, at, act, salt = VALID[ref]
        case = {"id": cid, "description": desc, "commitment_ref": ref, "authorized_at": str(NOW)}
        if extra:
            case.update(extra)
        case.update(auth_fields(a, auth_canon(a)))
        case["check"] = check_block(at, act, NOW, salt=salt)
        cases.append(case)
        return case

    add("auth_v1_strict_da", "v1_minimal_included_blob, payload from DA (path 1), mode 1, no deadline.",
        "v1_minimal_included_blob", base_auth("v1_minimal_included_blob", 1, 1, None))
    add("auth_v1_strict_archive", "v1_mandate_ref, payload from the archive (path 2), mode 1.",
        "v1_mandate_ref", base_auth("v1_mandate_ref", 2, 1, None))
    w = v1.fast_window(1, H0_FIBRE, H0_FIBRE + 2, 100, 10, 200, chain_window=1000)
    add("auth_v1_fast_fibre", f"v1_pending_fibre_mandate_ref in fast mode: head = h0 + 2, FastWindowBlocks 100, "
        f"mandate bound 200, chain window 1000, so anchor_deadline = h0 + 100 = {w}.",
        "v1_pending_fibre_mandate_ref", base_auth("v1_pending_fibre_mandate_ref", 1, 2, w),
        {"window_inputs": {"da": "1", "h0": str(H0_FIBRE), "head": str(H0_FIBRE + 2), "fast_window_blocks": "100",
                           "max_h0_age": "10", "fast_mode_max_delay": "200", "chain_window": "1000",
                           "min_fast_slack_blocks": "3"}})
    w = v1.fast_window(2, H0_BLOB, H0_BLOB + 1, 100, 10, 200, timeout_height=H0_BLOB + 40)
    add("auth_v1_fast_blob_timeout_lowered", f"v1_pending_blob_mandate_ref in fast mode: the PFB's "
        f"timeout_height h0 + 40 is below h0 + 100 (mandate bound 200), so anchor_deadline = {w}, which is at "
        f"least head + MinFastSlackBlocks.",
        "v1_pending_blob_mandate_ref", base_auth("v1_pending_blob_mandate_ref", 2, 2, w),
        {"window_inputs": {"da": "2", "h0": str(H0_BLOB), "head": str(H0_BLOB + 1), "fast_window_blocks": "100",
                           "max_h0_age": "10", "fast_mode_max_delay": "200", "timeout_height": str(H0_BLOB + 40),
                           "min_fast_slack_blocks": "3"}})
    big = {"version": 1, "commitment_hash": g.h("v1 auth max commitment"), "action_hash": g.h("v1 auth max action"),
           "gate_id": "g" * 64, "expires": v0.MAX_INT, "path": 2, "mode": 2, "anchor_deadline": v0.MAX_INT}
    canon = auth_canon(big)
    case = {"id": "auth_v1_max_size", "description": "Largest v1 SignedAuthorization: gate_id 64 chars, expires and "
            "anchor_deadline 2^63-1 (9-byte heads), 233 bytes. Encoding and signature only (stand-in hashes)."}
    case.update(auth_fields(big, canon))
    assert len(bytes.fromhex(case["signed_authorization_hex"])) == 233
    cases.append(case)

    def rej(cid, stage, rule, desc, canon_or_map, expect, ref="v1_pending_blob_mandate_ref", tags="v1",
            signer="gate1", accept=None, executor="v1", a=None, data=None):
        _, _, at, act, salt = VALID[ref]
        canon = canon_or_map if isinstance(canon_or_map, bytes) else encode(canon_or_map)
        case = {"id": cid, "stage": stage, "rule": rule, "executor": executor, "description": desc,
                "commitment_ref": ref}
        case.update(auth_fields(a, canon, tags, signer))
        if data is not None:
            case["signed_authorization_hex"] = data.hex()
        case["check"] = check_block(at, act, NOW, accept, salt=salt if executor == "v1" else None)
        case["expect_error"] = expect
        reject.append(case)

    fast = base_auth("v1_pending_blob_mandate_ref", 2, 2, H0_BLOB + 40)
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
    reject[-1]["check"].pop("action_salt_hex")
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
    reject[-1]["check"].pop("action_salt_hex")
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
    ms = dict(strict)
    rej("exec_v1_salt_missing", "X", "X2s", "auth_v1_strict_da presented without action_salt.", auth_canon(ms),
        "ErrMissingField", ref="v1_minimal_included_blob", a=ms)
    reject[-1]["check"].pop("action_salt_hex")
    rej("exec_v1_salt_31", "X", "X2s", "auth_v1_strict_da with a 31-byte action_salt.", auth_canon(ms),
        "ErrFieldSize", ref="v1_minimal_included_blob", a=ms)
    reject[-1]["check"]["action_salt_hex"] = reject[-1]["check"]["action_salt_hex"][:62]
    rej("exec_v1_wrong_salt", "X", "X3", "auth_v1_strict_da with the salt's first bit flipped.", auth_canon(ms),
        "ErrActionMismatch", ref="v1_minimal_included_blob", a=ms)
    sb = bytearray(bytes.fromhex(reject[-1]["check"]["action_salt_hex"]))
    sb[0] ^= 0x80
    reject[-1]["check"]["action_salt_hex"] = sb.hex()
    rej("exec_v0_salt_present", "X", "X2s", "A v0 Authorization (v0 minimal_lmt, path 1, v0 tags) presented with a "
        "32-byte action_salt: a v0 commitment has no salt.", encode(v0.to_cbor(a0b, v0.AUTHORIZATION)),
        "ErrUnknownKey", ref=case_ref, tags="v0")
    reject[-1]["input"] = _conv(a0b, v0.AUTHORIZATION, True)
    reject[-1]["check"]["action_salt_hex"] = salt_of("v0 with salt").hex()
    padded = bytes.fromhex(cases[-1]["signed_authorization_hex"]) + bytes(256 - 233 + 1)
    rej("auth_v1_too_large", "D", "D0", "auth_v1_max_size followed by 24 zero bytes: 257 bytes.", auth_canon(big),
        "ErrTooLarge", data=padded, a=big)
    return {"format": FORMAT, "revision": REVISION, "max_authorization_ttl_s": str(MAX_AUTH_TTL),
            "gate": gate_to_json(GATE), "patterns": PATTERNS, "cases": cases, "reject": reject}


# limits.json

def limits_vectors() -> dict:
    c, canon, at, act, _ = VALID["v1_maximal"]
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

    def win(cid, desc, da, h0, head, fwb, age, delay, chain=None, timeout=0, slack=3, included=None, promise=None):
        inp = {"da": str(da), "fast_window_blocks": str(fwb), "h0": str(h0), "head": str(head), "max_h0_age": str(age),
               "fast_mode_max_delay": str(delay), "min_fast_slack_blocks": str(slack)}
        if chain is not None:
            inp["chain_window"] = str(chain)
        if da == 2:
            inp["timeout_height"] = str(timeout)
        if included is not None:
            inp["included_at"], inp["included_code"] = str(included[0]), str(included[1])
        if promise is not None:
            inp["promise"] = {k: str(v) for k, v in promise.items()}
        try:
            e = {"anchor_deadline": str(v1.fast_window(da, h0, head, fwb, age, delay, chain, timeout, slack, included,
                                                       promise))}
        except Reject as err:
            e = {"expect_error": err.sentinel}
        return {"id": cid, "description": desc, "input": inp, "expect": e}

    h0 = H0_FIBRE
    tp = T0 - 3000
    window = [
        win("window_gate_min", "FastWindowBlocks 100 is the smallest bound.", 1, h0, h0 + 3, 100, 10, 500, 1000),
        win("window_mandate_min", "The mandate's fast_mode_max_delay 40 is the smallest bound.", 1, h0, h0 + 3, 100,
            10, 40, 1000),
        win("window_chain_min", "The chain's payment_promise_height_window 30 is the smallest bound.", 1, h0, h0 + 3,
            100, 10, 500, 30),
        win("window_blob_gate_min", "da = 2: window = FastWindowBlocks below the mandate bound (replaces "
            "window_no_mandate_blob of v1-draft.3: fast mode needs a mandate since v1-draft.4).", 2, H0_BLOB,
            H0_BLOB, 100, 10, 500),
        win("timeout_lowers_deadline", "da = 2: timeout_height h0 + 25 < h0 + 100 lowers the deadline.", 2, H0_BLOB,
            H0_BLOB + 1, 100, 10, 500, timeout=H0_BLOB + 25),
        win("timeout_above_window", "da = 2: timeout_height above h0 + window does not raise it.", 2, H0_BLOB,
            H0_BLOB + 1, 100, 10, 500, timeout=H0_BLOB + 500),
        win("timeout_zero_ignored", "da = 2: timeout_height 0 means none.", 2, H0_BLOB, H0_BLOB + 1, 100, 10, 500,
            timeout=0),
        win("h0_age_at_bound", "head - h0 == MaxH0AgeBlocks: accepted (deadline h0 + 100 >= head + 3).", 1, h0,
            h0 + 10, 100, 10, 500, 1000),
        win("h0_too_old", "head - h0 == MaxH0AgeBlocks + 1.", 1, h0, h0 + 11, 100, 10, 500, 1000),
        win("window_closed", "head - h0 = 6 within the age bound 10, window 5 (mandate bound): deadline h0 + 5 is "
            "below head + 3.", 1, h0, h0 + 6, 100, 10, 5, 1000),
        win("window_at_bound", "head - h0 == window: the deadline equals the head, below head + MinFastSlackBlocks "
            "(accepted in v1-draft.3, refused since v1-draft.4).", 1, h0, h0 + 5, 100, 10, 5, 1000),
        win("window_slack_at_bound", "deadline == head + MinFastSlackBlocks (window 8, head h0 + 5): accepted.", 1, h0,
            h0 + 5, 100, 10, 8, 1000),
        win("window_slack_one_short", "deadline == head + 2 (window 7, head h0 + 5): refused.", 1, h0, h0 + 5, 100, 10,
            7, 1000),
        win("timeout_below_head", "da = 2, h0 100, timeout_height 101, head 105: the lowered deadline is below the "
            "head.", 2, 100, 105, 100, 10, 500, timeout=101),
        win("timeout_at_head_plus_slack", "da = 2, timeout_height = head + 3: accepted, deadline = timeout_height.", 2,
            100, 105, 100, 10, 500, timeout=108),
        win("slack_waived_included", "Slack fails (deadline = head), but the lookup finds the tx included with code 0 "
            "at h0 + 4 <= deadline: the failure is waived.", 1, h0, h0 + 5, 100, 10, 5, 1000,
            included=(h0 + 4, 0)),
        win("slack_not_waived_nonzero", "Slack fails and the tx is included with code 4: refused.", 1, h0, h0 + 5, 100,
            10, 5, 1000, included=(h0 + 4, 4)),
        win("promise_slack", "da = 1: T(h) + MinPromiseSlackSeconds == creation_timestamp + payment_promise_timeout "
            "(15 s left is not enough), tx not found.", 1, h0, h0 + 3, 100, 10, 500, 1000,
            promise={"t_head": tp, "creation": tp - 3585, "timeout": 3600, "min_slack": 15}),
        win("promise_slack_ok", "da = 1: 16 s left before the promise expires: accepted.", 1, h0, h0 + 3, 100, 10, 500,
            1000, promise={"t_head": tp, "creation": tp - 3584, "timeout": 3600, "min_slack": 15}),
        win("window_chain_zero", "Chain payment_promise_height_window 0: window 0 is refused (window >= 1), even "
            "at head = h0.", 1, h0, h0, 100, 10, 500, 0),
        win("head_below_h0", "Head below h0: the consensus endpoint is behind.", 1, h0, h0 - 1, 100, 10, 500, 1000),
    ]
    return {"format": FORMAT, "revision": REVISION, "margin_cap": "600", "k1": k1, "k2": k2s, "window": window}


# action.json

def action_vectors() -> dict:
    salt = salt_of("minimal")
    pre = preimage_prefix_v1(IBKR) + salt + ACTION
    cases = [{"id": "action_v1_minimal", "description": "ActionHashV1 of the core minimal_lmt action (IBKR order) "
              "with the salt of label action-salt/minimal.", "version": "1",
              **action_fields_v1(IBKR, ACTION, salt, with_hash=False),
              "preimage_hex": pre.hex(), "preimage_size": str(len(pre)),
              "action_hash_hex": hashlib.sha256(pre).hexdigest()}]
    assert cases[0]["action_hash_hex"] == v1.action_hash_v1(IBKR, salt, ACTION).hex()
    big = g.ACTION_MAX
    salt_m = salt_of("max")
    pre_m = preimage_prefix_v1(g.TYPE_128) + salt_m + big
    cases.append({"id": "action_v1_max", "description": "128-byte type and 65,536 action bytes (pattern): the "
                  "preimage is the prefix, the salt, then the bytes.", "version": "1",
                  **action_fields_v1(g.TYPE_128, big, salt_m, with_hash=False),
                  "preimage_prefix_hex": preimage_prefix_v1(g.TYPE_128).hex(), "preimage_size": str(len(pre_m)),
                  "action_hash_hex": hashlib.sha256(pre_m).hexdigest()})
    t = IBKR.encode()
    v1h = v1.action_hash_v1(IBKR, salt, ACTION)
    reject = []

    def rj(cid, rule, desc, version, committed, presented_salt, action=ACTION, committed_preimage=None):
        r = {"id": cid, "stage": "A", "rule": rule, "description": desc, "version": str(version),
             "action_type": IBKR, "action_hex": action.hex(), "committed_action_hash_hex": committed.hex()}
        if committed_preimage is not None:
            r["committed_preimage_hex"] = committed_preimage.hex()
        if presented_salt is not None:
            r["action_salt_hex"] = presented_salt.hex()
        c = {"action": {"type": IBKR, "hash": committed}}
        try:
            v1.gate_stage_a(version, c, action, presented_salt)
            raise AssertionError(cid)
        except Reject as e:
            r["expect_error"] = e.sentinel
        reject.append(r)

    wrong = bytes([salt[0] ^ 1]) + salt[1:]
    rj("action_v1_wrong_salt", "A1", "The committed salt with its lowest bit flipped.", 1, v1h, wrong)
    rj("action_v1_salt_missing", "A0s", "v1 commitment, no salt presented.", 1, v1h, None)
    rj("action_v1_salt_31", "A0s", "A 31-byte salt.", 1, v1h, salt[:31])
    rj("action_v1_salt_33", "A0s", "A 33-byte salt.", 1, v1h, salt + b"\x00")
    pre_v0tag = v0.tagged(v0.TAG_ACTION) + bytes([len(t)]) + t + salt + ACTION
    rj("action_v1_v0_tag", "A1", "Committed with the v1 preimage under edicta/v0/action.", 1,
       hashlib.sha256(pre_v0tag).digest(), salt, committed_preimage=pre_v0tag)
    rj("action_v1_unsalted", "A1", "Committed with core ActionHash (no salt).", 1, v0.action_hash(IBKR, ACTION), salt)
    pre_after = preimage_prefix_v1(IBKR) + ACTION + salt
    rj("action_v1_salt_after_bytes", "A1", "Committed with the salt after the action bytes.", 1,
       hashlib.sha256(pre_after).digest(), salt, committed_preimage=pre_after)
    rj("action_v0_with_salt", "A0s", "v0 commitment (core ActionHash) presented with a salt.", 0,
       v0.action_hash(IBKR, ACTION), salt)
    rj("action_v0_salt_prefixed_bytes", "A1", "v0 commitment whose action.hash is ActionHashV1(type, salt, bytes); "
       "the presented v0 action is salt || bytes. Core ActionHash(type, salt || bytes) differs from it: the tag "
       "separation.", 0, v1h, None, action=salt + ACTION)
    assert v0.action_hash(IBKR, salt + ACTION) != v1h
    return {"format": FORMAT, "revision": REVISION, "tag": v0.tagged(v1.TAG_ACTION_V1).hex(),
            "salt_derivation": "action_salt = SHA-256(\"action-salt/\" || label)", "cases": cases, "reject": reject}


# gate.json

def gate_vectors() -> dict:
    ns = g.NAMESPACE
    base = {"fast_mode": True, "pending_namespaces": [ns]}
    out = []

    def case(cid, desc, cfg, mandate=True, allowlist=None):
        allow = allowlist if allowlist is not None else GATE["action_types"]
        j = {k: ([x.hex() for x in v] if k == "pending_namespaces" else (v if isinstance(v, (bool, list)) else str(v)))
             for k, v in cfg.items()}
        try:
            v1.validate_gate_config(cfg, mandate, allow)
            e = {"result": "ok"}
        except Reject as err:
            e = {"error": err.sentinel, "cause": err.detail}
        out.append({"id": cid, "description": desc, "config": j, "mandate": mandate, "expect": e})

    case("defaults_fast_mode", "FastMode with a namespace, a mandate and every default.", base)
    case("fast_mode_without_mandate", "FastMode at a gate without a mandate: no mandate, no fast mode.", base,
         mandate=False)
    case("strict_without_mandate", "FastMode off and no mandate: accepted.", {"fast_mode": False}, mandate=False)
    case("fast_mode_without_namespaces", "FastMode with no PendingNamespaces.", {"fast_mode": True})
    case("max_h0_age_equals_window", "MaxH0AgeBlocks = FastWindowBlocks (the range is 1..FastWindowBlocks - 1).",
         dict(base, fast_window_blocks=20, max_h0_age_blocks=20))
    case("age_plus_slack_over_window", "MaxH0AgeBlocks 18 + MinFastSlackBlocks 3 > FastWindowBlocks 20.",
         dict(base, fast_window_blocks=20, max_h0_age_blocks=18))
    case("age_plus_slack_at_window", "MaxH0AgeBlocks 17 + MinFastSlackBlocks 3 = FastWindowBlocks 20: accepted.",
         dict(base, fast_window_blocks=20, max_h0_age_blocks=17))
    case("min_fast_slack_0", "MinFastSlackBlocks 0.", dict(base, min_fast_slack_blocks=0))
    case("min_fast_slack_101", "MinFastSlackBlocks 101.", dict(base, min_fast_slack_blocks=101))
    case("min_promise_slack_0", "MinPromiseSlackSeconds 0.", dict(base, min_promise_slack_seconds=0))
    case("min_promise_slack_601", "MinPromiseSlackSeconds 601.", dict(base, min_promise_slack_seconds=601))
    case("fast_window_1001", "FastWindowBlocks 1001.", dict(base, fast_window_blocks=1001))
    case("reveal_type_allowlisted", "RevealOnExecution names an allowlisted type: accepted.",
         dict(base, reveal_on_execution=[g.TYPE_JSON]))
    case("reveal_type_not_allowlisted", "RevealOnExecution names a type outside the allowlist.",
         dict(base, reveal_on_execution=["application/vnd.edicta.other.v0+cbor"]))
    return {"format": FORMAT, "revision": REVISION, "allowlist": GATE["action_types"],
            "defaults": {k: (v if isinstance(v, bool) else str(v)) for k, v in v1.GATE_CONFIG_DEFAULTS.items()},
            "cases": out}


# payload.json

def payload_v1_dict(salt: bytes, action: bytes = ACTION) -> dict:
    return {"version": 1, "model": {"id": "edicta-test-model"}, "policy": {"id": "edicta-test-policy"},
            "context": {"media_type": "application/json", "data": b'{"note":"v1 payload vector"}'},
            "action": {"type": IBKR, "data": action, "action_salt": salt}}


def payload_vectors() -> dict:
    import edicta_payload_v0 as pv0
    import hpke_base as hpke
    salt = salt_of("payload")
    committed = v1.action_hash_v1(IBKR, salt, ACTION)
    aead_salt = g.h("v1 payload aead salt")
    pt = v1.payload_encode_v1(payload_v1_dict(salt))
    ikm = g.h("v1 payload recipient ikm")
    sk_r, pk_r = hpke.derive_key_pair(ikm)
    sk_e = hpke.derive_key_pair(g.h("v1 payload ephemeral ikm"))[0]
    blob, _ = pv0.seal(aead_salt, pt, [pv0.Recipient(b"auditor-1", pk_r, sk_e)], g.h("v1 payload dek"),
                       g.h("v1 payload nonce")[:12])
    aead_pt = pv0.open_blob(blob, sk_r)
    assert aead_pt == aead_salt + pt
    v1.o8(1, aead_pt, IBKR, committed)
    valid = {"id": "payload_v1_minimal", "description": "Payload v1 with action_salt (key 5 of the action), sealed "
             "with the unchanged blob layout to one recipient; O1 to O7 as core, then O8 v1 passes.",
             "commitment_version": "1", "action_type": IBKR, "committed_action_hash_hex": committed.hex(),
             "action_salt_hex": salt.hex(), "plaintext_cbor_hex": pt.hex(), "aead_salt_hex": aead_salt.hex(),
             "plaintext_hash_hex": hashlib.sha256(aead_salt + pt).hexdigest(),
             "recipient": {"kid_hex": b"auditor-1".hex(), "ikm_hex": ikm.hex(), "sk_hex": sk_r.hex(), "pk_hex": pk_r.hex()},
             "blob_hex": blob.hex(), "ciphertext_hash_hex": hashlib.sha256(blob).hexdigest(),
             "payload_size": str(len(blob))}
    reject = []

    def rj(cid, desc, plaintext: bytes, version: int, committed_hash: bytes = committed):
        r = {"id": cid, "description": desc, "commitment_version": str(version), "action_type": IBKR,
             "committed_action_hash_hex": committed_hash.hex(), "plaintext_cbor_hex": plaintext.hex()}
        try:
            v1.o8(version, aead_salt + plaintext, IBKR, committed_hash)
            raise AssertionError(cid)
        except Reject as e:
            r["expect_error"] = e.sentinel
        reject.append(r)

    def raw(m: dict) -> bytes:
        return encode(m)

    p = payload_v1_dict(salt)
    m = {1: 1, 2: {1: "edicta-test-model"}, 3: {1: "edicta-test-policy"},
         4: {1: "application/json", 2: p["context"]["data"]}, 5: {3: IBKR, 4: ACTION, 5: salt}}
    assert raw(m) == pt
    m2 = copy.deepcopy(m); del m2[5][5]
    rj("payload_v1_salt_missing", "Under a v1 commitment, the action has no key 5 (PV3).", raw(m2), 1)
    m2 = copy.deepcopy(m); m2[5][5] = salt[:31]
    rj("payload_v1_salt_31", "A 31-byte action_salt (PV3).", raw(m2), 1)
    m2 = copy.deepcopy(m); m2[5][5] = salt.hex()
    rj("payload_v1_salt_tstr", "action_salt as text (PV3).", raw(m2), 1)
    m2 = copy.deepcopy(m); m2[1] = 0
    rj("payload_v1_version_0", "Under a v1 commitment, a payload with version 0 and a salt: well-formed for the v1 "
       "schema except the version (PV2).", raw(m2), 1)
    m2 = copy.deepcopy(m); m2[1] = 0; del m2[5][5]
    rj("payload_v0_under_v1_commitment", "A core v0 payload (no salt, version 0) under a v1 commitment: PV1 selects "
       "the v1 schema, so key 5 is missing (PV3).", raw(m2), 1)
    m2 = copy.deepcopy(m); m2[1] = 0
    rj("payload_v0_with_salt", "Under a v0 commitment (core 9.3 verbatim), an action key 5 is unknown.", raw(m2), 0,
       v0.action_hash(IBKR, ACTION))
    rj("payload_v1_under_v0_commitment", "A payload v1 under a v0 commitment: key 5 is unknown to core 9.3.", pt, 0,
       v0.action_hash(IBKR, ACTION))
    m2 = copy.deepcopy(m); m2[5][5] = bytes([salt[0] ^ 1]) + salt[1:]
    rj("payload_v1_wrong_salt", "O8 v1: the payload's salt differs from the committed one by one bit.", raw(m2), 1)
    rj("payload_v1_unsalted_commitment", "O8 v1: the commitment's action.hash is core ActionHash of the same "
       "bytes.", pt, 1, v0.action_hash(IBKR, ACTION))
    return {"format": FORMAT, "revision": REVISION, "cases": [valid], "reject": reject}


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
            "authorization.json": auth, "limits.json": limits_vectors(), "anchor.json": anchor_vectors(),
            "action.json": action_vectors(), "gate.json": gate_vectors(), "payload.json": payload_vectors()}


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    for name, obj in build().items():
        write(name, obj)


if __name__ == "__main__":
    main()
