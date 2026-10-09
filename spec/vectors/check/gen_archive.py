#!/usr/bin/env python3
"""Generates spec/vectors/archive/records.json and state.json (v1-draft.5): archive records of
format 1 for the payload, evidence, decision, Authorization and rejection kinds. Deterministic.

Decisions, Authorizations and payloads are real vector data from the core set (v1/valid.json,
v1/authorization.json, keys.json) and the DA sets (da/blob_commit.json, da/fibre_commit.json).
Celestia objects inside evidence records (headers, proofs, txs, validator sets) are placeholders: the
record layer carries them as opaque byte strings, and these files fix the record layout, not their
content. spec/vectors/v1/archive.json (gen_archive_v1.py) covers the other kinds.

Usage: python3 spec/vectors/check/gen_archive.py [--core DIR] [--out DIR]
Defaults: --core spec/vectors/v1; --out spec/vectors/archive.
"""

from __future__ import annotations

import sys

sys.dont_write_bytecode = True

import hashlib
import json
from pathlib import Path

import archive as av
from cbor_strict import Pairs, Raw, encode
from ed25519_point import BASE, L, challenge, encode as pt_encode, mul

HERE = Path(__file__).resolve().parent
VECTORS = HERE.parent


def arg(name: str, default: Path) -> Path:
    if name in sys.argv:
        return Path(sys.argv[sys.argv.index(name) + 1]).resolve()
    return default


CORE = arg("--core", VECTORS / "v1")
OUT = arg("--out", VECTORS / "archive")
FORMAT = "edicta-vectors/v1"
REVISION = "v1-draft.5"
GENERATOR = "spec/vectors/check/gen_archive.py"
INLINE_MAX = 1024
RECORD_INLINE_MAX = 4096
PATTERNS = {"affine-7-3": "byte i is (7*i + 3) mod 256, for i from 0"}


def load(p: Path) -> dict:
    return json.loads(p.read_text())


VALID = {c["id"]: c for c in load(CORE / "valid.json")["cases"]}
AUTHS = {c["id"]: c for c in load(CORE / "authorization.json")["cases"]}
DA_BLOB = {c["id"]: c for c in load(VECTORS / "da" / "blob_commit.json")["cases"]}
FIBRE = {c["id"]: c for c in load(VECTORS / "da" / "fibre_commit.json")["cases"]}
KEYS = load(VECTORS / "keys.json")["keys"]


PERIOD = bytes((7 * i + 3) & 0xFF for i in range(256))


def pattern(size: int) -> bytes:
    return (PERIOD * (size // 256 + 1))[:size]


def blob_of(c: dict) -> bytes:
    if "blob_hex" in c:
        return bytes.fromhex(c["blob_hex"])
    return pattern(int(c["size"]))


def action_of(c: dict) -> bytes:
    if "action_hex" in c:
        return bytes.fromhex(c["action_hex"])
    return pattern(int(c["action_size"]))


# ---------------------------------------------------------------- JSON form

def field_json(name: str, typ, val):
    if isinstance(typ, dict):
        return {n: field_json(n, t, val[n]) for k, (n, t, _, _) in sorted(typ.items()) if n in val}
    if typ == "uint":
        return str(val)
    if typ == "bstr":
        if len(val) > INLINE_MAX:
            expect = pattern(len(val))
            assert val == expect, f"{name}: large field is not the affine-7-3 pattern"
            return {"pattern": "affine-7-3", "size": str(len(val)), "sha256_hex": hashlib.sha256(val).hexdigest()}
        return val.hex()
    return val


def input_json(rec: dict) -> dict:
    schema = av.SCHEMAS[rec["kind"]]
    out = {"kind": av.KIND_NAMES[rec["kind"]]}
    for k in sorted(schema):
        name, typ, _, _ = schema[k]
        if name in rec:
            out[name] = field_json(name, typ, rec[name])
    return out


def record_fields(data: bytes) -> dict:
    if len(data) <= RECORD_INLINE_MAX:
        return {"record_cbor_hex": data.hex()}
    return {"record_size": str(len(data)), "record_sha256_hex": hashlib.sha256(data).hexdigest()}


# ---------------------------------------------------------------- inputs

def resign(case: dict, label: str) -> bytes:
    """The same commitment signed again with another nonce r: a second valid
    Ed25519 signature by the same key (not RFC 8032 deterministic signing)."""
    seed = bytes.fromhex(KEYS[case["signer"]]["seed_hex"])
    hs = hashlib.sha512(seed).digest()
    a = int.from_bytes(hs[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    pub = bytes.fromhex(KEYS[case["signer"]]["public_key_hex"])
    msg = bytes.fromhex(case["signed_message_hex"])
    r = int.from_bytes(hashlib.sha512(f"edicta/v0 test archive resign|{label}".encode()).digest(), "little") % L
    r_enc = pt_encode(mul(r, BASE))
    s = (r + challenge(r_enc, pub, msg) * a) % L
    sig = r_enc + s.to_bytes(32, "little")
    env = bytes.fromhex(case["envelope_hex"])
    assert env[-66:-64] == b"\x58\x40" and env[-64:] == bytes.fromhex(case["signature_hex"])
    out = env[:-64] + sig
    assert out != env
    return out


def ph(label: str, size: int) -> bytes:
    return av.placeholder(label, size)


def payload_da2(case_id: str, intent: int) -> dict:
    c = DA_BLOB[case_id]
    return {"kind": av.KIND_PAYLOAD, "da": 2, "commitment": bytes.fromhex(c["commitment_hex"]),
            "namespace": bytes.fromhex(c["namespace_hex"]), "signer": bytes.fromhex(c["signer_hex"]),
            "blob": blob_of(c), "intent_height": intent}


def payload_da1(case_id: str, intent: int) -> dict:
    c = FIBRE[case_id]
    return {"kind": av.KIND_PAYLOAD, "da": 1, "commitment": bytes.fromhex(c["commitment_hex"]),
            "blob": blob_of(c), "intent_height": intent}


def evidence_da2(label: str, height: int, with_tx: bool) -> dict:
    c = DA_BLOB["blob_v1_minimal_lmt_payload"]
    rec = {"kind": av.KIND_EVIDENCE, "da": 2, "commitment": bytes.fromhex(c["commitment_hex"]),
           "namespace": bytes.fromhex(c["namespace_hex"]), "height": height,
           "header": ph(f"{label}|header", 96), "blob_proof": ph(f"{label}|blob_proof", 160)}
    if with_tx:
        rec |= {"anchor_tx": ph(f"{label}|anchor_tx", 120), "anchor_tx_index": 3,
                "anchor_tx_proof": ph(f"{label}|anchor_tx_proof", 140)}
    return rec


def evidence_da1(label: str, height: int) -> dict:
    c = FIBRE["fibre_live_mocha_popsmin1"]
    return {"kind": av.KIND_EVIDENCE, "da": 1, "commitment": bytes.fromhex(c["commitment_hex"]),
            "namespace": bytes.fromhex(c["live"]["namespace_hex"]), "height": height,
            "header": ph(f"{label}|header", 96), "anchor_tx": ph(f"{label}|anchor_tx", 200),
            "anchor_tx_index": 0, "tx_code": 0, "system_blob": ph(f"{label}|system_blob", 90),
            "system_blob_proof": ph(f"{label}|system_blob_proof", 160), "promise_height": 1402813,
            "promise_header": ph(f"{label}|promise_header", 96),
            "historical_info": ph(f"{label}|historical_info", 300)}


def decision(case_id: str, envelope: bytes | None = None) -> dict:
    c = VALID[case_id]
    return {"kind": av.KIND_DECISION, "envelope": envelope or bytes.fromhex(c["envelope_hex"]),
            "form": av.FORM_PUBLIC, "action": action_of(c), "action_salt": bytes.fromhex(c["action_salt_hex"])}


def authorization(auth_id: str, k2: dict | None) -> dict:
    a = AUTHS[auth_id]
    rec = {"kind": av.KIND_AUTHORIZATION, "signed_authorization": bytes.fromhex(a["signed_authorization_hex"]),
           "authorized_at": int(a["authorized_at"])}
    if k2 is not None:
        rec["k2"] = k2
    return rec


def k2_da2(checked_at: int, block_time: int) -> dict:
    return {"da": 2, "checked_at": checked_at, "block_time": block_time, "blob_retention_s": 14400}


def k2_da1(checked_at: int, block_time: int, created: int | None, source: int) -> dict:
    k = {"da": 1, "checked_at": checked_at, "block_time": block_time, "retention_latest_s": 14400,
         "retention_at_height_s": 14400, "retention_source": source}
    if created is not None:
        k["promise_created"] = created
    return k


def rejection(case_id: str, error: str, at: int) -> dict:
    return {"kind": av.KIND_REJECTION, "commitment_hash": bytes.fromhex(VALID[case_id]["commitment_hash_hex"]),
            "error": error, "gate_id": "gate-paper-1", "rejected_at": at}


T_H = 1790999950

CASES = [
    ("payload_da2_minimal_lmt", "da = 2 payload of valid case minimal_lmt (da/blob_commit.json blob_v1_minimal_lmt_payload); namespace and signer present because the share commitment covers them.",
     payload_da2("blob_v1_minimal_lmt_payload", 4199990), {"da_blob": "blob_v1_minimal_lmt_payload"}, []),
    ("payload_da2_minimal_lmt_later_intent", "Same blob archived again with a later intent height: same identity, the stored record (first intent) is kept.",
     payload_da2("blob_v1_minimal_lmt_payload", 4199995), {"da_blob": "blob_v1_minimal_lmt_payload"}, []),
    ("payload_da2_256k", "da = 2 payload of 262144 bytes (blob length head of 5 bytes), da/blob_commit.json blob_v1_size_262144.",
     payload_da2("blob_v1_size_262144", 4199990), {"da_blob": "blob_v1_size_262144"}, []),
    ("payload_da2_wrong_commitment", "Well-formed record whose commitment is not the share commitment of its blob (it is that of blob_v1_size_1): the store refuses it before writing.",
     {**payload_da2("blob_v1_minimal_lmt_payload", 4199990), "commitment": bytes.fromhex(DA_BLOB["blob_v1_size_1"]["commitment_hex"])},
     {"da_blob": "blob_v1_minimal_lmt_payload"}, []),
    ("payload_da1_live", "da = 1 payload: the live Mocha Fibre blob (fibre_commit.json fibre_live_mocha_popsmin1). No namespace and no signer: the Fibre commitment covers neither.",
     payload_da1("fibre_live_mocha_popsmin1", 1402810), {"fibre_commit": "fibre_live_mocha_popsmin1"}, []),
    ("payload_da1_live_later_intent", "Same Fibre blob, later intent height: no-op.",
     payload_da1("fibre_live_mocha_popsmin1", 1402900), {"fibre_commit": "fibre_live_mocha_popsmin1"}, []),
    ("evidence_da2_minimal_lmt", "da = 2 evidence, minimum: header at height and the blob's commitment proof.",
     evidence_da2("ev2", 4200000, False), {"da_blob": "blob_v1_minimal_lmt_payload"}, ["header", "blob_proof"]),
    ("evidence_da2_minimal_lmt_with_tx", "da = 2 evidence with the optional PFB tx, its index and its proof; same identity as evidence_da2_minimal_lmt.",
     evidence_da2("ev2tx", 4200000, True), {"da_blob": "blob_v1_minimal_lmt_payload"},
     ["header", "blob_proof", "anchor_tx", "anchor_tx_proof"]),
    ("evidence_da2_minimal_lmt_other_height", "Evidence for the same key at another height: a different anchor, a conflict.",
     evidence_da2("ev2h", 4200001, False), {"da_blob": "blob_v1_minimal_lmt_payload"}, ["header", "blob_proof"]),
    ("evidence_da1_live", "da = 1 evidence at the live anchor height 1402819, valset height 1402813; no PFF tx proof (optional).",
     evidence_da1("ev1", 1402819), {"fibre_commit": "fibre_live_mocha_popsmin1"},
     ["header", "anchor_tx", "system_blob", "system_blob_proof", "promise_header", "historical_info"]),
    ("evidence_da1_live_other_height", "da = 1 evidence for the same key at another height: conflict.",
     evidence_da1("ev1h", 1402820), {"fibre_commit": "fibre_live_mocha_popsmin1"},
     ["header", "anchor_tx", "system_blob", "system_blob_proof", "promise_header", "historical_info"]),
    ("decision_minimal_lmt", "Decision record (kind 17, form 1: the action bytes and the salt in clear) of valid case minimal_lmt.",
     decision("minimal_lmt"), {"valid": "minimal_lmt"}, []),
    ("decision_minimal_lmt_resigned", "Same commitment, a second valid signature by agent1 (another nonce r): different bytes under the same key, a conflict the gate treats as success (AR2).",
     decision("minimal_lmt", resign(VALID["minimal_lmt"], "minimal_lmt")), {"valid": "minimal_lmt"}, []),
    ("decision_fibre_small_payload", "Decision record of valid case fibre_small_payload (da = 1).",
     decision("fibre_small_payload"), {"valid": "fibre_small_payload"}, []),
    ("decision_action_json_bytes", "Decision record of valid case action_json_bytes.",
     decision("action_json_bytes"), {"valid": "action_json_bytes"}, []),
    ("decision_action_max_size", "Decision record with a 65536-byte action (action length head of 5 bytes); given by size and SHA-256.",
     decision("action_max_size"), {"valid": "action_max_size"}, []),
    ("authorization_minimal_lmt_da", "Authorization auth_minimal_lmt_da with the K2 inputs (da = 2).",
     authorization("auth_minimal_lmt_da", k2_da2(1791000060, T_H)), {"authorization": "auth_minimal_lmt_da"}, []),
    ("authorization_minimal_lmt_da_repaired", "The same Authorization written by the startup repair from the registry: no K2 inputs. Same identity as authorization_minimal_lmt_da.",
     authorization("auth_minimal_lmt_da", None), {"authorization": "auth_minimal_lmt_da"}, []),
    ("authorization_minimal_lmt_archive", "Another Authorization for the same commitment (path = 2): conflict.",
     authorization("auth_minimal_lmt_archive", k2_da2(1791000060, T_H)), {"authorization": "auth_minimal_lmt_archive"}, []),
    ("authorization_fibre_small_payload", "da = 1 Authorization with every K2 input, at-height value from both sources.",
     authorization("auth_fibre_small_payload", k2_da1(1791000060, T_H, T_H - 10, av.SOURCE_BOTH)),
     {"authorization": "auth_fibre_small_payload"}, []),
    ("authorization_action_json_bytes", "Authorization auth_action_json_bytes, K2 inputs da = 2.",
     authorization("auth_action_json_bytes", k2_da2(1791000060, T_H)), {"authorization": "auth_action_json_bytes"}, []),
    ("rejection_minimal_lmt_not_yet_valid", "minimal_lmt refused with ErrNotYetValid.",
     rejection("minimal_lmt", "ErrNotYetValid", 1790999990), {"valid": "minimal_lmt"}, []),
    ("rejection_minimal_lmt_not_yet_valid_later", "The same name again, later: no-op, the first marker stays.",
     rejection("minimal_lmt", "ErrNotYetValid", 1791000010), {"valid": "minimal_lmt"}, []),
    ("rejection_minimal_lmt_payload_unavailable", "minimal_lmt refused with ErrPayloadUnavailable.",
     rejection("minimal_lmt", "ErrPayloadUnavailable", 1791000030), {"valid": "minimal_lmt"}, []),
    ("rejection_action_json_bytes_expired", "action_json_bytes refused with ErrExpired.",
     rejection("action_json_bytes", "ErrExpired", 1791000901), {"valid": "action_json_bytes"}, []),
    ("rejection_fibre_small_payload_retention", "fibre_small_payload refused with ErrRetentionUnavailable.",
     rejection("fibre_small_payload", "ErrRetentionUnavailable", 1791000060), {"valid": "fibre_small_payload"}, []),
    ("authorization_minimal_lmt_da_k2_da1", "Authorization auth_minimal_lmt_da with da = 1 K2 inputs, while the decision has da = 2: well-formed alone, corrupt next to its decision (the store refuses to write it, a reader reports it corrupt).",
     authorization("auth_minimal_lmt_da", k2_da1(1791000060, T_H, T_H - 10, av.SOURCE_DIRECT)),
     {"authorization": "auth_minimal_lmt_da"}, []),
]


def build_cases():
    out, recs = [], {}
    for cid, desc, rec, refs, placeholders in CASES:
        data = av.encode_record(rec)
        assert av.decode_record(data) == rec, cid
        recs[cid] = rec
        entry = {"id": cid, "description": desc, "kind": av.KIND_NAMES[rec["kind"]], "input": input_json(rec),
                 "key": av.key_path(av.record_key(rec)), **record_fields(data), "refs": refs}
        if placeholders:
            entry["placeholders"] = placeholders
        out.append(entry)
    return out, recs


# ---------------------------------------------------------------- rejects

def cbor_map(pairs) -> bytes:
    return encode(Pairs(tuple(pairs)))


def mutate(base: dict, **changes) -> bytes:
    """Encode base with named fields replaced (None removes); keeps key order."""
    m = av.to_cbor(base)
    schema = av.schema_of(base["kind"])
    by_name = {f[0]: k for k, f in schema.items()}
    for name, val in changes.items():
        k = by_name[name] if not name.startswith("key_") else int(name[4:])
        if val is None:
            m.pop(k, None)
        else:
            m[k] = val
    return encode(m)


def build_rejects(recs: dict):
    p2 = recs["payload_da2_minimal_lmt"]
    p1 = recs["payload_da1_live"]
    e2 = recs["evidence_da2_minimal_lmt"]
    e1 = recs["evidence_da1_live"]
    d = recs["decision_minimal_lmt"]
    a = recs["authorization_minimal_lmt_da"]
    a1 = recs["authorization_fibre_small_payload"]
    r = recs["rejection_minimal_lmt_not_yet_valid"]
    good_p2 = av.encode_record(p2)
    good_r = av.encode_record(r)
    k2_1 = av._to_int_keys(a1["k2"], av.K2)
    k2_2 = av._to_int_keys(a["k2"], av.K2)

    rej = [
        ("rec_not_map", "A record that is an array.", encode([0, 1]), "ErrWrongType"),
        ("rec_trailing_byte", "A valid rejection record followed by one byte.", good_r + b"\x00", "ErrTrailingData"),
        ("rec_float", "format encoded as a float.", Raw(b""), "ErrFloat"),
        ("rec_tag", "A tagged bstr as the commitment.", Raw(b""), "ErrTag"),
        ("rec_unsorted", "kind before format.", cbor_map([(2, 5), (1, 1)]), "ErrUnsortedMap"),
        ("rec_non_minimal", "format 1 encoded in two bytes.", Raw(b""), "ErrNonMinimalInt"),
        ("rec_too_many_entries", "25 entries in one map.", cbor_map([(k, 0) for k in range(1, 26)]), "ErrTooLarge"),
        ("rec_nesting_3", "A map inside the K2 map.", mutate(a, k2={**k2_2, 2: {1: 0}}), "ErrNestingTooDeep"),
        ("rec_format_missing", "No format key.", cbor_map([(2, 5)]), "ErrMissingField"),
        ("rec_format_0", "format = 0: archive records of the unsupported v0 drafts are refused at the header.",
         mutate(r, format=0), "ErrUnsupportedVersion"),
        ("rec_format_2", "format = 2.", mutate(r, format=2), "ErrUnsupportedVersion"),
        ("rec_kind_missing", "No kind key.", cbor_map([(1, 1)]), "ErrMissingField"),
        ("rec_kind_tstr", "kind as a text string.", cbor_map([(1, 1), (2, "rejection")]), "ErrWrongType"),
        ("rec_kind_0", "kind = 0.", mutate(r, kind=0), "ErrInvalidEnum"),
        ("rec_kind_6", "kind = 6.", mutate(r, kind=6), "ErrInvalidEnum"),
        ("rec_kind_3", "kind = 3: unassigned in format 1 (the decision record is kind 17).", mutate(r, kind=3),
         "ErrInvalidEnum"),
        ("rec_kind_19", "kind = 19: undefined.", mutate(r, kind=19), "ErrInvalidEnum"),
        ("rec_kind_size_cap", "A decision record labelled as a rejection: above the 256-byte cap of that kind, refused before the schema.",
         mutate(d, kind=5), "ErrTooLarge"),
        ("rec_kind_mismatch", "An Authorization record labelled as a rejection: key 3 is not a 32-byte hash.",
         mutate(a, kind=5, k2=None), "ErrFieldSize"),
        ("payload_unknown_key", "Payload key 9.", mutate(p2, key_9=1), "ErrUnknownKey"),
        ("payload_da1_namespace", "da = 1 payload with a namespace.", mutate(p1, key_5=p2["namespace"]), "ErrUnknownKey"),
        ("payload_da2_no_signer", "da = 2 payload without signer.", mutate(p2, signer=None), "ErrMissingField"),
        ("payload_da3", "da = 3.", mutate(p1, da=3), "ErrInvalidEnum"),
        ("payload_commitment_33", "33-byte commitment (a BlobID).", mutate(p1, commitment=b"\x00" + p1["commitment"]), "ErrFieldSize"),
        ("payload_blob_empty", "Empty blob.", mutate(p1, blob=b""), "ErrFieldSize"),
        ("payload_signer_tstr", "signer as bech32 text.", mutate(p2, signer="celestia1rxcpgc9d67garayuh9jtv0ha" ), "ErrWrongType"),
        ("payload_intent_0", "intent_height = 0.", mutate(p2, intent_height=0), "ErrZeroValue"),
        ("payload_intent_2_63", "intent_height = 2^63.", mutate(p2, intent_height=1 << 63), "ErrIntRange"),
        ("payload_namespace_reserved", "Namespace with version 255.", mutate(p2, namespace=b"\xff" + p2["namespace"][1:]), "ErrInvalidNamespace"),
        ("evidence_da1_no_historical_info", "da = 1 evidence without the validator set at the promise height.",
         mutate(e1, historical_info=None), "ErrMissingField"),
        ("evidence_da1_no_anchor_tx", "da = 1 evidence without the PFF tx (and its index).",
         mutate(e1, anchor_tx=None, anchor_tx_index=None), "ErrMissingField"),
        ("evidence_da1_tx_code_1", "da = 1 evidence with tx_code = 1.", mutate(e1, tx_code=1), "ErrIntRange"),
        ("evidence_da1_blob_proof", "da = 1 evidence with a da = 2 blob proof.", mutate(e1, blob_proof=b"\x01"), "ErrUnknownKey"),
        ("evidence_da2_system_blob", "da = 2 evidence with a system blob.", mutate(e2, system_blob=b"\x01"), "ErrUnknownKey"),
        ("evidence_da2_index_without_tx", "da = 2 evidence with anchor_tx_index but no anchor_tx.",
         mutate(e2, anchor_tx_index=3), "ErrUnknownKey"),
        ("evidence_da2_tx_without_index", "da = 2 evidence with anchor_tx but no index.",
         mutate(e2, anchor_tx=b"\x01"), "ErrMissingField"),
        ("evidence_height_0", "height = 0.", mutate(e2, height=0), "ErrZeroValue"),
        ("evidence_promise_height_0", "promise_height = 0.", mutate(e1, promise_height=0), "ErrZeroValue"),
        ("evidence_header_empty", "Empty header.", mutate(e2, header=b""), "ErrFieldSize"),
        ("decision_action_empty", "Empty action.", mutate(d, action=b""), "ErrFieldSize"),
        ("decision_envelope_trailing", "Envelope with a trailing byte.", mutate(d, envelope=d["envelope"] + b"\x00"), "ErrTrailingData"),
        ("decision_envelope_not_envelope", "Envelope bytes that are a SignedAuthorization.",
         mutate(d, envelope=a["signed_authorization"]), "ErrWrongType"),
        ("decision_unknown_key", "Decision key 7.", mutate(d, key_7=b"\x01"), "ErrUnknownKey"),
        ("decision_envelope_version_0", "A decision record whose envelope carries version 0 (a v0-shaped commitment): refused like any envelope failing S1.",
         mutate(d, envelope=_version0_envelope(d["envelope"])), "ErrUnsupportedVersion"),
        ("evidence_da1_promise_valset", "da = 1 evidence with key 18: unassigned in format 1.",
         mutate(e1, key_18=b"\x01"), "ErrUnknownKey"),
        ("authorization_garbage", "signed_authorization that is not CBOR.", mutate(a, signed_authorization=b"\xff"), "ErrMalformed"),
        ("authorization_path_3", "An Authorization with path = 3 (signature irrelevant at decoding).",
         mutate(a, signed_authorization=_path3(a["signed_authorization"])), "ErrInvalidEnum"),
        ("authorization_at_0", "authorized_at = 0.", mutate(a, authorized_at=0), "ErrZeroValue"),
        ("k2_da2_latest", "da = 2 K2 inputs with retention_latest_s.", mutate(a, k2={**k2_2, 5: 14400}), "ErrUnknownKey"),
        ("k2_da1_no_at_height", "da = 1 K2 inputs without the at-height value.",
         mutate(a1, k2={k: v for k, v in k2_1.items() if k != 6}), "ErrMissingField"),
        ("k2_da1_no_source", "da = 1 K2 inputs without the at-height source.",
         mutate(a1, k2={k: v for k, v in k2_1.items() if k != 7}), "ErrMissingField"),
        ("k2_source_4", "retention_source = 4.", mutate(a1, k2={**k2_1, 7: 4}), "ErrInvalidEnum"),
        ("k2_da_3", "K2 da = 3.", mutate(a, k2={**k2_2, 1: 3}), "ErrInvalidEnum"),
        ("k2_promise_created_0", "promise_created = 0 (unknown is absent, never 0).", mutate(a1, k2={**k2_1, 8: 0}), "ErrZeroValue"),
        ("k2_da2_promise_created", "da = 2 K2 inputs with promise_created.", mutate(a, k2={**k2_2, 8: T_H}), "ErrUnknownKey"),
        ("k2_not_map", "k2 as a byte string.", mutate(a, k2=b"\x00"), "ErrWrongType"),
        ("rejection_operational_name", "ErrChainUnavailable is operational, never a marker.", mutate(r, error="ErrChainUnavailable"), "ErrInvalidEnum"),
        ("rejection_name_space", "Name with a space.", mutate(r, error="Err Expired"), "ErrInvalidString"),
        ("rejection_name_no_prefix", "Name without the Err prefix.", mutate(r, error="Expired"), "ErrInvalidString"),
        ("rejection_name_package", "Name with a package prefix.", mutate(r, error="gate.ErrNonceUsed"), "ErrInvalidString"),
        ("rejection_gate_id_space", "gate_id with a space.", mutate(r, gate_id="gate paper"), "ErrInvalidString"),
        ("rejection_hash_31", "31-byte commitment_hash.", mutate(r, commitment_hash=r["commitment_hash"][:31]), "ErrFieldSize"),
        ("rejection_at_0", "rejected_at = 0.", mutate(r, rejected_at=0), "ErrZeroValue"),
    ]
    rej += strict_rejects(recs, good_r)
    out = []
    for item in rej:
        rid, desc, data, cause = item[:4]
        if rid == "rec_float":
            data = bytes([0xA2, 0x01, 0xF9, 0x3C, 0x00, 0x02, 0x05])
        elif rid == "rec_tag":
            data = mutate(p1, commitment=Raw(bytes([0xC2]) + encode(p1["commitment"])))
        elif rid == "rec_non_minimal":
            data = bytes([0xA2, 0x01, 0x18, 0x01, 0x02, 0x05])
        if isinstance(data, Raw):
            data = data.data
        try:
            av.decode_record(data)
            raise AssertionError(f"{rid}: decodes")
        except av.Reject as e:
            assert e.sentinel == cause, f"{rid}: got {e.sentinel}, want {cause}"
        entry = {"id": rid, "description": desc, "record_cbor_hex": data.hex(),
                 "expect_error": "archive.ErrCorrupt", "cause": cause}
        if len(item) > 4:
            assert item[4][0] == cause, rid
            entry["defects"] = list(item[4])
        out.append(entry)
    return out


def strict_rejects(recs: dict, good_r: bytes) -> list:
    """Generic well-formedness causes with no other vector, and records with
    several defects whose cause is the earliest stage of section 19.1. An
    entry with a fifth element lists every defect, the expected cause first."""
    p2 = recs["payload_da2_minimal_lmt"]
    p1 = recs["payload_da1_live"]
    e1 = recs["evidence_da1_live"]
    d = recs["decision_minimal_lmt"]
    a = recs["authorization_minimal_lmt_da"]
    r = recs["rejection_minimal_lmt_not_yet_valid"]
    r_pairs = sorted(av.to_cbor(r).items())
    k2_2 = av._to_int_keys(a["k2"], av.K2)
    assert good_r[0] == 0xA6 and d["envelope"][0] == 0xA2

    def pairs(items) -> bytes:
        return encode(Pairs(tuple(items)))

    def tstr_raw(b: bytes) -> Raw:
        assert len(b) < 24
        return Raw(bytes([0x60 | len(b)]) + b)

    return [
        ("rec_indefinite_map", "The record map with an indefinite length (0xbf ... 0xff).",
         b"\xbf" + good_r[1:] + b"\xff", "ErrIndefiniteLength"),
        ("rejection_error_indefinite_tstr", "error as an indefinite-length text string of one chunk.",
         mutate(r, error=Raw(b"\x7f" + encode("ErrNotYetValid") + b"\xff")), "ErrIndefiniteLength"),
        ("payload_blob_indefinite_bstr", "blob as an indefinite-length byte string of one chunk.",
         mutate(p1, blob=Raw(b"\x5f" + encode(p1["blob"]) + b"\xff")), "ErrIndefiniteLength"),
        ("rec_break_stray", "A break byte (0xff) as the value of format: additional info 31 on major 7.",
         mutate(r, format=Raw(b"\xff")), "ErrMalformed"),
        ("rec_duplicate_key", "Key 1 (format) twice, both 1.",
         pairs(r_pairs[:1] + r_pairs[:1] + r_pairs[1:]), "ErrDuplicateKey"),
        ("rec_duplicate_last_key", "Key 6 (rejected_at) twice with different values.",
         pairs(r_pairs + [(6, r["rejected_at"] + 1)]), "ErrDuplicateKey"),
        ("k2_duplicate_key", "Key 2 (checked_at) twice inside the K2 inputs.",
         mutate(a, k2=Pairs(tuple(sorted(k2_2.items())[:2] + sorted(k2_2.items())[1:]))), "ErrDuplicateKey"),
        ("rec_simple_true", "format = true (0xf5).", mutate(r, format=Raw(b"\xf5")), "ErrSimpleValue"),
        ("rec_simple_null", "rejected_at = null (0xf6).", mutate(r, rejected_at=Raw(b"\xf6")), "ErrSimpleValue"),
        ("rec_simple_32", "rejected_at = simple(32), two-byte form (0xf8 0x20).",
         mutate(r, rejected_at=Raw(b"\xf8\x20")), "ErrSimpleValue"),
        ("rec_key_tstr", "A text key \"x\" after the last key.", pairs(r_pairs + [("x", 0)]), "ErrKeyType"),
        ("rec_key_negative", "Key -1 before format.", pairs([(-1, 0)] + r_pairs), "ErrKeyType"),
        ("k2_key_bstr", "A byte-string key inside the K2 inputs.",
         mutate(a, k2=Pairs(tuple(sorted(k2_2.items()) + [(b"\x09", 0)]))), "ErrKeyType"),
        ("rejection_error_utf8_ff", "error with the byte 0xff in place of its last letter.",
         mutate(r, error=tstr_raw(b"ErrNotYetVali\xff")), "ErrInvalidString"),
        ("rejection_gate_id_utf8_overlong", "gate_id with an overlong encoding of '/' (0xc0 0xaf).",
         mutate(r, gate_id=tstr_raw(b"gate\xc0\xafpaper")), "ErrInvalidString"),
        ("rejection_gate_id_utf8_surrogate", "gate_id with an encoded UTF-16 surrogate (0xed 0xa0 0x80).",
         mutate(r, gate_id=tstr_raw(b"gate\xed\xa0\x80")), "ErrInvalidString"),
        ("rejection_gate_id_utf8_truncated", "gate_id ending inside a three-byte sequence (0xe2 0x82).",
         mutate(r, gate_id=tstr_raw(b"gate\xe2\x82")), "ErrInvalidString"),
        ("rec_reserved_ai_28", "format with major 0, additional info 28 (0x1c).",
         mutate(r, format=Raw(b"\x1c")), "ErrMalformed"),
        ("rec_reserved_ai_30_major_7", "rejected_at with major 7, additional info 30 (0xfe): reserved, checked before the simple value rule.",
         mutate(r, rejected_at=Raw(b"\xfe")), "ErrMalformed"),
        ("payload_reserved_ai_29_bstr", "commitment with major 2, additional info 29 (0x5d).",
         mutate(p1, commitment=Raw(b"\x5d")), "ErrMalformed"),
        ("decision_envelope_indefinite", "Envelope whose top map has an indefinite length: the nested strict decoding of section 6 fails (stage 8).",
         mutate(d, envelope=b"\xbf" + d["envelope"][1:] + b"\xff"), "ErrIndefiniteLength"),
        ("decision_envelope_unsorted", "Envelope with its two keys swapped: stage 8, cause from section 6.",
         mutate(d, envelope=_swap_envelope(d["envelope"])), "ErrUnsortedMap"),
        # Several defects: the earliest stage of section 19.1 decides.
        ("multi_unsorted_and_format_0", "Stage 2 before stage 3: kind before format, and format = 0.",
         pairs([(2, 5), (1, 0)] + r_pairs[2:]), "ErrUnsortedMap", ("ErrUnsortedMap", "ErrUnsupportedVersion")),
        ("multi_format_0_and_kind_size", "Stage 3 before stage 4: a decision record labelled as a rejection, with format = 0.",
         mutate(d, format=0, kind=5), "ErrUnsupportedVersion", ("ErrUnsupportedVersion", "ErrTooLarge")),
        ("multi_kind_missing_and_format_tstr", "Stage 3 reads format before kind: format as text, kind absent.",
         pairs([(1, "1")] + r_pairs[2:]), "ErrWrongType", ("ErrWrongType", "ErrMissingField")),
        ("multi_unknown_key_and_missing", "Stage 5 before stage 6: da = 2 payload with key 9 and without signer.",
         mutate(p2, signer=None, key_9=1), "ErrUnknownKey", ("ErrUnknownKey", "ErrMissingField")),
        ("multi_undefined_for_da_and_missing", "Stage 5 before stage 6, for one da: da = 1 evidence with a blob_proof (not defined for da = 1) and without historical_info (required for da = 1).",
         mutate(e1, blob_proof=b"\x01", historical_info=None), "ErrUnknownKey", ("ErrUnknownKey", "ErrMissingField")),
        ("multi_key_order_wrong_type_first", "Stage 5 runs in key order: signer as text (key 6) before an unknown key 9.",
         mutate(p2, signer="celestia1rxcpgc9d67garayuh9jtv0ha", key_9=1), "ErrWrongType", ("ErrWrongType", "ErrUnknownKey")),
        ("multi_key_order_size_first", "Stage 5 runs in key order: a 31-byte commitment (key 4) before a namespace with a wrong type (key 5).",
         mutate(p2, commitment=p2["commitment"][:31], namespace=1), "ErrFieldSize", ("ErrFieldSize", "ErrWrongType")),
        ("multi_wrong_type_and_enum", "Stage 5 before stage 7: an operational error name, and rejected_at as text.",
         mutate(r, error="ErrChainUnavailable", rejected_at="1790999990"), "ErrWrongType", ("ErrWrongType", "ErrInvalidEnum")),
        ("multi_missing_and_enum", "Stage 6 before stage 7: rejected_at absent, and an operational error name.",
         mutate(r, rejected_at=None, error="ErrChainUnavailable"), "ErrMissingField", ("ErrMissingField", "ErrInvalidEnum")),
        ("multi_int_range_enum_zero_namespace", "Stage 7 order: intent_height = 2^63, da = 3 (namespace and signer pass stage 5 for an unknown da), reserved namespace.",
         mutate(p2, da=3, intent_height=1 << 63, namespace=b"\xff" + p2["namespace"][1:]), "ErrIntRange",
         ("ErrIntRange", "ErrInvalidEnum", "ErrInvalidNamespace")),
        ("multi_enum_zero_namespace", "Stage 7 order: da = 3, intent_height = 0, reserved namespace.",
         mutate(p2, da=3, intent_height=0, namespace=b"\xff" + p2["namespace"][1:]), "ErrInvalidEnum",
         ("ErrInvalidEnum", "ErrZeroValue", "ErrInvalidNamespace")),
        ("multi_zero_namespace", "Stage 7 order: intent_height = 0 and a reserved namespace.",
         mutate(p2, intent_height=0, namespace=b"\xff" + p2["namespace"][1:]), "ErrZeroValue",
         ("ErrZeroValue", "ErrInvalidNamespace")),
        ("multi_tx_code_and_zero", "Stage 7 order: tx_code = 1 (an integer range rule) before promise_height = 0.",
         mutate(e1, tx_code=1, promise_height=0), "ErrIntRange", ("ErrIntRange", "ErrZeroValue")),
        ("multi_zero_and_nested", "Stage 7 before stage 8: authorized_at = 0 and signed_authorization that is not CBOR.",
         mutate(a, authorized_at=0, signed_authorization=b"\xff"), "ErrZeroValue", ("ErrZeroValue", "ErrMalformed")),
    ]


def large_rejects(recs: dict) -> list:
    """Records too big to embed: a da = 1 payload map without intent_height
    whose blob is the affine-7-3 pattern, sized so the whole record has
    record_size bytes. Given as the prefix (every byte before the blob
    content), the pattern size, and the SHA-256 of the whole record."""
    p1 = recs["payload_da1_live"]
    out = []
    for rid, desc, size, cause in (
        ("payload_max_record_size_plus_1", "MaxRecordSize + 1 bytes: refused before parsing (stage 1), although the blob is also above 2^27 and intent_height is missing.",
         av.MAX_RECORD_SIZE + 1, "ErrTooLarge"),
        ("payload_max_record_size", "Exactly MaxRecordSize bytes: stage 1 and the payload cap of stage 4 pass (the bound is inclusive); the blob above 2^27 fails at stage 5.",
         av.MAX_RECORD_SIZE, "ErrFieldSize"),
    ):
        fixed = encode(Pairs(((1, 1), (2, av.KIND_PAYLOAD), (3, 1), (4, p1["commitment"])))) + b"\x07\x5a"
        n = size - len(fixed) - 4
        prefix = bytes([0xA5]) + fixed[1:] + n.to_bytes(4, "big")
        data = prefix + pattern(n)
        assert len(data) == size and n > av.MAX_BLOB
        try:
            av.decode_record(data)
            raise AssertionError(f"{rid}: decodes")
        except av.Reject as e:
            assert e.sentinel == cause, f"{rid}: got {e.sentinel}, want {cause}"
        out.append({"id": rid, "description": desc, "record_prefix_hex": prefix.hex(),
                    "record_suffix": {"pattern": "affine-7-3", "size": str(n)},
                    "record_size": str(size), "record_sha256_hex": hashlib.sha256(data).hexdigest(),
                    "expect_error": "archive.ErrCorrupt", "cause": cause})
    return out


def _swap_envelope(env: bytes) -> bytes:
    """{1: commitment, 2: signature} re-emitted as {2: signature, 1: commitment}."""
    assert env[0] == 0xA2 and env[1] == 0x01 and env[-67:-64] == b"\x02\x58\x40"
    return b"\xa2" + env[-67:] + env[1:-67]


def _version0_envelope(env: bytes) -> bytes:
    """The envelope with its commitment's version (key 1) set to 0; decoding reads no signature."""
    i = env.find(bytes([0x01, 0x01]), 2)
    assert env[:2] == b"\xa2\x01" and i == 3, i
    return env[:i + 1] + b"\x00" + env[i + 2:]


def _path3(sa: bytes) -> bytes:
    s = bytearray(sa)
    i = s.find(bytes([0x06, 0x01]))
    assert i > 0 and s.count(bytes([0x06, 0x01])) == 1
    s[i + 1] = 0x03
    return bytes(s)


# ---------------------------------------------------------------- state

def h_of(case_id: str) -> str:
    return VALID[case_id]["commitment_hash_hex"]


def S(case_id: str, state: str, names: list[str]) -> dict:
    return {"commitment_hash_hex": h_of(case_id), "state": state, "rejections": names}


SCENARIOS = [
    ("authorized_is_final", "Decision written once; an Authorization makes it final; a later refusal leaves no marker.", [
        ("decision_minimal_lmt", "written", S("minimal_lmt", "pending", [])),
        ("decision_minimal_lmt", "unchanged", None),
        ("decision_minimal_lmt_resigned", "archive.ErrConflict", None),
        ("authorization_minimal_lmt_da", "written", S("minimal_lmt", "authorized", [])),
        ("authorization_minimal_lmt_da_repaired", "unchanged", None),
        ("authorization_minimal_lmt_archive", "archive.ErrConflict", None),
        ("rejection_minimal_lmt_not_yet_valid", "unchanged", S("minimal_lmt", "authorized", [])),
    ]),
    ("rejected_then_authorized", "Retryable refusals are marked; a later success authorizes and the names stay as history.", [
        ("decision_minimal_lmt", "written", None),
        ("rejection_minimal_lmt_not_yet_valid", "written", S("minimal_lmt", "rejected", ["ErrNotYetValid"])),
        ("rejection_minimal_lmt_not_yet_valid_later", "unchanged", S("minimal_lmt", "rejected", ["ErrNotYetValid"])),
        ("rejection_minimal_lmt_payload_unavailable", "written",
         S("minimal_lmt", "rejected", ["ErrNotYetValid", "ErrPayloadUnavailable"])),
        ("authorization_minimal_lmt_da_repaired", "written",
         S("minimal_lmt", "authorized", ["ErrNotYetValid", "ErrPayloadUnavailable"])),
        ("authorization_minimal_lmt_da", "unchanged", None),
    ]),
    ("stays_rejected", "A final refusal: rejected, never authorized.", [
        ("decision_action_json_bytes", "written", S("action_json_bytes", "pending", [])),
        ("rejection_action_json_bytes_expired", "written", S("action_json_bytes", "rejected", ["ErrExpired"])),
    ]),
    ("da1_decision", "A da = 1 decision refused, then authorized.", [
        ("decision_fibre_small_payload", "written", None),
        ("rejection_fibre_small_payload_retention", "written",
         S("fibre_small_payload", "rejected", ["ErrRetentionUnavailable"])),
        ("authorization_fibre_small_payload", "written",
         S("fibre_small_payload", "authorized", ["ErrRetentionUnavailable"])),
    ]),
    ("orphans", "Markers and Authorizations need the decision record; evidence needs the payload record.", [
        ("rejection_minimal_lmt_not_yet_valid", "archive.ErrNotFound", S("minimal_lmt", "absent", [])),
        ("authorization_minimal_lmt_da", "archive.ErrNotFound", S("minimal_lmt", "absent", [])),
        ("evidence_da2_minimal_lmt", "archive.ErrNotFound", None),
        ("evidence_da1_live", "archive.ErrNotFound", None),
    ]),
    ("payload_and_evidence_da2", "Payload intent is first-write-wins; evidence identity is the anchor.", [
        ("payload_da2_wrong_commitment", "gate.ErrDACommitmentMismatch", None),
        ("payload_da2_minimal_lmt", "written", None),
        ("payload_da2_minimal_lmt_later_intent", "unchanged", None),
        ("payload_da2_256k", "written", None),
        ("evidence_da2_minimal_lmt", "written", None),
        ("evidence_da2_minimal_lmt_with_tx", "unchanged", None),
        ("evidence_da2_minimal_lmt_other_height", "archive.ErrConflict", None),
    ]),
    ("k2_da_mismatch", "An Authorization whose K2 inputs name another da than the decision is refused as corrupt and nothing is written, also after the consistent one is stored (the check precedes the identity comparison).", [
        ("decision_minimal_lmt", "written", None),
        ("authorization_minimal_lmt_da_k2_da1", "archive.ErrCorrupt", S("minimal_lmt", "pending", [])),
        ("authorization_minimal_lmt_da", "written", S("minimal_lmt", "authorized", [])),
        ("authorization_minimal_lmt_da_k2_da1", "archive.ErrCorrupt", S("minimal_lmt", "authorized", [])),
    ]),
    ("payload_and_evidence_da1", "The same rules for da = 1.", [
        ("payload_da1_live", "written", None),
        ("payload_da1_live_later_intent", "unchanged", None),
        ("evidence_da1_live", "written", None),
        ("evidence_da1_live", "unchanged", None),
        ("evidence_da1_live_other_height", "archive.ErrConflict", None),
    ]),
]

FINAL_STORED = {
    "authorized_is_final": ["decision_minimal_lmt", "authorization_minimal_lmt_da"],
    "rejected_then_authorized": ["decision_minimal_lmt", "rejection_minimal_lmt_not_yet_valid",
                                 "rejection_minimal_lmt_payload_unavailable", "authorization_minimal_lmt_da_repaired"],
    "stays_rejected": ["decision_action_json_bytes", "rejection_action_json_bytes_expired"],
    "da1_decision": ["decision_fibre_small_payload", "rejection_fibre_small_payload_retention",
                     "authorization_fibre_small_payload"],
    "orphans": [],
    "payload_and_evidence_da2": ["payload_da2_minimal_lmt", "payload_da2_256k", "evidence_da2_minimal_lmt"],
    "payload_and_evidence_da1": ["payload_da1_live", "evidence_da1_live"],
    "k2_da_mismatch": ["decision_minimal_lmt", "authorization_minimal_lmt_da"],
}

# Records placed in a store directly (by a writer that skipped the checks,
# or by tampering), then read back with the reader checks.
READS = [
    ("authorization_k2_da_mismatch", "A stored Authorization whose K2 da differs from its decision's da: the reader reports it corrupt.",
     ["decision_minimal_lmt", "authorization_minimal_lmt_da_k2_da1"], "minimal_lmt", "archive.ErrCorrupt"),
    ("authorization_k2_da_match", "The consistent record reads back.",
     ["decision_minimal_lmt", "authorization_minimal_lmt_da"], "minimal_lmt", "ok"),
    ("authorization_repaired_no_k2", "Without K2 inputs there is nothing to compare.",
     ["decision_minimal_lmt", "authorization_minimal_lmt_da_repaired"], "minimal_lmt", "ok"),
]


def run_reads(recs: dict) -> list:
    out = []
    for rid, desc, stored, case, want in READS:
        store = av.Store(lambda _: True)
        for name in stored:
            store.records[av.record_key(recs[name])] = av.encode_record(recs[name])
        try:
            store.authorization(bytes.fromhex(h_of(case)))
            got = "ok"
        except (av.Corrupt, av.NotFound) as e:
            got = e.sentinel
        assert got == want, f"{rid}: got {got}, want {want}"
        out.append({"id": rid, "description": desc, "stored": stored,
                    "read": {"kind": "authorization", "commitment_hash_hex": h_of(case)}, "expect": want})
    return out


def da_pairs() -> list[dict]:
    out = []
    for cid, c in DA_BLOB.items():
        out.append({"da": "2", "ref": cid, "commitment_hex": c["commitment_hex"], "blob_sha256_hex": c["blob_sha256_hex"]})
    for cid, c in FIBRE.items():
        out.append({"da": "1", "ref": cid, "commitment_hex": c["commitment_hex"], "blob_sha256_hex": c["blob_sha256_hex"]})
    return out


def da_check_from(pairs: list[dict]):
    known = {(int(p["da"]), p["commitment_hex"], p["blob_sha256_hex"]) for p in pairs}
    return lambda rec: (rec["da"], rec["commitment"].hex(), hashlib.sha256(rec["blob"]).hexdigest()) in known


def run_scenarios(recs: dict, pairs: list[dict]):
    out = []
    for sid, desc, steps in SCENARIOS:
        store = av.Store(da_check_from(pairs))
        js = []
        for rid, expect, state in steps:
            try:
                got = "written" if store.put(recs[rid]) else "unchanged"
            except (av.Conflict, av.NotFound, av.DAMismatch, av.Corrupt) as e:
                got = e.sentinel
            assert got == expect, f"{sid}/{rid}: got {got}, want {expect}"
            step = {"put": rid, "expect": expect}
            if state is not None:
                assert store.state(bytes.fromhex(state["commitment_hash_hex"])) == \
                    {"state": state["state"], "rejections": state["rejections"]}, f"{sid}/{rid}: state"
                step["state_after"] = state
            js.append(step)
        stored = sorted(av.key_path(k) for k in store.records)
        want = sorted(av.key_path(av.record_key(recs[r])) for r in FINAL_STORED[sid])
        assert stored == want, f"{sid}: stored {stored}"
        for r in FINAL_STORED[sid]:
            assert store.records[av.record_key(recs[r])] == av.encode_record(recs[r]), f"{sid}: {r} bytes"
        out.append({"id": sid, "description": desc, "steps": js, "final_records": FINAL_STORED[sid]})
    return out


def main() -> int:
    cases, recs = build_cases()
    rejects = build_rejects(recs)
    params = {
        "format": str(av.FORMAT),
        "kinds": {av.KIND_NAMES[k]: str(k) for k in sorted(av.KIND_NAMES)},
        "max_record_size": str(av.MAX_RECORD_SIZE),
        "max_kind_size": {av.KIND_NAMES[k]: str(v) for k, v in sorted(av.MAX_KIND_SIZE.items())},
        "max_depth": str(av.MAX_DEPTH),
        "max_entries": str(av.MAX_PAIRS),
        "max_opaque_size": str(av.MAX_OPAQUE),
        "verdicts": sorted(av.VERDICTS),
    }
    header = {"format": FORMAT, "revision": REVISION, "generator": GENERATOR,
              "refs": {"core": "spec/vectors/v1", "blob_commit": "spec/vectors/da/blob_commit.json",
                       "fibre_commit": "spec/vectors/da/fibre_commit.json"}}
    records = {**header, "params": params, "patterns": PATTERNS,
               "placeholder": "SHA-256(\"edicta/v0 test archive placeholder|\" + label + \"|\" + i) for i = 0, 1, ..., concatenated and cut to the size; not valid upstream encodings",
               "cases": cases, "reject": rejects, "reject_large": large_rejects(recs)}
    pairs = da_pairs()
    state = {**header, "records": "spec/vectors/archive/records.json", "da_check": pairs,
             "scenarios": run_scenarios(recs, pairs), "reads": run_reads(recs)}
    OUT.mkdir(parents=True, exist_ok=True)
    for name, obj in (("records.json", records), ("state.json", state)):
        (OUT / name).write_text(json.dumps(obj, indent=2, sort_keys=False) + "\n")
    print(f"wrote {OUT}/records.json ({len(cases)} cases, {len(rejects)} rejects), state.json ({len(state['scenarios'])} scenarios)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
