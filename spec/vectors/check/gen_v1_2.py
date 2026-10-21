#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Writes the vector files of spec revision v1.2 (minor revision: the JSON transport of core 18.4) and of the
security patch revisions v1.0.5 and v1.1.1 (an undefined payload_ref.da is unsupported_revision, core 20.1):

- api/errors_v1.2.json: the match order (unchanged from v1.1) and the replacing case of the frozen
  api/errors.json#publish_wrong_media_type;
- api/json_v1.2.json: the JSON transport (JT1 to JT11), from json_transport.py;
- SUPERSEDED_v1.2.json: the frozen cases v1.2 supersedes;
- v1/unknown_da_v1.0.5.json: commitments with an undefined da (4, 5), signed by agent1, with the gate outcome of
  every revision;
- verifier/reasons_v1.0.5.json: the reason unsupported_revision, its cases and the archive reader cases.

The frozen files are read, never written; SUPERSEDED.json stays as v1.0.3 wrote it.

Usage: python3 spec/vectors/check/gen_v1_2.py [--check]
"""

from __future__ import annotations

import sys

sys.dont_write_bytecode = True

import base64
import hashlib
import json
from pathlib import Path

import archive as A
import edicta as E
import json_transport as JT
import records as RD
from cbor_strict import encode
from ed25519_point import BASE, L, cofactorless_ok, encode as ed_encode, mul as ed_mul, public_key_problem
from edicta import Reject

VECTORS = Path(__file__).resolve().parent.parent
FORMAT, REVISION = "edicta-vectors/v1", "v1.2"
GENERATOR = "spec/vectors/check/gen_v1_2.py"
ERRORS_FILE = "api/errors_v1.2.json"
JSON_FILE = "api/json_v1.2.json"
UNKNOWN_DA_FILE = "v1/unknown_da_v1.0.5.json"
REASONS_FILE = "verifier/reasons_v1.0.5.json"
DEFINED_DA = (1, 2)


def load(rel: str) -> dict:
    return json.loads((VECTORS / rel).read_text())


def dump(d: dict) -> str:
    return json.dumps(d, indent=2, ensure_ascii=True) + "\n"


def b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def plain(v):
    if isinstance(v, bytes):
        return v.hex()
    if isinstance(v, bool):
        return v
    if isinstance(v, int):
        return str(v)
    if isinstance(v, dict):
        return {str(k): plain(x) for k, x in v.items()}
    if isinstance(v, list):
        return [plain(x) for x in v]
    return v


# ---------------------------------------------------------------- api/errors_v1.2.json

def errors_file() -> dict:
    v11 = load("api/errors_v1.1.json")
    frozen = next(x for x in load("api/errors.json")["examples"] if x["id"] == "publish_wrong_media_type")
    malformed = {"code": "ErrMalformed", "message": "json: top-level value is not an object", "retryable": 0}
    return {
        "format": FORMAT, "revision": REVISION, "generator": GENERATOR,
        "description": (
            "API error mapping of spec revision v1.2 (core 18.3, 18.4, 21), additive to api/errors.json and "
            "api/errors_v1.1.json, which stay byte-identical. v1.2 adds no code; order: the whole match order of v1.2 "
            "(that of v1.1). examples: publish_wrong_media_type replaces the frozen case of api/errors.json for a "
            "v1.2 server (SUPERSEDED_v1.2.json): the same request, now read as JSON (core 18.4), is 400 ErrMalformed "
            "with a JSON body; publish_text_plain_media_type keeps the 415 of a type the API does not accept. message "
            "is not normative."),
        "base": "api/errors.json",
        "extends": "api/errors_v1.1.json",
        "additions": [],
        "order": v11["order"],
        "examples": [
            {"id": "publish_wrong_media_type", "replaces": "api/errors.json#publish_wrong_media_type",
             "endpoint": "/v1/publish", "method": "POST",
             "description": "The frozen request (Content-Type application/json, a CBOR body): under v1.2 JSON is accepted "
                            "(18.4), the body is not a JSON object, so the answer is 400 ErrMalformed in JSON.",
             "content_type": frozen["content_type"], "request_cbor_hex": frozen["request_cbor_hex"], "status": "400",
             "response_media_type": "application/json", "response_json": malformed},
            {"id": "publish_text_plain_media_type", "endpoint": "/v1/publish", "method": "POST",
             "description": "Content-Type text/plain: 415 before the body is read (the intent of the frozen case).",
             "content_type": "text/plain", "request_cbor_hex": frozen["request_cbor_hex"], "status": "415",
             "response_media_type": "application/cbor", "response_cbor_hex": frozen["response_cbor_hex"]},
        ],
        "bodies": [],
    }


# ---------------------------------------------------------------- api/json_v1.2.json

def json_file() -> dict:
    errors = load("api/errors.json")
    ex = {x["id"]: x for x in errors["examples"]}
    pub = load("api/publish_request.json")
    pcase = pub["cases"][0]
    auth_req = bytes.fromhex(ex["authorize_ok"]["request_cbor_hex"])
    rec_req = bytes.fromhex(ex["record_ok"]["request_cbor_hex"])
    pub_req = bytes.fromhex(pcase["request_cbor_hex"])
    from cbor_strict import decode_strict, to_plain
    a = to_plain(decode_strict(auth_req))
    r = to_plain(decode_strict(rec_req))
    pr = to_plain(decode_strict(pub_req))

    def j(obj: dict) -> str:
        return json.dumps(obj, separators=(",", ":"), ensure_ascii=True)

    auth_obj = {"envelope": b64(a[1]), "action": b64(a[2]), "action_salt": b64(a[3])}
    rec_obj = {"envelope": b64(r[1]), "rail_ref": r[2], "executor_pubkey": b64(r[3]), "executor_signature": b64(r[4])}
    pub_obj = {"blob": b64(pr[1]), "agent_id": pr[2], "requested_at": pr[3], "signature": b64(pr[4])}

    requests = []

    def req(cid: str, desc: str, endpoint: str, body: str | bytes, cbor_equivalent: str | None = None):
        raw = body.encode("utf-8") if isinstance(body, str) else body
        schema = JT.ROUTES[endpoint][0]
        try:
            out = JT.json_to_cbor(raw, schema)
            exp = {"cbor_hex": out.hex()}
        except JT.Refusal as e:
            exp = {"error": e.sentinel, "stage": "json", "why": e.why}
        entry = {"id": cid, "description": desc, "endpoint": endpoint}
        if isinstance(body, bytes):
            entry["body_hex"] = raw.hex()
        else:
            entry["body"] = body
        entry["expect"] = exp
        if cbor_equivalent:
            entry["cbor_wrapper"] = cbor_equivalent
        requests.append(entry)

    req("authorize_ok", "api/errors.json authorize_ok as JSON: converts to its exact CBOR request.", "/v1/authorize", j(auth_obj))
    req("authorize_reordered_whitespace", "Members in another order, with space, tab, LF and CR between tokens.",
        "/v1/authorize", "{\r\n\t\"action_salt\" : " + json.dumps(auth_obj["action_salt"]) + " ,\n \"action\":"
        + json.dumps(auth_obj["action"]) + ",\"envelope\":" + json.dumps(auth_obj["envelope"]) + "\t}\n")
    esc = auth_obj["action_salt"]
    req("authorize_escaped_base64", "The salt's first base64 character written as a \\u escape: escapes are decoded first.",
        "/v1/authorize", j({**auth_obj, "action_salt": "__X__"}).replace("__X__", "\\u%04x" % ord(esc[0]) + esc[1:]))
    req("authorize_escaped_member_name", "The member name envelope with an escaped letter: names compare after unescaping.",
        "/v1/authorize", j(auth_obj).replace('"envelope"', '"envelop\\u0065"'))
    req("authorize_duplicate_after_unescape", "envelope twice, once escaped: a duplicate member.", "/v1/authorize",
        j(auth_obj)[:-1] + ',"envelop\\u0065":' + json.dumps(auth_obj["envelope"]) + "}")
    req("authorize_duplicate_member", "action_salt twice.", "/v1/authorize",
        j(auth_obj)[:-1] + ',"action_salt":' + json.dumps(auth_obj["action_salt"]) + "}")
    req("authorize_unknown_member", "An extra member mode.", "/v1/authorize", j({**auth_obj, "mode": 1}))
    req("authorize_member_case", "Envelope with an upper-case E: an unknown member.", "/v1/authorize",
        j(auth_obj).replace('"envelope"', '"Envelope"'))
    req("authorize_base64_unpadded", "The salt without its padding.", "/v1/authorize",
        j({**auth_obj, "action_salt": auth_obj["action_salt"].rstrip("=")}))
    url = base64.urlsafe_b64encode(a[1]).decode()
    if url == auth_obj["envelope"]:
        raise SystemExit("the envelope's base64 has no + or /")
    req("authorize_base64_url_alphabet", "The envelope in the URL-safe alphabet.", "/v1/authorize", j({**auth_obj, "envelope": url}))
    s = auth_obj["action_salt"]
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    if not (s.endswith("=") and not s.endswith("==") and alphabet.index(s[-2]) & 3 == 0):
        raise SystemExit("the salt's base64 does not end in a character with two zero trailing bits")
    req("authorize_base64_trailing_bits", "The salt's last character with a non-zero trailing bit.", "/v1/authorize",
        j({**auth_obj, "action_salt": s[:-2] + alphabet[alphabet.index(s[-2]) | 1] + s[-1]}))
    req("authorize_base64_line_break", "A JSON-escaped line feed inside the envelope's base64.", "/v1/authorize",
        j(auth_obj).replace(auth_obj["envelope"], auth_obj["envelope"][:8] + "\\n" + auth_obj["envelope"][8:]))
    req("authorize_number_for_bytes", "action_salt as a number: ErrWrongType.", "/v1/authorize", j({**auth_obj, "action_salt": 1}))
    req("authorize_array_for_bytes", "action_salt as an array of integers: ErrWrongType.", "/v1/authorize",
        j({**auth_obj, "action_salt": [1, 2]}))
    req("authorize_null_value", "action_salt null.", "/v1/authorize", j(auth_obj).replace(json.dumps(auth_obj["action_salt"]), "null"))
    req("authorize_true_value", "action_salt true.", "/v1/authorize", j(auth_obj).replace(json.dumps(auth_obj["action_salt"]), "true"))
    req("authorize_object_value", "action_salt an object.", "/v1/authorize",
        j(auth_obj).replace(json.dumps(auth_obj["action_salt"]), "{}"))
    req("authorize_trailing_data", "A second object after the first.", "/v1/authorize", j(auth_obj) + "{}")
    req("authorize_bom", "A UTF-8 byte order mark before the object.", "/v1/authorize", b"\xef\xbb\xbf" + j(auth_obj).encode())
    req("authorize_top_level_array", "A JSON array as the body.", "/v1/authorize", "[" + j(auth_obj) + "]")
    req("authorize_vertical_tab", "A vertical tab (not JSON whitespace) before the object.", "/v1/authorize", b"\x0b" + j(auth_obj).encode())
    req("authorize_empty_object", "{}: converts to the empty map; wrapper decoding then gives ErrMissingField.",
        "/v1/authorize", "{}", "ErrMissingField")
    req("authorize_salt_missing", "Without action_salt: wrapper decoding gives ErrMissingField.", "/v1/authorize",
        j({k: v for k, v in auth_obj.items() if k != "action_salt"}), "ErrMissingField")
    req("authorize_salt_31", "A 31-byte salt: wrapper decoding gives ErrFieldSize.", "/v1/authorize",
        j({**auth_obj, "action_salt": b64(a[3][:31])}), "ErrFieldSize")
    req("record_ok", "api/errors.json record_ok as JSON.", "/v1/record", j(rec_obj))
    req("record_rail_ref_escaped", "rail_ref with every character escaped: the text is the unescaped string.", "/v1/record",
        j(rec_obj).replace(json.dumps(rec_obj["rail_ref"]), '"' + "".join("\\u%04x" % ord(c) for c in rec_obj["rail_ref"]) + '"'))
    req("record_rail_ref_unpaired_surrogate", "rail_ref with an unpaired high surrogate.", "/v1/record",
        j({**rec_obj, "rail_ref": "__S__"}).replace("__S__", "\\ud800"))
    req("record_rail_ref_lone_low_surrogate", "rail_ref with a lone low surrogate.", "/v1/record",
        j({**rec_obj, "rail_ref": "__S__"}).replace("__S__", "\\udc00"))
    req("record_rail_ref_control", "rail_ref with a raw control character 0x01.", "/v1/record",
        j({**rec_obj, "rail_ref": "__S__"}).replace("__S__", "a\x01b").encode("latin-1"))
    req("record_rail_ref_invalid_utf8", "rail_ref with the byte 0xff (invalid UTF-8).", "/v1/record",
        j({**rec_obj, "rail_ref": "__S__"}).encode().replace(b"__S__", b"a\xffb"))
    req("record_rail_ref_number", "rail_ref as a number: ErrWrongType.", "/v1/record", j({**rec_obj, "rail_ref": 5}))
    req("publish_ok", "api/publish_request.json " + pcase["id"] + " as JSON.", "/v1/publish", j(pub_obj))
    for cid, text in (("publish_requested_at_leading_zero", "0" + str(pr[3])), ("publish_requested_at_fraction", f"{pr[3]}.0"),
                      ("publish_requested_at_exponent", "1e9"), ("publish_requested_at_negative", "-1"),
                      ("publish_requested_at_2pow53", str(1 << 53)), ("publish_requested_at_minus_zero", "-0")):
        req(cid, f"requested_at written as {text}.", "/v1/publish",
            j({**pub_obj, "requested_at": 0}).replace('"requested_at":0', '"requested_at":' + text))
    req("publish_requested_at_2pow53_minus_1", "requested_at 2^53 - 1: converts (the wrapper accepts it; PR5 later "
        "refuses the request as stale).", "/v1/publish", j({**pub_obj, "requested_at": (1 << 53) - 1}))
    req("publish_requested_at_string", "requested_at as a string: ErrWrongType.", "/v1/publish",
        j({**pub_obj, "requested_at": str(pr[3])}))

    media = [{"content_type": ct, "expect": JT.request_media(ct) or "415"} for ct in (
        "application/json", "application/json; charset=utf-8", "application/json; charset=UTF-8", "Application/JSON",
        "application/json; foo=bar", "application/json; charset=latin-1", "application/problem+json",
        "application/json-seq", "text/plain", "", "application/cbor", "application/cbor; foo=bar", "application/json;")]
    accept = [{"accept": acc, "expect": "json" if JT.wants_json(acc) else "cbor"} for acc in (
        None, "application/json", "application/cbor", "*/*", "application/*", "application/json, application/cbor",
        "application/json;q=0.9, application/cbor;q=0.8", "application/json;q=0", "text/html",
        "application/cbor;q=0.5, application/json;q=0.6", "application/json;q=1.5")]

    responses = []

    def resp(cid: str, desc: str, schema: str, cbor_hex: str):
        try:
            exp = {"json": JT.cbor_to_json(bytes.fromhex(cbor_hex), schema)}
        except JT.Refusal as e:
            exp = {"status": "500", "code": "edictaapi.ErrInternal", "why": e.why}
        responses.append({"id": cid, "description": desc, "schema": schema, "cbor_hex": cbor_hex, "expect": exp})

    resp("authorize_ok", "The 200 of api/errors.json authorize_ok.", "authorize_response", ex["authorize_ok"]["response_cbor_hex"])
    resp("record_ok", "The 200 of api/errors.json record_ok.", "record_response", ex["record_ok"]["response_cbor_hex"])
    resp("publish_ok", "The 200 of api/errors.json publish_ok.", "publish_response", ex["publish_ok"]["response_cbor_hex"])
    resp("health_ok", "The 200 of api/errors.json health_ok.", "health_response", ex["health_ok"]["response_cbor_hex"])
    resp("health_no_recorder", "health_degraded_no_recorder: keys 7 and 8 absent.", "health_response",
         ex["health_degraded_no_recorder"]["response_cbor_hex"])
    resp("error_nonce_used_stored", "409 ErrNonceUsed with the stored Authorization.", "error",
         ex["authorize_retry_same_commitment"]["response_cbor_hex"])
    resp("error_chain_down", "503 ErrChainUnavailable, retryable 1.", "error", ex["authorize_chain_down"]["response_cbor_hex"])
    big = encode({1: bytes.fromhex(load("api/publish_request.json")["response"][0]["payload_ref_cbor_hex"]), 2: 1 << 53, 3: 0})
    resp("publish_block_time_2pow53", "A publish response whose block_time is 2^53: a server bug, answered 500 in JSON (JT8).",
         "publish_response", big.hex())

    limits = {}
    for name, lim in (("authorize", 67771), ("record", 2560)):
        limits[name] = {"cbor": str(lim), "json": str(JT.body_limit(lim))}
    limits["publish"] = {"cbor": "max_blob_bytes + 256", "json": "4 * ceil((max_blob_bytes + 256) / 3) + 1024",
                         "json_at_1048576": str(JT.body_limit(1048576 + 256))}
    order = [
        {"id": "oversized_and_unknown_member", "description": "A JSON body one byte above the authorize JSON limit that also "
         "has an unknown member: 413 in JSON (size first); its CBOR twin is 413 as well.", "json_size": str(JT.body_limit(67771) + 1),
         "expect": {"status": "413", "code": "ErrTooLarge"}},
        {"id": "within_json_limit_cbor_over", "description": "A well-formed JSON authorize body within the JSON limit whose "
         "converted wrapper is above 67771 bytes: 413 after conversion (JT6).", "expect": {"status": "413", "code": "ErrTooLarge"}},
        {"id": "within_json_limit_unknown_member_cbor_over", "description": "As the previous one with an unknown member: 400 "
         "ErrMalformed in JSON (JSON decoding before the CBOR size), where the CBOR request with an unknown key is 413.",
         "expect": {"status": "400", "code": "ErrMalformed"}, "cbor_twin": {"status": "413", "code": "ErrTooLarge"}},
    ]
    return {
        "format": FORMAT, "revision": REVISION, "generator": GENERATOR,
        "description": (
            "The JSON transport of core 18.4 (spec revision v1.2). requests: a request body (body, or body_hex for bytes "
            "that are not UTF-8) and its conversion: cbor_hex, the exact canonical CBOR wrapper the server then runs, or "
            "the refusal of the JSON stage (ErrMalformed, ErrWrongType; 400); cbor_wrapper names the sentinel the CBOR "
            "wrapper decoding then gives. media_types: JT1 ('json', 'cbor' or 415). accept: JT2 for a GET. responses: "
            "the JSON object a server renders for a CBOR response (compared as JSON values, member order and whitespace "
            "free), or the 500 of JT8. limits and check_order: JT6."),
        "schemas": {k: {n: {"key": str(v[0]), "kind": v[1]} for n, v in s.items()} for k, s in JT.SCHEMAS.items()},
        "requests": requests,
        "media_types": media,
        "accept": accept,
        "responses": responses,
        "limits": limits,
        "check_order": order,
    }


# ---------------------------------------------------------------- SUPERSEDED_v1.2.json

def superseded_file() -> dict:
    return {
        "format": FORMAT, "revision": REVISION, "generator": GENERATOR,
        "description": (
            "Frozen vector cases whose expectation spec revision v1.2 (minor) changed, in the layout of "
            "SUPERSEDED.json, which stays byte-identical (core section 0, v1.2 amendment: every revision lists its "
            "superseded cases in its own file). A checker or test of v1.2 or later skips a frozen case only through "
            "SUPERSEDED.json and these lists, and runs replaced_by instead, on the same inputs."),
        "entries": [{"file": "api/errors.json", "case": "publish_wrong_media_type", "revision": "v1.2", "type": "minor",
                     "replaced_by": "api/errors_v1.2.json#publish_wrong_media_type"}],
    }


# ---------------------------------------------------------------- v1/unknown_da_v1.0.5.json

def ed_sign(seed: bytes, msg: bytes) -> bytes:
    """RFC 8032 Ed25519 signing (used for the vector commitments)."""
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    pub = ed_encode(ed_mul(a, BASE))
    r = int.from_bytes(hashlib.sha512(h[32:] + msg).digest(), "little") % L
    rb = ed_encode(ed_mul(r, BASE))
    k = int.from_bytes(hashlib.sha512(rb + pub + msg).digest(), "little") % L
    return rb + ((r + k * a) % L).to_bytes(32, "little")


def gate_outcome(envelope: bytes, now: int, gate: dict, p: E.Params) -> str:
    """Stages D, S, G, T and C of a gate of every revision (the frozen rules), without OpenSSL."""
    try:
        p.validate()
        signed, canon = E.decode_signed(envelope)
        c = signed["commitment"]
        E.validate_static(c, p)
        h = E.commitment_hash(canon)
        if public_key_problem(c["agent_pubkey"]):
            raise Reject("ErrInvalidPublicKey")
        sig = signed["signature"]
        if int.from_bytes(sig[32:], "little") >= L or not cofactorless_ok(c["agent_pubkey"], E.signing_message(h), sig):
            raise Reject("ErrSignatureInvalid")
        E.check_time(c, now, p)
        E.check_scope(c, gate)
        return "ok"
    except Reject as e:
        return e.sentinel


def unknown_da_file() -> dict:
    keys = load("keys.json")["keys"]
    seed = bytes.fromhex(keys["agent1"]["seed_hex"])
    pub = bytes.fromhex(keys["agent1"]["public_key_hex"])
    gate = load("v1/valid.json")["gate"]
    p = E.Params()
    now = 1793000110
    action_type = "application/octet-stream"
    namespace = bytes.fromhex("0000000000000000000000000000000000000037586d889dd7a6a44ca8")
    signer = hashlib.sha256(b"unknown-da signer").digest()[:20]
    out = []
    for cid, desc, da, extra in (
            ("da_4", "da = 4 with namespace, commitment, height and a 20-byte signer: undefined in every revision "
             "so far (the Eden publication target is a design draft, not in this spec).", 4, {}),
            ("da_4_signer_19", "da = 4 with a 19-byte signer: D18 would refuse it for da = 2; under the opaque "
             "reading of an undefined da it is not applied.", 4, {5: signer[:19]}),
            ("da_5", "da = 5, every key of the da = 2 layout.", 5, {}),
            ("da_5_key_7", "da = 5 with the reserved payload_ref key 7 (32 bytes): D15 at a gate.", 5, {7: bytes(32)}),
            ("da_5_height_2_63", "da = 5 with payload_ref key 4 (height) = 2^63: S2 at a gate; under the opaque "
             "reading S2 covers da only.", 5, {4: 1 << 63})):
        payload = hashlib.sha256(b"unknown-da payload/" + cid.encode()).digest() * 8
        salt = hashlib.sha256(b"action-salt/" + cid.encode()).digest()
        action = b"unknown-da action " + cid.encode()
        c = {"version": 1, "agent_id": "dca-agent-1", "agent_pubkey": pub,
             "nonce": hashlib.sha256(b"unknown-da nonce/" + cid.encode()).digest()[:16], "issued_at": 1793000100,
             "valid_until": 1793001000, "scope": {"gate_id": gate["gate_id"]},
             "action": {"type": action_type, "hash": E.action_hash(action_type, salt, action)},
             "payload_ref": {"da": 2, "namespace": namespace,
                             "commitment": hashlib.sha256(b"unknown-da commitment/" + cid.encode()).digest(),
                             "height": 5000103, "signer": signer},
             "ciphertext_hash": hashlib.sha256(payload).digest(),
             "plaintext_hash": hashlib.sha256(b"unknown-da plaintext/" + cid.encode()).digest(),
             "payload_size": len(payload)}
        m = E.to_cbor(c, E.COMMITMENT)
        pr = next(k for k, v in m.items() if isinstance(v, dict) and v.get(1) == 2)
        m[pr] = {**m[pr], 1: da, **extra}
        canon = encode(m)
        h = E.commitment_hash(canon)
        sig = ed_sign(seed, E.signing_message(h))
        env = encode({1: m, 2: sig})
        out.append({"id": cid, "description": desc, "payload_ref": plain(m[pr]), "commitment_cbor_hex": canon.hex(),
                    "commitment_hash_hex": h.hex(), "signature_hex": sig.hex(), "envelope_hex": env.hex(),
                    "now": str(now), "action_type": action_type, "action_hex": action.hex(),
                    "action_salt_hex": salt.hex(), "gate": gate_outcome(env, now, gate, p)})
    return {
        "format": FORMAT, "revision": "v1.0.5", "generator": GENERATOR,
        "description": (
            "Commitments with an undefined payload_ref.da (security patch revisions v1.0.5 and v1.1.1, core 20.1), "
            "signed by agent1 of keys.json for the gate of v1/valid.json. payload_ref gives the map as signed "
            "(integer keys). gate: the outcome of a gate of every revision (D, S, G, T, C), always a refusal. The "
            "verifier outcomes are in verifier/reasons_v1.0.5.json."),
        "cases": out,
    }


# ---------------------------------------------------------------- verifier/reasons_v1.0.5.json

def archive_reader_cases(core: dict) -> list:
    """Kind 17 decision records whose envelope has an undefined da: the strict reader of v1.0.4 and v1.1 refuses
    some of them (19.1 step 8); the reader of v1.0.5, v1.1.1 and later reads their payload_ref as opaque."""
    by_id = {x["id"]: x for x in core["cases"]}
    out = []
    for cid, desc in (("da_5_key_7", "da = 5 with the reserved payload_ref key 7."),
                      ("da_4_signer_19", "da = 4 with a 19-byte signer."),
                      ("da_5_height_2_63", "da = 5 with payload_ref key 4 = 2^63 (S2 is not part of step 8)."),
                      ("da_5", "da = 5, every key as defined for da = 2: strict stage D passes in every revision.")):
        x = by_id[cid]
        rec = {"kind": A.KIND_DECISION, "envelope": bytes.fromhex(x["envelope_hex"]), "form": 1,
               "action": bytes.fromhex(x["action_hex"]), "action_salt": bytes.fromhex(x["action_salt_hex"])}
        raw = A.encode_record(rec)
        out.append({"id": f"reader_{cid}", "description": desc, "commitment": f"{UNKNOWN_DA_FILE}#{cid}",
                    "record_cbor_hex": raw.hex(), "path": f"decision/{x['commitment_hash_hex']}",
                    "v1_0_4_reader_cause": RD.cause(raw),
                    "expect": {"reader": "ok", "path": f"decision/{x['commitment_hash_hex']}",
                               "envelope": "unchecked", "reason": "unsupported_revision"}})
    return out


def reasons_file(core: dict) -> dict:
    unchecked = {"check": "envelope", "status": "unchecked", "reason": "unsupported_revision",
                 "record_state": "authorized", "verdict": "unchecked", "exit": "2"}
    v104 = {"check": "envelope", "status": "fail", "verdict": "invalid", "exit": "1"}
    cases = []
    for cid, desc in (("da_4", "An authorized decision with da = 4."),
                      ("da_5", "A decision with da = 5."),
                      ("da_5_key_7", "da = 5 with the reserved payload_ref key 7: the opaque reading skips D15, so a "
                                     "later revision may give an undefined da new keys."),
                      ("da_5_height_2_63", "da = 5 with payload_ref key 4 = 2^63: inside an opaque payload_ref S2 "
                                           "covers da only, so S3 on da decides."),
                      ("da_4_signer_19", "da = 4 with a 19-byte signer: the opaque reading does not apply D18.")):
        cases.append({"id": f"unsupported_revision_{cid}", "description": desc,
                      "setup": {"commitment": f"{UNKNOWN_DA_FILE}#{cid}"}, "refs": [f"{UNKNOWN_DA_FILE}#{cid}"],
                      "expect": unchecked, "v1_0_4": v104,
                      "v1_2": {"check": "envelope", "status": "unchecked", "reason": "unsupported_revision"}})
    return {
        "format": FORMAT, "revision": "v1.0.5", "generator": GENERATOR,
        "description": (
            "Reasons added by the security patch revisions v1.0.5 and v1.1.1 (core section 0 and 20.1.1; pending the "
            "human's approval and tags), in the layout of verifier/reasons.json. The enum of v1.0.5 is the enum of "
            "extends plus these (45 reasons); every frozen case keeps its outcome. Cases: a verifier of v1.0.5, "
            "v1.1.1 or later reads the payload_ref of a da it does not define (outside {1, 2}) as an opaque map "
            "(stage D checks only its canonical form and its da; stage S applies S2 to da only), and an envelope "
            "whose first failure is then S3 on that da is unchecked, not fail; v1_0_4 states the outcome before the "
            "patch; v1_2 that of a v1.2 verifier, which defines no further da. archive_reader: kind 17 decision "
            "records with such envelopes; the general reader of v1.0.5 and later accepts them at 19.1 step 8 under "
            "path; v1_0_4_reader_cause is the strict reader's refusal before the patch (null: accepted). Writers "
            "may keep refusing them."),
        "extends": "verifier/reasons_v1.0.3.json",
        "reasons": [{
            "name": "unsupported_revision", "group": "configuration", "checks": ["envelope"],
            "meaning": ("The commitment hashes to the reference, payload_ref.da is a value this verifier's revision "
                        "does not define (outside {1, 2}), and with that payload_ref read as opaque the first "
                        "failure is S3 on da. A later revision may define the value and its keys, so this is not a "
                        "verdict on the decision. The report prints the da value."),
            "advice": "A verifier of a revision that defines this da (release notes name the revision).",
        }],
        "cases": cases,
        "boundary": [
            {"id": "ttl_still_fails", "description": "A stage S failure other than S3 on da stays fail (verifier/"
             "reasons.json commitment_rule_broken, ttl_3601).", "refs": ["verifier/reasons.json#commitment_rule_broken"],
             "expect": {"check": "envelope", "status": "fail", "verdict": "invalid", "exit": "1"}},
            {"id": "defined_da_signer_size_fails", "description": "A da = 2 commitment with a 19-byte signer: da = 2 "
             "is defined, so D18 applies and the envelope fails in every revision (verifier/reasons.json "
             "commitment_rule_broken stands for the defined-da failures).",
             "refs": ["verifier/reasons.json#commitment_rule_broken"],
             "expect": {"check": "envelope", "status": "fail", "verdict": "invalid", "exit": "1"}},
        ],
        "archive_reader": archive_reader_cases(core),
    }


# ---------------------------------------------------------------- main

def write(rel: str, d: dict, check: bool) -> bool:
    p = VECTORS / rel
    text = dump(d)
    if check:
        return p.exists() and p.read_text() == text
    p.write_text(text)
    return True


def main() -> int:
    check = "--check" in sys.argv
    core = unknown_da_file()
    files = ((ERRORS_FILE, errors_file()), (JSON_FILE, json_file()), ("SUPERSEDED_v1.2.json", superseded_file()),
             (UNKNOWN_DA_FILE, core), (REASONS_FILE, reasons_file(core)))
    ok = True
    for rel, d in files:
        if not write(rel, d, check):
            print(f"FAIL (gen v1.2): {rel} differs from the generator output", file=sys.stderr)
            ok = False
    if ok:
        print(f"OK (gen v1.2): {'checked' if check else 'wrote'} " + ", ".join(rel for rel, _ in files))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
