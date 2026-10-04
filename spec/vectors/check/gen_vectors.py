#!/usr/bin/env python3
"""Generates the v0-draft.9 core vectors. Deterministic: rerunning yields identical files.

Usage: python3 spec/vectors/check/gen_vectors.py [--out DIR]
Default output directory is spec/vectors/v0. da_blob.json is not written here: it comes from
spec/vectors/tools/dacommit-gen and is copied unchanged.
"""

from __future__ import annotations

import sys

sys.dont_write_bytecode = True

import copy
import hashlib
import json
import struct
from pathlib import Path

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
except ImportError:
    sys.exit("missing dependency 'cryptography'; see spec/vectors/check/requirements.txt")

import ed25519_point as ed
from cbor_strict import Pairs, Raw, encode, head
from edicta_v0 import (AUTHORIZATION, DA_CELESTIA_BLOB, DA_FIBRE, ED25519_L, MAX_ACTION_SIZE,
                      MAX_AUTHORIZATION_SIZE, MAX_RECEIPT_SIZE, RECEIPT, TAG_ACTION,
                      TAG_AUTHORIZATION_SIG, TAG_COMMITMENT, TAG_RECEIPT,
                      TAG_RECEIPT_SIG, TAG_SIG, U64_MAX, AuthorizationCheck, Params, Reject,
                      action_hash, action_preimage_prefix, authorization_expires,
                      authorization_hash, check_anchor_time, check_registry_epoch,
                      commitment_hash, receipt_hash, retention_margin, retention_window, route,
                      signing_message, tagged, to_cbor, verify_authorization, within_retention)
from vecjson import (PATTERNS, authorization_to_json, commitment_to_json, gate_to_json,
                     params_to_json, pattern_bytes, receipt_to_json)
import gen_payload_blob
from profile_dca_agent import ACTION_TYPE_IBKR_ORDER_V0 as IBKR, order_encode

OUT = Path(__file__).resolve().parent.parent / "v0"
if "--out" in sys.argv:
    OUT = Path(sys.argv[sys.argv.index("--out") + 1]).resolve()
FORMAT = "edicta-vectors/v0"
REVISION = "v0-draft.9"

KEYS = {
    "agent1": {
        "source": "RFC 8032 section 7.1 TEST 1",
        "seed_hex": "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        "public_key_hex": "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "kat_message_hex": "",
        "kat_signature_hex": "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    },
    "agent2": {
        "source": "RFC 8032 section 7.1 TEST 2",
        "seed_hex": "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        "public_key_hex": "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        "kat_message_hex": "72",
        "kat_signature_hex": "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
    },
    "gate1": {
        "source": "RFC 8032 section 7.1 TEST 3",
        "seed_hex": "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
        "public_key_hex": "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        "kat_message_hex": "af82",
        "kat_signature_hex": "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
    },
}

PARAMS = Params()
T0 = 1791000000
NOW = T0 + 60

TYPE_JSON = "application/json"
TYPE_OCTETS = "application/octet-stream"
TYPE_128 = "application/vnd.edicta.test." + "a" * 95 + "+cbor"
assert len(TYPE_128) == 128
TYPE_NOT_ALLOWED = "application/vnd.example.evm.tx.v0+rlp"
GATE = {"gate_id": "gate-paper-1", "action_types": [IBKR, TYPE_JSON, TYPE_OCTETS, TYPE_128]}
PATTERN = "affine-7-3"


def h(label: str) -> bytes:
    return hashlib.sha256(label.encode()).digest()


def sk(name: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(KEYS[name]["seed_hex"]))


NAMESPACE = bytes(19) + b"edicta/d01"  # version 0, 18 zero bytes, 10-byte sub-id
# Recorder account: raw 20-byte address (bech32-decoded MsgPayForBlobs.signer).
SIGNER = h("edicta/v0 test recorder account")[:20]


def payload_blob() -> bytes:
    return encode({
        1: 0,
        2: [
            {1: b"gate-paper-1", 2: h("enc-gate")[:32], 3: (h("wrap-gate") + h("wrap-gate-2"))[:48]},
            {1: b"auditor-1", 2: h("enc-auditor")[:32], 3: (h("wrap-auditor") + h("wrap-auditor-2"))[:48]},
        ],
        3: h("aead-nonce")[:12],
        4: (h("ct-1") + h("ct-2") + h("ct-3"))[:80],
    })


SALT = h("edicta/v0 test salt")
PLAINTEXT = b'{"decision":"buy","policy":"dca-weekly","model":"example-model"}'
BLOB = payload_blob()

# The dogfood action: an IBKR order in the dca-agent profile encoding. The core
# treats it as opaque bytes of type IBKR.
ORDER_MINIMAL = {"account": "DU1234567", "conid": 265598, "side": 1, "qty": 100000, "order_type": 1,
                 "limit_price": 19050000000, "currency": "USD", "tif": 1}
ACTION_MINIMAL = order_encode(ORDER_MINIMAL)
ACTION_JSON = b'{"op":"transfer","to":"acct-42","amount":"10.00","currency":"USD"}'
ACTION_MAX = pattern_bytes(PATTERN, MAX_ACTION_SIZE)


def with_action(c: dict, action_type: str, action: bytes) -> dict:
    c = copy.deepcopy(c)
    c["action"] = {"type": action_type, "hash": action_hash(action_type, action)}
    return c


def base() -> dict:
    """minimal_lmt: celestia_blob locator, the minimal IBKR order as its action."""
    return {
        "version": 0,
        "agent_id": "dca-agent-1",
        "agent_pubkey": bytes.fromhex(KEYS["agent1"]["public_key_hex"]),
        "nonce": h("nonce-minimal")[:16],
        "issued_at": T0,
        "valid_until": T0 + 900,
        "scope": {"gate_id": "gate-paper-1"},
        "action": {"type": IBKR, "hash": action_hash(IBKR, ACTION_MINIMAL)},
        "payload_ref": {"da": 2, "namespace": NAMESPACE, "commitment": h("share-commitment-minimal"), "height": 4200000,
                        "signer": SIGNER},
        "ciphertext_hash": hashlib.sha256(BLOB).digest(),
        "plaintext_hash": hashlib.sha256(SALT + PLAINTEXT).digest(),
        "payload_size": len(BLOB),
    }


def fibre() -> dict:
    c = base()
    c["nonce"] = h("nonce-full")[:16]
    c["payload_ref"] = {"da": 1, "namespace": NAMESPACE, "commitment": h("fibre-commitment-full"), "height": 4200123}
    c["ciphertext_hash"] = h("blob-full")
    c["payload_size"] = 300000
    return c


def mod(c: dict, path: str, value) -> dict:
    """Returns a copy with path ("a.b.c") set; value None deletes the field."""
    c = copy.deepcopy(c)
    parts = path.split(".")
    d = c
    for p in parts[:-1]:
        d = d[p]
    if value is None:
        d.pop(parts[-1], None)
    else:
        d[parts[-1]] = value
    return c


def sign_canon(canon: bytes, signer: str = "agent1"):
    hh = commitment_hash(canon)
    msg = signing_message(hh)
    return hh, msg, sk(signer).sign(msg)


def envelope(inner, sig) -> bytes:
    return encode({1: inner if isinstance(inner, Raw) else Raw(inner), 2: sig})


def signed_case(c: dict, signer: str = "agent1") -> dict:
    canon = encode(to_cbor(c))
    hh, msg, sig = sign_canon(canon, signer)
    return {
        "input": commitment_to_json(c),
        "commitment_cbor_hex": canon.hex(),
        "commitment_hash_hex": hh.hex(),
        "signer": signer,
        "signed_message_hex": msg.hex(),
        "signature_hex": sig.hex(),
        "envelope_hex": envelope(canon, sig).hex(),
    }


def action_fields(action_type: str, action: bytes, with_hash: bool = True) -> dict:
    """JSON fields describing supplied action bytes; actions over 1024 bytes are given as a pattern."""
    out = {"action_type": action_type}
    if len(action) > 1024:
        out.update({"action_pattern": PATTERN, "action_size": str(len(action)),
                    "action_sha256_hex": hashlib.sha256(action).hexdigest()})
        assert pattern_bytes(PATTERN, len(action)) == action
    else:
        out["action_hex"] = action.hex()
    if with_hash:
        out["action_preimage_prefix_hex"] = action_preimage_prefix(action_type).hex()
        out["action_hash_hex"] = action_hash(action_type, action).hex()
    return out


VALID_ACTIONS = {}


def valid_cases() -> list:
    out = []

    def add(cid, desc, c, action_type=IBKR, action=ACTION_MINIMAL, now=NOW, params=None):
        c = with_action(c, action_type, action)
        case = {"id": cid, "description": desc}
        case.update(signed_case(c))
        case["now"] = str(now)
        if params is not None:
            case["params"] = params_to_json(params)
        case.update(action_fields(action_type, action))
        note = ("Placeholder: SHA-256 of a fixed label, not the DA commitment of any blob. The commitment "
                "bytes and hashes of this vector are normative; the value is not a real anchor.")
        if cid == "minimal_lmt":
            note += (" The real share commitment of this payload (payload.json ciphertext_hash_small_blob) "
                     "with this namespace and signer is da_blob.json case blob_v1_minimal_lmt_payload.")
        case["placeholders"] = {"payload_ref.commitment": note}
        VALID_ACTIONS[cid] = (action_type, action)
        out.append(case)

    add("minimal_lmt", "da=celestia_blob; the action is the minimal IBKR limit order of the dca-agent profile; payload is ciphertext_hash_small_blob in payload.json.", base())
    add("ttl_exactly_max", "TTL == MaxTTL(da) == min(3600, 14400/4).", mod(base(), "valid_until", T0 + 3600))
    add("fibre_small_payload", "Q9: da=fibre with payload_size 1024 is accepted; the 256 KiB split is a Recorder routing rule.",
        mod(fibre(), "payload_size", 1024))
    add("blob_large_payload", "Q9: da=celestia_blob with payload_size 262144 is accepted.", mod(base(), "payload_size", 262144))
    c = mod(base(), "issued_at", NOW + 30)
    c["valid_until"] = NOW + 930
    add("issued_at_within_skew", "issued_at == now + skew is accepted.", c)

    c = mod(base(), "nonce", h("nonce-small-ints")[:16])
    c["payload_ref"]["height"] = 65535
    c["payload_size"] = 65536
    add("int_head_widths", "Integer heads at the 3-byte/5-byte boundary: height 65535 (0x19ffff), payload_size 65536 (0x1a00010000); issued_at in 5 bytes, version and da in 1.", c)
    c = mod(base(), "nonce", h("nonce-small-ints-2")[:16])
    c["payload_ref"]["height"] = 23
    c["payload_size"] = 24
    add("int_head_widths_1_2", "Integer heads at the 1-byte/2-byte boundary: height 23 (0x17), payload_size 24 (0x1818).", c)
    c = mod(base(), "nonce", h("nonce-small-ints-3")[:16])
    c["payload_ref"]["height"] = 255
    c["payload_size"] = 256
    add("int_head_widths_2_3", "Integer heads at the 2-byte/3-byte boundary: height 255 (0x18ff), payload_size 256 (0x190100).", c)

    c = mod(base(), "nonce", h("nonce-max-ints")[:16])
    c["payload_ref"]["height"] = (1 << 63) - 1
    c["payload_size"] = 1 << 27
    add("max_int_values", "Largest allowed values: height 2^63-1 in a 9-byte head, payload_size == 2^27.", c)

    add("ttl_max_at_601s_retention", "fibre_retention_s=601: MaxTTL = floor(601/4) = 150; TTL 150 is accepted.",
        mod(fibre(), "valid_until", T0 + 150), params=Params(601, 14400, 30))

    add("action_type_128_chars", "action.type of 128 bytes, the maximum; the gate's action_types list contains it.",
        mod(base(), "nonce", h("nonce-type-128")[:16]), action_type=TYPE_128, action=b"edicta test action")
    add("action_one_byte", "A one-byte action (0x2a) of type application/octet-stream; the minimum size.",
        mod(base(), "nonce", h("nonce-one-byte")[:16]), action_type=TYPE_OCTETS, action=b"\x2a")
    add("action_max_size", f"An action of {MAX_ACTION_SIZE} bytes (MaxActionSize), given as pattern {PATTERN}.",
        mod(base(), "nonce", h("nonce-max-size")[:16]), action_type=TYPE_OCTETS, action=ACTION_MAX)
    add("action_json_bytes", "A JSON action: the bytes are hashed as given; the core never parses or re-encodes them.",
        mod(base(), "nonce", h("nonce-json")[:16]), action_type=TYPE_JSON, action=ACTION_JSON)
    return out


def d_case(cid, rule, desc, env: bytes, expect: str) -> dict:
    return {"id": cid, "stage": "D", "rule": rule, "description": desc,
            "envelope_hex": env.hex(), "now": str(NOW), "expect_error": expect}


def resigned(inner: bytes) -> bytes:
    """Envelope around (possibly malformed) commitment bytes, signed over those bytes."""
    _, _, sig = sign_canon(inner)
    return envelope(inner, sig)


def commitment_with(c: dict, top: dict) -> bytes:
    """Canonical commitment with some top-level values replaced by raw encodings."""
    m = to_cbor(c)
    m.update(top)
    return encode(m)


def draft8_minimal_lmt_envelope() -> bytes:
    """The v0-draft.8 minimal_lmt envelope, rebuilt from its draft.8 fields."""
    b = base()
    m = {1: 0, 2: b["agent_id"], 3: b["agent_pubkey"], 4: b["nonce"], 5: T0, 6: T0 + 900,
         7: {1: "gate-paper-1", 2: 1, 3: "DU1234567"},
         8: {1: "ibkr.order.v0", 2: {1: "DU1234567", 2: 265598, 4: 1, 5: 100000, 6: 1, 7: 19050000000, 8: "USD", 9: 1}},
         9: {1: 200000000000},
         10: {1: 2, 2: NAMESPACE, 3: h("share-commitment-minimal"), 4: 4200000, 5: SIGNER},
         11: b["ciphertext_hash"], 12: b["plaintext_hash"], 13: b["payload_size"]}
    canon = encode(m)
    hh = commitment_hash(canon)
    assert hh.hex() == "4bc3051bf054d997def958be87502122d7acdfcc065d5632442efe64a8465880"
    return envelope(canon, sk("agent1").sign(signing_message(hh)))


def reject_cases() -> list:
    out = []
    b = base()
    canon = encode(to_cbor(b))
    _, _, sig = sign_canon(canon)
    good = envelope(canon, sig)

    def action_with(repl: dict) -> bytes:
        m = to_cbor(b)
        m[8].update(repl)
        return encode(m)

    def ref_with(repl: dict, c: dict = b) -> bytes:
        m = to_cbor(c)
        m[10].update(repl)
        return encode(m)

    # Decoding: encoding and schema.
    out.append(d_case("too_large", "D0", "2177 bytes: a valid envelope padded with zero bytes. The size check runs before any parsing.",
                      good + bytes(2177 - len(good)), "ErrTooLarge"))
    out.append(d_case("truncated", "D1", "Valid envelope with its last byte removed.", good[:-1], "ErrMalformed"))
    out.append(d_case("reserved_additional_info", "D1", "issued_at head uses reserved additional info 28 (0x1c).",
                      resigned(commitment_with(b, {5: Raw(b"\x1c")})), "ErrMalformed"))
    out.append(d_case("trailing_byte", "D2", "Valid envelope followed by one 0x00 byte.", good + b"\x00", "ErrTrailingData"))
    out.append(d_case("float_payload_size", "D3", "payload_size encoded as float64 (0xfb).",
                      resigned(commitment_with(b, {13: Raw(b"\xfb" + struct.pack(">d", float(b["payload_size"])))})), "ErrFloat"))
    out.append(d_case("float16_height", "D3", "payload_ref.height encoded as float16 1.0 (0xf93c00).",
                      resigned(ref_with({4: Raw(b"\xf9\x3c\x00")})), "ErrFloat"))
    out.append(d_case("null_action_type", "D4", "action.type encoded as null (0xf6).",
                      resigned(action_with({3: Raw(b"\xf6")})), "ErrSimpleValue"))
    out.append(d_case("true_da", "D4", "payload_ref.da encoded as true (0xf5).",
                      resigned(ref_with({1: Raw(b"\xf5")})), "ErrSimpleValue"))
    psz = b["payload_size"].to_bytes(2, "big")
    out.append(d_case("tag_bignum_payload_size", "D5", f"payload_size encoded as tag 2 bignum h'{psz.hex()}'.",
                      resigned(commitment_with(b, {13: Raw(b"\xc2\x42" + psz)})), "ErrTag"))
    out.append(d_case("indef_map", "D6", "Commitment map encoded with indefinite length (0xbf ... 0xff).",
                      resigned(b"\xbf" + canon[1:] + b"\xff"), "ErrIndefiniteLength"))
    out.append(d_case("indef_tstr", "D6", "agent_id as an indefinite-length text string of two chunks.",
                      resigned(commitment_with(b, {2: Raw(b"\x7f" + encode("dca-") + encode("agent-1") + b"\xff")})), "ErrIndefiniteLength"))
    out.append(d_case("nonminimal_uint", "D7", "issued_at encoded in 8 bytes (0x1b) although it fits in 4.",
                      resigned(commitment_with(b, {5: Raw(b"\x1b" + T0.to_bytes(8, "big"))})), "ErrNonMinimalInt"))
    out.append(d_case("nonminimal_len", "D7", "nonce length 16 encoded as 0x58 0x10 instead of 0x50.",
                      resigned(commitment_with(b, {4: Raw(b"\x58\x10" + b["nonce"])})), "ErrNonMinimalInt"))
    items = sorted(to_cbor(b).items())
    pairs = [(Raw(b"\x18\x01") if k == 1 else k, v) for k, v in items]
    out.append(d_case("nonminimal_key", "D7", "Top-level key 1 encoded as 0x18 0x01.",
                      resigned(encode(Pairs(tuple(pairs)))), "ErrNonMinimalInt"))
    out.append(d_case("deep_nesting", "D8", "action.type replaced by the map {1: {1: 0}}; the inner map is a container at depth 5.",
                      resigned(action_with({3: {1: {1: 0}}})), "ErrNestingTooDeep"))
    m = to_cbor(b)
    for k in (14, 15, 16, 17, 18):
        m[k] = 0
    out.append(d_case("map_17_pairs", "D9", "Commitment map with 17 pairs (12 defined keys plus 14..18).",
                      resigned(encode(m)), "ErrTooLarge"))
    pairs = list(items)
    i12 = next(i for i, (k, _) in enumerate(pairs) if k == 12)
    pairs[i12], pairs[i12 + 1] = pairs[i12 + 1], pairs[i12]
    out.append(d_case("unsorted_map", "D10", "Top-level keys 12 and 13 swapped.", resigned(encode(Pairs(tuple(pairs)))), "ErrUnsortedMap"))
    pairs = list(items) + [(13, b["payload_size"])]
    out.append(d_case("dup_key", "D11", "Top-level key 13 appears twice with the same value.", resigned(encode(Pairs(tuple(pairs)))), "ErrDuplicateKey"))
    pairs = list(items) + [("x", 0)]
    out.append(d_case("tstr_key", "D12", "Commitment map gains a text-string key \"x\".", resigned(encode(Pairs(tuple(pairs)))), "ErrKeyType"))
    out.append(d_case("invalid_utf8", "D13", "agent_id is a text string containing the byte 0xff.",
                      resigned(commitment_with(b, {2: Raw(b"\x6b" + b"dca-agent-\xff")})), "ErrInvalidString"))

    type_len = 2048 - len(canon) + len(IBKR) + 30
    big = action_with({3: Raw(head(3, type_len) + b"a" * type_len)})
    big_env = resigned(big)
    assert len(big) > 2048 and len(big_env) <= 2176, (len(big), len(big_env))
    out.append(d_case("commitment_too_large", "D14", f"Commitment of {len(big)} bytes (action.type of {type_len} bytes) in an envelope of {len(big_env)} bytes. The commitment size is checked before its fields.",
                      big_env, "ErrTooLarge"))

    out.append(d_case("unknown_top_key", "D15", "Commitment has an extra key 14.", resigned(commitment_with(b, {14: 0})), "ErrUnknownKey"))
    out.append(d_case("retired_constraints_key", "D15", "Commitment carries key 9 (constraints, retired in draft.9) with {1: max_notional}.",
                      resigned(commitment_with(b, {9: {1: 200000000000}})), "ErrUnknownKey"))
    m = to_cbor(b)
    m[7][2] = 1
    out.append(d_case("retired_scope_rail_key", "D15", "scope carries key 2 (rail, retired in draft.9).", resigned(encode(m)), "ErrUnknownKey"))
    m = to_cbor(b)
    m[7][3] = "DU1234567"
    out.append(d_case("retired_scope_account_key", "D15", "scope carries key 3 (account, retired in draft.9).", resigned(encode(m)), "ErrUnknownKey"))
    m = to_cbor(b)
    m[7][4] = "celestia"
    out.append(d_case("retired_scope_chain_id_key", "D15", "scope carries key 4 (chain_id, retired in draft.9).", resigned(encode(m)), "ErrUnknownKey"))
    out.append(d_case("draft8_minimal_lmt_envelope", "D15", "The v0-draft.8 minimal_lmt envelope, byte for byte. Its scope key 2 (rail) is retired, so it fails loudly instead of being misread.",
                      draft8_minimal_lmt_envelope(), "ErrUnknownKey"))
    out.append(d_case("unknown_action_key", "D15", "action has an extra key 5.", resigned(action_with({5: 0})), "ErrUnknownKey"))
    out.append(d_case("retired_action_kind_key", "D15", "action carries key 1 (kind, retired in draft.9) next to type and hash.",
                      resigned(action_with({1: "ibkr.order.v0"})), "ErrUnknownKey"))
    out.append(d_case("retired_action_params_key", "D15", "action carries key 2 (params, retired in draft.9) next to type and hash.",
                      resigned(action_with({2: {2: 265598}})), "ErrUnknownKey"))
    out.append(d_case("unknown_payload_ref_key", "D15", "payload_ref has an extra key 6.", resigned(ref_with({6: 0})), "ErrUnknownKey"))
    f = fibre()
    out.append(d_case("signer_on_fibre", "D15", "da=fibre locator carries payload_ref key 5 (signer), which is defined only for celestia_blob.",
                      resigned(ref_with({5: SIGNER}, f)), "ErrUnknownKey"))
    out.append(d_case("unknown_envelope_key", "D15", "Envelope has an extra key 3.", encode({1: Raw(canon), 2: sig, 3: 0}), "ErrUnknownKey"))
    out.append(d_case("nint_payload_size", "D16", "payload_size encoded as a negative integer.",
                      resigned(commitment_with(b, {13: -b["payload_size"]})), "ErrWrongType"))
    out.append(d_case("bstr_for_tstr", "D16", "agent_id encoded as a byte string.",
                      resigned(commitment_with(b, {2: b"dca-agent-1"})), "ErrWrongType"))
    m = to_cbor(b)
    m[7] = ["gate-paper-1"]
    out.append(d_case("array_for_scope", "D16", "scope encoded as an array.", resigned(encode(m)), "ErrWrongType"))
    out.append(d_case("action_hash_tstr", "D16", "action.hash given as 64 lowercase hex characters (a text string) instead of 32 bytes.",
                      resigned(action_with({4: b["action"]["hash"].hex()})), "ErrWrongType"))
    out.append(d_case("signer_bech32_tstr", "D16", "payload_ref.signer given as a bech32 text string instead of the raw 20-byte address.",
                      resigned(ref_with({5: "celestia1" + "q" * 38})), "ErrWrongType"))
    out.append(d_case("missing_nonce", "D17", "Top-level key 4 absent.", resigned(encode({k: v for k, v in to_cbor(b).items() if k != 4})), "ErrMissingField"))
    m = to_cbor(b)
    del m[8][4]
    out.append(d_case("missing_action_hash", "D17", "action key 4 (hash) absent.", resigned(encode(m)), "ErrMissingField"))
    m = to_cbor(b)
    del m[10][4]
    out.append(d_case("missing_height", "D17", "payload_ref key 4 (height) absent.", resigned(encode(m)), "ErrMissingField"))
    m = to_cbor(b)
    del m[10][3]
    out.append(d_case("missing_locator_commitment", "D17", "payload_ref key 3 (commitment) absent.", resigned(encode(m)), "ErrMissingField"))
    m = to_cbor(b)
    del m[10][5]
    out.append(d_case("missing_locator_signer", "D17", "da=celestia_blob without payload_ref key 5 (signer).", resigned(encode(m)), "ErrMissingField"))
    out.append(d_case("missing_signature", "D17", "Envelope without key 2.", encode({1: Raw(canon)}), "ErrMissingField"))
    out.append(d_case("nonce_15_bytes", "D18", "nonce of 15 bytes.", resigned(commitment_with(b, {4: b["nonce"][:15]})), "ErrFieldSize"))
    out.append(d_case("sig_63_bytes", "D18", "Signature of 63 bytes.", envelope(canon, sig[:63]), "ErrFieldSize"))
    out.append(d_case("namespace_28_bytes", "D18", "namespace of 28 bytes.", resigned(ref_with({2: NAMESPACE[:28]})), "ErrFieldSize"))
    out.append(d_case("share_commitment_31_bytes", "D18", "da=celestia_blob with a 31-byte share commitment.",
                      resigned(ref_with({3: h("share-commitment-minimal")[:31]})), "ErrFieldSize"))
    out.append(d_case("fibre_commitment_33_bytes", "D18", "da=fibre with a 33-byte Fibre BlobID (version byte || commitment) instead of the 32-byte commitment.",
                      resigned(ref_with({3: b"\x00" + f["payload_ref"]["commitment"]}, f)), "ErrFieldSize"))
    out.append(d_case("signer_19_bytes", "D18", "da=celestia_blob with a 19-byte signer.", resigned(ref_with({5: SIGNER[:19]})), "ErrFieldSize"))
    out.append(d_case("signer_32_bytes", "D18", "da=celestia_blob with a 32-byte address (for example a module or ICA account); share version 1 requires exactly 20 bytes.",
                      resigned(ref_with({5: h("edicta/v0 test 32-byte account")})), "ErrFieldSize"))
    out.append(d_case("agent_id_empty", "D18", "agent_id is the empty string.", resigned(commitment_with(b, {2: ""})), "ErrFieldSize"))
    out.append(d_case("agent_id_65_chars", "D18", "agent_id of 65 characters.", resigned(commitment_with(b, {2: "a" * 65})), "ErrFieldSize"))
    out.append(d_case("action_type_129_chars", "D18", "action.type of 129 bytes (otherwise grammatical).",
                      resigned(action_with({3: TYPE_128[:-5] + "a+cbor"})), "ErrFieldSize"))
    out.append(d_case("action_type_empty", "D18", "action.type is the empty string.", resigned(action_with({3: ""})), "ErrFieldSize"))
    out.append(d_case("action_type_2_chars", "D18", "action.type \"ab\": 2 bytes, below the minimum of 3 (the shortest type is \"a/b\").",
                      resigned(action_with({3: "ab"})), "ErrFieldSize"))
    out.append(d_case("action_hash_31_bytes", "D18", "action.hash of 31 bytes.", resigned(action_with({4: b["action"]["hash"][:31]})), "ErrFieldSize"))
    m = to_cbor(b)
    m[7][1] = "gate-paper-ο1"
    out.append(d_case("gate_id_unicode", "D19", "gate_id contains U+03BF (Greek small omicron), a look-alike of 'o'.", resigned(encode(m)), "ErrInvalidString"))
    for cid, t, desc in [
        ("action_type_uppercase", "Application/vnd.edicta.ibkr.order.v0+cbor", "Upper-case letter; types are lower case so each type has one byte string."),
        ("action_type_space", "application/ json", "Contains a space."),
        ("action_type_no_slash", "application-json", "No slash."),
        ("action_type_two_slashes", "application/vnd.x/y", "Two slashes."),
        ("action_type_parameter", "application/json;charset=utf-8", "A media-type parameter."),
        ("action_type_bad_first_char", "application/.json", "Subtype starts with '.', outside [a-z0-9]."),
        ("action_type_unicode", "application/vnd.edicta.οrder", "Contains U+03BF (Greek small omicron)."),
    ]:
        out.append(d_case(cid, "D19", f"action.type {t!r}: {desc}", resigned(action_with({3: t})), "ErrInvalidString"))

    # Every later check: a schema-valid commitment with exactly one defect, correctly signed.
    def s_case(cid, stage, rule, desc, c, expect, now=NOW, params=None, gate=None, action=None, signer="agent1",
               preimage=None):
        case = {"id": cid, "stage": stage, "rule": rule, "description": desc}
        case.update(signed_case(c, signer))
        case["now"] = str(now)
        if params is not None:
            case["params"] = params_to_json(params)
        if gate is not None:
            case["gate"] = gate_to_json(gate)
        if action is not None:
            case.update(action_fields(*action, with_hash=False))
        if preimage is not None:
            assert hashlib.sha256(preimage).digest() == c["action"]["hash"], cid
            case["committed_preimage_hex"] = preimage.hex()
        case["expect_error"] = expect
        out.append(case)
        return case

    s_case("version_1", "S", "S1", "version 1.", mod(b, "version", 1), "ErrUnsupportedVersion")
    s_case("height_2pow63", "S", "S2", "payload_ref.height = 2^63 (9-byte head 0x1b8000000000000000).",
           mod(b, "payload_ref.height", 1 << 63), "ErrIntRange")
    s_case("da_0", "S", "S3", "da 0.", mod(b, "payload_ref.da", 0), "ErrInvalidEnum")
    s_case("da_3", "S", "S3", "da 3.", mod(b, "payload_ref.da", 3), "ErrInvalidEnum")
    s_case("da_256", "S", "S3", "da 256: enums decode at uint64 width, so this is an enum error, not a decode error.",
           mod(b, "payload_ref.da", 256), "ErrInvalidEnum")
    s_case("issued_at_0", "S", "S6", "issued_at 0.", mod(b, "issued_at", 0), "ErrZeroValue")
    s_case("height_0", "S", "S6", "payload_ref.height 0.", mod(b, "payload_ref.height", 0), "ErrZeroValue")
    s_case("payload_size_0", "S", "S6", "payload_size 0.", mod(b, "payload_size", 0), "ErrZeroValue")
    s_case("payload_size_2pow27_plus1", "S", "S7", "payload_size 2^27 + 1.", mod(b, "payload_size", (1 << 27) + 1), "ErrPayloadTooLarge")
    s_case("namespace_version_1", "S", "S8", "Namespace version byte 1.", mod(b, "payload_ref.namespace", b"\x01" + NAMESPACE[1:]), "ErrInvalidNamespace")
    s_case("namespace_nonzero_prefix", "S", "S8", "Version 0 namespace whose 18-byte id prefix is not all zero.",
           mod(b, "payload_ref.namespace", b"\x00\x01" + NAMESPACE[2:]), "ErrInvalidNamespace")
    s_case("namespace_reserved", "S", "S8", "Primary reserved namespace 0x00..0004 (PayForBlob).",
           mod(b, "payload_ref.namespace", bytes(28) + b"\x04"), "ErrInvalidNamespace")
    s_case("valid_until_eq_issued", "S", "S12", "valid_until == issued_at.", mod(b, "valid_until", T0), "ErrTimeOrder")
    s_case("valid_until_lt_issued", "S", "S12", "valid_until < issued_at.", mod(b, "valid_until", T0 - 1), "ErrTimeOrder")
    s_case("ttl_3601", "S", "S14", "TTL 3601 with default params (MaxTTL 3600).", mod(b, "valid_until", T0 + 3601), "ErrTTLTooLong")
    s_case("ttl_ok_at_4h_rejected_at_10m", "S", "S14",
           "da=fibre, TTL 900. Valid at fibre_retention_s=14400; here retention was lowered to 600 (MaxTTL 150) and is read at check time.",
           mod(fibre(), "nonce", h("nonce-ttl-gov")[:16]), "ErrTTLTooLong", params=Params(600, 14400, 30))
    s_case("ttl_floor_division", "S", "S14", "fibre_retention_s=601: MaxTTL = floor(601/4) = 150; TTL 151 is rejected.",
           mod(fibre(), "valid_until", T0 + 151), "ErrTTLTooLong", params=Params(601, 14400, 30))

    for cid, desc, enc in g0_keys():
        small = (pt := ed.decode(enc, strict=False)) is not None and ed.is_small_order(pt)
        for i in range(64):  # vary the nonce until a forgery exists (expected within a few tries)
            c = mod(b, "agent_pubkey", enc)
            c["nonce"] = h(f"nonce-{cid}-{i}")[:16]
            canon_c = encode(to_cbor(c))
            hh = commitment_hash(canon_c)
            sig_c, forged = small_order_forgery(enc, signing_message(hh))
            if forged or not small:
                break
        assert forged == small, cid
        note = (" The signature R || S=0 satisfies the cofactorless equation [S]B = R + [k]A for this A, so a verifier without G0 accepts it."
                if forged else " Signature R=identity, S=0.")
        out.append({"id": cid, "stage": "G", "rule": "G0", "description": desc + note, "input": commitment_to_json(c),
                    "commitment_cbor_hex": canon_c.hex(), "commitment_hash_hex": hh.hex(),
                    "envelope_hex": envelope(canon_c, sig_c).hex(), "now": str(NOW), "expect_error": "ErrInvalidPublicKey"})

    def g_case(cid, rule, desc, c, msg_fn, sig_fn=None):
        canon_c = encode(to_cbor(c))
        hh = commitment_hash(canon_c)
        s = sk("agent1").sign(msg_fn(canon_c, hh))
        if sig_fn:
            s = sig_fn(s)
        out.append({"id": cid, "stage": "G", "rule": rule, "description": desc, "input": commitment_to_json(c),
                    "commitment_cbor_hex": canon_c.hex(), "commitment_hash_hex": hh.hex(),
                    "envelope_hex": envelope(canon_c, s).hex(), "now": str(NOW), "expect_error": "ErrSignatureInvalid"})

    g_case("wrong_sig_tag", "G1", "Signed message uses the receipt tag: 0x11 || \"edicta/v0/receipt\" || commitment_hash.",
           b, lambda cc, hh: tagged(TAG_RECEIPT) + hh)
    g_case("sig_under_authorization_sig_tag", "G1", "Signed message uses the Authorization signature tag: 0x1b || \"edicta/v0/authorization-sig\" || commitment_hash.",
           b, lambda cc, hh: tagged(TAG_AUTHORIZATION_SIG) + hh)
    g_case("sig_tag_no_length_prefix", "G1", "Signed message omits the tag length byte: \"edicta/v0/sig\" || commitment_hash.",
           b, lambda cc, hh: TAG_SIG + hh)
    g_case("wrong_hash_tag", "G1", "commitment hash computed with the receipt tag instead of the commitment tag.",
           b, lambda cc, hh: tagged(TAG_SIG) + hashlib.sha256(tagged(TAG_RECEIPT) + cc).digest())
    g_case("hash_without_tag", "G1", "commitment hash computed as SHA-256(canon) with no domain tag.",
           b, lambda cc, hh: tagged(TAG_SIG) + hashlib.sha256(cc).digest())
    g_case("sig_raw_cbor", "G1", "Signature over the raw canonical CBOR instead of the tagged hash.", b, lambda cc, hh: cc)
    g_case("sig_raw_hash", "G1", "Signature over commitment_hash without the signature tag.", b, lambda cc, hh: hh)

    def plus_l(s: bytes) -> bytes:
        v = int.from_bytes(s[32:], "little") + ED25519_L
        return s[:32] + v.to_bytes(32, "little")

    g_case("sig_noncanonical_s", "G2", "Valid signature with S replaced by S + L (malleated).",
           b, lambda cc, hh: signing_message(hh), plus_l)
    s_case("sig_wrong_key", "G", "G1", "agent_pubkey is agent1, signature made by agent2.", b, "ErrSignatureInvalid", signer="agent2")

    orig = encode(to_cbor(b))
    _, _, osig = sign_canon(orig)
    other_order = order_encode(dict(ORDER_MINIMAL, qty=100001))
    flipped = with_action(b, IBKR, other_order)
    fcanon = encode(to_cbor(flipped))
    out.append({"id": "flipped_field", "stage": "G", "rule": "G1",
                "description": "action.hash replaced after signing by the hash of the same order with qty 100001; the signature is over minimal_lmt.",
                "input": commitment_to_json(flipped), "commitment_cbor_hex": fcanon.hex(),
                "commitment_hash_hex": commitment_hash(fcanon).hex(),
                "envelope_hex": envelope(fcanon, osig).hex(), "now": str(NOW), "expect_error": "ErrSignatureInvalid"})

    canon_t = encode(to_cbor(b))
    tsig = torsion_r_signature(signing_message(commitment_hash(canon_t)))
    out.append({"id": "sig_torsion_r", "stage": "G", "rule": "G1",
                "description": "Signature by agent1 with R = [r]B + T, T an order-8 point, and S = r + k*a mod L < L. "
                               "It satisfies the cofactored equation [8][S]B = [8]R + [8][k]A but not the cofactorless "
                               "equation encode([S]B - [k]A) == R, so it is rejected; a cofactored verifier would accept it.",
                "input": commitment_to_json(b), "commitment_cbor_hex": canon_t.hex(),
                "commitment_hash_hex": commitment_hash(canon_t).hex(),
                "envelope_hex": envelope(canon_t, tsig).hex(), "now": str(NOW), "expect_error": "ErrSignatureInvalid"})

    s_case("future_issued", "T", "T1", "issued_at == now + skew + 1.", mod(mod(b, "issued_at", NOW + 31), "valid_until", NOW + 931), "ErrNotYetValid")
    s_case("expired", "T", "T2", "now well past valid_until.", b, "ErrExpired", now=T0 + 1000)
    s_case("expiry_within_skew", "T", "T2", "now + skew == valid_until.", b, "ErrExpired", now=T0 + 900 - 30)

    s_case("foreign_gate_id", "C", "C1", "Gate id differs.", b, "ErrScopeMismatch", gate=dict(GATE, gate_id="gate-paper-2"))
    c = with_action(mod(b, "nonce", h("nonce-type-not-allowed")[:16]), TYPE_NOT_ALLOWED, bytes.fromhex("f86c098504a817c800825208"))
    s_case("action_type_not_allowed", "C", "C2", f"action.type {TYPE_NOT_ALLOWED} is well formed but not in the gate's action_types.",
           c, "ErrActionTypeNotAllowed")
    s_case("action_type_suffix_differs", "C", "C2",
           "The gate allows application/vnd.edicta.ibkr.order.v0+json only; the committed type differs in the suffix. Membership is bytewise equality.",
           b, "ErrActionTypeNotAllowed", gate=dict(GATE, action_types=["application/vnd.edicta.ibkr.order.v0+json"]))

    good_preimage = action_preimage_prefix(IBKR) + ACTION_MINIMAL

    def a_case(cid, rule, desc, c, action, expect, preimage=good_preimage):
        s_case(cid, "A", rule, desc, c, expect, action=action, preimage=preimage)

    def flip(x: bytes, i: int) -> bytes:
        y = bytearray(x)
        y[i] ^= 0x01
        return bytes(y)

    a_case("action_byte_flipped", "A1", "The supplied order bytes have their last byte flipped (tif 1 -> 0).", b, (IBKR, flip(ACTION_MINIMAL, -1)), "ErrActionMismatch")
    a_case("action_truncated", "A1", "The supplied order bytes miss their last byte.", b, (IBKR, ACTION_MINIMAL[:-1]), "ErrActionMismatch")
    a_case("action_extra_byte", "A1", "The supplied order bytes carry one extra 0x00 byte at the end.", b, (IBKR, ACTION_MINIMAL + b"\x00"), "ErrActionMismatch")
    a_case("action_qty_differs", "A1", "The supplied order is the committed one with qty 100001; the core does not interpret it, the hash differs.",
           b, (IBKR, other_order), "ErrActionMismatch")
    nc = bytearray(ACTION_MINIMAL)
    conid_head = encode(265598)
    i = nc.index(b"\x02" + conid_head)
    noncanon = bytes(nc[:i + 1]) + b"\x1b" + (265598).to_bytes(8, "big") + bytes(nc[i + 1 + len(conid_head):])
    a_case("action_reencoded_noncanonical", "A1", "The same order with conid in a 9-byte head: the same meaning in a lenient decoder, other bytes, so not authorized.",
           b, (IBKR, noncanon), "ErrActionMismatch")
    c = mod(b, "nonce", h("nonce-hash-other-type")[:16])
    c["action"]["hash"] = action_hash(TYPE_OCTETS, ACTION_MINIMAL)
    a_case("action_hash_of_other_type", "A1", "action.hash was computed under application/octet-stream over the right bytes; the committed type is the IBKR order type.",
           c, (IBKR, ACTION_MINIMAL), "ErrActionMismatch", preimage=action_preimage_prefix(TYPE_OCTETS) + ACTION_MINIMAL)
    c = mod(b, "nonce", h("nonce-hash-untagged")[:16])
    t = IBKR.encode()
    c["action"]["hash"] = hashlib.sha256(bytes([len(t)]) + t + ACTION_MINIMAL).digest()
    a_case("action_hash_untagged", "A1", "action.hash = SHA-256(uint8(len(type)) || type || bytes), without the edicta/v0/action tag.",
           c, (IBKR, ACTION_MINIMAL), "ErrActionMismatch", preimage=bytes([len(t)]) + t + ACTION_MINIMAL)
    c = mod(b, "nonce", h("nonce-hash-type-unprefixed")[:16])
    c["action"]["hash"] = hashlib.sha256(tagged(TAG_ACTION) + t + ACTION_MINIMAL).digest()
    a_case("action_hash_type_unprefixed", "A1", "action.hash = SHA-256(tag || type || bytes), without the type length byte.",
           c, (IBKR, ACTION_MINIMAL), "ErrActionMismatch", preimage=tagged(TAG_ACTION) + t + ACTION_MINIMAL)
    c = mod(b, "nonce", h("nonce-hash-bare")[:16])
    c["action"]["hash"] = hashlib.sha256(ACTION_MINIMAL).digest()
    a_case("action_hash_bare_sha256", "A1", "action.hash = SHA-256(bytes): no tag, no type.",
           c, (IBKR, ACTION_MINIMAL), "ErrActionMismatch", preimage=ACTION_MINIMAL)
    a_case("action_empty", "A0", "No action bytes supplied (length 0).", b, (IBKR, b""), "ErrActionSize")
    a_case("action_too_large", "A0", f"{MAX_ACTION_SIZE + 1} bytes supplied (pattern {PATTERN}); the size is checked before hashing.",
           b, (IBKR, pattern_bytes(PATTERN, MAX_ACTION_SIZE + 1)), "ErrActionSize")
    return out


def g0_keys() -> list:
    """(id, description, 32-byte agent_pubkey) cases that the public-key
    validity check must reject."""
    p = ed.P
    names = {1: "identity", 2: "order 2", 4: "order 4", 8: "order 8"}
    out = []
    count = {}
    for pt in ed.torsion_points():
        o = ed.order(pt)
        count[o] = count.get(o, 0) + 1
        enc = ed.encode(pt)
        suffix = "" if o in (1, 2) else f"_{'abcd'[count[o] - 1]}"
        cid = "pubkey_identity" if o == 1 else f"pubkey_order{o}{suffix}"
        out.append((cid, f"agent_pubkey is the canonical encoding of the {names[o]} point {enc.hex()}.", enc))

    def raw(y: int, sign: int) -> bytes:
        return (y | (sign << 255)).to_bytes(32, "little")

    out += [
        ("pubkey_identity_negzero", "agent_pubkey y=1 with the sign bit set (x = 0, \"negative zero\"); RFC 8032 decoding fails, lenient decoders return the identity.", raw(1, 1)),
        ("pubkey_order2_negzero", "agent_pubkey y=p-1 with the sign bit set (x = 0); lenient decoders return the order-2 point.", raw(p - 1, 1)),
        ("pubkey_order4_y_eq_p", "agent_pubkey y=p (non-canonical 0), sign 0; lenient decoders return an order-4 point.", raw(p, 0)),
        ("pubkey_order4_y_eq_p_sign", "agent_pubkey y=p (non-canonical 0), sign 1; lenient decoders return the other order-4 point.", raw(p, 1)),
        ("pubkey_identity_y_eq_p_plus_1", "agent_pubkey y=p+1 (non-canonical 1), sign 0; lenient decoders return the identity.", raw(p + 1, 0)),
        ("pubkey_identity_y_eq_p_plus_1_sign", "agent_pubkey y=p+1 (non-canonical 1), sign 1; lenient decoders return the identity.", raw(p + 1, 1)),
    ]
    for k in range(2, 19):
        enc = raw(p + k, 0)
        pt = ed.decode(enc, strict=False)
        if pt is not None and not ed.is_small_order(pt):
            out.append(("pubkey_noncanonical_y", f"agent_pubkey y=p+{k}: a non-canonical encoding of a large-order point (y={k}).", enc))
            break
    else:
        raise AssertionError("no non-canonical large-order encoding found")
    y = 2
    while ed.decode(raw(y, 0)) is not None:
        y += 1
    out.append(("pubkey_not_on_curve", f"agent_pubkey y={y}: no x satisfies the curve equation.", raw(y, 0)))
    for cid, _, enc in out:
        assert ed.public_key_problem(enc), cid
    return out


def small_order_forgery(a_enc: bytes, msg: bytes):
    """For a small-order A (decoded leniently), find R in the 8-torsion with
    R == -[k]A, k = SHA-512(R || A || msg) mod L. Then (R, S=0) passes the
    cofactorless check [S]B == R + [k]A, as done by Go crypto/ed25519 and OpenSSL."""
    a = ed.decode(a_enc, strict=False)
    if a is not None and ed.is_small_order(a):
        for r in ed.torsion_points():
            r_enc = ed.encode(r)
            k = int.from_bytes(hashlib.sha512(r_enc + a_enc + msg).digest(), "little") % ed.L
            if ed.encode(ed.neg(ed.mul(k, a))) == r_enc:
                return r_enc + bytes(32), True
    return ed.encode(ed.IDENTITY) + bytes(32), False


def torsion_r_signature(msg: bytes, signer: str = "agent1") -> bytes:
    """Signature that only a cofactored verifier accepts, so the cofactorless
    equation must reject it. Uses the signer's secret scalar a
    (RFC 8032 5.1.5) and a deterministic r:
    R = [r]B + T with T of order 8, k = SHA-512(R || A || msg) mod L,
    S = (r + k*a) mod L. Then [S]B - [k]A = [r]B != R, while
    [8][S]B = [8]R + [8][k]A holds because [8]T = identity."""
    digest = hashlib.sha512(bytes.fromhex(KEYS[signer]["seed_hex"])).digest()
    a = int.from_bytes(digest[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    a_enc = bytes.fromhex(KEYS[signer]["public_key_hex"])
    assert ed.encode(ed.mul(a, ed.BASE)) == a_enc
    t = ed.torsion_points()[1]
    assert ed.order(t) == 8
    r = int.from_bytes(hashlib.sha512(b"edicta/v0 test torsion-R nonce" + msg).digest(), "little") % ed.L
    r_enc = ed.encode(ed.add(ed.mul(r, ed.BASE), t))
    k = ed.challenge(r_enc, a_enc, msg)
    sig = r_enc + ((r + k * a) % ed.L).to_bytes(32, "little")
    assert ed.cofactored_ok(a_enc, msg, sig) and not ed.cofactorless_ok(a_enc, msg, sig)
    return sig


def share_frame(ns: bytes, signer: bytes, data: bytes) -> bytes:
    """Illustrative single share-version-1 sparse share: namespace, info byte
    (version 1 << 1 | sequence start = 0x03), 4-byte sequence length, 20-byte
    signer, data, zero padding to 512 bytes."""
    assert len(signer) == 20 and len(data) <= 458
    s = ns + b"\x03" + struct.pack(">I", len(data)) + signer + data
    return s + bytes(512 - len(s))


def payload_vectors() -> dict:
    blob_hash = hashlib.sha256(BLOB).digest()
    flipped = bytearray(BLOB)
    flipped[-1] ^= 0x01
    framed = share_frame(NAMESPACE, SIGNER, BLOB)
    return {
        "format": FORMAT,
        "cases": [
            {"id": "ciphertext_hash_small_blob",
             "description": "Canonical payload envelope with two wrapped-key entries and dummy bytes; ciphertext_hash = SHA-256(blob).",
             "blob_hex": BLOB.hex(), "payload_size": str(len(BLOB)), "ciphertext_hash_hex": blob_hash.hex()},
            {"id": "plaintext_hash_basic", "description": "plaintext_hash = SHA-256(salt(32) || plaintext).",
             "salt_hex": SALT.hex(), "plaintext_hex": PLAINTEXT.hex(),
             "plaintext_hash_hex": hashlib.sha256(SALT + PLAINTEXT).digest().hex()},
        ],
        "reject": [
            {"id": "blob_flipped_byte", "commitment_ref": "minimal_lmt",
             "description": "Last byte of the blob flipped.",
             "payload_size": str(len(BLOB)), "ciphertext_hash_hex": blob_hash.hex(),
             "blob_hex": bytes(flipped).hex(), "expect_error": "ErrPayloadHashMismatch"},
            {"id": "blob_with_share_padding",
             "description": "The producer hashed the share-framed bytes (namespace, info byte, sequence length, signer, zero padding; share version 1) instead of the blob; the fetched blob is the raw envelope.",
             "payload_size": str(len(BLOB)), "ciphertext_hash_hex": hashlib.sha256(framed).hexdigest(),
             "framed_hex": framed.hex(), "blob_hex": BLOB.hex(), "expect_error": "ErrPayloadHashMismatch"},
            {"id": "blob_truncated", "commitment_ref": "minimal_lmt",
             "description": "Blob missing its last byte; size is checked before the hash.",
             "payload_size": str(len(BLOB)), "ciphertext_hash_hex": blob_hash.hex(),
             "blob_hex": BLOB[:-1].hex(), "expect_error": "ErrPayloadSizeMismatch"},
        ],
    }


# Authorizations, receipts and anchor rules.

GATE_KEY = "gate1"
AUTHORIZED_AT = NOW
MAX_AUTHORIZATION_TTL = 300
RECORDED_AT = NOW + 2
IBKR_ORDER_ID = "1370093239"
ID_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._:/-"


def gate_pub(name: str = GATE_KEY) -> bytes:
    return bytes.fromhex(KEYS[name]["public_key_hex"])


def check_block(action_type: str, action: bytes, now: int = NOW, gate_id: str = "gate-paper-1",
                pub: bytes | None = None, skew: int = 30) -> dict:
    out = {"gate_pubkey_hex": (pub or gate_pub()).hex(), "gate_id": gate_id}
    out.update(action_fields(action_type, action, with_hash=False))
    out.update({"now": str(now), "skew_s": str(skew)})
    return out


def check_of(blk: dict) -> AuthorizationCheck:
    from vecjson import action_from_case
    return AuthorizationCheck(bytes.fromhex(blk["gate_pubkey_hex"]), blk["gate_id"], blk["action_type"],
                              action_from_case(blk), int(blk["now"]), int(blk["skew_s"]))


def sign_tagged(canon: bytes, hash_fn, tag: bytes, signer: str = GATE_KEY):
    hh = hash_fn(canon)
    msg = signing_message(hh, tag)
    return hh, msg, sk(signer).sign(msg)


def signed_pair(inner: bytes, sig: bytes) -> bytes:
    return encode({1: Raw(inner), 2: sig})


def authorization_for(valid_case: dict, path: int = 1, authorized_at: int = AUTHORIZED_AT) -> dict:
    inp = valid_case["input"]
    return {
        "version": 0,
        "commitment_hash": bytes.fromhex(valid_case["commitment_hash_hex"]),
        "action_hash": bytes.fromhex(inp["action"]["hash"]),
        "gate_id": inp["scope"]["gate_id"],
        "expires": authorization_expires(int(inp["valid_until"]), authorized_at, MAX_AUTHORIZATION_TTL),
        "path": path,
    }


AUTH_SIGNATURES = {}


def authorization_vectors(valid: list) -> dict:
    by_id = {v["id"]: v for v in valid}
    cases = []

    def add(cid, desc, ref, path=1):
        v = by_id[ref]
        a = authorization_for(v, path)
        canon = encode(to_cbor(a, AUTHORIZATION))
        ah, msg, sig = sign_tagged(canon, authorization_hash, TAG_AUTHORIZATION_SIG)
        data = signed_pair(canon, sig)
        assert len(msg) == 60 and len(data) <= MAX_AUTHORIZATION_SIZE
        at, action = VALID_ACTIONS[ref]
        blk = check_block(at, action)
        verify_authorization(data, check_of(blk))
        AUTH_SIGNATURES[cid] = (canon, sig)
        cases.append({
            "id": cid, "description": desc, "commitment_ref": ref, "authorized_at": str(AUTHORIZED_AT),
            "signer": GATE_KEY, "input": authorization_to_json(a),
            "authorization_cbor_hex": canon.hex(), "authorization_hash_hex": ah.hex(),
            "signed_message_hex": msg.hex(), "signature_hex": sig.hex(),
            "signed_authorization_hex": data.hex(), "check": blk,
        })

    add("auth_minimal_lmt_da", "minimal_lmt authorized at now; payload accepted from the DA layer (path 1). expires = min(valid_until, authorized_at + 300) = authorized_at + 300.",
        "minimal_lmt")
    add("auth_minimal_lmt_archive", "As auth_minimal_lmt_da with path 2 (archive). Differs only in key 6.", "minimal_lmt", path=2)
    add("auth_expires_is_valid_until", "ttl_max_at_601s_retention: valid_until is 90 s after authorized_at, so expires = valid_until.",
        "ttl_max_at_601s_retention")
    add("auth_fibre_small_payload", "fibre_small_payload (da = fibre), DA path.", "fibre_small_payload")
    add("auth_action_json_bytes", "action_json_bytes: the executor recomputes the action hash with type application/json over the JSON bytes.",
        "action_json_bytes")
    add("auth_action_max_size", f"action_max_size: {MAX_ACTION_SIZE} action bytes (pattern {PATTERN}).", "action_max_size")
    add("auth_action_type_128_chars", "action_type_128_chars: a 128-byte action type inside the action hash preimage.",
        "action_type_128_chars")

    m = by_id["minimal_lmt"]
    base_a = authorization_for(m)
    base_canon = encode(to_cbor(base_a, AUTHORIZATION))
    _, _, base_sig = sign_tagged(base_canon, authorization_hash, TAG_AUTHORIZATION_SIG)
    base_signed = signed_pair(base_canon, base_sig)
    base_check = check_block(IBKR, ACTION_MINIMAL)
    rejects = []

    def rj(cid, stage, rule, desc, data: bytes, expect, a=None, chk=None):
        blk = chk or base_check
        case = {"id": cid, "stage": stage, "rule": rule, "description": desc,
                "signed_authorization_hex": data.hex(), "check": blk, "expect_error": expect}
        if a is not None:
            canon = encode(to_cbor(a, AUTHORIZATION))
            case["input"] = authorization_to_json(a)
            case["authorization_cbor_hex"] = canon.hex()
            case["authorization_hash_hex"] = authorization_hash(canon).hex()
        try:
            verify_authorization(data, check_of(blk))
        except Reject as e:
            assert e.sentinel == expect, (cid, e)
        else:
            raise AssertionError(f"{cid} verifies")
        rejects.append(case)

    def resign(inner: bytes) -> bytes:
        _, _, s = sign_tagged(inner, authorization_hash, TAG_AUTHORIZATION_SIG)
        return signed_pair(inner, s)

    def raw_auth(repl: dict, drop=()) -> bytes:
        mm = to_cbor(base_a, AUTHORIZATION)
        mm.update(repl)
        for k in drop:
            mm.pop(k)
        return encode(mm)

    def signed_static(a: dict) -> bytes:
        return resign(encode(to_cbor(a, AUTHORIZATION)))

    # Decoding.
    rj("authorization_too_large", "D", "D0", f"{MAX_AUTHORIZATION_SIZE + 1} bytes: a valid Authorization followed by zero bytes. Size is checked before parsing.",
       base_signed + bytes(MAX_AUTHORIZATION_SIZE + 1 - len(base_signed)), "ErrTooLarge")
    rj("authorization_trailing_byte", "D", "D2", "A valid SignedAuthorization followed by one zero byte.", base_signed + b"\x00", "ErrTrailingData")
    rj("authorization_unknown_key", "D", "D15", "Authorization key 7 (undefined) added.", resign(raw_auth({7: 1})), "ErrUnknownKey")
    rj("signed_authorization_unknown_key", "D", "D15", "SignedAuthorization key 3 (undefined) added.",
       encode({1: Raw(base_canon), 2: base_sig, 3: 0}), "ErrUnknownKey")
    rj("authorization_missing_path", "D", "D17", "Key 6 path absent.", resign(raw_auth({}, drop=(6,))), "ErrMissingField")
    rj("authorization_missing_expires", "D", "D17", "Key 5 expires absent.", resign(raw_auth({}, drop=(5,))), "ErrMissingField")
    rj("authorization_missing_signature", "D", "D17", "SignedAuthorization without key 2.", encode({1: Raw(base_canon)}), "ErrMissingField")
    rj("authorization_commitment_hash_31_bytes", "D", "D18", "commitment_hash of 31 bytes.",
       resign(raw_auth({2: base_a["commitment_hash"][:31]})), "ErrFieldSize")
    rj("authorization_action_hash_33_bytes", "D", "D18", "action_hash of 33 bytes.",
       resign(raw_auth({3: base_a["action_hash"] + b"\x00"})), "ErrFieldSize")
    rj("authorization_gate_id_empty", "D", "D18", "gate_id is the empty string.", resign(raw_auth({4: ""})), "ErrFieldSize")
    rj("authorization_gate_id_65_chars", "D", "D18", "gate_id of 65 characters.", resign(raw_auth({4: "g" * 65})), "ErrFieldSize")
    rj("authorization_sig_63_bytes", "D", "D18", "Signature of 63 bytes.", encode({1: Raw(base_canon), 2: base_sig[:63]}), "ErrFieldSize")
    rj("authorization_gate_id_unicode", "D", "D19", "gate_id contains U+03BF (Greek small omicron), a look-alike of 'o'.",
       resign(raw_auth({4: "gate-paper-ο1"})), "ErrInvalidString")
    rj("authorization_path_tstr", "D", "D16", "path encoded as the text string \"1\".", resign(raw_auth({6: "1"})), "ErrWrongType")
    rj("authorization_action_hash_tstr", "D", "D16", "action_hash as 64 hex characters.",
       resign(raw_auth({3: base_a["action_hash"].hex()})), "ErrWrongType")
    rj("authorization_expires_nonminimal", "D", "D7", "expires in a 9-byte head although it fits in 5.",
       resign(raw_auth({5: Raw(b"\x1b" + base_a["expires"].to_bytes(8, "big"))})), "ErrNonMinimalInt")
    rj("authorization_expires_float", "D", "D3", "expires as a float64.",
       resign(raw_auth({5: Raw(b"\xfb" + struct.pack(">d", float(base_a["expires"])))})), "ErrFloat")
    items = sorted(to_cbor(base_a, AUTHORIZATION).items())
    items[4], items[5] = items[5], items[4]
    rj("authorization_unsorted_map", "D", "D10", "Keys 5 and 6 swapped.", resign(encode(Pairs(tuple(items)))), "ErrUnsortedMap")

    # Static checks, correctly signed.
    def s_rj(cid, rule, desc, a, expect):
        rj(cid, "S", rule, desc, signed_static(a), expect, a)

    s_rj("authorization_version_1", "Q1", "version = 1.", dict(base_a, version=1), "ErrUnsupportedVersion")
    s_rj("authorization_expires_2pow63", "Q2", "expires = 2^63.", dict(base_a, expires=1 << 63), "ErrIntRange")
    s_rj("authorization_path_0", "Q3", "path = 0.", dict(base_a, path=0), "ErrInvalidEnum")
    s_rj("authorization_path_3", "Q3", "path = 3.", dict(base_a, path=3), "ErrInvalidEnum")
    s_rj("authorization_expires_0", "Q4", "expires = 0.", dict(base_a, expires=0), "ErrZeroValue")

    # Signature checks under the pinned gate key.
    def g_rj(cid, rule, desc, a, sig, chk=None):
        canon = encode(to_cbor(a, AUTHORIZATION))
        rj(cid, "G", rule, desc, signed_pair(canon, sig), "ErrInvalidPublicKey" if rule == "G0" else "ErrSignatureInvalid", a, chk)

    ident = ed.encode(ed.IDENTITY)
    sig_id, forged = small_order_forgery(ident, signing_message(authorization_hash(base_canon), TAG_AUTHORIZATION_SIG))
    assert forged
    g_rj("authorization_pinned_key_identity", "G0", "The executor pinned the identity point as the gate key; R = identity, S = 0 satisfies the cofactorless equation, so only G0 rejects it.",
         base_a, sig_id, check_block(IBKR, ACTION_MINIMAL, pub=ident))
    g_rj("authorization_signed_by_agent_key", "G1", "Signed by agent1 (an agent key) under the Authorization tags; the executor pins gate1.",
         base_a, sign_tagged(base_canon, authorization_hash, TAG_AUTHORIZATION_SIG, "agent1")[2])
    g_rj("authorization_signed_by_other_gate", "G1", "Signed by agent2's key standing in for another gate's key; the executor pins gate1.",
         base_a, sign_tagged(base_canon, authorization_hash, TAG_AUTHORIZATION_SIG, "agent2")[2])
    g_rj("authorization_signed_under_commitment_sig_tag", "G1", "gate1 signed edicta/v0/sig || authorization_hash (the agent signature tag).",
         base_a, sk(GATE_KEY).sign(signing_message(authorization_hash(base_canon), TAG_SIG)))
    g_rj("authorization_signed_under_receipt_sig_tag", "G1", "gate1 signed edicta/v0/receipt-sig || authorization_hash (the receipt signature tag).",
         base_a, sk(GATE_KEY).sign(signing_message(authorization_hash(base_canon), TAG_RECEIPT_SIG)))
    g_rj("authorization_wrong_hash_tag", "G1", "The Authorization bytes hashed under edicta/v0/receipt instead of edicta/v0/authorization.",
         base_a, sk(GATE_KEY).sign(signing_message(hashlib.sha256(tagged(TAG_RECEIPT) + base_canon).digest(), TAG_AUTHORIZATION_SIG)))
    g_rj("authorization_sig_raw_cbor", "G1", "Signature over the raw Authorization CBOR instead of the tagged message.",
         base_a, sk(GATE_KEY).sign(base_canon))
    g_rj("authorization_flipped_expires", "G1", "expires raised by one second after signing.",
         dict(base_a, expires=base_a["expires"] + 1), base_sig)
    agent_pub = gate_pub("agent1")
    minimal_sig = bytes.fromhex(m["signature_hex"])
    g_rj("authorization_reuses_commitment_signature", "G1",
         "The executor pins agent1 and the signature is agent1's signature over the minimal_lmt commitment. Different tags and hashes, so it must not verify.",
         base_a, minimal_sig, check_block(IBKR, ACTION_MINIMAL, pub=agent_pub))
    s_int = int.from_bytes(base_sig[32:], "little") + ED25519_L
    g_rj("authorization_sig_noncanonical_s", "G2", "S + L in place of S.", base_a, base_sig[:32] + s_int.to_bytes(32, "little"))

    # Executor checks on a correctly signed Authorization.
    def x_rj(cid, rule, desc, chk, expect):
        rj(cid, "X", rule, desc, base_signed, expect, base_a, chk)

    x_rj("authorization_foreign_gate_id", "X1", "The executor expects gate_id gate-paper-2.",
         check_block(IBKR, ACTION_MINIMAL, gate_id="gate-paper-2"), "ErrScopeMismatch")
    x_rj("authorization_action_empty", "X2", "The executor presents no action bytes.", check_block(IBKR, b""), "ErrActionSize")
    x_rj("authorization_action_too_large", "X2", f"The executor presents {MAX_ACTION_SIZE + 1} bytes (pattern {PATTERN}).",
         check_block(IBKR, pattern_bytes(PATTERN, MAX_ACTION_SIZE + 1)), "ErrActionSize")
    flipped = bytearray(ACTION_MINIMAL)
    flipped[-1] ^= 0x01
    x_rj("authorization_action_byte_flipped", "X3", "The bytes the executor is about to send differ in the last byte.",
         check_block(IBKR, bytes(flipped)), "ErrActionMismatch")
    x_rj("authorization_action_other_order", "X3", "The executor holds another order (qty 100001) than the one authorized.",
         check_block(IBKR, order_encode(dict(ORDER_MINIMAL, qty=100001))), "ErrActionMismatch")
    x_rj("authorization_action_other_type", "X3", "Right bytes, but the executor recomputes the hash under application/octet-stream.",
         check_block(TYPE_OCTETS, ACTION_MINIMAL), "ErrActionMismatch")
    x_rj("authorization_expired", "X4", "now + skew == expires.",
         check_block(IBKR, ACTION_MINIMAL, now=base_a["expires"] - 30), "ErrExpired")
    x_rj("authorization_expired_after", "X4", "now past expires.",
         check_block(IBKR, ACTION_MINIMAL, now=base_a["expires"] + 1), "ErrExpired")
    x_rj("authorization_expired_skew_0", "X4", "skew 0, now == expires.",
         check_block(IBKR, ACTION_MINIMAL, now=base_a["expires"], skew=0), "ErrExpired")

    return {"format": FORMAT, "revision": REVISION, "max_authorization_ttl_s": str(MAX_AUTHORIZATION_TTL),
            "gate": gate_to_json(GATE), "patterns": PATTERNS, "cases": cases, "reject": rejects}


def receipt_for(chash: bytes, rail_ref: str = IBKR_ORDER_ID, recorded_at: int = RECORDED_AT) -> dict:
    return {
        "version": 0,
        "commitment_hash": chash,
        "gate_id": GATE["gate_id"],
        "gate_pubkey": gate_pub(),
        "rail_ref": rail_ref,
        "recorded_at": recorded_at,
    }


def receipt_vectors(valid: list) -> dict:
    hashes = {v["id"]: bytes.fromhex(v["commitment_hash_hex"]) for v in valid}
    cases = []

    def add(cid, desc, ref, r):
        canon = encode(to_cbor(r, RECEIPT))
        rh, msg, sig = sign_tagged(canon, receipt_hash, TAG_RECEIPT_SIG)
        cases.append({
            "id": cid, "description": desc, "commitment_ref": ref, "signer": GATE_KEY,
            "input": receipt_to_json(r), "receipt_cbor_hex": canon.hex(), "receipt_hash_hex": rh.hex(),
            "signed_message_hex": msg.hex(), "signature_hex": sig.hex(),
            "signed_receipt_hex": signed_pair(canon, sig).hex(),
        })

    m = hashes["minimal_lmt"]
    add("receipt_minimal_lmt", "minimal_lmt: the integrator reported the IBKR order id 1370093239; the gate notarized it.",
        "minimal_lmt", receipt_for(m))
    add("receipt_fibre_small_payload", "fibre_small_payload (da = fibre).", "fibre_small_payload", receipt_for(hashes["fibre_small_payload"]))
    ref128 = (ID_ALPHABET * 2)[:128]
    add("receipt_rail_ref_max", "rail_ref of 128 characters covering the whole ID charset.", "minimal_lmt", receipt_for(m, rail_ref=ref128))
    add("receipt_rail_ref_tx_hash", "rail_ref holding a 64-character lowercase hex transaction hash, as an EVM integrator would report.",
        "action_json_bytes", receipt_for(hashes["action_json_bytes"], rail_ref=h("example tx").hex()))
    add("receipt_recorded_at_max", "recorded_at = 2^63-1, the largest allowed uint.", "minimal_lmt",
        receipt_for(m, recorded_at=(1 << 63) - 1))
    for c in cases:
        assert len(bytes.fromhex(c["signed_receipt_hex"])) <= MAX_RECEIPT_SIZE

    base_r = receipt_for(m)
    base_canon = encode(to_cbor(base_r, RECEIPT))
    _, _, base_sig = sign_tagged(base_canon, receipt_hash, TAG_RECEIPT_SIG)
    base_signed = signed_pair(base_canon, base_sig)
    rejects = []

    def rj(cid, stage, rule, desc, data: bytes, expect, r=None):
        case = {"id": cid, "stage": stage, "rule": rule, "description": desc,
                "signed_receipt_hex": data.hex(), "expect_error": expect}
        if r is not None:
            canon = encode(to_cbor(r, RECEIPT))
            case["input"] = receipt_to_json(r)
            case["receipt_cbor_hex"] = canon.hex()
            case["receipt_hash_hex"] = receipt_hash(canon).hex()
        rejects.append(case)

    def resign(inner: bytes) -> bytes:
        _, _, s = sign_tagged(inner, receipt_hash, TAG_RECEIPT_SIG)
        return signed_pair(inner, s)

    def raw_receipt(repl: dict, drop=()) -> bytes:
        mm = to_cbor(base_r, RECEIPT)
        mm.update(repl)
        for k in drop:
            mm.pop(k)
        return encode(mm)

    def signed_static(r: dict) -> bytes:
        return resign(encode(to_cbor(r, RECEIPT)))

    # Decoding.
    big = base_signed + bytes(MAX_RECEIPT_SIZE + 1 - len(base_signed))
    rj("receipt_too_large", "D", "D0", f"{MAX_RECEIPT_SIZE + 1} bytes: a valid receipt followed by zero bytes. Size is checked before parsing, so this is not ErrTrailingData.", big, "ErrTooLarge")
    rj("receipt_trailing_byte", "D", "D2", "A valid signed receipt followed by one zero byte.", base_signed + b"\x00", "ErrTrailingData")
    rj("receipt_unknown_key", "D", "D15", "Receipt key 9 (undefined) added.", resign(raw_receipt({9: 1})), "ErrUnknownKey")
    rj("receipt_retired_rail_key", "D", "D15", "Receipt carries key 5 (rail, retired in draft.9) = 1.", resign(raw_receipt({5: 1})), "ErrUnknownKey")
    rj("receipt_retired_path_key", "D", "D15", "Receipt carries key 7 (path, retired in draft.9; now in the Authorization) = 1.",
       resign(raw_receipt({7: 1})), "ErrUnknownKey")
    rj("signed_receipt_unknown_key", "D", "D15", "SignedReceipt key 3 (undefined) added.", encode({1: Raw(base_canon), 2: base_sig, 3: 0}), "ErrUnknownKey")
    rj("receipt_missing_rail_ref", "D", "D17", "Key 6 rail_ref absent.", resign(raw_receipt({}, drop=(6,))), "ErrMissingField")
    rj("receipt_missing_recorded_at", "D", "D17", "Key 8 recorded_at absent.", resign(raw_receipt({}, drop=(8,))), "ErrMissingField")
    rj("receipt_missing_signature", "D", "D17", "SignedReceipt without key 2.", encode({1: Raw(base_canon)}), "ErrMissingField")
    rj("receipt_rail_ref_bad_charset", "D", "D19", "rail_ref contains '#', outside the ID charset.", resign(raw_receipt({6: "1370093239#1"})), "ErrInvalidString")
    rj("receipt_rail_ref_empty", "D", "D18", "rail_ref is the empty string.", resign(raw_receipt({6: ""})), "ErrFieldSize")
    rj("receipt_rail_ref_129_chars", "D", "D18", "rail_ref of 129 characters.", resign(raw_receipt({6: "1" * 129})), "ErrFieldSize")
    rj("receipt_gate_id_unicode", "D", "D19", "gate_id contains U+03BF (Greek small omicron), a look-alike of 'o'.", resign(raw_receipt({3: "gate-paper-ο1"})), "ErrInvalidString")
    rj("receipt_commitment_hash_31_bytes", "D", "D18", "commitment_hash of 31 bytes.", resign(raw_receipt({2: m[:31]})), "ErrFieldSize")
    rj("receipt_gate_pubkey_33_bytes", "D", "D18", "gate_pubkey of 33 bytes.", resign(raw_receipt({4: base_r["gate_pubkey"] + b"\x00"})), "ErrFieldSize")
    rj("receipt_sig_63_bytes", "D", "D18", "Signature of 63 bytes.", encode({1: Raw(base_canon), 2: base_sig[:63]}), "ErrFieldSize")
    rj("receipt_recorded_at_tstr", "D", "D16", "recorded_at encoded as a text string.", resign(raw_receipt({8: str(RECORDED_AT)})), "ErrWrongType")
    rj("receipt_rail_ref_bstr", "D", "D16", "rail_ref encoded as a byte string.", resign(raw_receipt({6: IBKR_ORDER_ID.encode()})), "ErrWrongType")
    rj("receipt_recorded_at_nonminimal", "D", "D7", "recorded_at in a 9-byte head although it fits in 5.",
       resign(raw_receipt({8: Raw(bytes([0x1b]) + RECORDED_AT.to_bytes(8, "big"))})), "ErrNonMinimalInt")
    rj("receipt_recorded_at_float", "D", "D3", "recorded_at as a float64.",
       resign(raw_receipt({8: Raw(b"\xfb" + struct.pack(">d", float(RECORDED_AT)))})), "ErrFloat")
    items = sorted(to_cbor(base_r, RECEIPT).items())
    items[4], items[5] = items[5], items[4]
    rj("receipt_unsorted_map", "D", "D10", "Keys 6 and 8 swapped.", resign(encode(Pairs(tuple(items)))), "ErrUnsortedMap")
    env = bytes.fromhex(next(v for v in valid if v["id"] == "minimal_lmt")["envelope_hex"])
    rj("commitment_envelope_as_receipt", "D", "D16", "The minimal_lmt commitment envelope fed to the receipt decoder: key 2 is agent_id (tstr) where commitment_hash (bstr) is expected.", env, "ErrWrongType")
    a_canon, a_sig = AUTH_SIGNATURES["auth_minimal_lmt_da"]
    rj("authorization_as_receipt", "D", "D16", "The auth_minimal_lmt_da SignedAuthorization fed to the receipt decoder: key 3 is action_hash (bstr) where gate_id (tstr) is expected.",
       signed_pair(a_canon, a_sig), "ErrWrongType")

    # Static receipt checks, correctly signed.
    def s_rj(cid, rule, desc, r, expect):
        rj(cid, "S", rule, desc, signed_static(r), expect, r)

    s_rj("receipt_version_1", "R1", "version = 1.", dict(base_r, version=1), "ErrUnsupportedVersion")
    s_rj("receipt_recorded_at_2pow63", "R2", "recorded_at = 2^63.", dict(base_r, recorded_at=1 << 63), "ErrIntRange")
    s_rj("receipt_recorded_at_0", "R5", "recorded_at = 0.", dict(base_r, recorded_at=0), "ErrZeroValue")

    # Signature checks.
    def g_rj(cid, rule, desc, r, sig):
        canon = encode(to_cbor(r, RECEIPT))
        rj(cid, "G", rule, desc, signed_pair(canon, sig), "ErrInvalidPublicKey" if rule == "G0" else "ErrSignatureInvalid", r)

    ident = ed.encode(ed.IDENTITY)
    r_id = dict(base_r, gate_pubkey=ident)
    sig_id, forged = small_order_forgery(ident, signing_message(receipt_hash(encode(to_cbor(r_id, RECEIPT))), TAG_RECEIPT_SIG))
    assert forged
    g_rj("receipt_gate_pubkey_identity", "G0", "gate_pubkey is the identity point; R = identity, S = 0 satisfies the cofactorless equation, so only G0 rejects it.", r_id, sig_id)
    wrong_tag = sk(GATE_KEY).sign(signing_message(hashlib.sha256(tagged(TAG_COMMITMENT) + base_canon).digest(), TAG_RECEIPT_SIG))
    g_rj("receipt_wrong_hash_tag", "G1", "Signed over the receipt bytes hashed with the commitment tag instead of edicta/v0/receipt.", base_r, wrong_tag)
    g_rj("receipt_signed_under_commitment_sig_tag", "G1", "Signed over edicta/v0/sig || receipt_hash (the agent signature tag) instead of edicta/v0/receipt-sig || receipt_hash.",
         base_r, sk(GATE_KEY).sign(signing_message(receipt_hash(base_canon), TAG_SIG)))
    g_rj("receipt_signed_under_authorization_sig_tag", "G1", "Signed over edicta/v0/authorization-sig || receipt_hash (the Authorization signature tag).",
         base_r, sk(GATE_KEY).sign(signing_message(receipt_hash(base_canon), TAG_AUTHORIZATION_SIG)))
    g_rj("receipt_sig_raw_cbor", "G1", "Signature over the raw receipt CBOR instead of the tagged message.", base_r, sk(GATE_KEY).sign(base_canon))
    g_rj("receipt_sig_wrong_key", "G1", "Signed by agent1 while gate_pubkey is gate1.", base_r, sign_tagged(base_canon, receipt_hash, TAG_RECEIPT_SIG, "agent1")[2])
    g_rj("receipt_flipped_rail_ref", "G1", "rail_ref changed after signing (the signature is over rail_ref 1370093239).", dict(base_r, rail_ref="1370093238"), base_sig)
    agent_pub = gate_pub("agent1")
    minimal_sig = bytes.fromhex(next(v for v in valid if v["id"] == "minimal_lmt")["signature_hex"])
    g_rj("receipt_reuses_commitment_signature", "G1", "gate_pubkey = agent1 and the signature is agent1's signature over the minimal_lmt commitment. The receipt hash differs from the commitment hash, so it must not verify.",
         dict(base_r, gate_pubkey=agent_pub), minimal_sig)
    g_rj("receipt_reuses_authorization_signature", "G1", "The signature is gate1's signature over auth_minimal_lmt_da. Same key, other tags and hash, so it must not verify.",
         base_r, a_sig)
    s_int = int.from_bytes(base_sig[32:], "little") + ED25519_L
    g_rj("receipt_sig_noncanonical_s", "G2", "S + L in place of S.", base_r, base_sig[:32] + s_int.to_bytes(32, "little"))

    return {"format": FORMAT, "revision": REVISION, "gate": gate_to_json(GATE), "cases": cases, "reject": rejects}


def anchor_vectors() -> dict:
    """Signed-after-anchor, within-retention and registry-epoch checks. Expected values are written out
    from the boundary arithmetic and then cross-checked against edicta_v0."""
    b = T0 - 3000
    skew = PARAMS.skew_s
    k1 = [
        {"id": "k1_at_limit", "description": "issued_at + skew_s == block_time: accepted.", "issued_at": b - skew, "block_time": b, "skew_s": skew},
        {"id": "k1_one_second_early", "description": "issued_at + skew_s == block_time - 1.", "issued_at": b - skew - 1, "block_time": b, "skew_s": skew, "expect_error": "ErrIssuedBeforeAnchor"},
        {"id": "k1_skew_0_equal", "description": "skew_s = 0, issued_at == block_time: accepted.", "issued_at": b, "block_time": b, "skew_s": 0},
        {"id": "k1_skew_0_one_second_early", "description": "skew_s = 0, issued_at == block_time - 1.", "issued_at": b - 1, "block_time": b, "skew_s": 0, "expect_error": "ErrIssuedBeforeAnchor"},
        {"id": "k1_minimal_lmt", "description": "issued_at of minimal_lmt, signed 3000 s after the anchor block.", "issued_at": T0, "block_time": b, "skew_s": skew},
        {"id": "k1_block_time_u64_max", "description": "A block time of 2^64-1 (hostile header): rejected without overflow.", "issued_at": (1 << 63) - 1, "block_time": U64_MAX, "skew_s": 300, "expect_error": "ErrIssuedBeforeAnchor"},
    ]
    for c in k1:
        try:
            check_anchor_time(c["issued_at"], c["block_time"], c["skew_s"])
            got = None
        except Reject as e:
            got = e.sentinel
        assert got == c.get("expect_error"), c["id"]

    k2 = []

    def k2case(cid, desc, da, valid_until, block_time, expect_window, within, blob_r=None,
               latest=None, at_h=None, creation=None, error=None):
        c = {"id": cid, "description": desc, "da": da, "valid_until": valid_until, "block_time": block_time}
        if da == DA_CELESTIA_BLOB:
            c["blob_retention_s"] = blob_r
        else:
            c["fibre_retention_latest_s"] = latest
            if at_h is not None:
                c["fibre_retention_at_height_s"] = at_h
            c["creation_timestamp"] = creation
        if error is not None:
            c["expect"] = {"expect_error": error}
            try:
                retention_window(da, block_time, Params(latest, 14400, skew), latest, at_h, creation or 0)
            except Reject as e:
                assert e.sentinel == error, cid
            else:
                raise AssertionError(cid)
            k2.append(c)
            return
        exp = {"within": within}
        if expect_window is not None:
            r, start = expect_window
            exp.update({"r": r, "start": start, "margin": min(600, r // 8)})
        if within:
            exp["route"] = "da"
        elif da == DA_FIBRE:
            exp["expect_error"] = "ErrArchiveRecomputeUnsupported"
        else:
            exp["route"] = "archive"
        c["expect"] = exp
        p = Params(latest or 14400, blob_r or 14400, skew)
        w = retention_window(da, block_time, p, latest, at_h, creation or 0)
        assert (w is None) == (expect_window is None), cid
        if w is not None:
            assert w == expect_window and retention_margin(w[0]) == exp["margin"], cid
            assert within_retention(valid_until, *[w[1], w[0]]) == within, cid
        try:
            assert route(da, within) == exp.get("route"), cid
        except Reject as e:
            assert e.sentinel == exp.get("expect_error"), cid
        k2.append(c)

    r = 14400
    k2case("k2_blob_at_limit", "da = 2: valid_until + 600 == block_time + 14400. DA path.", 2, b + r - 600, b, (r, b), True, blob_r=r)
    k2case("k2_blob_one_second_over", "da = 2: one second past the limit. The DA path is skipped; archive with P1, P2, P3.", 2, b + r - 600 + 1, b, (r, b), False, blob_r=r)
    k2case("k2_blob_minimal_lmt", "da = 2: minimal_lmt valid_until, anchor 3000 s before issued_at.", 2, T0 + 900, b, (r, b), True, blob_r=r)
    k2case("k2_blob_u64_saturation", "da = 2: block_time + r exceeds 2^64-1; a saturating uint64 sum gives the exact verdict (K1 rejects such a block time first in the pipeline).", 2, (1 << 63) - 1, U64_MAX - 100, (r, U64_MAX - 100), True, blob_r=r)
    cr = b - 5
    k2case("k2_fibre_at_limit", "da = 1: start = min(block_time, creation_timestamp) = creation_timestamp; valid_until + 600 == start + 14400.", 1, cr + r - 600, b, (r, cr), True, latest=r, at_h=r, creation=cr)
    k2case("k2_fibre_one_second_over", "da = 1: one second past the limit; the archive path cannot recompute a Fibre commitment in v0.", 1, cr + r - 600 + 1, b, (r, cr), False, latest=r, at_h=r, creation=cr)
    k2case("k2_fibre_creation_after_block", "da = 1: creation_timestamp later than block_time; start = block_time.", 1, b + r - 600, b, (r, b), True, latest=r, at_h=r, creation=b + 10)
    k2case("k2_fibre_creation_unknown", "da = 1: creation_timestamp unknown (0); K2 is false.", 1, b + 600, b, None, False, latest=r, at_h=r, creation=0)
    k2case("k2_fibre_at_height_unreadable", "da = 1: retention at the anchor height cannot be read. The gate rejects and never substitutes the latest value.", 1, b + 600, b, None, False, latest=r, creation=cr, error="ErrRetentionUnavailable")
    k2case("k2_fibre_retention_lowered", "da = 1: latest 3600, at H 14400: r = 3600, margin 450; at the limit.", 1, cr + 3600 - 450, b, (3600, cr), True, latest=3600, at_h=r, creation=cr)
    k2case("k2_fibre_retention_lowered_over", "da = 1: as above, one second over.", 1, cr + 3600 - 450 + 1, b, (3600, cr), False, latest=3600, at_h=r, creation=cr)
    k2case("k2_fibre_retention_raised", "da = 1: latest 14400, at H 3600: r = 3600; at the limit.", 1, cr + 3600 - 450, b, (3600, cr), True, latest=r, at_h=3600, creation=cr)
    k2case("k2_fibre_governance_minimum", "da = 1: r = 600 (governance minimum), margin = 75; at the limit.", 1, cr + 600 - 75, b, (600, cr), True, latest=600, at_h=600, creation=cr)
    k2case("k2_fibre_governance_minimum_over", "da = 1: r = 600, one second over.", 1, cr + 600 - 75 + 1, b, (600, cr), False, latest=600, at_h=600, creation=cr)
    k2case("k2_margin_floor", "da = 2: r = 4799, margin = floor(4799 / 8) = 599 (below the 600 cap); at the limit.", 2, b + 4799 - 599, b, (4799, b), True, blob_r=4799)
    k2case("k2_margin_cap", "da = 2: r = 4800, margin = 600 (the cap); one second over.", 2, b + 4800 - 600 + 1, b, (4800, b), False, blob_r=4800)

    e0 = T0 - 86400
    epoch = [
        {"id": "epoch_one_second_after", "description": "issued_at == epoch + skew_s + 1: accepted.", "issued_at": e0 + skew + 1, "epoch": e0, "skew_s": skew},
        {"id": "epoch_at_limit", "description": "issued_at == epoch + skew_s: rejected (strict inequality).", "issued_at": e0 + skew, "epoch": e0, "skew_s": skew, "expect_error": "ErrBeforeRegistryEpoch"},
        {"id": "epoch_before", "description": "issued_at before the registry was created.", "issued_at": e0 - 1, "epoch": e0, "skew_s": skew, "expect_error": "ErrBeforeRegistryEpoch"},
        {"id": "epoch_skew_0", "description": "skew_s = 0, issued_at == epoch + 1: accepted.", "issued_at": e0 + 1, "epoch": e0, "skew_s": 0},
        {"id": "epoch_skew_0_equal", "description": "skew_s = 0, issued_at == epoch: rejected.", "issued_at": e0, "epoch": e0, "skew_s": 0, "expect_error": "ErrBeforeRegistryEpoch"},
        {"id": "epoch_u64_max", "description": "epoch = 2^64-1: epoch + skew_s saturates and every issued_at is rejected.", "issued_at": (1 << 63) - 1, "epoch": U64_MAX, "skew_s": skew, "expect_error": "ErrBeforeRegistryEpoch"},
    ]
    for c in epoch:
        try:
            check_registry_epoch(c["issued_at"], c["epoch"], c["skew_s"])
            got = None
        except Reject as e:
            got = e.sentinel
        assert got == c.get("expect_error"), c["id"]

    def js(o):
        if isinstance(o, bool) or isinstance(o, str):
            return o
        if isinstance(o, int):
            return str(o)
        if isinstance(o, dict):
            return {k: js(v) for k, v in o.items()}
        if isinstance(o, list):
            return [js(v) for v in o]
        return o

    return {"format": FORMAT, "margin_cap": "600", "k1": js(k1), "k2": js(k2), "epoch": js(epoch)}


def write(name: str, obj: dict):
    path = OUT / name
    path.write_text(json.dumps(obj, indent=2, ensure_ascii=True) + "\n")
    print(f"wrote {path}")


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    head_ = {"format": FORMAT, "revision": REVISION, "params": params_to_json(PARAMS), "gate": gate_to_json(GATE),
             "patterns": PATTERNS}
    valid = valid_cases()
    write("keys.json", {"format": FORMAT, "keys": KEYS})
    write("valid.json", dict(head_, cases=valid))
    write("reject.json", dict(head_, cases=reject_cases()))
    write("payload.json", payload_vectors())
    auth = authorization_vectors(valid)
    write("authorization.json", auth)
    write("receipt.json", receipt_vectors(valid))
    write("anchor.json", anchor_vectors())
    write("payload_blob.json", gen_payload_blob.build())


if __name__ == "__main__":
    main()
