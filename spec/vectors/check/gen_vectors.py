#!/usr/bin/env python3
"""Generates spec/vectors/v0/*.json. Deterministic: rerunning yields identical files.

Usage: python3 spec/vectors/check/gen_vectors.py [--out DIR]
Default output directory is spec/vectors/v0.
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
from prior_v0 import (ED25519_L, TAG_COMMITMENT, TAG_RECEIPT, TAG_SIG, Params,
                      commitment_hash, signing_message, tagged, to_cbor)
from vecjson import (commitment_to_json, gate_to_json, order_to_json,
                     params_to_json)

OUT = Path(__file__).resolve().parent.parent / "v0"
if "--out" in sys.argv:
    OUT = Path(sys.argv[sys.argv.index("--out") + 1]).resolve()
FORMAT = "prior-vectors/v0"

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
}

PARAMS = Params()
GATE = {"gate_id": "gate-paper-1", "rail": 1, "account": "DU1234567"}
T0 = 1791000000
NOW = T0 + 60


def h(label: str) -> bytes:
    return hashlib.sha256(label.encode()).digest()


def sk(name: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(KEYS[name]["seed_hex"]))


NAMESPACE = bytes(19) + b"prior/dc01"  # version 0, 18 zero bytes, 10-byte sub-id
# Recorder account: raw 20-byte address (bech32-decoded MsgPayForBlobs.signer).
SIGNER = h("prior/v0 test recorder account")[:20]


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


SALT = h("prior/v0 test salt")
PLAINTEXT = b'{"decision":"buy","policy":"dca-weekly","model":"example-model"}'
BLOB = payload_blob()


def base() -> dict:
    """minimal_lmt: celestia_blob locator, no optional fields."""
    return {
        "version": 0,
        "agent_id": "dca-agent-1",
        "agent_pubkey": bytes.fromhex(KEYS["agent1"]["public_key_hex"]),
        "nonce": h("nonce-minimal")[:16],
        "issued_at": T0,
        "valid_until": T0 + 900,
        "scope": {"gate_id": "gate-paper-1", "rail": 1, "account": "DU1234567"},
        "action": {
            "kind": "ibkr.order.v0",
            "params": {
                "account": "DU1234567",
                "conid": 265598,
                "side": 1,
                "qty": 100000,
                "order_type": 1,
                "limit_price": 19050000000,
                "currency": "USD",
                "tif": 1,
            },
        },
        "constraints": {"max_notional": 200000000000},
        "payload_ref": {"da": 2, "namespace": NAMESPACE, "commitment": h("share-commitment-minimal"), "height": 4200000,
                        "signer": SIGNER},
        "ciphertext_hash": hashlib.sha256(BLOB).digest(),
        "plaintext_hash": hashlib.sha256(SALT + PLAINTEXT).digest(),
        "payload_size": len(BLOB),
    }


def full() -> dict:
    c = base()
    c["nonce"] = h("nonce-full")[:16]
    c["action"]["params"].update({"symbol": "AAPL", "tif": 2})
    c["constraints"].update({"price_bound": 19100000000, "deadline": T0 + 600})
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


def valid_cases() -> list:
    out = []

    def add(cid, desc, c, now=NOW, params=None, request=None):
        case = {"id": cid, "description": desc}
        case.update(signed_case(c))
        case["now"] = str(now)
        if params is not None:
            case["params"] = params_to_json(params)
        case["request"] = order_to_json(request if request is not None else c["action"]["params"])
        out.append(case)

    add("minimal_lmt", "No optional fields; da=celestia_blob; payload is ciphertext_hash_small_blob in payload.json.", base())
    add("full_ibkr_order", "da=fibre; every optional field allowed for rail ibkr is present (symbol, price_bound, deadline). chain_id is forbidden for ibkr.", full())

    c = mod(base(), "nonce", h("nonce-sell")[:16])
    c["action"]["params"].update({"side": 2, "limit_price": 19500000000})
    c["constraints"]["price_bound"] = 19400000000
    add("sell_with_bound", "SELL requires limit_price >= price_bound.", c)

    c = mod(base(), "nonce", h("nonce-notional")[:16])
    c["constraints"]["max_notional"] = 100000 * 19050000000 // 10000
    add("notional_exact_equal", "qty * limit_price == max_notional * 10^4 is accepted.", c)

    c = mod(base(), "valid_until", T0 + 3600)
    add("ttl_exactly_max", "TTL == MaxTTL(da) == min(3600, 14400/4).", c)

    c = mod(full(), "constraints.deadline", T0 + 900)
    c["valid_until"] = T0 + 900
    add("deadline_eq_valid_until", "deadline == valid_until is allowed; expiry is the deadline.", c)

    c = mod(full(), "payload_size", 1024)
    add("fibre_small_payload", "Q9: da=fibre with payload_size 1024 is accepted; the 256 KiB split is a Recorder routing rule.", c)

    c = mod(base(), "payload_size", 262144)
    add("blob_large_payload", "Q9: da=celestia_blob with payload_size 262144 is accepted.", c)

    c = mod(base(), "issued_at", NOW + 30)
    c["valid_until"] = NOW + 930
    add("issued_at_within_skew", "issued_at == now + skew is accepted.", c)

    c = full()
    req = dict(c["action"]["params"])
    req["symbol"] = "NOT-AAPL"
    add("symbol_ignored_in_action_match", "Same as full_ibkr_order; the request carries a different symbol, which is informational only.", c, request=req)

    c = mod(base(), "nonce", h("nonce-small-ints")[:16])
    c["action"]["params"].update({"conid": 23, "qty": 24, "limit_price": 255})
    c["constraints"]["max_notional"] = 256
    c["payload_ref"]["height"] = 65535
    c["payload_size"] = 65536
    add("int_head_widths", "Integer heads of every width: 23 (1 byte), 24 and 255 (2 bytes), 256 and 65535 (3 bytes), 65536 and issued_at (5 bytes).", c)

    c = mod(base(), "nonce", h("nonce-max-ints")[:16])
    c["action"]["params"].update({"conid": (1 << 63) - 1, "qty": 1, "limit_price": 1})
    c["constraints"]["max_notional"] = (1 << 63) - 1
    c["payload_ref"]["height"] = (1 << 63) - 1
    c["payload_size"] = 1 << 27
    add("max_int_values", "Largest allowed values: 2^63-1 in 9-byte heads, payload_size == 2^27.", c)

    c = mod(full(), "valid_until", T0 + 150)
    c["constraints"]["deadline"] = T0 + 150
    add("ttl_max_at_601s_retention", "fibre_retention_s=601: MaxTTL = floor(601/4) = 150; TTL 150 is accepted.", c, params=Params(601, 14400, 30))
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


def params_with(c: dict, repl: dict) -> bytes:
    m = to_cbor(c)
    m[8][2].update(repl)
    return encode(m)


def reject_cases() -> list:
    out = []
    b = base()
    canon = encode(to_cbor(b))
    _, _, sig = sign_canon(canon)
    good = envelope(canon, sig)

    # Stage D: encoding and schema.
    out.append(d_case("too_large", "D0", "2177 bytes: a valid envelope padded with zero bytes. The size check runs before any parsing.",
                      good + bytes(2177 - len(good)), "ErrTooLarge"))
    out.append(d_case("truncated", "D1", "Valid envelope with its last byte removed.", good[:-1], "ErrMalformed"))
    out.append(d_case("reserved_additional_info", "D1", "issued_at head uses reserved additional info 28 (0x1c).",
                      resigned(commitment_with(b, {5: Raw(b"\x1c")})), "ErrMalformed"))
    out.append(d_case("trailing_byte", "D2", "Valid envelope followed by one 0x00 byte.", good + b"\x00", "ErrTrailingData"))
    out.append(d_case("float_qty", "D3", "qty encoded as float64 10.0 (0xfb).",
                      resigned(params_with(b, {5: Raw(b"\xfb" + struct.pack(">d", 10.0))})), "ErrFloat"))
    out.append(d_case("float16_tif", "D3", "tif encoded as float16 1.0 (0xf93c00).",
                      resigned(params_with(b, {9: Raw(b"\xf9\x3c\x00")})), "ErrFloat"))
    m = to_cbor(b)
    m[8][2][3] = Raw(b"\xf6")
    out.append(d_case("null_symbol", "D4", "Optional symbol encoded as null instead of being absent.", resigned(encode(m)), "ErrSimpleValue"))
    out.append(d_case("true_side", "D4", "side encoded as true (0xf5).",
                      resigned(params_with(b, {4: Raw(b"\xf5")})), "ErrSimpleValue"))
    out.append(d_case("tag_bignum_qty", "D5", "qty encoded as tag 2 bignum h'0186a0'.",
                      resigned(params_with(b, {5: Raw(b"\xc2\x43\x01\x86\xa0")})), "ErrTag"))
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
    out.append(d_case("deep_nesting", "D8", "symbol replaced by the map {1: 0}, a container at depth 5.",
                      resigned(params_with(b, {3: {1: 0}})), "ErrNestingTooDeep"))
    m = to_cbor(b)
    for k in (14, 15, 16, 17):
        m[k] = 0
    out.append(d_case("map_17_pairs", "D9", "Commitment map with 17 pairs (13 known keys plus 14..17).",
                      resigned(encode(m)), "ErrTooLarge"))
    pairs = list(items)
    pairs[11], pairs[12] = pairs[12], pairs[11]
    out.append(d_case("unsorted_map", "D10", "Top-level keys 12 and 13 swapped.", resigned(encode(Pairs(tuple(pairs)))), "ErrUnsortedMap"))
    pairs = list(items) + [(13, b["payload_size"])]
    out.append(d_case("dup_key", "D11", "Top-level key 13 appears twice with the same value.", resigned(encode(Pairs(tuple(pairs)))), "ErrDuplicateKey"))
    pairs = list(items) + [("x", 0)]
    out.append(d_case("tstr_key", "D12", "Commitment map gains a text-string key \"x\".", resigned(encode(Pairs(tuple(pairs)))), "ErrKeyType"))
    out.append(d_case("invalid_utf8", "D13", "agent_id is a text string containing the byte 0xff.",
                      resigned(commitment_with(b, {2: Raw(b"\x6b" + b"dca-agent-\xff")})), "ErrInvalidString"))

    filler = 2048 - len(canon) + 1
    m = to_cbor(b)
    m[8][2][3] = Raw(head(3, filler + 30) + b"A" * (filler + 30))
    big = encode(m)
    big_env = resigned(big)
    assert len(big) > 2048 and len(big_env) <= 2176, (len(big), len(big_env))
    out.append(d_case("commitment_too_large", "D14", f"Commitment of {len(big)} bytes (symbol of {filler + 30} chars) in an envelope of {len(big_env)} bytes.",
                      big_env, "ErrTooLarge"))

    out.append(d_case("unknown_top_key", "D15", "Commitment has an extra key 14.", resigned(commitment_with(b, {14: 0})), "ErrUnknownKey"))
    out.append(d_case("unknown_param_key", "D15", "ibkr.order.v0 params have an extra key 10.", resigned(params_with(b, {10: 0})), "ErrUnknownKey"))
    m = to_cbor(b)
    m[10][6] = 0
    out.append(d_case("unknown_payload_ref_key", "D15", "payload_ref has an extra key 6.", resigned(encode(m)), "ErrUnknownKey"))
    f = full()
    m = to_cbor(f)
    m[10][5] = SIGNER
    out.append(d_case("signer_on_fibre", "D15", "da=fibre locator carries payload_ref key 5 (signer), which is defined only for celestia_blob.",
                      resigned(encode(m)), "ErrUnknownKey"))
    out.append(d_case("unknown_envelope_key", "D15", "Envelope has an extra key 3.", encode({1: Raw(canon), 2: sig, 3: 0}), "ErrUnknownKey"))
    out.append(d_case("nint_qty", "D16", "qty encoded as the negative integer -100000.",
                      resigned(params_with(b, {5: -100000})), "ErrWrongType"))
    out.append(d_case("bstr_for_tstr", "D16", "agent_id encoded as a byte string.",
                      resigned(commitment_with(b, {2: b"dca-agent-1"})), "ErrWrongType"))
    m = to_cbor(b)
    m[7] = ["gate-paper-1", 1, "DU1234567"]
    out.append(d_case("array_for_scope", "D16", "scope encoded as an array.", resigned(encode(m)), "ErrWrongType"))
    m = to_cbor(b)
    m[10][5] = "celestia1" + "q" * 38
    out.append(d_case("signer_bech32_tstr", "D16", "payload_ref.signer given as a bech32 text string instead of the raw 20-byte address.",
                      resigned(encode(m)), "ErrWrongType"))
    out.append(d_case("missing_nonce", "D17", "Top-level key 4 absent.", resigned(encode({k: v for k, v in to_cbor(b).items() if k != 4})), "ErrMissingField"))
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
    m = to_cbor(b)
    m[10][2] = NAMESPACE[:28]
    out.append(d_case("namespace_28_bytes", "D18", "namespace of 28 bytes.", resigned(encode(m)), "ErrFieldSize"))
    m = to_cbor(b)
    m[10][3] = h("share-commitment-minimal")[:31]
    out.append(d_case("share_commitment_31_bytes", "D18", "da=celestia_blob with a 31-byte share commitment.", resigned(encode(m)), "ErrFieldSize"))
    f = full()
    m = to_cbor(f)
    m[10][3] = b"\x00" + f["payload_ref"]["commitment"]
    out.append(d_case("fibre_commitment_33_bytes", "D18", "da=fibre with a 33-byte Fibre BlobID (version byte || commitment) instead of the 32-byte commitment.",
                      resigned(encode(m)), "ErrFieldSize"))
    m = to_cbor(b)
    m[10][5] = SIGNER[:19]
    out.append(d_case("signer_19_bytes", "D18", "da=celestia_blob with a 19-byte signer.", resigned(encode(m)), "ErrFieldSize"))
    m = to_cbor(b)
    m[10][5] = h("prior/v0 test 32-byte account")
    out.append(d_case("signer_32_bytes", "D18", "da=celestia_blob with a 32-byte address (for example a module or ICA account); share version 1 requires exactly 20 bytes.",
                      resigned(encode(m)), "ErrFieldSize"))
    out.append(d_case("agent_id_empty", "D18", "agent_id is the empty string.", resigned(commitment_with(b, {2: ""})), "ErrFieldSize"))
    out.append(d_case("agent_id_65_chars", "D18", "agent_id of 65 characters.", resigned(commitment_with(b, {2: "a" * 65})), "ErrFieldSize"))
    out.append(d_case("currency_4_chars", "D18", "currency \"USDT\".", resigned(params_with(b, {8: "USDT"})), "ErrFieldSize"))
    m = to_cbor(b)
    m[7][1] = "gate-paper-\u03bf1"
    out.append(d_case("gate_id_unicode", "D19", "gate_id contains U+03BF (Greek small omicron), a look-alike of 'o'.", resigned(encode(m)), "ErrInvalidString"))
    out.append(d_case("currency_lowercase", "D19", "currency \"usd\".", resigned(params_with(b, {8: "usd"})), "ErrInvalidString"))
    out.append(d_case("symbol_control_char", "D19", "symbol \"AAPL\\n\" contains a control character.", resigned(params_with(b, {3: "AAPL\n"})), "ErrInvalidString"))
    m = to_cbor(b)
    m[8][1] = "ibkr.order.v1"
    out.append(d_case("kind_unknown", "D20", "action.kind \"ibkr.order.v1\"; params cannot be decoded against any schema.", resigned(encode(m)), "ErrUnsupportedActionKind"))

    # Stages S, G, T, C, A: a schema-valid commitment with exactly one defect, correctly signed.
    def s_case(cid, stage, rule, desc, c, expect, now=NOW, params=None, gate=None, request=None, signer="agent1"):
        case = {"id": cid, "stage": stage, "rule": rule, "description": desc}
        case.update(signed_case(c, signer))
        case["now"] = str(now)
        if params is not None:
            case["params"] = params_to_json(params)
        if gate is not None:
            case["gate"] = gate_to_json(gate)
        if request is not None:
            case["request"] = order_to_json(request)
        case["expect_error"] = expect
        out.append(case)
        return case

    s_case("version_1", "S", "S1", "version 1.", mod(b, "version", 1), "ErrUnsupportedVersion")
    c = mod(b, "action.params.qty", 1 << 63)
    s_case("qty_2pow63", "S", "S2", "qty = 2^63 (9-byte head 0x1b8000000000000000).", c, "ErrIntRange")
    s_case("side_0", "S", "S3", "side 0.", mod(b, "action.params.side", 0), "ErrInvalidEnum")
    s_case("side_256", "S", "S3", "side 256: enums decode at uint64 width, so this is an enum error, not a decode error.", mod(b, "action.params.side", 256), "ErrInvalidEnum")
    s_case("tif_9", "S", "S3", "tif 9.", mod(b, "action.params.tif", 9), "ErrInvalidEnum")
    s_case("da_0", "S", "S3", "da 0.", mod(b, "payload_ref.da", 0), "ErrInvalidEnum")
    s_case("da_3", "S", "S3", "da 3.", mod(b, "payload_ref.da", 3), "ErrInvalidEnum")
    s_case("rail_0", "S", "S3", "rail 0.", mod(b, "scope.rail", 0), "ErrInvalidEnum")
    s_case("rail_2", "S", "S4", "rail 2 (not defined in v0).", mod(b, "scope.rail", 2), "ErrUnsupportedRail")
    c = mod(b, "action.params.order_type", 2)
    c = mod(c, "action.params.limit_price", None)
    s_case("mkt_order", "S", "S5", "order_type MKT (2) without limit_price.", c, "ErrUnsupportedOrderType")
    s_case("qty_0", "S", "S6", "qty 0.", mod(b, "action.params.qty", 0), "ErrZeroValue")
    s_case("height_0", "S", "S6", "payload_ref.height 0.", mod(b, "payload_ref.height", 0), "ErrZeroValue")
    s_case("payload_size_0", "S", "S6", "payload_size 0.", mod(b, "payload_size", 0), "ErrZeroValue")
    s_case("payload_size_2pow27_plus1", "S", "S7", "payload_size 2^27 + 1.", mod(b, "payload_size", (1 << 27) + 1), "ErrPayloadTooLarge")
    s_case("namespace_version_1", "S", "S8", "Namespace version byte 1.", mod(b, "payload_ref.namespace", b"\x01" + NAMESPACE[1:]), "ErrInvalidNamespace")
    s_case("namespace_nonzero_prefix", "S", "S8", "Version 0 namespace whose 18-byte id prefix is not all zero.",
           mod(b, "payload_ref.namespace", b"\x00\x01" + NAMESPACE[2:]), "ErrInvalidNamespace")
    s_case("namespace_reserved", "S", "S8", "Primary reserved namespace 0x00..0004 (PayForBlob).",
           mod(b, "payload_ref.namespace", bytes(28) + b"\x04"), "ErrInvalidNamespace")
    s_case("lmt_no_price", "S", "S9", "LMT order without limit_price.", mod(b, "action.params.limit_price", None), "ErrLimitPrice")
    c = mod(b, "action.params.account", "DU7654321")
    s_case("account_mismatch", "S", "S10", "scope.account DU1234567, params.account DU7654321.", c, "ErrAccountMismatch")
    s_case("chain_id_on_ibkr", "S", "S11", "scope.chain_id present on rail ibkr.", mod(b, "scope.chain_id", "celestia"), "ErrChainIDRule")
    s_case("valid_until_eq_issued", "S", "S12", "valid_until == issued_at.", mod(b, "valid_until", T0), "ErrTimeOrder")
    s_case("valid_until_lt_issued", "S", "S12", "valid_until < issued_at.", mod(b, "valid_until", T0 - 1), "ErrTimeOrder")
    s_case("deadline_after_valid_until", "S", "S13", "deadline == valid_until + 1.", mod(b, "constraints.deadline", T0 + 901), "ErrDeadlineRange")
    s_case("deadline_eq_issued", "S", "S13", "deadline == issued_at.", mod(b, "constraints.deadline", T0), "ErrDeadlineRange")
    s_case("ttl_3601", "S", "S14", "TTL 3601 with default params (MaxTTL 3600).", mod(b, "valid_until", T0 + 3601), "ErrTTLTooLong")
    c = mod(full(), "nonce", h("nonce-ttl-gov")[:16])
    c["constraints"].pop("deadline")
    s_case("ttl_ok_at_4h_rejected_at_10m", "S", "S14",
           "da=fibre, TTL 900. Valid at fibre_retention_s=14400; here retention was lowered to 600 (MaxTTL 150) and is read at check time.",
           c, "ErrTTLTooLong", params=Params(600, 14400, 30))
    c = mod(full(), "valid_until", T0 + 151)
    c["constraints"]["deadline"] = T0 + 151
    s_case("ttl_floor_division", "S", "S14", "fibre_retention_s=601: MaxTTL = floor(601/4) = 150; TTL 151 is rejected.",
           c, "ErrTTLTooLong", params=Params(601, 14400, 30))
    s_case("buy_above_bound", "S", "S15", "BUY with limit_price > price_bound.", mod(b, "constraints.price_bound", 19049999999), "ErrPriceBound")
    c = mod(b, "action.params.side", 2)
    c["constraints"]["price_bound"] = 19050000001
    s_case("sell_below_bound", "S", "S15", "SELL with limit_price < price_bound.", c, "ErrPriceBound")
    s_case("notional_over", "S", "S16", "qty * limit_price == max_notional * 10^4 + 10^4.",
           mod(b, "constraints.max_notional", 100000 * 19050000000 // 10000 - 1), "ErrNotionalExceeded")
    c = mod(b, "action.params.qty", 1 << 32)
    c["action"]["params"]["limit_price"] = 1 << 32
    c["constraints"]["max_notional"] = 1
    s_case("notional_uint64_wrap", "S", "S16", "qty = limit_price = 2^32: the product is 2^64, which wraps to 0 in uint64 arithmetic.",
           c, "ErrNotionalExceeded")

    for cid, desc, enc in g0_keys():
        small = (pt := ed.decode(enc, strict=False)) is not None and ed.is_small_order(pt)
        for i in range(64):  # vary the nonce until a forgery exists (expected within a few tries)
            c = mod(b, "agent_pubkey", enc)
            c["nonce"] = h(f"nonce-{cid}-{i}")[:16]
            canon_c = encode(to_cbor(c))
            hh = commitment_hash(canon_c)
            sig, forged = small_order_forgery(enc, signing_message(hh))
            if forged or not small:
                break
        assert forged == small, cid
        note = (" The signature R || S=0 satisfies the cofactorless equation [S]B = R + [k]A for this A, so a verifier without G0 accepts it."
                if forged else " Signature R=identity, S=0.")
        out.append({"id": cid, "stage": "G", "rule": "G0", "description": desc + note, "input": commitment_to_json(c),
                    "commitment_cbor_hex": canon_c.hex(), "commitment_hash_hex": hh.hex(),
                    "envelope_hex": envelope(canon_c, sig).hex(), "now": str(NOW), "expect_error": "ErrInvalidPublicKey"})

    def g_case(cid, rule, desc, c, msg_fn, sig_fn=None):
        canon_c = encode(to_cbor(c))
        hh = commitment_hash(canon_c)
        s = sk("agent1").sign(msg_fn(canon_c, hh))
        if sig_fn:
            s = sig_fn(s)
        out.append({"id": cid, "stage": "G", "rule": rule, "description": desc, "input": commitment_to_json(c),
                    "commitment_cbor_hex": canon_c.hex(), "commitment_hash_hex": hh.hex(),
                    "envelope_hex": envelope(canon_c, s).hex(), "now": str(NOW), "expect_error": "ErrSignatureInvalid"})

    g_case("wrong_sig_tag", "G1", "Signed message uses the receipt tag: 0x10 || \"prior/v0/receipt\" || commitment_hash.",
           b, lambda cc, hh: tagged(TAG_RECEIPT) + hh)
    g_case("sig_tag_no_length_prefix", "G1", "Signed message omits the tag length byte: \"prior/v0/sig\" || commitment_hash.",
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
    flipped = mod(b, "action.params.qty", 100001)
    fcanon = encode(to_cbor(flipped))
    out.append({"id": "flipped_field", "stage": "G", "rule": "G1",
                "description": "qty changed from 100000 to 100001 after signing; the signature is over minimal_lmt.",
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
    c = mod(b, "constraints.deadline", T0 + 300)
    s_case("expired_by_deadline", "T", "T2", "now + skew >= deadline while valid_until is still in the future.", c, "ErrExpired", now=T0 + 400)

    s_case("foreign_gate_id", "C", "C1", "Gate id differs.", b, "ErrScopeMismatch", gate=dict(GATE, gate_id="gate-paper-2"))
    c = mod(b, "scope.account", "DU7654321")
    c["action"]["params"]["account"] = "DU7654321"
    s_case("foreign_account", "C", "C1", "Commitment scoped to account DU7654321; the gate serves DU1234567.", c, "ErrScopeMismatch")
    s_case("foreign_chain_id_on_gate", "C", "C1", "The gate is configured with a chain_id; the commitment has none.", b, "ErrScopeMismatch",
           gate=dict(GATE, chain_id="celestia"))

    req = dict(b["action"]["params"], qty=100001)
    s_case("action_qty_differs", "A", "A1", "Requested qty differs from the committed qty.", b, "ErrActionMismatch", request=req)
    req = dict(b["action"]["params"], limit_price=19050000001)
    s_case("action_limit_price_differs", "A", "A1", "Requested limit_price differs by one unit.", b, "ErrActionMismatch", request=req)
    req = dict(b["action"]["params"], symbol="AAPL")
    req.pop("limit_price")
    s_case("action_limit_price_absent", "A", "A1", "Request omits limit_price.", b, "ErrActionMismatch", request=req)
    return out


def g0_keys() -> list:
    """(id, description, 32-byte agent_pubkey) for rule G0."""
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
    """Signature that only a cofactored verifier accepts (spec 5, G1). Uses the
    signer's secret scalar a (RFC 8032 5.1.5) and a deterministic r:
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
    r = int.from_bytes(hashlib.sha512(b"prior/v0 test torsion-R nonce" + msg).digest(), "little") % ed.L
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


def write(name: str, obj: dict):
    path = OUT / name
    path.write_text(json.dumps(obj, indent=2, ensure_ascii=True) + "\n")
    print(f"wrote {path}")


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    head_ = {"format": FORMAT, "params": params_to_json(PARAMS), "gate": gate_to_json(GATE)}
    write("keys.json", {"format": FORMAT, "keys": KEYS})
    write("valid.json", dict(head_, cases=valid_cases()))
    write("reject.json", dict(head_, cases=reject_cases()))
    write("payload.json", payload_vectors())


if __name__ == "__main__":
    main()
