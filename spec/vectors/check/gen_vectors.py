#!/usr/bin/env python3
"""Generates the core vectors (v1-draft.5) under spec/vectors/v1 and spec/vectors/keys.json. Deterministic.

Usage: python3 spec/vectors/check/gen_vectors.py [--out DIR]
Writes valid.json, reject.json, authorization.json, receipt.json, record_request.json, payload.json,
payload_blob.json (gen_payload_blob.py), limits.json, anchor.json, action.json and gate.json under
the output directory, and keys.json one level up. archive.json and verify.json are written by
gen_archive.py. da/blob_commit.json comes from spec/vectors/tools/dacommit-gen.
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
import edicta as E
import edicta_payload as pv
import gen_payload_blob
from cbor_strict import Pairs, Raw, encode, head
from edicta import (AUTHORIZATION, COMMITMENT, DA_CELESTIA_BLOB, DA_FIBRE, ED25519_L, MAX_ACTION_SIZE,
                    MAX_AUTHORIZATION_SIZE, MAX_RECEIPT_SIZE, RECEIPT, TAG_ACTION, TAG_AUTHORIZATION_SIG,
                    TAG_COMMITMENT, TAG_RECEIPT, TAG_RECEIPT_SIG, TAG_RECORD_REQUEST, TAG_SIG, U64_MAX,
                    AuthorizationCheck, Params, Reject, action_hash, action_preimage_prefix, authorization_expires,
                    authorization_hash, check_anchor_time, check_registry_epoch, commitment_hash, receipt_hash,
                    record_message, retention_margin, retention_window, route, signing_message, tagged, to_cbor,
                    verify_authorization, verify_record_request, within_retention)
from profile_dca_agent import ACTION_TYPE_IBKR_ORDER_V0 as IBKR, order_encode
from vecjson import PATTERNS, _conv, gate_to_json, params_to_json, pattern_bytes

OUT = Path(__file__).resolve().parent.parent / "v1"
if "--out" in sys.argv:
    OUT = Path(sys.argv[sys.argv.index("--out") + 1]).resolve()
KEYS_OUT = Path(__file__).resolve().parent.parent / "keys.json"
FORMAT = "edicta-vectors/v1"
REVISION = "v1-draft.5"
# A file carries the revision of its last content change.
REVISIONS = {"limits.json": "v1-draft.4", "gate.json": "v1-draft.4"}
MANDATE_FILE = Path(__file__).resolve().parent.parent / "policy" / "mandate.json"

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

# Executor keys live in record_request.json, so keys.json stays as it was.
EXECUTOR_KEYS = {
    "executor1": {
        "source": "RFC 8032 section 7.1 TEST SHA(abc)",
        "seed_hex": "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42",
        "public_key_hex": "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf",
        "kat_message_hex": hashlib.sha512(b"abc").hexdigest(),
        "kat_signature_hex": "dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b58909351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704",
    },
    "executor2": {
        "source": "seed = SHA-256(\"edicta/v0 test executor2\")",
        "seed_hex": hashlib.sha256(b"edicta/v0 test executor2").hexdigest(),
    },
}
EXECUTOR_KEYS["executor2"]["public_key_hex"] = Ed25519PrivateKey.from_private_bytes(
    bytes.fromhex(EXECUTOR_KEYS["executor2"]["seed_hex"])).public_key().public_bytes_raw().hex()
KEYS_ALL = dict(KEYS, **EXECUTOR_KEYS)

PARAMS = Params()
T0 = 1791000000
NOW = T0 + 60
H0_FIBRE = 4200123
H0_BLOB = 4200000

TYPE_JSON = "application/json"
TYPE_OCTETS = "application/octet-stream"
TYPE_128 = "application/vnd.edicta.test." + "a" * 95 + "+cbor"
assert len(TYPE_128) == 128
TYPE_NOT_ALLOWED = "application/vnd.example.evm.tx.v0+rlp"
GID = "gate-paper-1"
GATE = {"gate_id": GID, "action_types": [IBKR, TYPE_JSON, TYPE_OCTETS, TYPE_128]}
PATTERN = "affine-7-3"
PLACEHOLDER = ("Placeholder: SHA-256 of a fixed label, not the DA commitment of any blob. The commitment "
               "bytes and hashes of this vector are normative; the value is not a real anchor.")


def h(label: str) -> bytes:
    return hashlib.sha256(label.encode()).digest()


def sk(name: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(KEYS_ALL[name]["seed_hex"]))


def pub(name: str) -> bytes:
    return bytes.fromhex(KEYS_ALL[name]["public_key_hex"])


NAMESPACE = bytes(19) + b"edicta/d01"  # version 0, 18 zero bytes, 10-byte sub-id
# Recorder account: raw 20-byte address (bech32-decoded MsgPayForBlobs.signer).
SIGNER = h("edicta/v0 test recorder account")[:20]


def payload_blob() -> bytes:
    """Dummy bytes in the shape of a payload blob (two wrapped-key entries, version field 0, label-derived
    keys and ciphertext). Stage P only hashes and measures the blob; nobody opens this one, and a reader
    that decoded it would refuse its version."""
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

# The dogfood action: an IBKR order in the dca-agent profile encoding. The core treats it as opaque
# bytes of type IBKR.
ORDER_MINIMAL = {"account": "DU1234567", "conid": 265598, "side": 1, "qty": 100000, "order_type": 1,
                 "limit_price": 19050000000, "currency": "USD", "tif": 1}
ACTION_MINIMAL = order_encode(ORDER_MINIMAL)
ACTION = ACTION_MINIMAL
ACTION_JSON = b'{"op":"transfer","to":"acct-42","amount":"10.00","currency":"USD"}'
ACTION_MAX = pattern_bytes(PATTERN, MAX_ACTION_SIZE)
MAX_AUTH_TTL = 300
MAX_AUTHORIZATION_TTL = MAX_AUTH_TTL


def salt_of(label: str) -> bytes:
    """Fixed action salt of a vector, from a label: SHA-256("action-salt/" + label)."""
    return h("action-salt/" + label)


def mandate_ref() -> bytes:
    """mandate_hash of policy mandate.json case m_full (gate gate-paper-1)."""
    cases = json.loads(MANDATE_FILE.read_text())["cases"]
    return bytes.fromhex(next(c for c in cases if c["id"] == "m_full")["mandate_hash_hex"])


def cj(c: dict) -> dict:
    return _conv(c, COMMITMENT, True)


def aj(a: dict) -> dict:
    return _conv(a, AUTHORIZATION, True)


def salted(c: dict, label: str, action_type: str = IBKR, action: bytes = ACTION) -> dict:
    c = copy.deepcopy(c)
    c["action"] = {"type": action_type, "hash": action_hash(action_type, salt_of(label), action)}
    c["_salt_label"] = label
    return c


def strip(c: dict) -> dict:
    return {k: v for k, v in c.items() if not k.startswith("_")}


def base() -> dict:
    """minimal_lmt: celestia_blob locator, the minimal IBKR order as its action."""
    return salted({
        "version": 1,
        "agent_id": "dca-agent-1",
        "agent_pubkey": pub("agent1"),
        "nonce": h("nonce-minimal")[:16],
        "issued_at": T0,
        "valid_until": T0 + 900,
        "scope": {"gate_id": "gate-paper-1"},
        "action": {},
        "payload_ref": {"da": 2, "namespace": NAMESPACE, "commitment": h("share-commitment-minimal"), "height": 4200000,
                        "signer": SIGNER},
        "ciphertext_hash": hashlib.sha256(BLOB).digest(),
        "plaintext_hash": hashlib.sha256(SALT + PLAINTEXT).digest(),
        "payload_size": len(BLOB),
    }, "minimal_lmt")


def fibre() -> dict:
    c = base()
    c["nonce"] = h("nonce-full")[:16]
    c["payload_ref"] = {"da": 1, "namespace": NAMESPACE, "commitment": h("fibre-commitment-full"), "height": 4200123}
    c["ciphertext_hash"] = h("blob-full")
    c["payload_size"] = 300000
    return c


def blob_v1() -> dict:
    c = base()
    c["nonce"] = h("v1 nonce blob")[:16]
    return salted(c, "v1 blob")


def fibre_v1() -> dict:
    c = fibre()
    c["nonce"] = h("v1 nonce fibre")[:16]
    c["payload_size"] = 1024
    return salted(c, "v1 fibre")


def pending(c: dict, h0: int, label: str) -> dict:
    c = copy.deepcopy(c)
    c["nonce"] = h(f"v1 nonce {label}")[:16]
    c["payload_ref"]["height"] = h0
    c["payload_ref"]["anchor"] = E.ANCHOR_PENDING
    return c


def maximal() -> dict:
    """Every field at its longest encoding: 596-byte commitment, 665-byte envelope."""
    c = blob_v1()
    c["agent_id"] = "a" * 64
    c["nonce"] = h("v1 nonce maximal")[:16]
    c["issued_at"] = E.MAX_INT - 3600
    c["valid_until"] = E.MAX_INT
    c["scope"] = {"gate_id": "g" * 64}
    c = salted(c, "v1 maximal", TYPE_128, b"edicta v1 maximal")
    c["payload_ref"]["height"] = E.MAX_INT
    c["payload_ref"]["anchor"] = E.ANCHOR_PENDING
    c["payload_size"] = 1 << 27
    c["mandate_ref"] = mandate_ref()
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


def canon_of(c: dict) -> bytes:
    return encode(to_cbor(strip(c), COMMITMENT))


def sign_commitment(canon: bytes, signer: str = "agent1"):
    hh = commitment_hash(canon)
    msg = signing_message(hh)
    return hh, msg, sk(signer).sign(msg)


def env(canon, sig: bytes) -> bytes:
    return encode({1: canon if isinstance(canon, Raw) else Raw(canon), 2: sig})


def signed_fields(c: dict | None, canon: bytes, signer: str = "agent1") -> dict:
    hh, msg, sig = sign_commitment(canon, signer)
    out = {}
    if c is not None:
        out["input"] = cj(strip(c))
    out.update({"commitment_cbor_hex": canon.hex(), "commitment_hash_hex": hh.hex(), "signer": signer,
                "signed_message_hex": msg.hex(), "signature_hex": sig.hex(), "envelope_hex": env(canon, sig).hex()})
    return out


def action_fields(action_type: str, action: bytes, salt: bytes | None, with_hash: bool = True) -> dict:
    """JSON fields describing supplied action bytes and salt; actions over 1024 bytes are given as a pattern."""
    out = {"action_type": action_type}
    if len(action) > 1024:
        out.update({"action_pattern": PATTERN, "action_size": str(len(action)),
                    "action_sha256_hex": hashlib.sha256(action).hexdigest()})
        assert pattern_bytes(PATTERN, len(action)) == action
    else:
        out["action_hex"] = action.hex()
    if salt is not None:
        out["action_salt_hex"] = salt.hex()
    if with_hash:
        out["action_preimage_prefix_hex"] = action_preimage_prefix(action_type).hex()
        out["action_hash_hex"] = action_hash(action_type, salt, action).hex()
    return out


# valid.json. VALID: id -> (commitment, canonical bytes, action type, action bytes, salt).

VALID: dict = {}


def valid_cases() -> list:
    out = []

    def add(cid, desc, c, action_type=IBKR, action=ACTION, now=NOW, params=None, gate=None):
        c = salted(c, cid, action_type, action)
        salt = salt_of(cid)
        canon = canon_of(c)
        case = {"id": cid, "description": desc}
        case.update(signed_fields(c, canon))
        case["now"] = str(now)
        if params is not None:
            case["params"] = params_to_json(params)
        if gate is not None:
            case["gate"] = gate_to_json(gate)
        case["pending"] = E.is_pending(c)
        case.update(action_fields(action_type, action, salt))
        case["placeholders"] = {"payload_ref.commitment": PLACEHOLDER}
        if "mandate_ref" in c:
            case["placeholders"]["mandate_ref"] = "mandate_hash of spec/vectors/policy/mandate.json case m_full."
        VALID[cid] = (strip(c), canon, action_type, action, salt)
        out.append(case)
        return case

    add("minimal_lmt", "da=celestia_blob; the action is the minimal IBKR limit order of the dca-agent profile; "
        "payload is ciphertext_hash_small_blob in payload.json.", base())
    add("ttl_exactly_max", "TTL == MaxTTL(da) == min(3600, 14400/4).", mod(base(), "valid_until", T0 + 3600))
    add("fibre_small_payload", "da=fibre with payload_size 1024 is accepted; the 256 KiB split is a Recorder "
        "routing rule.", mod(fibre(), "payload_size", 1024))
    add("blob_large_payload", "da=celestia_blob with payload_size 262144 is accepted.",
        mod(base(), "payload_size", 262144))
    c = mod(base(), "issued_at", NOW + 30)
    c["valid_until"] = NOW + 930
    add("issued_at_within_skew", "issued_at == now + skew is accepted.", c)
    c = mod(base(), "nonce", h("nonce-small-ints")[:16])
    c["payload_ref"]["height"] = 65535
    c["payload_size"] = 65536
    add("int_head_widths", "Integer heads at the 3-byte/5-byte boundary: height 65535 (0x19ffff), payload_size "
        "65536 (0x1a00010000); issued_at in 5 bytes, version and da in 1.", c)
    c = mod(base(), "nonce", h("nonce-small-ints-2")[:16])
    c["payload_ref"]["height"] = 23
    c["payload_size"] = 24
    add("int_head_widths_1_2", "Integer heads at the 1-byte/2-byte boundary: height 23 (0x17), payload_size 24 "
        "(0x1818).", c)
    c = mod(base(), "nonce", h("nonce-small-ints-3")[:16])
    c["payload_ref"]["height"] = 255
    c["payload_size"] = 256
    add("int_head_widths_2_3", "Integer heads at the 2-byte/3-byte boundary: height 255 (0x18ff), payload_size 256 "
        "(0x190100).", c)
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
    add("action_json_bytes", "A JSON action: the bytes are hashed as given; the core never parses or re-encodes "
        "them.", mod(base(), "nonce", h("nonce-json")[:16]), action_type=TYPE_JSON, action=ACTION_JSON)

    add("v1_minimal_included_fibre", "da = 1, included reference (anchor key absent).", fibre_v1())
    add("v1_minimal_included_blob", "da = 2, included reference.", blob_v1())
    add("v1_pending_fibre", f"da = 1, anchor = 2: payload_ref.height is the reference height h0 = {H0_FIBRE} "
        "(PaymentPromise.height of the upload).", pending(fibre_v1(), H0_FIBRE, "pending fibre"))
    add("v1_pending_blob", f"da = 2, anchor = 2: h0 = {H0_BLOB} is the head the Recorder read before building the "
        "PFB.", pending(blob_v1(), H0_BLOB, "pending blob"))
    c = blob_v1()
    c["nonce"] = h("v1 nonce mandate ref")[:16]
    c["mandate_ref"] = mandate_ref()
    add("v1_mandate_ref", "Included blob reference with mandate_ref (key 14).", c)
    c = pending(fibre_v1(), H0_FIBRE, "pending fibre mandate ref")
    c["mandate_ref"] = mandate_ref()
    add("v1_pending_fibre_mandate_ref", "Pending Fibre reference with mandate_ref: the fast-mode decision under a "
        "mandate.", c)
    c = pending(blob_v1(), H0_BLOB, "pending blob mandate ref")
    c["mandate_ref"] = mandate_ref()
    add("v1_pending_blob_mandate_ref", "Pending blob reference with mandate_ref: fast mode needs a mandate, so "
        "every fast-mode Authorization is for a decision that names one.", c)
    c = maximal()
    add("v1_maximal", "Largest schema-valid commitment: agent_id and gate_id 64 chars, action type 128, 9-byte heads "
        "for issued_at, valid_until and height, payload_size 2^27, da = 2 with signer, anchor = 2, mandate_ref. "
        "596-byte commitment, 665-byte envelope. Valid at its own issued_at (now = issued_at).", c,
        action_type=TYPE_128, action=b"edicta v1 maximal", now=c["issued_at"],
        gate={"gate_id": "g" * 64, "action_types": [TYPE_128]})
    assert len(VALID["v1_maximal"][1]) == 596, len(VALID["v1_maximal"][1])
    assert len(bytes.fromhex(out[-1]["envelope_hex"])) == 665
    return out


# reject.json

def d_case(cid, rule, desc, envb: bytes, expect: str) -> dict:
    return {"id": cid, "stage": "D", "rule": rule, "description": desc,
            "envelope_hex": envb.hex(), "now": str(NOW), "expect_error": expect}


def resigned(inner: bytes) -> bytes:
    """Envelope around (possibly malformed) commitment bytes, signed over those bytes."""
    _, _, sig = sign_commitment(inner)
    return env(inner, sig)


def commitment_with(c: dict, top: dict) -> bytes:
    """Canonical commitment with some top-level values replaced by raw encodings."""
    m = to_cbor(strip(c))
    m.update(top)
    return encode(m)


def draft8_shape_envelope() -> bytes:
    """minimal_lmt in the earliest draft layout (scope keys 2, 3, action keys 1, 2, key 9), version 1, signed."""
    b = base()
    m = {1: 1, 2: b["agent_id"], 3: b["agent_pubkey"], 4: b["nonce"], 5: T0, 6: T0 + 900,
         7: {1: "gate-paper-1", 2: 1, 3: "DU1234567"},
         8: {1: "ibkr.order.v0", 2: {1: "DU1234567", 2: 265598, 4: 1, 5: 100000, 6: 1, 7: 19050000000, 8: "USD", 9: 1}},
         9: {1: 200000000000},
         10: {1: 2, 2: NAMESPACE, 3: h("share-commitment-minimal"), 4: 4200000, 5: SIGNER},
         11: b["ciphertext_hash"], 12: b["plaintext_hash"], 13: b["payload_size"]}
    return resigned(encode(m))


def reject_cases() -> list:
    out = []
    b = base()
    canon = canon_of(b)
    _, _, sig = sign_commitment(canon)
    good = env(canon, sig)
    salt_b = salt_of("minimal_lmt")

    def action_with(repl: dict) -> bytes:
        m = to_cbor(strip(b))
        m[8].update(repl)
        return encode(m)

    def ref_with(repl: dict, c: dict = b) -> bytes:
        m = to_cbor(strip(c))
        m[10].update(repl)
        return encode(m)

    # Decoding: encoding and schema.
    out.append(d_case("too_large", "D0", "2177 bytes: a valid envelope padded with zero bytes. The size check runs "
                      "before any parsing.", good + bytes(2177 - len(good)), "ErrTooLarge"))
    out.append(d_case("truncated", "D1", "Valid envelope with its last byte removed.", good[:-1], "ErrMalformed"))
    out.append(d_case("reserved_additional_info", "D1", "issued_at head uses reserved additional info 28 (0x1c).",
                      resigned(commitment_with(b, {5: Raw(b"\x1c")})), "ErrMalformed"))
    out.append(d_case("trailing_byte", "D2", "Valid envelope followed by one 0x00 byte.", good + b"\x00",
                      "ErrTrailingData"))
    out.append(d_case("float_payload_size", "D3", "payload_size encoded as float64 (0xfb).",
                      resigned(commitment_with(b, {13: Raw(b"\xfb" + struct.pack(">d", float(b["payload_size"])))})),
                      "ErrFloat"))
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
                      resigned(commitment_with(b, {2: Raw(b"\x7f" + encode("dca-") + encode("agent-1") + b"\xff")})),
                      "ErrIndefiniteLength"))
    out.append(d_case("nonminimal_uint", "D7", "issued_at encoded in 8 bytes (0x1b) although it fits in 4.",
                      resigned(commitment_with(b, {5: Raw(b"\x1b" + T0.to_bytes(8, "big"))})), "ErrNonMinimalInt"))
    out.append(d_case("nonminimal_len", "D7", "nonce length 16 encoded as 0x58 0x10 instead of 0x50.",
                      resigned(commitment_with(b, {4: Raw(b"\x58\x10" + b["nonce"])})), "ErrNonMinimalInt"))
    items = sorted(to_cbor(strip(b)).items())
    pairs = [(Raw(b"\x18\x01") if k == 1 else k, v) for k, v in items]
    out.append(d_case("nonminimal_key", "D7", "Top-level key 1 encoded as 0x18 0x01.",
                      resigned(encode(Pairs(tuple(pairs)))), "ErrNonMinimalInt"))
    out.append(d_case("deep_nesting", "D8", "action.type replaced by the map {1: {1: 0}}; the inner map is a "
                      "container at depth 5.", resigned(action_with({3: {1: {1: 0}}})), "ErrNestingTooDeep"))
    m = to_cbor(strip(b))
    for k in (14, 15, 16, 17, 18):
        m[k] = 0
    out.append(d_case("map_17_pairs", "D9", "Commitment map with 17 pairs (the 12 required keys plus 14..18).",
                      resigned(encode(m)), "ErrTooLarge"))
    pairs = list(items)
    i12 = next(i for i, (k, _) in enumerate(pairs) if k == 12)
    pairs[i12], pairs[i12 + 1] = pairs[i12 + 1], pairs[i12]
    out.append(d_case("unsorted_map", "D10", "Top-level keys 12 and 13 swapped.", resigned(encode(Pairs(tuple(pairs)))),
                      "ErrUnsortedMap"))
    pairs = list(items) + [(13, b["payload_size"])]
    out.append(d_case("dup_key", "D11", "Top-level key 13 appears twice with the same value.",
                      resigned(encode(Pairs(tuple(pairs)))), "ErrDuplicateKey"))
    pairs = list(items) + [("x", 0)]
    out.append(d_case("tstr_key", "D12", "Commitment map gains a text-string key \"x\".",
                      resigned(encode(Pairs(tuple(pairs)))), "ErrKeyType"))
    out.append(d_case("invalid_utf8", "D13", "agent_id is a text string containing the byte 0xff.",
                      resigned(commitment_with(b, {2: Raw(b"\x6b" + b"dca-agent-\xff")})), "ErrInvalidString"))
    type_len = 2048 - len(canon) + len(IBKR) + 30
    big = action_with({3: Raw(head(3, type_len) + b"a" * type_len)})
    big_env = resigned(big)
    assert len(big) > 2048 and len(big_env) <= 2176, (len(big), len(big_env))
    out.append(d_case("commitment_too_large", "D14", f"Commitment of {len(big)} bytes (action.type of {type_len} "
                      f"bytes) in an envelope of {len(big_env)} bytes. The commitment size is checked before its "
                      "fields.", big_env, "ErrTooLarge"))
    out.append(d_case("unknown_top_key", "D15", "Commitment has an extra key 16 (unassigned).",
                      resigned(commitment_with(b, {16: 0})), "ErrUnknownKey"))
    out.append(d_case("retired_constraints_key", "D15", "Commitment carries key 9 (unassigned) with "
                      "{1: max_notional}.", resigned(commitment_with(b, {9: {1: 200000000000}})), "ErrUnknownKey"))
    for k, val, name in ((2, 1, "rail"), (3, "DU1234567", "account"), (4, "celestia", "chain_id")):
        m = to_cbor(strip(b))
        m[7][k] = val
        out.append(d_case(f"retired_scope_{name}_key", "D15", f"scope carries key {k} (unassigned).",
                          resigned(encode(m)), "ErrUnknownKey"))
    out.append(d_case("draft8_shape_envelope", "D15", "minimal_lmt laid out with the unassigned keys of an early "
                      "draft (scope 2 and 3, action 1 and 2, key 9), version 1, signed: it fails loudly at scope "
                      "key 2 instead of being misread.", draft8_shape_envelope(), "ErrUnknownKey"))
    out.append(d_case("unknown_action_key", "D15", "action has an extra key 5.", resigned(action_with({5: 0})),
                      "ErrUnknownKey"))
    out.append(d_case("retired_action_kind_key", "D15", "action carries key 1 (unassigned) next to type and hash.",
                      resigned(action_with({1: "ibkr.order.v0"})), "ErrUnknownKey"))
    out.append(d_case("retired_action_params_key", "D15", "action carries key 2 (unassigned) next to type and "
                      "hash.", resigned(action_with({2: {2: 265598}})), "ErrUnknownKey"))
    out.append(d_case("unknown_payload_ref_key", "D15", "payload_ref has an extra key 9 (unassigned).",
                      resigned(ref_with({9: 0})), "ErrUnknownKey"))
    f = fibre()
    out.append(d_case("signer_on_fibre", "D15", "da=fibre locator carries payload_ref key 5 (signer), which is "
                      "defined only for celestia_blob.", resigned(ref_with({5: SIGNER}, f)), "ErrUnknownKey"))
    out.append(d_case("unknown_envelope_key", "D15", "Envelope has an extra key 3.",
                      encode({1: Raw(canon), 2: sig, 3: 0}), "ErrUnknownKey"))
    out.append(d_case("nint_payload_size", "D16", "payload_size encoded as a negative integer.",
                      resigned(commitment_with(b, {13: -b["payload_size"]})), "ErrWrongType"))
    out.append(d_case("bstr_for_tstr", "D16", "agent_id encoded as a byte string.",
                      resigned(commitment_with(b, {2: b"dca-agent-1"})), "ErrWrongType"))
    m = to_cbor(strip(b))
    m[7] = ["gate-paper-1"]
    out.append(d_case("array_for_scope", "D16", "scope encoded as an array.", resigned(encode(m)), "ErrWrongType"))
    out.append(d_case("action_hash_tstr", "D16", "action.hash given as 64 lowercase hex characters (a text string) "
                      "instead of 32 bytes.", resigned(action_with({4: b["action"]["hash"].hex()})), "ErrWrongType"))
    out.append(d_case("signer_bech32_tstr", "D16", "payload_ref.signer given as a bech32 text string instead of the "
                      "raw 20-byte address.", resigned(ref_with({5: "celestia1" + "q" * 38})), "ErrWrongType"))
    out.append(d_case("missing_nonce", "D17", "Top-level key 4 absent.",
                      resigned(encode({k: v for k, v in to_cbor(strip(b)).items() if k != 4})), "ErrMissingField"))
    for path, desc, cid in (((8, 4), "action key 4 (hash) absent.", "missing_action_hash"),
                            ((10, 4), "payload_ref key 4 (height) absent.", "missing_height"),
                            ((10, 3), "payload_ref key 3 (commitment) absent.", "missing_locator_commitment"),
                            ((10, 5), "da=celestia_blob without payload_ref key 5 (signer).", "missing_locator_signer")):
        m = to_cbor(strip(b))
        del m[path[0]][path[1]]
        out.append(d_case(cid, "D17", desc, resigned(encode(m)), "ErrMissingField"))
    out.append(d_case("missing_signature", "D17", "Envelope without key 2.", encode({1: Raw(canon)}), "ErrMissingField"))
    out.append(d_case("nonce_15_bytes", "D18", "nonce of 15 bytes.",
                      resigned(commitment_with(b, {4: b["nonce"][:15]})), "ErrFieldSize"))
    out.append(d_case("sig_63_bytes", "D18", "Signature of 63 bytes.", env(canon, sig[:63]), "ErrFieldSize"))
    out.append(d_case("namespace_28_bytes", "D18", "namespace of 28 bytes.", resigned(ref_with({2: NAMESPACE[:28]})),
                      "ErrFieldSize"))
    out.append(d_case("share_commitment_31_bytes", "D18", "da=celestia_blob with a 31-byte share commitment.",
                      resigned(ref_with({3: h("share-commitment-minimal")[:31]})), "ErrFieldSize"))
    out.append(d_case("fibre_commitment_33_bytes", "D18", "da=fibre with a 33-byte Fibre BlobID (version byte || "
                      "commitment) instead of the 32-byte commitment.",
                      resigned(ref_with({3: b"\x00" + f["payload_ref"]["commitment"]}, f)), "ErrFieldSize"))
    out.append(d_case("signer_19_bytes", "D18", "da=celestia_blob with a 19-byte signer.",
                      resigned(ref_with({5: SIGNER[:19]})), "ErrFieldSize"))
    out.append(d_case("signer_32_bytes", "D18", "da=celestia_blob with a 32-byte address (for example a module or "
                      "ICA account); share version 1 requires exactly 20 bytes.",
                      resigned(ref_with({5: h("edicta/v0 test 32-byte account")})), "ErrFieldSize"))
    out.append(d_case("agent_id_empty", "D18", "agent_id is the empty string.", resigned(commitment_with(b, {2: ""})),
                      "ErrFieldSize"))
    out.append(d_case("agent_id_65_chars", "D18", "agent_id of 65 characters.",
                      resigned(commitment_with(b, {2: "a" * 65})), "ErrFieldSize"))
    out.append(d_case("action_type_129_chars", "D18", "action.type of 129 bytes (otherwise grammatical).",
                      resigned(action_with({3: TYPE_128[:-5] + "a+cbor"})), "ErrFieldSize"))
    out.append(d_case("action_type_empty", "D18", "action.type is the empty string.", resigned(action_with({3: ""})),
                      "ErrFieldSize"))
    out.append(d_case("action_type_2_chars", "D18", "action.type \"ab\": 2 bytes, below the minimum of 3 (the "
                      "shortest type is \"a/b\").", resigned(action_with({3: "ab"})), "ErrFieldSize"))
    out.append(d_case("action_hash_31_bytes", "D18", "action.hash of 31 bytes.",
                      resigned(action_with({4: b["action"]["hash"][:31]})), "ErrFieldSize"))
    m = to_cbor(strip(b))
    m[7][1] = "gate-paper-ο1"
    out.append(d_case("gate_id_unicode", "D19", "gate_id contains U+03BF (Greek small omicron), a look-alike of 'o'.",
                      resigned(encode(m)), "ErrInvalidString"))
    for cid, t, desc in [
        ("action_type_uppercase", "Application/vnd.edicta.ibkr.order.v0+cbor",
         "Upper-case letter; types are lower case so each type has one byte string."),
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
        case.update(signed_fields(c, canon_of(c), signer))
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

    s_case("version_0", "S", "S1", "version 0: every other field as minimal_lmt.", mod(b, "version", 0),
           "ErrUnsupportedVersion")
    s_case("height_2pow63", "S", "S2", "payload_ref.height = 2^63 (9-byte head 0x1b8000000000000000).",
           mod(b, "payload_ref.height", 1 << 63), "ErrIntRange")
    s_case("da_0", "S", "S3", "da 0.", mod(b, "payload_ref.da", 0), "ErrInvalidEnum")
    s_case("da_3", "S", "S3", "da 3 (reserved).", mod(b, "payload_ref.da", 3), "ErrInvalidEnum")
    s_case("da_256", "S", "S3", "da 256: enums decode at uint64 width, so this is an enum error, not a decode error.",
           mod(b, "payload_ref.da", 256), "ErrInvalidEnum")
    s_case("issued_at_0", "S", "S6", "issued_at 0.", mod(b, "issued_at", 0), "ErrZeroValue")
    s_case("height_0", "S", "S6", "payload_ref.height 0.", mod(b, "payload_ref.height", 0), "ErrZeroValue")
    s_case("payload_size_0", "S", "S6", "payload_size 0.", mod(b, "payload_size", 0), "ErrZeroValue")
    s_case("payload_size_2pow27_plus1", "S", "S7", "payload_size 2^27 + 1.", mod(b, "payload_size", (1 << 27) + 1),
           "ErrPayloadTooLarge")
    s_case("namespace_version_1", "S", "S8", "Namespace version byte 1.",
           mod(b, "payload_ref.namespace", b"\x01" + NAMESPACE[1:]), "ErrInvalidNamespace")
    s_case("namespace_nonzero_prefix", "S", "S8", "Version 0 namespace whose 18-byte id prefix is not all zero.",
           mod(b, "payload_ref.namespace", b"\x00\x01" + NAMESPACE[2:]), "ErrInvalidNamespace")
    s_case("namespace_reserved", "S", "S8", "Primary reserved namespace 0x00..0004 (PayForBlob).",
           mod(b, "payload_ref.namespace", bytes(28) + b"\x04"), "ErrInvalidNamespace")
    s_case("valid_until_eq_issued", "S", "S12", "valid_until == issued_at.", mod(b, "valid_until", T0), "ErrTimeOrder")
    s_case("valid_until_lt_issued", "S", "S12", "valid_until < issued_at.", mod(b, "valid_until", T0 - 1),
           "ErrTimeOrder")
    s_case("ttl_3601", "S", "S14", "TTL 3601 with default params (MaxTTL 3600).", mod(b, "valid_until", T0 + 3601),
           "ErrTTLTooLong")
    s_case("ttl_ok_at_4h_rejected_at_10m", "S", "S14",
           "da=fibre, TTL 900. Valid at fibre_retention_s=14400; here retention was lowered to 600 (MaxTTL 150) and "
           "is read at check time.", mod(fibre(), "nonce", h("nonce-ttl-gov")[:16]), "ErrTTLTooLong",
           params=Params(600, 14400, 30))
    s_case("ttl_floor_division", "S", "S14", "fibre_retention_s=601: MaxTTL = floor(601/4) = 150; TTL 151 is rejected.",
           mod(fibre(), "valid_until", T0 + 151), "ErrTTLTooLong", params=Params(601, 14400, 30))

    for cid, desc, enc in g0_keys():
        small = (pt := ed.decode(enc, strict=False)) is not None and ed.is_small_order(pt)
        for i in range(64):  # vary the nonce until a forgery exists (expected within a few tries)
            c = mod(b, "agent_pubkey", enc)
            c["nonce"] = h(f"nonce-{cid}-{i}")[:16]
            canon_c = canon_of(c)
            hh = commitment_hash(canon_c)
            sig_c, forged = small_order_forgery(enc, signing_message(hh))
            if forged or not small:
                break
        assert forged == small, cid
        note = (" The signature R || S=0 satisfies the cofactorless equation [S]B = R + [k]A for this A, so a verifier "
                "without G0 accepts it." if forged else " Signature R=identity, S=0.")
        out.append({"id": cid, "stage": "G", "rule": "G0", "description": desc + note, "input": cj(strip(c)),
                    "commitment_cbor_hex": canon_c.hex(), "commitment_hash_hex": hh.hex(),
                    "envelope_hex": env(canon_c, sig_c).hex(), "now": str(NOW), "expect_error": "ErrInvalidPublicKey"})

    def g_case(cid, rule, desc, c, msg_fn, sig_fn=None):
        canon_c = canon_of(c)
        hh = commitment_hash(canon_c)
        s = sk("agent1").sign(msg_fn(canon_c, hh))
        if sig_fn:
            s = sig_fn(s)
        out.append({"id": cid, "stage": "G", "rule": rule, "description": desc, "input": cj(strip(c)),
                    "commitment_cbor_hex": canon_c.hex(), "commitment_hash_hex": hh.hex(),
                    "envelope_hex": env(canon_c, s).hex(), "now": str(NOW), "expect_error": "ErrSignatureInvalid"})

    g_case("wrong_sig_tag", "G1", "Signed message uses the receipt tag: 0x11 || \"edicta/v1/receipt\" || "
           "commitment_hash.", b, lambda cc, hh: tagged(TAG_RECEIPT) + hh)
    g_case("sig_under_authorization_sig_tag", "G1", "Signed message uses the Authorization signature tag: 0x1b || "
           "\"edicta/v1/authorization-sig\" || commitment_hash.", b, lambda cc, hh: tagged(TAG_AUTHORIZATION_SIG) + hh)
    g_case("sig_tag_no_length_prefix", "G1", "Signed message omits the tag length byte: \"edicta/v1/sig\" || "
           "commitment_hash.", b, lambda cc, hh: TAG_SIG + hh)
    g_case("wrong_hash_tag", "G1", "commitment hash computed with the receipt tag instead of the commitment tag.",
           b, lambda cc, hh: tagged(TAG_SIG) + hashlib.sha256(tagged(TAG_RECEIPT) + cc).digest())
    g_case("hash_without_tag", "G1", "commitment hash computed as SHA-256(canon) with no domain tag.",
           b, lambda cc, hh: tagged(TAG_SIG) + hashlib.sha256(cc).digest())
    g_case("sig_raw_cbor", "G1", "Signature over the raw canonical CBOR instead of the tagged hash.", b,
           lambda cc, hh: cc)
    g_case("sig_raw_hash", "G1", "Signature over commitment_hash without the signature tag.", b, lambda cc, hh: hh)

    def plus_l(s: bytes) -> bytes:
        v = int.from_bytes(s[32:], "little") + ED25519_L
        return s[:32] + v.to_bytes(32, "little")

    g_case("sig_noncanonical_s", "G2", "Valid signature with S replaced by S + L (malleated).",
           b, lambda cc, hh: signing_message(hh), plus_l)
    s_case("sig_wrong_key", "G", "G1", "agent_pubkey is agent1, signature made by agent2.", b, "ErrSignatureInvalid",
           signer="agent2")

    _, _, osig = sign_commitment(canon)
    other_order = order_encode(dict(ORDER_MINIMAL, qty=100001))
    flipped = copy.deepcopy(b)
    flipped["action"]["hash"] = action_hash(IBKR, salt_b, other_order)
    fcanon = canon_of(flipped)
    out.append({"id": "flipped_field", "stage": "G", "rule": "G1",
                "description": "action.hash replaced after signing by the hash of the same order with qty 100001 "
                               "(same salt); the signature is over minimal_lmt.",
                "input": cj(strip(flipped)), "commitment_cbor_hex": fcanon.hex(),
                "commitment_hash_hex": commitment_hash(fcanon).hex(),
                "envelope_hex": env(fcanon, osig).hex(), "now": str(NOW), "expect_error": "ErrSignatureInvalid"})

    tsig = torsion_r_signature(signing_message(commitment_hash(canon)))
    out.append({"id": "sig_torsion_r", "stage": "G", "rule": "G1",
                "description": "Signature by agent1 with R = [r]B + T, T an order-8 point, and S = r + k*a mod L < L. "
                               "It satisfies the cofactored equation [8][S]B = [8]R + [8][k]A but not the cofactorless "
                               "equation encode([S]B - [k]A) == R, so it is rejected; a cofactored verifier would "
                               "accept it.",
                "input": cj(strip(b)), "commitment_cbor_hex": canon.hex(),
                "commitment_hash_hex": commitment_hash(canon).hex(),
                "envelope_hex": env(canon, tsig).hex(), "now": str(NOW), "expect_error": "ErrSignatureInvalid"})

    s_case("future_issued", "T", "T1", "issued_at == now + skew + 1.",
           mod(mod(b, "issued_at", NOW + 31), "valid_until", NOW + 931), "ErrNotYetValid")
    s_case("expired", "T", "T2", "now well past valid_until.", b, "ErrExpired", now=T0 + 1000)
    s_case("expiry_within_skew", "T", "T2", "now + skew == valid_until.", b, "ErrExpired", now=T0 + 900 - 30)

    s_case("foreign_gate_id", "C", "C1", "Gate id differs.", b, "ErrScopeMismatch", gate=dict(GATE, gate_id="gate-paper-2"))
    c = salted(mod(b, "nonce", h("nonce-type-not-allowed")[:16]), "action_type_not_allowed", TYPE_NOT_ALLOWED,
               bytes.fromhex("f86c098504a817c800825208"))
    s_case("action_type_not_allowed", "C", "C2", f"action.type {TYPE_NOT_ALLOWED} is well formed but not in the "
           "gate's action_types.", c, "ErrActionTypeNotAllowed")
    s_case("action_type_suffix_differs", "C", "C2",
           "The gate allows application/vnd.edicta.ibkr.order.v0+json only; the committed type differs in the "
           "suffix. Membership is bytewise equality.",
           b, "ErrActionTypeNotAllowed", gate=dict(GATE, action_types=["application/vnd.edicta.ibkr.order.v0+json"]))

    t = IBKR.encode()
    good_preimage = action_preimage_prefix(IBKR) + salt_b + ACTION_MINIMAL

    def a_case(cid, rule, desc, c, action, expect, preimage=good_preimage, salt=salt_b):
        s_case(cid, "A", rule, desc, c, expect, action=(action[0], action[1], salt), preimage=preimage)

    def flip(x: bytes, i: int) -> bytes:
        y = bytearray(x)
        y[i] ^= 0x01
        return bytes(y)

    a_case("action_byte_flipped", "A1", "The supplied order bytes have their last byte flipped (tif 1 -> 0).", b,
           (IBKR, flip(ACTION_MINIMAL, -1)), "ErrActionMismatch")
    a_case("action_truncated", "A1", "The supplied order bytes miss their last byte.", b,
           (IBKR, ACTION_MINIMAL[:-1]), "ErrActionMismatch")
    a_case("action_extra_byte", "A1", "The supplied order bytes carry one extra 0x00 byte at the end.", b,
           (IBKR, ACTION_MINIMAL + b"\x00"), "ErrActionMismatch")
    a_case("action_qty_differs", "A1", "The supplied order is the committed one with qty 100001; the core does not "
           "interpret it, the hash differs.", b, (IBKR, other_order), "ErrActionMismatch")
    nc = bytearray(ACTION_MINIMAL)
    conid_head = encode(265598)
    i = nc.index(b"\x02" + conid_head)
    noncanon = bytes(nc[:i + 1]) + b"\x1b" + (265598).to_bytes(8, "big") + bytes(nc[i + 1 + len(conid_head):])
    a_case("action_reencoded_noncanonical", "A1", "The same order with conid in a 9-byte head: the same meaning in a "
           "lenient decoder, other bytes, so not authorized.", b, (IBKR, noncanon), "ErrActionMismatch")
    a_case("action_wrong_salt", "A1", "The committed bytes with the salt's lowest bit flipped.", b,
           (IBKR, ACTION_MINIMAL), "ErrActionMismatch", salt=bytes([salt_b[0] ^ 1]) + salt_b[1:])

    def committed_as(cid: str, pre: bytes) -> dict:
        c = mod(b, "nonce", h(cid)[:16])
        c["action"]["hash"] = hashlib.sha256(pre).digest()
        return c

    pre = action_preimage_prefix(TYPE_OCTETS) + salt_b + ACTION_MINIMAL
    a_case("action_hash_of_other_type", "A1", "action.hash was computed under application/octet-stream over the right "
           "salt and bytes; the committed type is the IBKR order type.",
           committed_as("nonce-hash-other-type", pre), (IBKR, ACTION_MINIMAL), "ErrActionMismatch", preimage=pre)
    pre = bytes([len(t)]) + t + salt_b + ACTION_MINIMAL
    a_case("action_hash_untagged", "A1", "action.hash = SHA-256(uint8(len(type)) || type || salt || bytes), without "
           "the edicta/v1/action tag.", committed_as("nonce-hash-untagged", pre), (IBKR, ACTION_MINIMAL),
           "ErrActionMismatch", preimage=pre)
    pre = tagged(TAG_ACTION) + t + salt_b + ACTION_MINIMAL
    a_case("action_hash_type_unprefixed", "A1", "action.hash = SHA-256(tag || type || salt || bytes), without the type "
           "length byte.", committed_as("nonce-hash-type-unprefixed", pre), (IBKR, ACTION_MINIMAL), "ErrActionMismatch",
           preimage=pre)
    pre = action_preimage_prefix(IBKR) + ACTION_MINIMAL
    a_case("action_unsalted", "A1", "action.hash = SHA-256(tag || uint8(len(type)) || type || bytes): the salt left "
           "out.", committed_as("nonce-hash-unsalted", pre), (IBKR, ACTION_MINIMAL), "ErrActionMismatch", preimage=pre)
    pre = ACTION_MINIMAL
    a_case("action_hash_bare_sha256", "A1", "action.hash = SHA-256(bytes): no tag, no type, no salt.",
           committed_as("nonce-hash-bare", pre), (IBKR, ACTION_MINIMAL), "ErrActionMismatch", preimage=pre)
    a_case("action_empty", "A0", "No action bytes supplied (length 0).", b, (IBKR, b""), "ErrActionSize")
    a_case("action_too_large", "A0", f"{MAX_ACTION_SIZE + 1} bytes supplied (pattern {PATTERN}); the size is checked "
           "before hashing.", b, (IBKR, pattern_bytes(PATTERN, MAX_ACTION_SIZE + 1)), "ErrActionSize")
    a_case("action_salt_31", "A0s", "The committed bytes with a 31-byte salt.", b, (IBKR, ACTION_MINIMAL),
           "ErrFieldSize", salt=salt_b[:31])
    out.extend(reject_cases_v1())
    return out


def reject_cases_v1() -> list:
    """Reserved values, the anchor key, mandate_ref and the version key."""
    out = []
    b = blob_v1()
    f = fibre_v1()

    def raw_case(cid, stage, rule, desc, m: dict, expect, src=None):
        canon = encode(m)
        case = {"id": cid, "stage": stage, "rule": rule, "description": desc}
        case.update(signed_fields(src, canon))
        case["now"] = str(NOW)
        case["expect_error"] = expect
        out.append(case)

    def ikeyed(c: dict) -> dict:
        return to_cbor(strip(c), COMMITMENT)

    def mutate_pr(c, kv: dict):
        m = ikeyed(c)
        m[10].update(kv)
        return m

    raw_case("da_3_reserved", "S", "S3", "da = 3 is reserved for a batch leaf.", mutate_pr(b, {1: 3}), "ErrInvalidEnum")
    raw_case("da_3_with_anchor_2", "S", "S3", "da = 3 with anchor = 2 and a signer: S3 runs before the anchor rule.",
             mutate_pr(b, {1: 3, 6: 2}), "ErrInvalidEnum")
    raw_case("payload_ref_key_7_reserved", "D", "D15", "payload_ref key 7 (reserved leaf_hash, 32 bytes).",
             mutate_pr(b, {7: h("v1 leaf hash")}), "ErrUnknownKey")
    raw_case("payload_ref_key_8_reserved", "D", "D15", "payload_ref key 8 (reserved leaf_index = 0).",
             mutate_pr(b, {8: 0}), "ErrUnknownKey")
    m = ikeyed(b)
    m[15] = h("v1 attestation ref")
    raw_case("commitment_key_15_reserved", "D", "D15", "Commitment key 15 (reserved TEE attestation reference).",
             m, "ErrUnknownKey")
    for val, cid, desc in ((1, "anchor_1", "anchor = 1: included has one encoding, the absent key."),
                           (3, "anchor_3", "anchor = 3."),
                           (0, "anchor_0", "anchor = 0.")):
        raw_case(cid, "S", "S4", desc, mutate_pr(b, {6: val}), "ErrInvalidEnum")
    raw_case("anchor_2pow63", "S", "S2", "anchor = 2^63: S2 precedes the anchor rule.", mutate_pr(b, {6: 1 << 63}),
             "ErrIntRange")
    raw_case("anchor_tstr", "D", "D16", "anchor as the text \"2\".", mutate_pr(b, {6: "2"}), "ErrWrongType")
    for n, cid in ((31, "mandate_ref_31_bytes"), (33, "mandate_ref_33_bytes")):
        m = ikeyed(b)
        m[14] = (h("v1 mandate ref short") * 2)[:n]
        raw_case(cid, "D", "D18", f"mandate_ref of {n} bytes.", m, "ErrFieldSize")
    m = ikeyed(b)
    m[14] = mandate_ref().hex()
    raw_case("mandate_ref_tstr", "D", "D16", "mandate_ref as lower-case hex text.", m, "ErrWrongType")
    m = ikeyed(b)
    m[1] = 2
    raw_case("version_2", "S", "S1", "version = 2: S1 accepts only 1.", m, "ErrUnsupportedVersion")
    m = ikeyed(b)
    del m[1]
    raw_case("version_absent", "D", "D17", "version absent.", m, "ErrMissingField")
    m = ikeyed(b)
    m[9] = {1: 1}
    raw_case("retired_key_9", "D", "D15", "Key 9 is unassigned.", m, "ErrUnknownKey")
    m = ikeyed(pending(f, H0_FIBRE, "pending fibre"))
    m[10][5] = SIGNER
    raw_case("signer_on_fibre_pending", "D", "D15", "da = 1, anchor = 2, with a signer: key 5 is not defined for "
             "da = 1.", m, "ErrUnknownKey")
    m = ikeyed(pending(b, H0_BLOB, "pending blob"))
    del m[10][5]
    raw_case("missing_signer_blob_pending", "D", "D17", "da = 2, anchor = 2, without a signer.", m, "ErrMissingField")
    raw_case("height_0_pending", "S", "S6", "Pending reference with h0 = 0.",
             ikeyed(pending(b, 0, "pending zero")), "ErrZeroValue")
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
    """Illustrative single share-version-1 sparse share: namespace, info byte (version 1 << 1 | sequence
    start = 0x03), 4-byte sequence length, 20-byte signer, data, zero padding to 512 bytes."""
    assert len(signer) == 20 and len(data) <= 458
    s = ns + b"\x03" + struct.pack(">I", len(data)) + signer + data
    return s + bytes(512 - len(s))


# payload.json

def payload_v1_dict(salt: bytes, action: bytes = ACTION) -> dict:
    return {"version": 1, "model": {"id": "edicta-test-model"}, "policy": {"id": "edicta-test-policy"},
            "context": {"media_type": "application/json", "data": b'{"note":"v1 payload vector"}'},
            "action": {"type": IBKR, "data": action, "action_salt": salt}}


def payload_vectors() -> dict:
    import hpke_base as hpke
    blob_hash = hashlib.sha256(BLOB).digest()
    flipped = bytearray(BLOB)
    flipped[-1] ^= 0x01
    framed = share_frame(NAMESPACE, SIGNER, BLOB)
    cases = [
        {"id": "ciphertext_hash_small_blob",
         "description": "Dummy bytes in the shape of a payload blob (two wrapped-key entries, label-derived keys and "
                        "ciphertext); ciphertext_hash = SHA-256(blob). Stage P only hashes and measures; the blob is "
                        "not meant to be opened.",
         "blob_hex": BLOB.hex(), "payload_size": str(len(BLOB)), "ciphertext_hash_hex": blob_hash.hex()},
        {"id": "plaintext_hash_basic", "description": "plaintext_hash = SHA-256(salt(32) || plaintext).",
         "salt_hex": SALT.hex(), "plaintext_hex": PLAINTEXT.hex(),
         "plaintext_hash_hex": hashlib.sha256(SALT + PLAINTEXT).digest().hex()},
    ]
    reject = [
        {"id": "blob_flipped_byte", "commitment_ref": "minimal_lmt", "description": "Last byte of the blob flipped.",
         "payload_size": str(len(BLOB)), "ciphertext_hash_hex": blob_hash.hex(),
         "blob_hex": bytes(flipped).hex(), "expect_error": "ErrPayloadHashMismatch"},
        {"id": "blob_with_share_padding",
         "description": "The producer hashed the share-framed bytes (namespace, info byte, sequence length, signer, zero "
                        "padding; share version 1) instead of the blob; the fetched blob is the raw bytes.",
         "payload_size": str(len(BLOB)), "ciphertext_hash_hex": hashlib.sha256(framed).hexdigest(),
         "framed_hex": framed.hex(), "blob_hex": BLOB.hex(), "expect_error": "ErrPayloadHashMismatch"},
        {"id": "blob_truncated", "commitment_ref": "minimal_lmt",
         "description": "Blob missing its last byte; size is checked before the hash.",
         "payload_size": str(len(BLOB)), "ciphertext_hash_hex": blob_hash.hex(),
         "blob_hex": BLOB[:-1].hex(), "expect_error": "ErrPayloadSizeMismatch"},
    ]

    salt = salt_of("payload")
    committed = action_hash(IBKR, salt, ACTION)
    aead_salt = h("v1 payload aead salt")
    pt = pv.payload_encode(payload_v1_dict(salt))
    ikm = h("v1 payload recipient ikm")
    sk_r, pk_r = hpke.derive_key_pair(ikm)
    sk_e = hpke.derive_key_pair(h("v1 payload ephemeral ikm"))[0]
    blob, _ = pv.seal(aead_salt, pt, [pv.Recipient(b"auditor-1", pk_r, sk_e)], h("v1 payload dek"),
                      h("v1 payload nonce")[:12])
    aead_pt = pv.open_blob(blob, sk_r)
    assert aead_pt == aead_salt + pt
    pv.o8(aead_pt, IBKR, committed)
    cases.append({"id": "payload_v1_minimal", "description": "Payload with action_salt (key 5 of the action), "
                  "sealed to one recipient; O1 to O7 pass, then O8 passes.",
                  "action_type": IBKR, "committed_action_hash_hex": committed.hex(),
                  "action_salt_hex": salt.hex(), "plaintext_cbor_hex": pt.hex(), "aead_salt_hex": aead_salt.hex(),
                  "plaintext_hash_hex": hashlib.sha256(aead_salt + pt).hexdigest(),
                  "recipient": {"kid_hex": b"auditor-1".hex(), "ikm_hex": ikm.hex(), "sk_hex": sk_r.hex(),
                                "pk_hex": pk_r.hex()},
                  "blob_hex": blob.hex(), "ciphertext_hash_hex": hashlib.sha256(blob).hexdigest(),
                  "payload_size": str(len(blob))})
    open_reject = []

    def rj(cid, desc, plaintext: bytes, committed_hash: bytes = committed):
        r = {"id": cid, "description": desc, "action_type": IBKR,
             "committed_action_hash_hex": committed_hash.hex(), "plaintext_cbor_hex": plaintext.hex()}
        try:
            pv.o8(aead_salt + plaintext, IBKR, committed_hash)
            raise AssertionError(cid)
        except Reject as e:
            r["expect_error"] = e.sentinel
        open_reject.append(r)

    p = payload_v1_dict(salt)
    m = {1: 1, 2: {1: "edicta-test-model"}, 3: {1: "edicta-test-policy"},
         4: {1: "application/json", 2: p["context"]["data"]}, 5: {3: IBKR, 4: ACTION, 5: salt}}
    assert encode(m) == pt
    m2 = copy.deepcopy(m); del m2[5][5]
    rj("payload_v1_salt_missing", "The action has no key 5 (PV3).", encode(m2))
    m2 = copy.deepcopy(m); m2[5][5] = salt[:31]
    rj("payload_v1_salt_31", "A 31-byte action_salt (PV3).", encode(m2))
    m2 = copy.deepcopy(m); m2[5][5] = salt.hex()
    rj("payload_v1_salt_tstr", "action_salt as text (PV3).", encode(m2))
    m2 = copy.deepcopy(m); m2[1] = 0
    rj("payload_version_0", "A payload with version 0 and a salt: well-formed except the version (PV2).", encode(m2))
    m2 = copy.deepcopy(m); m2[5][5] = bytes([salt[0] ^ 1]) + salt[1:]
    rj("payload_v1_wrong_salt", "O8: the payload's salt differs from the committed one by one bit.", encode(m2))
    unsalted = hashlib.sha256(action_preimage_prefix(IBKR) + ACTION).digest()
    rj("payload_v1_unsalted_commitment", "O8: the commitment's action.hash is computed without the salt over the "
       "same bytes.", pt, unsalted)
    return {"format": FORMAT, "revision": REVISION, "cases": cases, "reject": reject, "open_reject": open_reject}


# authorization.json

def gate_pub(name: str = "gate1") -> bytes:
    return pub(name)


def check_block(action_type: str, action: bytes, now: int = NOW, salt: bytes | None = None, gate_id: str = GID,
                pubkey: bytes | None = None, skew: int = 30) -> dict:
    blk = {"gate_pubkey_hex": (pubkey or gate_pub()).hex(), "gate_id": gate_id}
    blk.update(action_fields(action_type, action, salt, with_hash=False))
    blk.update({"now": str(now), "skew_s": str(skew)})
    return blk


def check_of(blk: dict) -> AuthorizationCheck:
    from vecjson import action_from_case
    salt = bytes.fromhex(blk["action_salt_hex"]) if "action_salt_hex" in blk else None
    return AuthorizationCheck(bytes.fromhex(blk["gate_pubkey_hex"]), blk["gate_id"], blk["action_type"],
                              action_from_case(blk), int(blk["now"]), int(blk["skew_s"]), salt)


def auth_canon(a: dict) -> bytes:
    return encode(to_cbor(a, AUTHORIZATION))


def sign_auth(canon: bytes, signer: str = "gate1"):
    ah = authorization_hash(canon)
    msg = signing_message(ah, TAG_AUTHORIZATION_SIG)
    return ah, msg, sk(signer).sign(msg)


def signed_pair(inner: bytes, sig: bytes) -> bytes:
    return encode({1: Raw(inner), 2: sig})


def auth_fields(a: dict | None, canon: bytes, signer: str = "gate1") -> dict:
    ah, msg, sig = sign_auth(canon, signer)
    out = {}
    if a is not None:
        out["input"] = aj(a)
    out.update({"authorization_cbor_hex": canon.hex(), "authorization_hash_hex": ah.hex(), "signer": signer,
                "signed_message_hex": msg.hex(), "signature_hex": sig.hex(),
                "signed_authorization_hex": signed_pair(canon, sig).hex()})
    return out


def base_auth(ref: str, path: int = 1, mode: int = 1, deadline: int | None = None, authorized_at: int = NOW) -> dict:
    c, canon, _, _, _ = VALID[ref]
    a = {"version": 1, "commitment_hash": commitment_hash(canon), "action_hash": c["action"]["hash"],
         "gate_id": c["scope"]["gate_id"], "expires": authorization_expires(c["valid_until"], authorized_at, MAX_AUTH_TTL),
         "path": path, "mode": mode}
    if deadline is not None:
        a["anchor_deadline"] = deadline
    return a


AUTH_SIGNATURES: dict = {}
AUTH_CACHE: dict = {}


def authorization_vectors() -> dict:
    cases, rejects = [], []

    def add(cid, desc, ref, a, extra=None):
        _, _, at, act, salt = VALID[ref]
        canon = auth_canon(a)
        case = {"id": cid, "description": desc, "commitment_ref": ref, "authorized_at": str(NOW)}
        if extra:
            case.update(extra)
        case.update(auth_fields(a, canon))
        blk = check_block(at, act, NOW, salt)
        verify_authorization(bytes.fromhex(case["signed_authorization_hex"]), check_of(blk))
        case["check"] = blk
        AUTH_SIGNATURES[cid] = (canon, bytes.fromhex(case["signature_hex"]))
        cases.append(case)
        return case

    for cid, desc, ref, path in [
        ("auth_minimal_lmt_da", "minimal_lmt authorized at now; payload accepted from the DA layer (path 1); strict "
         "mode. expires = min(valid_until, authorized_at + 300) = authorized_at + 300.", "minimal_lmt", 1),
        ("auth_minimal_lmt_archive", "As auth_minimal_lmt_da with path 2 (archive). Differs only in key 6.",
         "minimal_lmt", 2),
        ("auth_expires_is_valid_until", "ttl_max_at_601s_retention: valid_until is 90 s after authorized_at, so "
         "expires = valid_until.", "ttl_max_at_601s_retention", 1),
        ("auth_fibre_small_payload", "fibre_small_payload (da = fibre), DA path.", "fibre_small_payload", 1),
        ("auth_action_json_bytes", "action_json_bytes: the executor recomputes the action hash with type "
         "application/json over the salt and the JSON bytes.", "action_json_bytes", 1),
        ("auth_action_max_size", f"action_max_size: {MAX_ACTION_SIZE} action bytes (pattern {PATTERN}).",
         "action_max_size", 1),
        ("auth_action_type_128_chars", "action_type_128_chars: a 128-byte action type inside the action hash preimage.",
         "action_type_128_chars", 1),
    ]:
        add(cid, desc, ref, base_auth(ref, path))
    add("auth_v1_strict_da", "v1_minimal_included_blob, payload from DA (path 1), mode 1, no deadline.",
        "v1_minimal_included_blob", base_auth("v1_minimal_included_blob", 1, 1, None))
    add("auth_v1_strict_archive", "v1_mandate_ref, payload from the archive (path 2), mode 1.",
        "v1_mandate_ref", base_auth("v1_mandate_ref", 2, 1, None))
    w = E.fast_window(1, H0_FIBRE, H0_FIBRE + 2, 100, 10, 200, chain_window=1000)
    add("auth_v1_fast_fibre", f"v1_pending_fibre_mandate_ref in fast mode: head = h0 + 2, FastWindowBlocks 100, "
        f"mandate bound 200, chain window 1000, so anchor_deadline = h0 + 100 = {w}.",
        "v1_pending_fibre_mandate_ref", base_auth("v1_pending_fibre_mandate_ref", 1, 2, w),
        {"window_inputs": {"da": "1", "h0": str(H0_FIBRE), "head": str(H0_FIBRE + 2), "fast_window_blocks": "100",
                           "max_h0_age": "10", "fast_mode_max_delay": "200", "chain_window": "1000",
                           "min_fast_slack_blocks": "3"}})
    w = E.fast_window(2, H0_BLOB, H0_BLOB + 1, 100, 10, 200, timeout_height=H0_BLOB + 40)
    add("auth_v1_fast_blob_timeout_lowered", f"v1_pending_blob_mandate_ref in fast mode: the PFB's "
        f"timeout_height h0 + 40 is below h0 + 100 (mandate bound 200), so anchor_deadline = {w}, which is at "
        f"least head + MinFastSlackBlocks.",
        "v1_pending_blob_mandate_ref", base_auth("v1_pending_blob_mandate_ref", 2, 2, w),
        {"window_inputs": {"da": "2", "h0": str(H0_BLOB), "head": str(H0_BLOB + 1), "fast_window_blocks": "100",
                           "max_h0_age": "10", "fast_mode_max_delay": "200", "timeout_height": str(H0_BLOB + 40),
                           "min_fast_slack_blocks": "3"}})
    big = {"version": 1, "commitment_hash": h("v1 auth max commitment"), "action_hash": h("v1 auth max action"),
           "gate_id": "g" * 64, "expires": E.MAX_INT, "path": 2, "mode": 2, "anchor_deadline": E.MAX_INT}
    case = {"id": "auth_v1_max_size", "description": "Largest SignedAuthorization: gate_id 64 chars, expires and "
            "anchor_deadline 2^63-1 (9-byte heads), 233 bytes. Encoding and signature only (stand-in hashes)."}
    case.update(auth_fields(big, auth_canon(big)))
    assert len(bytes.fromhex(case["signed_authorization_hex"])) == 233
    cases.append(case)

    m = VALID["minimal_lmt"]
    base_a = base_auth("minimal_lmt")
    base_canon = auth_canon(base_a)
    _, _, base_sig = sign_auth(base_canon)
    base_signed = signed_pair(base_canon, base_sig)
    salt_m = m[4]
    base_check = check_block(IBKR, ACTION_MINIMAL, salt=salt_m)

    def rj(cid, stage, rule, desc, data: bytes, expect, a=None, chk=None, ref="minimal_lmt"):
        blk = chk or base_check
        case = {"id": cid, "stage": stage, "rule": rule, "description": desc, "commitment_ref": ref,
                "signed_authorization_hex": data.hex(), "check": blk, "expect_error": expect}
        if a is not None:
            canon = auth_canon(a)
            case["input"] = aj(a)
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
        return signed_pair(inner, sign_auth(inner)[2])

    def raw_auth(repl: dict, drop=(), a=base_a) -> bytes:
        mm = to_cbor(a, AUTHORIZATION)
        mm.update(repl)
        for k in drop:
            mm.pop(k)
        return encode(mm)

    # Decoding.
    rj("authorization_too_large", "D", "D0", f"{MAX_AUTHORIZATION_SIZE + 1} bytes: a valid Authorization followed by "
       "zero bytes. Size is checked before parsing.",
       base_signed + bytes(MAX_AUTHORIZATION_SIZE + 1 - len(base_signed)), "ErrTooLarge")
    rj("authorization_trailing_byte", "D", "D2", "A valid SignedAuthorization followed by one zero byte.",
       base_signed + b"\x00", "ErrTrailingData")
    rj("authorization_unknown_key", "D", "D15", "Authorization key 9 (undefined) added.", resign(raw_auth({9: 1})),
       "ErrUnknownKey")
    rj("signed_authorization_unknown_key", "D", "D15", "SignedAuthorization key 3 (undefined) added.",
       encode({1: Raw(base_canon), 2: base_sig, 3: 0}), "ErrUnknownKey")
    rj("authorization_missing_path", "D", "D17", "Key 6 path absent.", resign(raw_auth({}, drop=(6,))),
       "ErrMissingField")
    rj("authorization_missing_expires", "D", "D17", "Key 5 expires absent.", resign(raw_auth({}, drop=(5,))),
       "ErrMissingField")
    rj("authorization_missing_signature", "D", "D17", "SignedAuthorization without key 2.", encode({1: Raw(base_canon)}),
       "ErrMissingField")
    rj("authorization_commitment_hash_31_bytes", "D", "D18", "commitment_hash of 31 bytes.",
       resign(raw_auth({2: base_a["commitment_hash"][:31]})), "ErrFieldSize")
    rj("authorization_action_hash_33_bytes", "D", "D18", "action_hash of 33 bytes.",
       resign(raw_auth({3: base_a["action_hash"] + b"\x00"})), "ErrFieldSize")
    rj("authorization_gate_id_empty", "D", "D18", "gate_id is the empty string.", resign(raw_auth({4: ""})),
       "ErrFieldSize")
    rj("authorization_gate_id_65_chars", "D", "D18", "gate_id of 65 characters.", resign(raw_auth({4: "g" * 65})),
       "ErrFieldSize")
    rj("authorization_sig_63_bytes", "D", "D18", "Signature of 63 bytes.", encode({1: Raw(base_canon), 2: base_sig[:63]}),
       "ErrFieldSize")
    rj("authorization_gate_id_unicode", "D", "D19", "gate_id contains U+03BF (Greek small omicron), a look-alike of "
       "'o'.", resign(raw_auth({4: "gate-paper-ο1"})), "ErrInvalidString")
    rj("authorization_path_tstr", "D", "D16", "path encoded as the text string \"1\".", resign(raw_auth({6: "1"})),
       "ErrWrongType")
    rj("authorization_action_hash_tstr", "D", "D16", "action_hash as 64 hex characters.",
       resign(raw_auth({3: base_a["action_hash"].hex()})), "ErrWrongType")
    rj("authorization_expires_nonminimal", "D", "D7", "expires in a 9-byte head although it fits in 5.",
       resign(raw_auth({5: Raw(b"\x1b" + base_a["expires"].to_bytes(8, "big"))})), "ErrNonMinimalInt")
    rj("authorization_expires_float", "D", "D3", "expires as a float64.",
       resign(raw_auth({5: Raw(b"\xfb" + struct.pack(">d", float(base_a["expires"])))})), "ErrFloat")
    items = sorted(to_cbor(base_a, AUTHORIZATION).items())
    items[4], items[5] = items[5], items[4]
    rj("authorization_unsorted_map", "D", "D10", "Keys 5 and 6 swapped.", resign(encode(Pairs(tuple(items)))),
       "ErrUnsortedMap")

    # Static checks, correctly signed.
    def s_rj(cid, rule, desc, a, expect):
        rj(cid, "S", rule, desc, resign(auth_canon(a)), expect, a)

    s_rj("authorization_version_0", "Q1", "version = 0, every other key as auth_minimal_lmt_da.",
         dict(base_a, version=0), "ErrUnsupportedVersion")
    s_rj("authorization_version_2", "Q1", "version = 2.", dict(base_a, version=2), "ErrUnsupportedVersion")
    s_rj("authorization_expires_2pow63", "Q2", "expires = 2^63.", dict(base_a, expires=1 << 63), "ErrIntRange")
    s_rj("authorization_path_0", "Q3", "path = 0.", dict(base_a, path=0), "ErrInvalidEnum")
    s_rj("authorization_path_3", "Q3", "path = 3.", dict(base_a, path=3), "ErrInvalidEnum")
    s_rj("authorization_expires_0", "Q4", "expires = 0.", dict(base_a, expires=0), "ErrZeroValue")

    # Signature checks under the pinned gate key.
    def g_rj(cid, rule, desc, a, sig, chk=None):
        rj(cid, "G", rule, desc, signed_pair(auth_canon(a), sig),
           "ErrInvalidPublicKey" if rule == "G0" else "ErrSignatureInvalid", a, chk)

    ident = ed.encode(ed.IDENTITY)
    sig_id, forged = small_order_forgery(ident, signing_message(authorization_hash(base_canon), TAG_AUTHORIZATION_SIG))
    assert forged
    g_rj("authorization_pinned_key_identity", "G0", "The executor pinned the identity point as the gate key; R = "
         "identity, S = 0 satisfies the cofactorless equation, so only G0 rejects it.",
         base_a, sig_id, check_block(IBKR, ACTION_MINIMAL, salt=salt_m, pubkey=ident))
    g_rj("authorization_signed_by_agent_key", "G1", "Signed by agent1 (an agent key) under the Authorization tags; the "
         "executor pins gate1.", base_a, sign_auth(base_canon, "agent1")[2])
    g_rj("authorization_signed_by_other_gate", "G1", "Signed by agent2's key standing in for another gate's key; the "
         "executor pins gate1.", base_a, sign_auth(base_canon, "agent2")[2])
    g_rj("authorization_signed_under_commitment_sig_tag", "G1", "gate1 signed edicta/v1/sig || authorization_hash (the "
         "agent signature tag).", base_a, sk("gate1").sign(signing_message(authorization_hash(base_canon), TAG_SIG)))
    g_rj("authorization_signed_under_receipt_sig_tag", "G1", "gate1 signed edicta/v1/receipt-sig || authorization_hash "
         "(the receipt signature tag).", base_a,
         sk("gate1").sign(signing_message(authorization_hash(base_canon), TAG_RECEIPT_SIG)))
    g_rj("authorization_wrong_hash_tag", "G1", "The Authorization bytes hashed under edicta/v1/receipt instead of "
         "edicta/v1/authorization.", base_a,
         sk("gate1").sign(signing_message(hashlib.sha256(tagged(TAG_RECEIPT) + base_canon).digest(),
                                          TAG_AUTHORIZATION_SIG)))
    g_rj("authorization_sig_raw_cbor", "G1", "Signature over the raw Authorization CBOR instead of the tagged message.",
         base_a, sk("gate1").sign(base_canon))
    g_rj("authorization_flipped_expires", "G1", "expires raised by one second after signing.",
         dict(base_a, expires=base_a["expires"] + 1), base_sig)
    _, _, minimal_sig = sign_commitment(m[1])
    g_rj("authorization_reuses_commitment_signature", "G1",
         "The executor pins agent1 and the signature is agent1's signature over the minimal_lmt commitment. Different "
         "tags and hashes, so it must not verify.",
         base_a, minimal_sig, check_block(IBKR, ACTION_MINIMAL, salt=salt_m, pubkey=gate_pub("agent1")))
    s_int = int.from_bytes(base_sig[32:], "little") + ED25519_L
    g_rj("authorization_sig_noncanonical_s", "G2", "S + L in place of S.", base_a,
         base_sig[:32] + s_int.to_bytes(32, "little"))

    # Executor checks on a correctly signed Authorization.
    def x_rj(cid, rule, desc, chk, expect):
        rj(cid, "X", rule, desc, base_signed, expect, base_a, chk)

    x_rj("authorization_foreign_gate_id", "X1", "The executor expects gate_id gate-paper-2.",
         check_block(IBKR, ACTION_MINIMAL, salt=salt_m, gate_id="gate-paper-2"), "ErrScopeMismatch")
    x_rj("authorization_action_empty", "X2", "The executor presents no action bytes.",
         check_block(IBKR, b"", salt=salt_m), "ErrActionSize")
    x_rj("authorization_action_too_large", "X2", f"The executor presents {MAX_ACTION_SIZE + 1} bytes (pattern "
         f"{PATTERN}).", check_block(IBKR, pattern_bytes(PATTERN, MAX_ACTION_SIZE + 1), salt=salt_m), "ErrActionSize")
    flipped = bytearray(ACTION_MINIMAL)
    flipped[-1] ^= 0x01
    x_rj("authorization_action_byte_flipped", "X3", "The bytes the executor is about to send differ in the last byte.",
         check_block(IBKR, bytes(flipped), salt=salt_m), "ErrActionMismatch")
    x_rj("authorization_action_other_order", "X3", "The executor holds another order (qty 100001) than the one "
         "authorized.", check_block(IBKR, order_encode(dict(ORDER_MINIMAL, qty=100001)), salt=salt_m),
         "ErrActionMismatch")
    x_rj("authorization_action_other_type", "X3", "Right bytes and salt, but the executor recomputes the hash under "
         "application/octet-stream.", check_block(TYPE_OCTETS, ACTION_MINIMAL, salt=salt_m), "ErrActionMismatch")
    x_rj("authorization_expired", "X4", "now + skew == expires.",
         check_block(IBKR, ACTION_MINIMAL, now=base_a["expires"] - 30, salt=salt_m), "ErrExpired")
    x_rj("authorization_expired_after", "X4", "now past expires.",
         check_block(IBKR, ACTION_MINIMAL, now=base_a["expires"] + 1, salt=salt_m), "ErrExpired")
    x_rj("authorization_expired_skew_0", "X4", "skew 0, now == expires.",
         check_block(IBKR, ACTION_MINIMAL, now=base_a["expires"], salt=salt_m, skew=0), "ErrExpired")

    # Mode and anchor deadline.
    fast = base_auth("v1_pending_blob_mandate_ref", 2, 2, H0_BLOB + 40)
    strict = base_auth("v1_minimal_included_blob", 1, 1, None)
    fref, sref = "v1_pending_blob_mandate_ref", "v1_minimal_included_blob"
    fchk = check_block(IBKR, VALID[fref][3], salt=VALID[fref][4])
    schk = check_block(IBKR, VALID[sref][3], salt=VALID[sref][4])

    def mrj(cid, stage, rule, desc, mm: dict, expect, a, chk, ref):
        rj(cid, stage, rule, desc, resign(encode(mm)), expect, None, chk, ref)
        rejects[-1]["authorization_cbor_hex"] = encode(mm).hex()

    mm = to_cbor(fast, AUTHORIZATION); del mm[8]
    mrj("auth_v1_fast_without_deadline", "D", "D17", "mode = 2 without anchor_deadline.", mm, "ErrMissingField",
        fast, fchk, fref)
    mm = to_cbor(strict, AUTHORIZATION); mm[8] = H0_BLOB + 100
    mrj("auth_v1_strict_with_deadline", "D", "D15", "mode = 1 with anchor_deadline: key 8 is not defined for mode 1.",
        mm, "ErrUnknownKey", strict, schk, sref)
    mm = to_cbor(fast, AUTHORIZATION); mm[7] = 3
    mrj("auth_v1_mode_3", "S", "Q5", "mode = 3 with a deadline: key 8 is optional at stage D for an unknown mode, Q5 "
        "refuses.", mm, "ErrInvalidEnum", fast, fchk, fref)
    mm = to_cbor(strict, AUTHORIZATION); mm[7] = 0
    mrj("auth_v1_mode_0", "S", "Q5", "mode = 0 without a deadline.", mm, "ErrInvalidEnum", strict, schk, sref)
    mm = to_cbor(strict, AUTHORIZATION); del mm[7]
    mrj("auth_v1_missing_mode", "D", "D17", "No mode key.", mm, "ErrMissingField", strict, schk, sref)
    mm = to_cbor(fast, AUTHORIZATION); del mm[7]
    mrj("auth_v1_missing_mode_with_deadline", "D", "D17", "anchor_deadline without mode: key 8 is optional while mode "
        "is unknown, then mode is missing.", mm, "ErrMissingField", fast, fchk, fref)
    mm = to_cbor(fast, AUTHORIZATION); mm[8] = 0
    mrj("auth_v1_deadline_0", "S", "Q6", "mode = 2, anchor_deadline = 0.", mm, "ErrZeroValue", fast, fchk, fref)
    mm = to_cbor(fast, AUTHORIZATION); mm[8] = 1 << 63
    mrj("auth_v1_deadline_2pow63", "S", "Q2", "anchor_deadline = 2^63.", mm, "ErrIntRange", fast, fchk, fref)
    mm = to_cbor(strict, AUTHORIZATION); mm[7] = 1 << 63
    mrj("auth_v1_mode_2pow63", "S", "Q2", "mode = 2^63: Q2 precedes Q5.", mm, "ErrIntRange", strict, schk, sref)
    mm = to_cbor(strict, AUTHORIZATION); mm[7] = "1"
    mrj("auth_v1_mode_tstr", "D", "D16", "mode as text.", mm, "ErrWrongType", strict, schk, sref)
    rj("auth_v1_signed_by_agent", "G", "G1", "auth_v1_strict_da signed by agent1 instead of the pinned gate1.",
       signed_pair(auth_canon(strict), sign_auth(auth_canon(strict), "agent1")[2]), "ErrSignatureInvalid", strict, schk,
       sref)
    rj("auth_v1_expired", "X", "X4", "auth_v1_strict_da checked at now = expires - skew.",
       resign(auth_canon(strict)), "ErrExpired", strict,
       check_block(IBKR, VALID[sref][3], now=strict["expires"] - 30, salt=VALID[sref][4]), sref)
    a_fl = VALID[sref][3][:-1] + bytes([VALID[sref][3][-1] ^ 1])
    rj("auth_v1_action_mismatch", "X", "X3", "auth_v1_strict_da with the action's last byte flipped.",
       resign(auth_canon(strict)), "ErrActionMismatch", strict, check_block(IBKR, a_fl, salt=VALID[sref][4]), sref)
    ssalt = VALID[sref][4]
    for cid, rule, desc, salt, expect in (
            ("exec_v1_salt_missing", "X2s", "auth_v1_strict_da presented without action_salt.", None,
             "ErrMissingField"),
            ("exec_v1_salt_31", "X2s", "auth_v1_strict_da with a 31-byte action_salt.", ssalt[:31], "ErrFieldSize"),
            ("exec_v1_wrong_salt", "X3", "auth_v1_strict_da with the salt's first bit flipped.",
             bytes([ssalt[0] ^ 0x80]) + ssalt[1:], "ErrActionMismatch")):
        rj(cid, "X", rule, desc, resign(auth_canon(strict)), expect, strict,
           check_block(IBKR, VALID[sref][3], salt=salt), sref)
    padded = bytes.fromhex(cases[-1]["signed_authorization_hex"]) + bytes(256 - 233 + 1)
    rj("auth_v1_too_large", "D", "D0", "auth_v1_max_size followed by 24 zero bytes: 257 bytes.", padded,
       "ErrTooLarge", big, schk, sref)
    rejects[-1].pop("commitment_ref")
    return {"format": FORMAT, "revision": REVISION, "max_authorization_ttl_s": str(MAX_AUTH_TTL),
            "gate": gate_to_json(GATE), "patterns": PATTERNS, "cases": cases, "reject": rejects}


# receipt.json and record_request.json

RECORDED_AT = NOW + 2
IBKR_ORDER_ID = "1370093239"
ID_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._:/-"
EXECUTOR = "executor1"


def receipt_for(chash: bytes, rail_ref: str = IBKR_ORDER_ID, recorded_at: int = RECORDED_AT,
                executor: str = EXECUTOR) -> dict:
    return {
        "version": 1,
        "commitment_hash": chash,
        "gate_id": GID,
        "gate_pubkey": gate_pub(),
        "rail_ref": rail_ref,
        "recorded_at": recorded_at,
        "executor_pubkey": gate_pub(executor),
        "executor_signature": sk(executor).sign(record_message(chash, GID, rail_ref)),
    }


def signed_receipt(r: dict, signer: str = "gate1") -> bytes:
    canon = encode(to_cbor(r, RECEIPT))
    return signed_pair(canon, sk(signer).sign(signing_message(receipt_hash(canon), TAG_RECEIPT_SIG)))


def receipt_vectors() -> dict:
    hashes = {k: commitment_hash(v[1]) for k, v in VALID.items()}
    cases = []

    def rjson(r: dict) -> dict:
        return _conv(r, RECEIPT, True)

    def add(cid, desc, ref, r):
        canon = encode(to_cbor(r, RECEIPT))
        rh = receipt_hash(canon)
        msg = signing_message(rh, TAG_RECEIPT_SIG)
        sig = sk("gate1").sign(msg)
        cases.append({
            "id": cid, "description": desc, "commitment_ref": ref, "signer": "gate1",
            "input": rjson(r), "receipt_cbor_hex": canon.hex(), "receipt_hash_hex": rh.hex(),
            "signed_message_hex": msg.hex(), "signature_hex": sig.hex(),
            "signed_receipt_hex": signed_pair(canon, sig).hex(),
        })

    m = hashes["minimal_lmt"]
    add("receipt_minimal_lmt", "minimal_lmt: the integrator reported the IBKR order id 1370093239; the gate notarized "
        "it.", "minimal_lmt", receipt_for(m))
    add("receipt_fibre_small_payload", "fibre_small_payload (da = fibre).", "fibre_small_payload",
        receipt_for(hashes["fibre_small_payload"]))
    ref128 = (ID_ALPHABET * 2)[:128]
    add("receipt_rail_ref_max", "rail_ref of 128 characters covering the whole ID charset.", "minimal_lmt",
        receipt_for(m, rail_ref=ref128))
    add("receipt_rail_ref_tx_hash", "rail_ref holding a 64-character lowercase hex transaction hash, as an EVM "
        "integrator would report.", "action_json_bytes", receipt_for(hashes["action_json_bytes"],
                                                                     rail_ref=h("example tx").hex()))
    add("receipt_recorded_at_max", "recorded_at = 2^63-1, the largest allowed uint.", "minimal_lmt",
        receipt_for(m, recorded_at=(1 << 63) - 1))
    add("receipt_executor2", "The claim came from executor2, the other allowlisted executor.", "minimal_lmt",
        receipt_for(m, executor="executor2"))
    for c in cases:
        assert len(bytes.fromhex(c["signed_receipt_hex"])) <= MAX_RECEIPT_SIZE

    base_r = receipt_for(m)
    base_canon = encode(to_cbor(base_r, RECEIPT))
    base_sig = sk("gate1").sign(signing_message(receipt_hash(base_canon), TAG_RECEIPT_SIG))
    base_signed = signed_pair(base_canon, base_sig)
    rejects = []

    def rj(cid, stage, rule, desc, data: bytes, expect, r=None):
        case = {"id": cid, "stage": stage, "rule": rule, "description": desc,
                "signed_receipt_hex": data.hex(), "expect_error": expect}
        if r is not None:
            canon = encode(to_cbor(r, RECEIPT))
            case["input"] = rjson(r)
            case["receipt_cbor_hex"] = canon.hex()
            case["receipt_hash_hex"] = receipt_hash(canon).hex()
        try:
            E.verify_receipt(data)
        except Reject as e:
            assert e.sentinel == expect, (cid, e)
        else:
            raise AssertionError(cid)
        rejects.append(case)

    def resign(inner: bytes) -> bytes:
        return signed_pair(inner, sk("gate1").sign(signing_message(receipt_hash(inner), TAG_RECEIPT_SIG)))

    def raw_receipt(repl: dict, drop=()) -> bytes:
        mm = to_cbor(base_r, RECEIPT)
        mm.update(repl)
        for k in drop:
            mm.pop(k)
        return encode(mm)

    big = base_signed + bytes(MAX_RECEIPT_SIZE + 1 - len(base_signed))
    rj("receipt_too_large", "D", "D0", f"{MAX_RECEIPT_SIZE + 1} bytes: a valid receipt followed by zero bytes. Size is "
       "checked before parsing, so this is not ErrTrailingData.", big, "ErrTooLarge")
    rj("receipt_trailing_byte", "D", "D2", "A valid signed receipt followed by one zero byte.", base_signed + b"\x00",
       "ErrTrailingData")
    rj("receipt_unknown_key", "D", "D15", "Receipt key 11 (undefined) added.", resign(raw_receipt({11: 1})),
       "ErrUnknownKey")
    rj("receipt_retired_rail_key", "D", "D15", "Receipt carries key 5 (unassigned) = 1.", resign(raw_receipt({5: 1})),
       "ErrUnknownKey")
    rj("receipt_retired_path_key", "D", "D15", "Receipt carries key 7 (unassigned; the path is in the Authorization) "
       "= 1.", resign(raw_receipt({7: 1})), "ErrUnknownKey")
    rj("signed_receipt_unknown_key", "D", "D15", "SignedReceipt key 3 (undefined) added.",
       encode({1: Raw(base_canon), 2: base_sig, 3: 0}), "ErrUnknownKey")
    for k, name in ((6, "rail_ref"), (8, "recorded_at"), (9, "executor_pubkey"), (10, "executor_signature")):
        rj(f"receipt_missing_{name}", "D", "D17", f"Key {k} {name} absent.", resign(raw_receipt({}, drop=(k,))),
           "ErrMissingField")
    rj("receipt_missing_signature", "D", "D17", "SignedReceipt without key 2.", encode({1: Raw(base_canon)}),
       "ErrMissingField")
    rj("receipt_executor_pubkey_31_bytes", "D", "D18", "executor_pubkey of 31 bytes.",
       resign(raw_receipt({9: base_r["executor_pubkey"][:31]})), "ErrFieldSize")
    rj("receipt_executor_signature_63_bytes", "D", "D18", "executor_signature of 63 bytes.",
       resign(raw_receipt({10: base_r["executor_signature"][:63]})), "ErrFieldSize")
    rj("receipt_rail_ref_bad_charset", "D", "D19", "rail_ref contains '#', outside the ID charset.",
       resign(raw_receipt({6: "1370093239#1"})), "ErrInvalidString")
    rj("receipt_rail_ref_empty", "D", "D18", "rail_ref is the empty string.", resign(raw_receipt({6: ""})),
       "ErrFieldSize")
    rj("receipt_rail_ref_129_chars", "D", "D18", "rail_ref of 129 characters.", resign(raw_receipt({6: "1" * 129})),
       "ErrFieldSize")
    rj("receipt_gate_id_unicode", "D", "D19", "gate_id contains U+03BF (Greek small omicron), a look-alike of 'o'.",
       resign(raw_receipt({3: "gate-paper-ο1"})), "ErrInvalidString")
    rj("receipt_commitment_hash_31_bytes", "D", "D18", "commitment_hash of 31 bytes.", resign(raw_receipt({2: m[:31]})),
       "ErrFieldSize")
    rj("receipt_gate_pubkey_33_bytes", "D", "D18", "gate_pubkey of 33 bytes.",
       resign(raw_receipt({4: base_r["gate_pubkey"] + b"\x00"})), "ErrFieldSize")
    rj("receipt_sig_63_bytes", "D", "D18", "Signature of 63 bytes.", encode({1: Raw(base_canon), 2: base_sig[:63]}),
       "ErrFieldSize")
    rj("receipt_recorded_at_tstr", "D", "D16", "recorded_at encoded as a text string.",
       resign(raw_receipt({8: str(RECORDED_AT)})), "ErrWrongType")
    rj("receipt_rail_ref_bstr", "D", "D16", "rail_ref encoded as a byte string.",
       resign(raw_receipt({6: IBKR_ORDER_ID.encode()})), "ErrWrongType")
    rj("receipt_recorded_at_nonminimal", "D", "D7", "recorded_at in a 9-byte head although it fits in 5.",
       resign(raw_receipt({8: Raw(bytes([0x1b]) + RECORDED_AT.to_bytes(8, "big"))})), "ErrNonMinimalInt")
    rj("receipt_recorded_at_float", "D", "D3", "recorded_at as a float64.",
       resign(raw_receipt({8: Raw(b"\xfb" + struct.pack(">d", float(RECORDED_AT)))})), "ErrFloat")
    items = sorted(to_cbor(base_r, RECEIPT).items())
    items[4], items[5] = items[5], items[4]
    rj("receipt_unsorted_map", "D", "D10", "Keys 6 and 8 swapped.", resign(encode(Pairs(tuple(items)))),
       "ErrUnsortedMap")
    _, _, msig = sign_commitment(VALID["minimal_lmt"][1])
    rj("commitment_envelope_as_receipt", "D", "D16", "The minimal_lmt commitment envelope fed to the receipt decoder: "
       "key 2 is agent_id (tstr) where commitment_hash (bstr) is expected.", env(VALID["minimal_lmt"][1], msig),
       "ErrWrongType")
    a_canon, a_sig = AUTH_SIGNATURES["auth_minimal_lmt_da"]
    rj("authorization_as_receipt", "D", "D16", "The auth_minimal_lmt_da SignedAuthorization fed to the receipt "
       "decoder: key 3 is action_hash (bstr) where gate_id (tstr) is expected.", signed_pair(a_canon, a_sig),
       "ErrWrongType")

    def s_rj(cid, rule, desc, r, expect):
        rj(cid, "S", rule, desc, resign(encode(to_cbor(r, RECEIPT))), expect, r)

    s_rj("receipt_version_0", "R1", "version = 0, every other key as receipt_minimal_lmt.", dict(base_r, version=0),
         "ErrUnsupportedVersion")
    s_rj("receipt_version_2", "R1", "version = 2.", dict(base_r, version=2), "ErrUnsupportedVersion")
    s_rj("receipt_recorded_at_2pow63", "R2", "recorded_at = 2^63.", dict(base_r, recorded_at=1 << 63), "ErrIntRange")
    s_rj("receipt_recorded_at_0", "R5", "recorded_at = 0.", dict(base_r, recorded_at=0), "ErrZeroValue")
    gate_as_exec = dict(base_r, executor_pubkey=gate_pub(),
                        executor_signature=sk("gate1").sign(record_message(m, GID, IBKR_ORDER_ID)))
    s_rj("receipt_executor_is_gate_key", "R6", "executor_pubkey equals gate_pubkey; both signatures are valid. One key "
         "in two roles.", gate_as_exec, "ErrKeyRole")

    def g_rj(cid, rule, desc, r, sig):
        canon = encode(to_cbor(r, RECEIPT))
        rj(cid, "G", rule, desc, signed_pair(canon, sig), "ErrInvalidPublicKey" if rule == "G0" else "ErrSignatureInvalid",
           r)

    ident = ed.encode(ed.IDENTITY)
    r_id = dict(base_r, gate_pubkey=ident)
    sig_id, forged = small_order_forgery(ident, signing_message(receipt_hash(encode(to_cbor(r_id, RECEIPT))),
                                                                TAG_RECEIPT_SIG))
    assert forged
    g_rj("receipt_gate_pubkey_identity", "G0", "gate_pubkey is the identity point; R = identity, S = 0 satisfies the "
         "cofactorless equation, so only G0 rejects it.", r_id, sig_id)
    g_rj("receipt_wrong_hash_tag", "G1", "Signed over the receipt bytes hashed with the commitment tag instead of "
         "edicta/v1/receipt.", base_r,
         sk("gate1").sign(signing_message(hashlib.sha256(tagged(TAG_COMMITMENT) + base_canon).digest(), TAG_RECEIPT_SIG)))
    g_rj("receipt_signed_under_commitment_sig_tag", "G1", "Signed over edicta/v1/sig || receipt_hash (the agent "
         "signature tag) instead of edicta/v1/receipt-sig || receipt_hash.", base_r,
         sk("gate1").sign(signing_message(receipt_hash(base_canon), TAG_SIG)))
    g_rj("receipt_signed_under_authorization_sig_tag", "G1", "Signed over edicta/v1/authorization-sig || receipt_hash "
         "(the Authorization signature tag).", base_r,
         sk("gate1").sign(signing_message(receipt_hash(base_canon), TAG_AUTHORIZATION_SIG)))
    g_rj("receipt_sig_raw_cbor", "G1", "Signature over the raw receipt CBOR instead of the tagged message.", base_r,
         sk("gate1").sign(base_canon))
    g_rj("receipt_sig_wrong_key", "G1", "Signed by agent1 while gate_pubkey is gate1.", base_r,
         sk("agent1").sign(signing_message(receipt_hash(base_canon), TAG_RECEIPT_SIG)))
    g_rj("receipt_flipped_rail_ref", "G1", "rail_ref changed after signing (the signature is over rail_ref "
         "1370093239).", dict(base_r, rail_ref="1370093238"), base_sig)
    g_rj("receipt_reuses_commitment_signature", "G1", "gate_pubkey = agent1 and the signature is agent1's signature "
         "over the minimal_lmt commitment. The receipt hash differs from the commitment hash, so it must not verify.",
         dict(base_r, gate_pubkey=gate_pub("agent1")), msig)
    g_rj("receipt_reuses_authorization_signature", "G1", "The signature is gate1's signature over auth_minimal_lmt_da. "
         "Same key, other tags and hash, so it must not verify.", base_r, a_sig)
    s_int = int.from_bytes(base_sig[32:], "little") + ED25519_L
    g_rj("receipt_sig_noncanonical_s", "G2", "S + L in place of S.", base_r, base_sig[:32] + s_int.to_bytes(32, "little"))

    def ge_rj(cid, rule, desc, r):
        canon = encode(to_cbor(r, RECEIPT))
        sig = sk("gate1").sign(signing_message(receipt_hash(canon), TAG_RECEIPT_SIG))
        rj(cid, "G", rule, desc, signed_pair(canon, sig), "ErrInvalidPublicKey" if rule == "G0" else "ErrSignatureInvalid",
           r)

    msg_m = record_message(m, GID, IBKR_ORDER_ID)
    r_ei = dict(base_r, executor_pubkey=ident)
    r_ei["executor_signature"], forged = small_order_forgery(ident, msg_m)
    assert forged
    ge_rj("receipt_executor_pubkey_identity", "G0", "executor_pubkey is the identity point with a forged R = identity, "
          "S = 0 claim; the gate signature is valid.", r_ei)
    ge_rj("receipt_executor_signature_other_key", "G1", "executor_signature made by executor2 while executor_pubkey is "
          "executor1.", dict(base_r, executor_signature=sk("executor2").sign(msg_m)))
    ge_rj("receipt_executor_signature_other_rail_ref", "G1", "The executor signed rail_ref 1370093238; the receipt says "
          "1370093239 and the gate signed that.",
          dict(base_r, executor_signature=sk(EXECUTOR).sign(record_message(m, GID, "1370093238"))))
    ge_rj("receipt_executor_signature_unprefixed_rail_ref", "G1", "The executor signed the message with the rail_ref "
          "length byte missing.", dict(base_r, executor_signature=sk(EXECUTOR).sign(
              tagged(TAG_RECORD_REQUEST) + m + bytes([len(GID)]) + GID.encode() + IBKR_ORDER_ID.encode())))
    ge_rj("receipt_executor_signature_other_gate", "G1", "The executor signed the same claim for gate-paper-2; the "
          "receipt is from gate-paper-1.",
          dict(base_r, executor_signature=sk(EXECUTOR).sign(record_message(m, "gate-paper-2", IBKR_ORDER_ID))))
    es = base_r["executor_signature"]
    es_int = int.from_bytes(es[32:], "little") + ED25519_L
    ge_rj("receipt_executor_signature_noncanonical_s", "G2", "executor_signature with S + L in place of S.",
          dict(base_r, executor_signature=es[:32] + es_int.to_bytes(32, "little")))
    return {"format": FORMAT, "revision": REVISION, "gate": gate_to_json(GATE), "cases": cases, "reject": rejects}


def record_request_vectors() -> dict:
    executors = [gate_pub("executor1"), gate_pub("executor2")]
    gate_keys = [gate_pub()]
    agent = gate_pub("agent1")

    def ctx(ref):
        return commitment_hash(VALID[ref][1])

    cases = []

    def add(cid, desc, ref, rail_ref, signer=EXECUTOR):
        ch = ctx(ref)
        msg = record_message(ch, GID, rail_ref)
        sig = sk(signer).sign(msg)
        verify_record_request(ch, agent, GID, rail_ref, gate_pub(signer), sig, executors, gate_keys)
        cases.append({"id": cid, "description": desc, "commitment_ref": ref, "commitment_hash_hex": ch.hex(),
                      "agent_pubkey_hex": agent.hex(), "rail_ref": rail_ref, "signer": signer,
                      "executor_pubkey_hex": gate_pub(signer).hex(), "record_message_hex": msg.hex(),
                      "signature_hex": sig.hex()})

    add("rec_minimal_lmt", "executor1 claims IBKR order id 1370093239 for minimal_lmt.", "minimal_lmt", IBKR_ORDER_ID)
    add("rec_executor2", "executor2, the other allowlisted executor.", "minimal_lmt", IBKR_ORDER_ID, "executor2")
    add("rec_rail_ref_one_char", "rail_ref of 1 character (length byte 0x01).", "minimal_lmt", "7")
    add("rec_rail_ref_max", "rail_ref of 128 characters covering the whole ID charset (length byte 0x80).",
        "minimal_lmt", (ID_ALPHABET * 2)[:128])
    add("rec_rail_ref_tx_hash", "A 64-character hex transaction hash for the JSON action.", "action_json_bytes",
        h("example tx").hex())

    m = ctx("minimal_lmt")
    good_msg = record_message(m, GID, IBKR_ORDER_ID)
    good_sig = sk(EXECUTOR).sign(good_msg)
    rejects = []

    def rj(cid, stage, rule, desc, expect, rail_ref=IBKR_ORDER_ID, key=gate_pub(EXECUTOR), sig=good_sig,
           executor_keys=None, chash=m):
        ek = executors if executor_keys is None else executor_keys
        case = {"id": cid, "stage": stage, "rule": rule, "description": desc, "commitment_hash_hex": chash.hex(),
                "agent_pubkey_hex": agent.hex(), "rail_ref": rail_ref, "executor_pubkey_hex": key.hex(),
                "signature_hex": sig.hex()}
        if executor_keys is not None:
            case["executor_keys"] = [k.hex() for k in executor_keys]
        case["expect_error"] = expect
        try:
            verify_record_request(chash, agent, GID, rail_ref, key, sig, ek, gate_keys)
        except Reject as e:
            assert e.sentinel == expect, (cid, e)
        else:
            raise AssertionError(f"{cid} accepted")
        rejects.append(case)

    def raw_msg(rail: bytes, chash: bytes = m) -> bytes:
        return tagged(TAG_RECORD_REQUEST) + chash + bytes([len(GID)]) + GID.encode() + bytes([len(rail)]) + rail

    for cid, rr, exp, desc in [
        ("rec_rail_ref_empty", "", "ErrFieldSize", "rail_ref is empty."),
        ("rec_rail_ref_129_chars", "1" * 129, "ErrFieldSize", "rail_ref of 129 characters."),
        ("rec_rail_ref_bad_charset", "1370093239#1", "ErrInvalidString", "rail_ref contains '#'."),
        ("rec_rail_ref_unicode", "13700932ο9", "ErrInvalidString", "rail_ref contains U+03BF (Greek small omicron)."),
    ]:
        b = rr.encode("utf-8")
        sig = sk(EXECUTOR).sign(raw_msg(b))
        rj(cid, "D", "RQ1", desc + " Signed by executor1 over the raw bytes, so only the rail_ref rule fails.", exp,
           rail_ref=rr, sig=sig)
    ident = ed.encode(ed.IDENTITY)
    fsig, forged = small_order_forgery(ident, good_msg)
    assert forged
    rj("rec_executor_key_identity", "G", "G0", "Presented executor key is the identity point; R = identity, S = 0 "
       "satisfies the cofactorless equation, so only G0 rejects it.", "ErrInvalidPublicKey", key=ident, sig=fsig,
       executor_keys=executors + [ident])
    rj("rec_sig_wrong_key", "G", "G1", "Signed by executor2, presented as executor1.", "ErrSignatureInvalid",
       sig=sk("executor2").sign(good_msg))
    rj("rec_sig_other_rail_ref", "G", "G1", "Signed over rail_ref 1370093238, presented with 1370093239.",
       "ErrSignatureInvalid", sig=sk(EXECUTOR).sign(record_message(m, GID, "1370093238")))
    rj("rec_sig_other_commitment", "G", "G1", "Signed over the commitment_hash of ttl_exactly_max, presented for "
       "minimal_lmt.", "ErrSignatureInvalid", sig=sk(EXECUTOR).sign(record_message(ctx("ttl_exactly_max"), GID,
                                                                                 IBKR_ORDER_ID)))
    rj("rec_sig_other_gate", "G", "G1", "Signed for gate-paper-2, presented to gate-paper-1: the gate binds its own "
       "gate_id into the message.", "ErrSignatureInvalid",
       sig=sk(EXECUTOR).sign(record_message(m, "gate-paper-2", IBKR_ORDER_ID)))
    rj("rec_sig_gate_id_unprefixed", "G", "G1", "Signed over the gate_id without its length byte.", "ErrSignatureInvalid",
       sig=sk(EXECUTOR).sign(tagged(TAG_RECORD_REQUEST) + m + GID.encode() + bytes([10]) + IBKR_ORDER_ID.encode()))
    rj("rec_sig_rail_ref_unprefixed", "G", "G1", "Signed with the rail_ref length byte missing.", "ErrSignatureInvalid",
       sig=sk(EXECUTOR).sign(tagged(TAG_RECORD_REQUEST) + m + bytes([len(GID)]) + GID.encode() + IBKR_ORDER_ID.encode()))
    rj("rec_sig_tag_unprefixed", "G", "G1", "Signed over the tag without its length byte.", "ErrSignatureInvalid",
       sig=sk(EXECUTOR).sign(TAG_RECORD_REQUEST + m + bytes([len(GID)]) + GID.encode() + bytes([10])
                             + IBKR_ORDER_ID.encode()))
    rj("rec_sig_under_receipt_sig_tag", "G", "G1", "Signed with edicta/v1/receipt-sig in place of "
       "edicta/v1/record-request.", "ErrSignatureInvalid",
       sig=sk(EXECUTOR).sign(tagged(TAG_RECEIPT_SIG) + m + bytes([len(GID)]) + GID.encode() + bytes([10])
                             + IBKR_ORDER_ID.encode()))
    rj("rec_sig_over_hash", "G", "G1", "Signed over SHA-256(record message) instead of the message itself.",
       "ErrSignatureInvalid", sig=sk(EXECUTOR).sign(hashlib.sha256(good_msg).digest()))
    s_int = int.from_bytes(good_sig[32:], "little") + ED25519_L
    rj("rec_sig_noncanonical_s", "G", "G2", "S + L in place of S.", "ErrSignatureInvalid",
       sig=good_sig[:32] + s_int.to_bytes(32, "little"))
    rj("rec_executor_not_allowed", "R", "RQ3", "A valid request signed by agent2, which is not in the executor "
       "allowlist.", "ErrExecutorNotAllowed", key=gate_pub("agent2"), sig=sk("agent2").sign(good_msg))
    rj("rec_gate_key_not_executor", "R", "RQ3", "A valid request signed by the gate's own key, which is not in the "
       "executor allowlist.", "ErrExecutorNotAllowed", key=gate_pub(), sig=sk("gate1").sign(good_msg))
    rj("rec_gate_key_in_allowlist", "R", "RQ4", "Misconfigured allowlist that contains the gate key; the request is "
       "signed by the gate key.", "ErrKeyRole", key=gate_pub(), sig=sk("gate1").sign(good_msg),
       executor_keys=executors + [gate_pub()])
    rj("rec_agent_key_in_allowlist", "R", "RQ4", "Misconfigured allowlist that contains agent1, the commitment's own "
       "agent key; signed by agent1.", "ErrKeyRole", key=agent, sig=sk("agent1").sign(good_msg),
       executor_keys=executors + [agent])
    return {"format": FORMAT, "revision": REVISION,
            "gate": {"gate_id": GID, "gate_pubkey_hex": gate_pub().hex(),
                     "executor_keys": [k.hex() for k in executors]},
            "keys": EXECUTOR_KEYS, "cases": cases, "reject": rejects}


# limits.json

def limits_vectors() -> dict:
    c, canon, _, _, _ = VALID["v1_maximal"]
    _, _, sig = sign_commitment(canon)
    envb = env(canon, sig)
    over = envb + bytes(E.MAX_SIGNED_SIZE + 1 - len(envb))
    m = to_cbor(c, COMMITMENT)
    m[16] = bytes(2048 - len(canon) - 4 + 1)
    big = encode(m)
    assert len(big) == 2049, len(big)
    _, _, bsig = sign_commitment(big)
    big_env = env(big, bsig)
    assert len(big_env) <= E.MAX_SIGNED_SIZE
    auth = AUTH_CACHE["auth_v1_max_size"]
    return {"format": FORMAT, "revision": REVISIONS["limits.json"],
            "limits": {"max_signed_size": str(E.MAX_SIGNED_SIZE), "max_commitment_size": str(E.MAX_COMMITMENT_SIZE),
                       "max_authorization_size": str(E.MAX_AUTHORIZATION_SIZE),
                       "max_v1_commitment": "596", "max_v1_envelope": "665", "max_v1_signed_authorization": "233"},
            "cases": [
                {"id": "v1_envelope_maximal", "description": "valid.json v1_maximal: 665 bytes, accepted.",
                 "envelope_hex": envb.hex(), "size": str(len(envb)), "now": str(c["issued_at"]),
                 "gate": gate_to_json({"gate_id": "g" * 64, "action_types": [TYPE_128]}), "expect": "accept"},
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
    skew = PARAMS.skew_s

    def k1case(cid, desc, issued_at, t, sk_, da=None, form="included", err=None):
        c = {"id": cid, "description": desc}
        if da is not None:
            c["da"] = str(da)
        c.update({"form": form, "issued_at": str(issued_at), "t_ref": str(t), "skew_s": str(sk_)})
        if err:
            c["expect_error"] = err
        try:
            check_anchor_time(issued_at, t, sk_)
            assert err is None, cid
        except Reject as e:
            assert e.sentinel == err, cid
        return c

    b = t_ref
    k1 = [
        k1case("k1_pending_fibre_at_limit", "Pending Fibre reference: issued_at + skew == T_ref (header time at h0).",
               t_ref - 30, t_ref, 30, 1, "pending"),
        k1case("k1_pending_blob_one_second_early", "Pending blob reference: issued_at + skew == T_ref - 1.",
               t_ref - 31, t_ref, 30, 2, "pending", "ErrIssuedBeforeAnchor"),
        k1case("k1_included_blob", "Included reference: T_ref = T_H.", t_ref, t_ref, 30, 2),
        k1case("k1_at_limit", "issued_at + skew_s == T_ref: accepted.", b - skew, b, skew),
        k1case("k1_one_second_early", "issued_at + skew_s == T_ref - 1.", b - skew - 1, b, skew,
               err="ErrIssuedBeforeAnchor"),
        k1case("k1_skew_0_equal", "skew_s = 0, issued_at == T_ref: accepted.", b, b, 0),
        k1case("k1_skew_0_one_second_early", "skew_s = 0, issued_at == T_ref - 1.", b - 1, b, 0,
               err="ErrIssuedBeforeAnchor"),
        k1case("k1_minimal_lmt", "issued_at of minimal_lmt, signed 3000 s after the anchor block.", T0, b, skew),
        k1case("k1_block_time_u64_max", "A block time of 2^64-1 (hostile header): rejected without overflow.",
               (1 << 63) - 1, U64_MAX, 300, err="ErrIssuedBeforeAnchor"),
    ]

    def k2(cid, desc, da, form, valid_until, r, creation=None, created_at=None):
        start = E.retention_start(da, form == "pending", t_ref, creation or 0, created_at or 0)
        within = within_retention(valid_until, start, r)
        case = {"id": cid, "description": desc, "da": str(da), "form": form, "t_ref": str(t_ref),
                "valid_until": str(valid_until), "retention_s": str(r)}
        if creation is not None:
            case["creation_timestamp"] = str(creation)
        if created_at is not None:
            case["intent_created_at"] = str(created_at)
        case["expect"] = {"start": str(start), "margin": str(retention_margin(r)), "within": within}
        return case

    k2s = [
        k2("k2_pending_fibre_created_before", "Pending Fibre: intent created_at = floor(promise.creation_timestamp) "
           "= T_ref - 20, so start = created_at; valid_until + 600 == start + 14400.", 1, "pending",
           t_ref - 20 + 14400 - 600, 14400, created_at=t_ref - 20),
        k2("k2_pending_fibre_one_over", "Same, one second over.", 1, "pending", t_ref - 20 + 14400 - 600 + 1, 14400,
           created_at=t_ref - 20),
        k2("k2_pending_fibre_created_after", "created_at after T_ref (clock skew of the promise): start = T_ref.",
           1, "pending", t_ref + 14400 - 600, 14400, created_at=t_ref + 5),
        k2("k2_included_fibre", "Included Fibre reference: start = min(T_ref, promise creation).", 1,
           "included", t_ref - 7 + 14400 - 600, 14400, creation=t_ref - 7),
        k2("k2_pending_blob", "Pending blob: start = T_ref (header time at h0).", 2, "pending", t_ref + 14400 - 600,
           14400),
        k2("k2_pending_blob_one_over", "Pending blob, one second over.", 2, "pending", t_ref + 14400 - 600 + 1, 14400),
    ]

    k2r = []

    def k2case(cid, desc, da, valid_until, block_time, expect_window, within, blob_r=None,
               latest=None, at_h=None, creation=None, error=None):
        c = {"id": cid, "description": desc, "da": str(da), "valid_until": str(valid_until), "t_ref": str(block_time)}
        if da == DA_CELESTIA_BLOB:
            c["blob_retention_s"] = str(blob_r)
        else:
            c["fibre_retention_latest_s"] = str(latest)
            if at_h is not None:
                c["fibre_retention_at_height_s"] = str(at_h)
            c["creation_timestamp"] = str(creation)
        if error is not None:
            c["expect"] = {"expect_error": error}
            try:
                retention_window(da, block_time, Params(latest, 14400, skew), latest, at_h, creation or 0)
            except Reject as e:
                assert e.sentinel == error, cid
            else:
                raise AssertionError(cid)
            k2r.append(c)
            return
        exp = {"within": within}
        if expect_window is not None:
            r, start = expect_window
            exp.update({"r": str(r), "start": str(start), "margin": str(min(600, r // 8))})
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
            assert w == expect_window, cid
            assert within_retention(valid_until, w[1], w[0]) == within, cid
        try:
            assert route(da, within) == exp.get("route"), cid
        except Reject as e:
            assert e.sentinel == exp.get("expect_error"), cid
        k2r.append(c)

    r = 14400
    k2case("k2_blob_at_limit", "da = 2: valid_until + 600 == T_ref + 14400. DA path.", 2, b + r - 600, b, (r, b), True,
           blob_r=r)
    k2case("k2_blob_one_second_over", "da = 2: one second past the limit. The DA path is skipped; archive with P1, P2, "
           "P3.", 2, b + r - 600 + 1, b, (r, b), False, blob_r=r)
    k2case("k2_blob_minimal_lmt", "da = 2: minimal_lmt valid_until, anchor 3000 s before issued_at.", 2, T0 + 900, b,
           (r, b), True, blob_r=r)
    k2case("k2_blob_u64_saturation", "da = 2: T_ref + r exceeds 2^64-1; a saturating uint64 sum gives the exact verdict "
           "(K1 rejects such a block time first in the pipeline).", 2, (1 << 63) - 1, U64_MAX - 100,
           (r, U64_MAX - 100), True, blob_r=r)
    cr = b - 5
    k2case("k2_fibre_at_limit", "da = 1: start = min(T_ref, creation_timestamp) = creation_timestamp; valid_until + "
           "600 == start + 14400.", 1, cr + r - 600, b, (r, cr), True, latest=r, at_h=r, creation=cr)
    k2case("k2_fibre_one_second_over", "da = 1: one second past the limit; a gate without a Fibre committer cannot take "
           "the archive path.", 1, cr + r - 600 + 1, b, (r, cr), False, latest=r, at_h=r, creation=cr)
    k2case("k2_fibre_creation_after_block", "da = 1: creation_timestamp later than T_ref; start = T_ref.", 1,
           b + r - 600, b, (r, b), True, latest=r, at_h=r, creation=b + 10)
    k2case("k2_fibre_creation_unknown", "da = 1: creation_timestamp unknown (0); K2 is false.", 1, b + 600, b, None,
           False, latest=r, at_h=r, creation=0)
    k2case("k2_fibre_at_height_unreadable", "da = 1: retention at the anchor height cannot be read. The gate rejects "
           "and never substitutes the latest value.", 1, b + 600, b, None, False, latest=r, creation=cr,
           error="ErrRetentionUnavailable")
    k2case("k2_fibre_retention_lowered", "da = 1: latest 3600, at H 14400: r = 3600, margin 450; at the limit.", 1,
           cr + 3600 - 450, b, (3600, cr), True, latest=3600, at_h=r, creation=cr)
    k2case("k2_fibre_retention_lowered_over", "da = 1: as above, one second over.", 1, cr + 3600 - 450 + 1, b,
           (3600, cr), False, latest=3600, at_h=r, creation=cr)
    k2case("k2_fibre_retention_raised", "da = 1: latest 14400, at H 3600: r = 3600; at the limit.", 1, cr + 3600 - 450,
           b, (3600, cr), True, latest=r, at_h=3600, creation=cr)
    k2case("k2_fibre_governance_minimum", "da = 1: r = 600 (governance minimum), margin = 75; at the limit.", 1,
           cr + 600 - 75, b, (600, cr), True, latest=600, at_h=600, creation=cr)
    k2case("k2_fibre_governance_minimum_over", "da = 1: r = 600, one second over.", 1, cr + 600 - 75 + 1, b, (600, cr),
           False, latest=600, at_h=600, creation=cr)
    k2case("k2_margin_floor", "da = 2: r = 4799, margin = floor(4799 / 8) = 599 (below the 600 cap); at the limit.", 2,
           b + 4799 - 599, b, (4799, b), True, blob_r=4799)
    k2case("k2_margin_cap", "da = 2: r = 4800, margin = 600 (the cap); one second over.", 2, b + 4800 - 600 + 1, b,
           (4800, b), False, blob_r=4800)

    e0 = T0 - 86400
    epoch = []
    for cid, desc, ia, ep, sk_, err in [
        ("epoch_one_second_after", "issued_at == epoch + skew_s + 1: accepted.", e0 + skew + 1, e0, skew, None),
        ("epoch_at_limit", "issued_at == epoch + skew_s: rejected (strict inequality).", e0 + skew, e0, skew,
         "ErrBeforeRegistryEpoch"),
        ("epoch_before", "issued_at before the registry was created.", e0 - 1, e0, skew, "ErrBeforeRegistryEpoch"),
        ("epoch_skew_0", "skew_s = 0, issued_at == epoch + 1: accepted.", e0 + 1, e0, 0, None),
        ("epoch_skew_0_equal", "skew_s = 0, issued_at == epoch: rejected.", e0, e0, 0, "ErrBeforeRegistryEpoch"),
        ("epoch_u64_max", "epoch = 2^64-1: epoch + skew_s saturates and every issued_at is rejected.", (1 << 63) - 1,
         U64_MAX, skew, "ErrBeforeRegistryEpoch"),
    ]:
        c = {"id": cid, "description": desc, "issued_at": str(ia), "epoch": str(ep), "skew_s": str(sk_)}
        if err:
            c["expect_error"] = err
        try:
            check_registry_epoch(ia, ep, sk_)
            assert err is None, cid
        except Reject as e:
            assert e.sentinel == err, cid
        epoch.append(c)

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
            e = {"anchor_deadline": str(E.fast_window(da, h0, head, fwb, age, delay, chain, timeout, slack, included,
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
        win("window_blob_gate_min", "da = 2: window = FastWindowBlocks below the mandate bound.", 2, H0_BLOB,
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
        win("window_at_bound", "head - h0 == window: the deadline equals the head, below head + "
            "MinFastSlackBlocks.", 1, h0, h0 + 5, 100, 10, 5, 1000),
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
    return {"format": FORMAT, "revision": REVISION, "margin_cap": "600", "k1": k1, "k2": k2s, "k2_included": k2r,
            "epoch": epoch, "window": window}


# action.json

def action_vectors() -> dict:
    salt = salt_of("minimal")
    pre = action_preimage_prefix(IBKR) + salt + ACTION
    cases = [{"id": "action_v1_minimal", "description": "ActionHash of the minimal_lmt action (IBKR order) with the "
              "salt of label action-salt/minimal.", **action_fields(IBKR, ACTION, salt, with_hash=False),
              "preimage_hex": pre.hex(), "preimage_size": str(len(pre)),
              "action_hash_hex": hashlib.sha256(pre).hexdigest()}]
    assert cases[0]["action_hash_hex"] == action_hash(IBKR, salt, ACTION).hex()
    salt_m = salt_of("max")
    pre_m = action_preimage_prefix(TYPE_128) + salt_m + ACTION_MAX
    cases.append({"id": "action_v1_max", "description": "128-byte type and 65,536 action bytes (pattern): the "
                  "preimage is the prefix, the salt, then the bytes.", **action_fields(TYPE_128, ACTION_MAX, salt_m,
                                                                                      with_hash=False),
                  "preimage_prefix_hex": action_preimage_prefix(TYPE_128).hex(), "preimage_size": str(len(pre_m)),
                  "action_hash_hex": hashlib.sha256(pre_m).hexdigest()})
    committed = action_hash(IBKR, salt, ACTION)
    reject = []

    def rj(cid, rule, desc, committed_, presented_salt, action=ACTION, committed_preimage=None):
        r = {"id": cid, "stage": "A", "rule": rule, "description": desc, "action_type": IBKR, "action_hex": action.hex(),
             "committed_action_hash_hex": committed_.hex()}
        if committed_preimage is not None:
            r["committed_preimage_hex"] = committed_preimage.hex()
        if presented_salt is not None:
            r["action_salt_hex"] = presented_salt.hex()
        try:
            E.check_action({"action": {"type": IBKR, "hash": committed_}}, action, presented_salt)
            raise AssertionError(cid)
        except Reject as e:
            r["expect_error"] = e.sentinel
        reject.append(r)

    rj("action_v1_wrong_salt", "A1", "The committed salt with its lowest bit flipped.", committed,
       bytes([salt[0] ^ 1]) + salt[1:])
    rj("action_v1_salt_missing", "A0s", "No salt presented.", committed, None)
    rj("action_v1_salt_31", "A0s", "A 31-byte salt.", committed, salt[:31])
    rj("action_v1_salt_33", "A0s", "A 33-byte salt.", committed, salt + b"\x00")
    unsalted = action_preimage_prefix(IBKR) + ACTION
    rj("action_unsalted", "A1", "Committed without the salt: SHA-256(tag || uint8(len(type)) || type || bytes).",
       hashlib.sha256(unsalted).digest(), salt, committed_preimage=unsalted)
    pre_after = action_preimage_prefix(IBKR) + ACTION + salt
    rj("action_v1_salt_after_bytes", "A1", "Committed with the salt after the action bytes.",
       hashlib.sha256(pre_after).digest(), salt, committed_preimage=pre_after)
    return {"format": FORMAT, "revision": REVISION, "tag": tagged(TAG_ACTION).hex(),
            "salt_derivation": "action_salt = SHA-256(\"action-salt/\" || label)", "cases": cases, "reject": reject}


# gate.json

def gate_vectors() -> dict:
    base_cfg = {"fast_mode": True, "pending_namespaces": [NAMESPACE]}
    out = []

    def case(cid, desc, cfg, mandate=True, allowlist=None):
        allow = allowlist if allowlist is not None else GATE["action_types"]
        j = {k: ([x.hex() for x in v] if k == "pending_namespaces" else (v if isinstance(v, (bool, list)) else str(v)))
             for k, v in cfg.items()}
        try:
            E.validate_gate_config(cfg, mandate, allow)
            e = {"result": "ok"}
        except Reject as err:
            e = {"error": err.sentinel, "cause": err.detail}
        out.append({"id": cid, "description": desc, "config": j, "mandate": mandate, "expect": e})

    case("defaults_fast_mode", "FastMode with a namespace, a mandate and every default.", base_cfg)
    case("fast_mode_without_mandate", "FastMode at a gate without a mandate: no mandate, no fast mode.", base_cfg,
         mandate=False)
    case("strict_without_mandate", "FastMode off and no mandate: accepted.", {"fast_mode": False}, mandate=False)
    case("fast_mode_without_namespaces", "FastMode with no PendingNamespaces.", {"fast_mode": True})
    case("max_h0_age_equals_window", "MaxH0AgeBlocks = FastWindowBlocks (the range is 1..FastWindowBlocks - 1).",
         dict(base_cfg, fast_window_blocks=20, max_h0_age_blocks=20))
    case("age_plus_slack_over_window", "MaxH0AgeBlocks 18 + MinFastSlackBlocks 3 > FastWindowBlocks 20.",
         dict(base_cfg, fast_window_blocks=20, max_h0_age_blocks=18))
    case("age_plus_slack_at_window", "MaxH0AgeBlocks 17 + MinFastSlackBlocks 3 = FastWindowBlocks 20: accepted.",
         dict(base_cfg, fast_window_blocks=20, max_h0_age_blocks=17))
    case("min_fast_slack_0", "MinFastSlackBlocks 0.", dict(base_cfg, min_fast_slack_blocks=0))
    case("min_fast_slack_101", "MinFastSlackBlocks 101.", dict(base_cfg, min_fast_slack_blocks=101))
    case("min_promise_slack_0", "MinPromiseSlackSeconds 0.", dict(base_cfg, min_promise_slack_seconds=0))
    case("min_promise_slack_601", "MinPromiseSlackSeconds 601.", dict(base_cfg, min_promise_slack_seconds=601))
    case("fast_window_1001", "FastWindowBlocks 1001.", dict(base_cfg, fast_window_blocks=1001))
    case("reveal_type_allowlisted", "RevealOnExecution names an allowlisted type: accepted.",
         dict(base_cfg, reveal_on_execution=[TYPE_JSON]))
    case("reveal_type_not_allowlisted", "RevealOnExecution names a type outside the allowlist.",
         dict(base_cfg, reveal_on_execution=["application/vnd.edicta.other.v0+cbor"]))
    return {"format": FORMAT, "revision": REVISIONS["gate.json"], "allowlist": GATE["action_types"],
            "defaults": {k: (v if isinstance(v, bool) else str(v)) for k, v in E.GATE_CONFIG_DEFAULTS.items()},
            "cases": out}


def build() -> dict:
    """Every core vector file, by name relative to the output directory."""
    VALID.clear()
    AUTH_CACHE.clear()
    AUTH_SIGNATURES.clear()
    head_ = {"format": FORMAT, "revision": REVISION, "params": params_to_json(PARAMS), "gate": gate_to_json(GATE),
             "patterns": PATTERNS, "keys": "spec/vectors/keys.json"}
    valid = valid_cases()
    reject = reject_cases()
    auth = authorization_vectors()
    AUTH_CACHE.update({c["id"]: c for c in auth["cases"]})
    return {"valid.json": dict(head_, cases=valid), "reject.json": dict(head_, cases=reject),
            "authorization.json": auth, "receipt.json": receipt_vectors(),
            "record_request.json": record_request_vectors(), "payload.json": payload_vectors(),
            "payload_blob.json": gen_payload_blob.build(), "limits.json": limits_vectors(),
            "anchor.json": anchor_vectors(), "action.json": action_vectors(), "gate.json": gate_vectors()}


def keys_file() -> dict:
    return {"format": FORMAT, "keys": KEYS}


def dump(obj: dict) -> str:
    return json.dumps(obj, indent=2, ensure_ascii=True) + "\n"


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    for name, obj in build().items():
        (OUT / name).write_text(dump(obj))
        print(f"wrote {OUT / name}")
    KEYS_OUT.write_text(dump(keys_file()))
    print(f"wrote {KEYS_OUT}")


if __name__ == "__main__":
    main()
