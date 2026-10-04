#!/usr/bin/env python3
"""Generates spec/vectors/v0/payload_blob.json. Deterministic: rerunning yields an identical file.

Every value that is random in production is derived from a fixed label here:
  recipient key   (sk, pk) = DeriveKeyPair(SHA-256("edicta/v0 test recipient|" + name))
  ephemeral key   skE      = DeriveKeyPair(SHA-256("edicta/v0 test ephemeral|" + case_id + "|" + index)).sk
  DEK                      = SHA-256("edicta/v0 test dek|" + case_id)
  AEAD nonce               = SHA-256("edicta/v0 test aead nonce|" + case_id)[:12]
  salt                     = SHA-256("edicta/v0 test payload salt|" + case_id)
DeriveKeyPair is the RFC 9180 key derivation of DHKEM(X25519, HKDF-SHA256).

Usage: python3 spec/vectors/check/gen_payload_blob.py [--out DIR]
"""

from __future__ import annotations

import sys

sys.dont_write_bytecode = True

import copy
import hashlib
import json
from pathlib import Path

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
except ImportError:
    sys.exit("missing dependency 'cryptography'; see spec/vectors/check/requirements.txt")

import edicta_payload_v0 as pv
import hpke_base as hpke
from cbor_strict import Pairs, Raw, encode, head
from edicta_v0 import (ACTION, CONSTRAINTS, TAG_RECEIPT, Params, commitment_hash, signing_message,
                      tagged, to_cbor, verify_for_gate)
from vecjson import _conv, commitment_to_json, gate_to_json, params_to_json

OUT = Path(__file__).resolve().parent.parent / "v0"
if "--out" in sys.argv:
    OUT = Path(sys.argv[sys.argv.index("--out") + 1]).resolve()
FORMAT = "edicta-vectors/v0"
KAT_RFC_TEXT = Path(__file__).resolve().parent / "hpke_rfc9180_a2_1.json"

AGENT1_SEED = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
PARAMS = Params()
GATE = {"gate_id": "gate-paper-1", "rail": 1, "account": "DU1234567"}
T0 = 1791000000
NOW = T0 + 60


def h(label: str) -> bytes:
    return hashlib.sha256(label.encode()).digest()


def w(d: dict, k, v) -> dict:
    """Copy of d with key k set to v."""
    x = dict(d)
    x[k] = v
    return x


NAMESPACE = bytes(19) + b"edicta/d01"
SIGNER = h("edicta/v0 test recorder account")[:20]

RECIPIENT_NAMES = (["gate-paper-1", "auditor-1", "counterparty-1"]
                   + [f"rcpt-{i:02d}" for i in range(4, 18)] + ["opaque-32"])


def kid_of(name: str) -> bytes:
    return h("edicta/v0 test kid|opaque-32") if name == "opaque-32" else name.encode()


KEYS = {}
for _n in RECIPIENT_NAMES:
    _ikm = h("edicta/v0 test recipient|" + _n)
    _sk, _pk = hpke.derive_key_pair(_ikm)
    KEYS[_n] = {"ikm": _ikm, "sk": _sk, "pk": _pk, "kid": kid_of(_n)}


def ephemeral(case_id: str, i: int) -> tuple[bytes, bytes]:
    ikm = h(f"edicta/v0 test ephemeral|{case_id}|{i}")
    return ikm, hpke.derive_key_pair(ikm)[0]


def payload_to_json(p: dict) -> dict:
    return _conv(p, pv.PAYLOAD, True)


def dca_to_json(d: dict) -> dict:
    out = {}
    for name, val in d.items():
        if name == "last_fills":
            out[name] = [{k: str(v) for k, v in f.items()} for f in val]
        elif name == "strategy_id":
            out[name] = val
        else:
            out[name] = {k: (v if isinstance(v, str) else str(v)) for k, v in val.items()}
    return out


# ---------------------------------------------------------------- decisions

ACTION_BUY = {
    "kind": "ibkr.order.v0",
    "params": {"account": "DU1234567", "conid": 756733, "symbol": "SPY", "side": 1, "qty": 20000,
               "order_type": 1, "limit_price": 57250000000, "currency": "USD", "tif": 1},
}

DCA_MINIMAL = {
    "strategy_id": "dca-spy-weekly",
    "schedule": {"period_s": 604800, "period_start": 1790726400},
    "budget": {"currency": "USD", "per_period": 120000000000, "spent": 0},
    "price": {"source": "ibkr.snapshot", "conid": 756733, "price": 57200000000, "observed_at": T0 - 30},
    "order": {"side": 1, "qty": 20000, "limit_price": 57250000000},
}

DCA_WITH_FILLS = dict(copy.deepcopy(DCA_MINIMAL), last_fills=[
    {"filled_at": T0 - 604800 + 95, "side": 1, "qty": 20000, "price": 56810000000},
    {"filled_at": T0 - 2 * 604800 + 120, "side": 1, "qty": 20000, "price": 55990000000},
])

POLICY_TEXT = (b"Buy SPY once per week with a limit at most 0.1% above the snapshot price; "
               b"spend at most 1200.00 USD per week; skip the week if the budget is spent.")


def payload_dca_minimal() -> dict:
    return {
        "version": 0,
        "model": {"id": "example-model"},
        "policy": {"id": "dca-weekly"},
        "context": {"media_type": pv.MEDIA_TYPE_DCA_V0, "data": pv.dca_encode(DCA_MINIMAL)},
        "action": copy.deepcopy(ACTION_BUY),
        "constraints": {"max_notional": 120000000000},
    }


def payload_dca_full() -> dict:
    return {
        "version": 0,
        "model": {"id": "example-model", "version": "2026-06", "digest": h("edicta/v0 test model weights")},
        "policy": {"id": "dca-weekly", "version": "3", "digest": hashlib.sha256(POLICY_TEXT).digest(),
                   "text": POLICY_TEXT},
        "context": {"media_type": pv.MEDIA_TYPE_DCA_V0, "data": pv.dca_encode(DCA_WITH_FILLS)},
        "action": copy.deepcopy(ACTION_BUY),
        "constraints": {"max_notional": 120000000000, "price_bound": 57300000000, "deadline": T0 + 600},
        "metadata": {"media_type": "application/json",
                     "data": b'{"run_id":"2026-10-03T00:00:00Z","host":"dca-agent-1"}'},
    }


def payload_json_sell() -> dict:
    return {
        "version": 0,
        "model": {"id": "example-model", "version": "2026-06"},
        "policy": {"id": "rebalance-monthly"},
        "context": {"media_type": "application/json",
                    "data": b'{"signal":"rebalance","target_weight_spy":"0.60","current_weight_spy":"0.64"}'},
        "action": {"kind": "ibkr.order.v0",
                   "params": {"account": "DU1234567", "conid": 756733, "side": 2, "qty": 10000,
                              "order_type": 1, "limit_price": 57100000000, "currency": "USD", "tif": 3}},
        "constraints": {"max_notional": 60000000000, "price_bound": 57000000000},
        "metadata": {"media_type": "text/plain", "data": b"monthly rebalance, SPY overweight by 4 points"},
    }


def payload_empty_context() -> dict:
    return {
        "version": 0,
        "model": {"id": "rule-engine-1"},
        "policy": {"id": "fixed-order"},
        "context": {"media_type": "application/octet-stream", "data": b""},
        "action": copy.deepcopy(ACTION_BUY),
        "constraints": {"max_notional": 120000000000},
    }


# ---------------------------------------------------------------- sealing

def material(case_id: str):
    return (h(f"edicta/v0 test payload salt|{case_id}"), h(f"edicta/v0 test dek|{case_id}"),
            h(f"edicta/v0 test aead nonce|{case_id}")[:12])


def recipients_for(case_id: str, names: list) -> tuple[list, list]:
    rs, eph = [], []
    for i, n in enumerate(names):
        ikm_e, sk_e = ephemeral(case_id, i)
        rs.append(pv.Recipient(KEYS[n]["kid"], KEYS[n]["pk"], sk_e))
        eph.append((ikm_e, sk_e))
    return rs, eph


def seal_case(case_id: str, plaintext: bytes, names: list, **kw) -> dict:
    salt, dek, nonce = material(case_id)
    rs, eph = recipients_for(case_id, names)
    blob, trace = pv.seal(salt, plaintext, rs, dek, nonce, **kw)
    return {"salt": salt, "dek": dek, "nonce": nonce, "rs": rs, "eph": eph, "trace": trace, "blob": blob,
            "plaintext": plaintext, "names": names}


def commitment_for(case_id: str, p: dict, s: dict) -> dict:
    c = {
        "version": 0,
        "agent_id": "dca-agent-1",
        "agent_pubkey": Ed25519PrivateKey.from_private_bytes(AGENT1_SEED).public_key().public_bytes_raw(),
        "nonce": h(f"nonce-{case_id}")[:16],
        "issued_at": T0,
        "valid_until": T0 + 900,
        "scope": dict(GATE),
        "action": copy.deepcopy(p["action"]),
        "constraints": copy.deepcopy(p["constraints"]),
        "payload_ref": {"da": 2, "namespace": NAMESPACE, "commitment": h(f"share-commitment-{case_id}"),
                        "height": 4200000, "signer": SIGNER},
        "ciphertext_hash": hashlib.sha256(s["blob"]).digest(),
        "plaintext_hash": hashlib.sha256(s["salt"] + s["plaintext"]).digest(),
        "payload_size": len(s["blob"]),
    }
    canon = encode(to_cbor(c))
    ch = commitment_hash(canon)
    sig = Ed25519PrivateKey.from_private_bytes(AGENT1_SEED).sign(signing_message(ch))
    env = encode({1: Raw(canon), 2: sig})
    verify_for_gate(env, NOW, GATE, PARAMS)
    return {
        "input": commitment_to_json(c),
        "commitment_cbor_hex": canon.hex(),
        "commitment_hash_hex": ch.hex(),
        "signer": "agent1",
        "envelope_hex": env.hex(),
        "now": str(NOW),
        "placeholders": {"payload_ref.commitment": "SHA-256 of a label, not a real share commitment"},
    }


def valid_case(case_id: str, desc: str, p: dict, names: list) -> tuple[dict, dict]:
    pt = pv.payload_encode(p)
    assert pv.payload_decode(pt) == p
    s = seal_case(case_id, pt, names)
    action_cbor = encode(to_cbor(p["action"], ACTION))
    constraints_cbor = encode(to_cbor(p["constraints"], CONSTRAINTS))
    case = {
        "id": case_id,
        "description": desc,
        "payload": payload_to_json(p),
    }
    if p["context"]["media_type"] == pv.MEDIA_TYPE_DCA_V0:
        d = pv.dca_decode(p["context"]["data"])
        assert not pv.dca_consistency(d, p["action"]), case_id
        case["context_dca"] = dca_to_json(d)
    case.update({
        "plaintext_cbor_hex": pt.hex(),
        "salt_hex": s["salt"].hex(),
        "plaintext_hash_hex": hashlib.sha256(s["salt"] + pt).hexdigest(),
        "dek_hex": s["dek"].hex(),
        "aead_nonce_hex": s["nonce"].hex(),
        "recipients": [{
            "key": n,
            "kid_hex": KEYS[n]["kid"].hex(),
            "ikme_hex": s["eph"][i][0].hex(),
            "ske_hex": s["eph"][i][1].hex(),
            "enc_hex": s["trace"][i]["enc"].hex(),
            "shared_secret_hex": s["trace"][i]["shared_secret"].hex(),
            "hpke_key_hex": s["trace"][i]["key"].hex(),
            "hpke_base_nonce_hex": s["trace"][i]["base_nonce"].hex(),
            "wrapped_dek_hex": s["trace"][i]["wrapped_dek"].hex(),
        } for i, n in enumerate(names)],
        "ciphertext_hex": pv.blob_decode(s["blob"]).ciphertext.hex(),
        "blob_hex": s["blob"].hex(),
        "payload_size": str(len(s["blob"])),
        "ciphertext_hash_hex": hashlib.sha256(s["blob"]).hexdigest(),
        "action_cbor_hex": action_cbor.hex(),
        "constraints_cbor_hex": constraints_cbor.hex(),
        "commitment": commitment_for(case_id, p, s),
    })
    for i, n in enumerate(names):
        assert pv.open_payload(s["blob"], KEYS[n]["sk"], KEYS[n]["kid"],
                               bytes.fromhex(case["plaintext_hash_hex"]), action_cbor, constraints_cbor) == p
    return case, s


# ---------------------------------------------------------------- rejects

def rj(cid: str, stage: str, rule: str, desc: str, blob: bytes, expect: str, **kw) -> dict:
    out = {"id": cid, "stage": stage, "rule": rule, "description": desc, "blob_hex": blob.hex()}
    for k, v in kw.items():
        out[k] = v.hex() if isinstance(v, bytes) else v
    out["expect_error"] = expect
    return out


def raw_blob(version=0, entries=None, nonce=None, ct=None, base: pv.Blob | None = None) -> pv.Blob:
    return pv.Blob(version, entries if entries is not None else base.recipients,
                   nonce if nonce is not None else base.aead_nonce, ct if ct is not None else base.ciphertext)


def entry_cbor(e: pv.Entry) -> dict:
    return {1: e.kid, 2: e.enc, 3: e.wrapped_dek}


def flip(b: bytes, i: int, mask: int = 0x01) -> bytes:
    x = bytearray(b)
    x[i] ^= mask
    return bytes(x)


def decode_rejects(s1: dict) -> list:
    b = pv.blob_decode(s1["blob"])
    e0 = b.recipients[0]
    raw = s1["blob"]
    out = []

    def top(*pairs):
        return encode(Pairs(tuple(pairs)))

    def blob_with(entries=None, **kw):
        return pv.blob_encode(raw_blob(entries=entries, base=b, **kw))

    def entry_with(**kw):
        return pv.Entry(kw.get("kid", e0.kid), kw.get("enc", e0.enc), kw.get("wrapped_dek", e0.wrapped_dek))

    out.append(rj("pb_recipients_0", "decode", "B3", "Recipients array is empty.",
                  blob_with(entries=[]), "blob.ErrRecipients"))
    names17 = RECIPIENT_NAMES[:17]
    rs17, _ = recipients_for("pb_recipients_17", names17)
    blob17, _ = pv.seal(s1["salt"], s1["plaintext"], rs17, s1["dek"], s1["nonce"], check=False)
    out.append(rj("pb_recipients_17", "decode", "B3",
                  "17 correctly wrapped entries; the limit is 16, checked at the array head.",
                  blob17, "blob.ErrRecipients"))
    rsd, _ = recipients_for("pb_duplicate_kid", ["gate-paper-1", "auditor-1"])
    rsd[1] = pv.Recipient(rsd[0].kid, rsd[1].pk, rsd[1].sk_e)
    blobd, _ = pv.seal(s1["salt"], s1["plaintext"], rsd, s1["dek"], s1["nonce"], check=False)
    out.append(rj("pb_duplicate_kid", "decode", "B5",
                  "Two entries, both labelled gate-paper-1; the second wraps the DEK for the auditor key.",
                  blobd, "blob.ErrDuplicateKID"))
    out.append(rj("pb_blob_version_1", "decode", "B2", "Blob version 1.",
                  pv.blob_encode(raw_blob(version=1, base=b)), "blob.ErrVersion"))
    out.append(rj("pb_blob_version_tstr", "decode", "B1", "Blob version is the text string \"0\".",
                  top((1, "0"), (2, [entry_cbor(e) for e in b.recipients]), (3, b.aead_nonce), (4, b.ciphertext)),
                  "blob.ErrMalformed"))
    out.append(rj("pb_blob_truncated", "decode", "B1", "Last byte of the blob removed.",
                  raw[:-1], "blob.ErrMalformed"))
    out.append(rj("pb_blob_trailing_byte", "decode", "B7", "One zero byte after the top-level map.",
                  raw + b"\x00", "blob.ErrMalformed"))
    out.append(rj("pb_blob_nonminimal_version", "decode", "B1",
                  "Version 0 encoded as 0x18 0x00 (non-minimal head).",
                  top((1, Raw(b"\x18\x00")), (2, [entry_cbor(e) for e in b.recipients]), (3, b.aead_nonce),
                      (4, b.ciphertext)), "blob.ErrMalformed"))
    out.append(rj("pb_blob_nonminimal_nonce_len", "decode", "B1",
                  "aead_nonce length 12 encoded as 0x58 0x0c (non-minimal head).",
                  top((1, 0), (2, [entry_cbor(e) for e in b.recipients]), (3, Raw(b"\x58\x0c" + b.aead_nonce)),
                      (4, b.ciphertext)), "blob.ErrMalformed"))
    out.append(rj("pb_blob_unsorted_keys", "decode", "B1", "Top-level keys in the order 1, 3, 2, 4.",
                  top((1, 0), (3, b.aead_nonce), (2, [entry_cbor(e) for e in b.recipients]), (4, b.ciphertext)),
                  "blob.ErrMalformed"))
    out.append(rj("pb_blob_extra_key", "decode", "B1", "A fifth top-level key 5.",
                  top((1, 0), (2, [entry_cbor(e) for e in b.recipients]), (3, b.aead_nonce), (4, b.ciphertext),
                      (5, b"")), "blob.ErrMalformed"))
    indef = b"\x9f" + b"".join(encode(entry_cbor(e)) for e in b.recipients) + b"\xff"
    out.append(rj("pb_blob_indefinite_array", "decode", "B1", "Recipients as an indefinite-length array.",
                  top((1, 0), (2, Raw(indef)), (3, b.aead_nonce), (4, b.ciphertext)), "blob.ErrMalformed"))
    out.append(rj("pb_blob_float_version", "decode", "B1", "Version as half-precision float 0.0 (0xf9 0x0000).",
                  top((1, Raw(b"\xf9\x00\x00")), (2, [entry_cbor(e) for e in b.recipients]), (3, b.aead_nonce),
                      (4, b.ciphertext)), "blob.ErrMalformed"))
    out.append(rj("pb_kid_empty", "decode", "B4", "kid of length 0.",
                  blob_with(entries=[entry_with(kid=b"")]), "blob.ErrMalformed"))
    out.append(rj("pb_kid_33_bytes", "decode", "B4", "kid of 33 bytes.",
                  blob_with(entries=[entry_with(kid=b"k" * 33)]), "blob.ErrMalformed"))
    out.append(rj("pb_kid_tstr", "decode", "B4", "kid as a text string.",
                  top((1, 0), (2, [{1: e0.kid.decode(), 2: e0.enc, 3: e0.wrapped_dek}]), (3, b.aead_nonce),
                      (4, b.ciphertext)), "blob.ErrMalformed"))
    out.append(rj("pb_enc_31_bytes", "decode", "B4", "enc of 31 bytes.",
                  blob_with(entries=[entry_with(enc=e0.enc[:31])]), "blob.ErrMalformed"))
    out.append(rj("pb_wrapped_dek_49_bytes", "decode", "B4", "wrapped_dek of 49 bytes.",
                  blob_with(entries=[entry_with(wrapped_dek=e0.wrapped_dek + b"\x00")]), "blob.ErrMalformed"))
    out.append(rj("pb_entry_missing_wrapped_dek", "decode", "B4", "Recipient entry with keys 1 and 2 only.",
                  top((1, 0), (2, [{1: e0.kid, 2: e0.enc}]), (3, b.aead_nonce), (4, b.ciphertext)),
                  "blob.ErrMalformed"))
    out.append(rj("pb_nonce_11_bytes", "decode", "B6", "aead_nonce of 11 bytes.",
                  blob_with(nonce=b.aead_nonce[:11]), "blob.ErrMalformed"))
    out.append(rj("pb_ciphertext_48_bytes", "decode", "B6",
                  "ciphertext of 48 bytes (salt and tag with an empty plaintext); the minimum is 49.",
                  blob_with(ct=b.ciphertext[:48]), "blob.ErrMalformed"))
    return out


def open_rejects(s1: dict, s3: dict) -> list:
    """s1: one recipient (gate-paper-1); s3: two recipients (gate-paper-1, auditor-1)."""
    g, a = KEYS["gate-paper-1"], KEYS["auditor-1"]
    b3 = pv.blob_decode(s3["blob"])
    out = []

    def tamper(cid, desc, blob, expect, key="gate-paper-1", kid: bytes | None = g["kid"]):
        extra = {"key": key}
        if kid is not None:
            extra["kid_hex"] = kid
        return rj(cid, "open", {"blob.ErrNoRecipient": "O4", "blob.ErrUnwrap": "O5",
                                "blob.ErrDecrypt": "O6"}[expect], desc, blob, expect, **extra)

    out.append(tamper("pb_wrong_recipient_key", "Entry gate-paper-1 opened with the auditor-1 private key.",
                      s1["blob"], "blob.ErrUnwrap", key="auditor-1"))
    out.append(tamper("pb_wrong_recipient_key_try_all",
                      "No kid given; the only entry does not unwrap under the auditor-1 key.",
                      s1["blob"], "blob.ErrUnwrap", key="auditor-1", kid=None))
    out.append(tamper("pb_kid_absent", "The auditor-1 kid is not in a blob sealed for gate-paper-1 only.",
                      s1["blob"], "blob.ErrNoRecipient", key="auditor-1", kid=a["kid"]))
    sw = [pv.Entry(b3.recipients[1].kid, b3.recipients[0].enc, b3.recipients[0].wrapped_dek),
          pv.Entry(b3.recipients[0].kid, b3.recipients[1].enc, b3.recipients[1].wrapped_dek)]
    out.append(tamper("pb_kids_swapped", "Two-recipient blob with the two kids swapped; the HPKE aad binds the kid.",
                      pv.blob_encode(raw_blob(entries=sw, base=b3)), "blob.ErrUnwrap", key="auditor-1", kid=a["kid"]))
    se = [pv.Entry(b3.recipients[0].kid, b3.recipients[1].enc, b3.recipients[0].wrapped_dek),
          pv.Entry(b3.recipients[1].kid, b3.recipients[0].enc, b3.recipients[1].wrapped_dek)]
    out.append(tamper("pb_enc_swapped", "Two-recipient blob with the two enc values swapped.",
                      pv.blob_encode(raw_blob(entries=se, base=b3)), "blob.ErrUnwrap"))
    b1 = pv.blob_decode(s1["blob"])
    e0 = b1.recipients[0]

    def with_entry(**kw):
        e = pv.Entry(kw.get("kid", e0.kid), kw.get("enc", e0.enc), kw.get("wrapped_dek", e0.wrapped_dek))
        return pv.blob_encode(raw_blob(entries=[e], base=b1))

    out.append(tamper("pb_flipped_wrapped_dek", "Last byte of wrapped_dek flipped.",
                      with_entry(wrapped_dek=flip(e0.wrapped_dek, 47)), "blob.ErrUnwrap"))
    out.append(tamper("pb_flipped_enc", "First byte of enc flipped.",
                      with_entry(enc=flip(e0.enc, 0)), "blob.ErrUnwrap"))
    out.append(tamper("pb_enc_low_order", "enc is the X25519 point u = 0; the shared secret would be all zero.",
                      with_entry(enc=bytes(32)), "blob.ErrUnwrap"))
    out.append(tamper("pb_flipped_ciphertext", "First ciphertext byte flipped.",
                      pv.blob_encode(raw_blob(ct=flip(b1.ciphertext, 0), base=b1)), "blob.ErrDecrypt"))
    out.append(tamper("pb_flipped_aead_tag", "Last ciphertext byte (inside the Poly1305 tag) flipped.",
                      pv.blob_encode(raw_blob(ct=flip(b1.ciphertext, len(b1.ciphertext) - 1), base=b1)),
                      "blob.ErrDecrypt"))
    out.append(tamper("pb_flipped_aead_nonce", "First aead_nonce byte flipped.",
                      pv.blob_encode(raw_blob(nonce=flip(b1.aead_nonce, 0), base=b1)), "blob.ErrDecrypt"))
    names = ["gate-paper-1"]
    pt = s1["plaintext"]
    variants = [
        ("pb_hpke_info_unprefixed", "HPKE info is the bare ASCII edicta/v0/payload-dek, without the length byte.",
         {"info": pv.TAG_PAYLOAD_DEK}, "blob.ErrUnwrap"),
        ("pb_hpke_info_payload_tag", "HPKE info is tag(edicta/v0/payload), the AEAD tag.",
         {"info": tagged(pv.TAG_PAYLOAD_AEAD)}, "blob.ErrUnwrap"),
        ("pb_hpke_info_empty", "HPKE info is empty.", {"info": b""}, "blob.ErrUnwrap"),
        ("pb_hpke_aad_kid_unprefixed", "HPKE aad is the kid without its length byte.",
         {"aad_of": lambda kid: kid}, "blob.ErrUnwrap"),
        ("pb_aead_aad_unprefixed", "Payload AEAD aad is the bare ASCII edicta/v0/payload, without the length byte.",
         {"aead_aad": pv.TAG_PAYLOAD_AEAD}, "blob.ErrDecrypt"),
        ("pb_aead_aad_receipt_tag", "Payload AEAD aad is tag(edicta/v0/receipt): same length, another tag.",
         {"aead_aad": tagged(TAG_RECEIPT)}, "blob.ErrDecrypt"),
        ("pb_aead_aad_dek_tag", "Payload AEAD aad is tag(edicta/v0/payload-dek), the HPKE tag.",
         {"aead_aad": tagged(pv.TAG_PAYLOAD_DEK)}, "blob.ErrDecrypt"),
        ("pb_aead_aad_empty", "Payload AEAD aad is empty.", {"aead_aad": b""}, "blob.ErrDecrypt"),
    ]
    for cid, desc, kw, expect in variants:
        blob, _ = pv.seal(s1["salt"], pt, recipients_for(cid, names)[0], s1["dek"], s1["nonce"], **kw)
        out.append(tamper(cid, desc, blob, expect))
    return out


def plaintext_rejects(p1: dict, s1: dict) -> list:
    out = []
    action_cbor = encode(to_cbor(p1["action"], ACTION))
    constraints_cbor = encode(to_cbor(p1["constraints"], CONSTRAINTS))

    def sealed(cid, desc, rule, pt_bytes, expect, ph=None, ac=action_cbor, cc=constraints_cbor):
        s = seal_case(cid, pt_bytes, ["gate-paper-1"])
        if ph is None:
            ph = hashlib.sha256(s["salt"] + pt_bytes).digest()
        return rj(cid, "plaintext", rule, desc, s["blob"], expect, key="gate-paper-1",
                  kid_hex=KEYS["gate-paper-1"]["kid"], plaintext_hash_hex=ph, action_cbor_hex=ac,
                  constraints_cbor_hex=cc)

    pt1 = pv.payload_encode(p1)
    out.append(sealed("pb_plaintext_hash_unsalted", "The commitment carries SHA-256(plaintext) without the salt.",
                      "O7", pt1, "sdk.ErrPlaintextHashMismatch", ph=hashlib.sha256(pt1).digest()))
    out.append(sealed("pb_plaintext_hash_of_other_salt", "The commitment carries SHA-256(salt' || plaintext) with another salt.",
                      "O7", pt1, "sdk.ErrPlaintextHashMismatch",
                      ph=hashlib.sha256(h("edicta/v0 test other salt") + pt1).digest()))
    p = to_cbor(p1, pv.PAYLOAD)
    unsorted = encode(Pairs(tuple(sorted(p.items(), key=lambda kv: {5: 0}.get(kv[0], kv[0])))))
    out.append(sealed("pb_payload_unsorted_keys", "Payload keys in the order 5, 1, 2, 3, 4, 6; the hash matches the bytes.",
                      "O8", unsorted, "payload.ErrMalformed"))
    nonmin = b"\xa6\x01\x18\x00" + pt1[3:]
    assert pt1[:3] == b"\xa6\x01\x00"
    out.append(sealed("pb_payload_nonminimal_version", "Payload version 0 encoded as 0x18 0x00.", "O8", nonmin,
                      "payload.ErrMalformed"))
    out.append(sealed("pb_payload_unknown_key", "Payload with an extra key 8.", "O8",
                      encode(w(p, 8, b"x")), "payload.ErrMalformed"))
    out.append(sealed("pb_payload_float_version", "Payload version as half-precision float 0.0.", "O8",
                      b"\xa6\x01\xf9\x00\x00" + pt1[3:], "payload.ErrMalformed"))
    out.append(sealed("pb_payload_trailing_byte", "One zero byte after the payload map.", "O8", pt1 + b"\x00",
                      "payload.ErrMalformed"))
    out.append(sealed("pb_payload_version_1", "Payload version 1, otherwise valid.", "O8",
                      encode(w(p, 1, 1)), "payload.ErrVersion"))
    ctx_no_mt = w(p, 4, {2: p[4][2]})
    out.append(sealed("pb_payload_context_missing_media_type", "context without key 1 (media_type).", "O8",
                      encode(ctx_no_mt), "payload.ErrMalformed"))
    md = w(p, 7, {2: b'{"run_id":"x"}'})
    out.append(sealed("pb_payload_metadata_missing_media_type", "metadata present without key 1 (media_type).", "O8",
                      encode(md), "payload.ErrMalformed"))
    for cid, mt, desc in [
        ("pb_payload_media_type_empty", "", "Empty context media_type."),
        ("pb_payload_media_type_uppercase", "Application/JSON", "Upper-case media_type; v0 requires lower case."),
        ("pb_payload_media_type_parameter", "application/json;charset=utf-8", "media_type with a parameter."),
        ("pb_payload_media_type_no_slash", "application", "media_type without a subtype."),
        ("pb_payload_media_type_two_slashes", "application/vnd.x/y", "media_type with two slashes."),
        ("pb_payload_media_type_65_chars", "application/" + "x" * 53, "media_type of 65 bytes."),
    ]:
        out.append(sealed(cid, desc, "O8", encode(w(p, 4, {1: mt, 2: p[4][2]})), "payload.ErrMalformed"))
    out.append(sealed("pb_payload_metadata_empty_data", "metadata with an empty data byte string.", "O8",
                      encode(w(p, 7, {1: "application/json", 2: b""})), "payload.ErrMalformed"))
    out.append(sealed("pb_payload_unknown_action_kind", "action.kind is ibkr.order.v1.", "O8",
                      encode(w(p, 5, {1: "ibkr.order.v1", 2: p[5][2]})), "payload.ErrMalformed"))
    other_action = encode(to_cbor(dict(p1["action"], params=dict(p1["action"]["params"], qty=10000)), ACTION))
    out.append(sealed("pb_payload_action_differs", "The commitment's action has qty 10000 (statically valid: notional 572.50 <= max_notional 1200.00); the payload has 20000.",
                      "O8", pt1, "sdk.ErrPayloadMismatch", ac=other_action))
    other_constraints = encode(to_cbor({"max_notional": 120000000001}, CONSTRAINTS))
    out.append(sealed("pb_payload_constraints_differs", "The commitment's max_notional is one unit higher.",
                      "O8", pt1, "sdk.ErrPayloadMismatch", cc=other_constraints))
    return out


# ---------------------------------------------------------------- key commitment

P1305 = (1 << 130) - 5


def _otk(key: bytes, nonce: bytes) -> tuple[int, int]:
    block = Cipher(algorithms.ChaCha20(key, bytes(4) + nonce), mode=None).encryptor().update(bytes(64))
    r = int.from_bytes(block[:16], "little") & 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF
    return r, int.from_bytes(block[16:32], "little")


def _keystream(key: bytes, nonce: bytes, n: int) -> bytes:
    return Cipher(algorithms.ChaCha20(key, (1).to_bytes(4, "little") + nonce), mode=None).encryptor().update(bytes(n))


def _pad16(x: bytes) -> bytes:
    return bytes(-len(x) % 16)


def _poly_acc(aad: bytes, ct: bytes, r: int) -> tuple[int, int]:
    data = aad + _pad16(aad) + ct + _pad16(ct) + len(aad).to_bytes(8, "little") + len(ct).to_bytes(8, "little")
    acc = 0
    blocks = [data[i:i + 16] for i in range(0, len(data), 16)]
    for blk in blocks:
        acc = (acc + int.from_bytes(blk, "little") + (1 << 128)) * r % P1305
    return acc, len(blocks)


def key_commitment_blob(p1: dict) -> dict:
    """One ciphertext that ChaCha20-Poly1305 accepts under two DEKs.

    Recipient gate-paper-1 gets DEK1 and decrypts salt || payload; recipient auditor-1 gets DEK2 and
    decrypts other bytes. The first 16 ciphertext bytes (the first half of the salt under DEK1) are
    solved so that both Poly1305 tags coincide; the second half of the salt is varied until a solution exists."""
    cid = "pb_key_commitment_two_deks"
    _, dek1, nonce = material(cid)
    dek2 = h(f"edicta/v0 test dek 2|{cid}")
    pt = pv.payload_encode(p1)
    aad = pv.payload_aad()
    r1, s1 = _otk(dek1, nonce)
    r2, s2 = _otk(dek2, nonce)
    n = pv.SALT_SIZE + len(pt)
    ks1 = _keystream(dek1, nonce, n)
    j = (len(aad) + len(_pad16(aad))) // 16
    for t in range(1 << 16):
        salt_tail = h(f"edicta/v0 test salt tail|{cid}|{t}")[:16]
        c_rest = bytes(x ^ y for x, y in zip(salt_tail + pt, ks1[16:]))
        ct0 = bytes(16) + c_rest
        a1, m = _poly_acc(aad, ct0, r1)
        a2, _ = _poly_acc(aad, ct0, r2)
        e = m - j
        coef = (pow(r1, e, P1305) - pow(r2, e, P1305)) % P1305
        if coef == 0:
            continue
        inv = pow(coef, -1, P1305)
        d0 = (s2 - s1) % (1 << 128)
        for k in range(-5, 5):
            d = d0 + k * (1 << 128)
            if not -P1305 < d < P1305:
                continue
            x = ((d - (a1 - a2)) * inv) % P1305
            if x >= 1 << 128:
                continue
            ct = x.to_bytes(16, "little") + c_rest
            p1v, _ = _poly_acc(aad, ct, r1)
            p2v, _ = _poly_acc(aad, ct, r2)
            if (p1v + s1) % (1 << 128) != (p2v + s2) % (1 << 128):
                continue
            tag = ((p1v + s1) % (1 << 128)).to_bytes(16, "little")
            full = ct + tag
            m1 = ChaCha20Poly1305(dek1).decrypt(nonce, full, aad)
            m2 = ChaCha20Poly1305(dek2).decrypt(nonce, full, aad)
            assert m1[pv.SALT_SIZE:] == pt and m1[16:32] == salt_tail and m1 != m2
            rs, _ = recipients_for(cid, ["gate-paper-1", "auditor-1"])
            entries = []
            for rcp, dek in zip(rs, (dek1, dek2)):
                enc, ctx = hpke.setup_base_s(rcp.pk, pv.hpke_info(), rcp.sk_e)
                entries.append(pv.Entry(rcp.kid, enc, ctx.seal(pv.hpke_aad(rcp.kid), dek)))
            blob = pv.blob_encode(pv.Blob(0, entries, nonce, full))
            return {"blob": blob, "m1": m1, "m2": m2, "dek1": dek1, "dek2": dek2, "tries": t + 1}
    raise RuntimeError("no key-commitment solution found")


# ---------------------------------------------------------------- DCA body vectors

def dca_vectors() -> dict:
    cases = []
    for cid, d, desc in [("dca_minimal", DCA_MINIMAL, "No last_fills."),
                         ("dca_with_fills", DCA_WITH_FILLS, "Two fills from the previous periods.")]:
        b = pv.dca_encode(d)
        assert pv.dca_decode(b) == d
        cases.append({"id": cid, "description": desc, "input": dca_to_json(d), "cbor_hex": b.hex(),
                      "action_ref": "pb_one_recipient_dca"})
    base = pv.dca_to_cbor(DCA_MINIMAL)
    rejects = []

    def r(cid, desc, b):
        try:
            pv.dca_decode(b)
        except Exception as e:  # noqa: BLE001
            assert getattr(e, "sentinel", "") == "dca.ErrMalformed", (cid, e)
        else:
            raise AssertionError(f"{cid} decodes")
        rejects.append({"id": cid, "description": desc, "cbor_hex": b.hex(), "expect_error": "dca.ErrMalformed"})

    r("dca_unknown_key", "Extra key 7.", encode(w(base, 7, 0)))
    r("dca_missing_order", "Key 6 (order) absent.", encode({k: v for k, v in base.items() if k != 6}))
    r("dca_unsorted_keys", "Keys 2 and 1 swapped.",
      encode(Pairs(tuple([(2, base[2]), (1, base[1])] + [(k, base[k]) for k in (3, 4, 6)]))))
    r("dca_float_price", "price.price as a double.",
      encode(w(base, 4, Pairs(((1, "ibkr.snapshot"), (2, 756733), (3, Raw(b"\xfb\x40\x81\xe0\x00\x00\x00\x00\x00")),
                                (4, T0 - 30))))))
    r("dca_last_fills_empty", "last_fills present with 0 entries; an optional field is absent, never empty.",
      encode(w(base, 5, [])))
    r("dca_last_fills_9", "last_fills with 9 entries.",
      encode(w(base, 5, [{1: T0 - i, 2: 1, 3: 1, 4: 1} for i in range(1, 10)])))
    r("dca_currency_lowercase", "budget.currency usd.",
      encode(w(base, 3, w(base[3], 1, "usd"))))
    r("dca_order_side_3", "order.side 3.", encode(w(base, 6, w(base[6], 1, 3))))
    r("dca_period_zero", "schedule.period_s 0.", encode(w(base, 2, w(base[2], 1, 0))))
    r("dca_strategy_id_space", "strategy_id with a space.", encode(w(base, 1, "dca spy")))
    return {"cases": cases, "reject": rejects}


# ---------------------------------------------------------------- main

def rfc_text_kat() -> dict:
    """The RFC 9180 A.2.1 values printed in the RFC text (setup, encryptions 0, 1, 2, 4, 255, 256, exports)."""
    v = json.loads(KAT_RFC_TEXT.read_text())["vector"]
    keep = ["mode", "kem_id", "kdf_id", "aead_id", "info", "ikmE", "pkEm", "skEm", "ikmR", "pkRm", "skRm", "enc",
            "shared_secret", "key_schedule_context", "secret", "key", "base_nonce", "exporter_secret"]
    out = {k: (str(v[k]) if isinstance(v[k], int) else v[k]) for k in keep}
    out["encryptions"] = [dict(seq=str(i), **{k: v["encryptions"][i][k] for k in ("pt", "aad", "nonce", "ct")})
                          for i in (0, 1, 2, 4, 255, 256)]
    out["exports"] = [{"exporter_context": x["exporter_context"], "L": str(x["L"]),
                       "exported_value": x["exported_value"]} for x in v["exports"]]
    out["source"] = "RFC 9180 Appendix A.2.1 (base mode, DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20Poly1305)"
    return out


def build() -> dict:
    p1 = payload_dca_minimal()
    c1, s1 = valid_case("pb_one_recipient_dca", "One recipient; context is the DCA media type without fills.",
                        p1, ["gate-paper-1"])
    names16 = ["gate-paper-1", "auditor-1", "counterparty-1"] + [f"rcpt-{i:02d}" for i in range(4, 17)]
    c2, _ = valid_case("pb_sixteen_recipients_dca",
                       "16 recipients; DCA context with fills; every optional payload field present; JSON metadata.",
                       payload_dca_full(), names16)
    c3, s3 = valid_case("pb_two_recipients_json_context",
                        "Two recipients; JSON context, text/plain metadata; SELL with a price bound.",
                        payload_json_sell(), ["gate-paper-1", "auditor-1"])
    c4, _ = valid_case("pb_opaque_kid_empty_context",
                       "One recipient with a 32-byte binary kid; application/octet-stream context with empty data.",
                       payload_empty_context(), ["opaque-32"])
    kc = key_commitment_blob(p1)
    g = KEYS["gate-paper-1"]
    ph = hashlib.sha256(kc["m1"]).digest()
    action_cbor = encode(to_cbor(p1["action"], ACTION))
    constraints_cbor = encode(to_cbor(p1["constraints"], CONSTRAINTS))
    assert pv.open_payload(kc["blob"], g["sk"], g["kid"], ph, action_cbor, constraints_cbor) == p1
    kc_case = rj("pb_key_commitment_two_deks", "plaintext", "O7",
                 "One ciphertext that ChaCha20-Poly1305 accepts under two DEKs. gate-paper-1 unwraps DEK1 and opens "
                 "the committed payload; auditor-1 unwraps DEK2, the AEAD check passes, and the bytes differ. Only "
                 "the plaintext_hash comparison, made before parsing, rejects them.",
                 kc["blob"], "sdk.ErrPlaintextHashMismatch", key="auditor-1", kid_hex=KEYS["auditor-1"]["kid"],
                 plaintext_hash_hex=ph, action_cbor_hex=action_cbor, constraints_cbor_hex=constraints_cbor,
                 honest_key="gate-paper-1", honest_kid_hex=g["kid"], dek1_hex=kc["dek1"], dek2_hex=kc["dek2"],
                 auditor_aead_plaintext_hex=kc["m2"])
    rejects = decode_rejects(s1) + open_rejects(s1, s3) + plaintext_rejects(p1, s1) + [kc_case]
    for rcase in rejects:
        assert rcase["expect_error"]
    return {
        "format": FORMAT,
        "suite": {
            "hpke_mode": "0", "kem_id": "32", "kdf_id": "1", "aead_id": "3",
            "hpke_info_hex": pv.hpke_info().hex(),
            "hpke_aad": "uint8(len(kid)) || kid",
            "payload_aead": "ChaCha20-Poly1305 (RFC 8439)",
            "payload_aad_hex": pv.payload_aad().hex(),
        },
        "derivation": {
            "recipient_key": "(sk, pk) = DeriveKeyPair(SHA-256(\"edicta/v0 test recipient|\" + name)), RFC 9180 section 7.1.3",
            "ephemeral_key": "skE = DeriveKeyPair(SHA-256(\"edicta/v0 test ephemeral|\" + case_id + \"|\" + index)).sk; index is the 0-based recipient position",
            "dek": "SHA-256(\"edicta/v0 test dek|\" + case_id)",
            "aead_nonce": "SHA-256(\"edicta/v0 test aead nonce|\" + case_id)[0:12]",
            "salt": "SHA-256(\"edicta/v0 test payload salt|\" + case_id)",
            "note": "Production draws all of these from a CSPRNG. Reject vectors built from a valid case reuse that case's salt, DEK and nonce; their ephemeral keys use their own id.",
        },
        "params": params_to_json(PARAMS),
        "gate": gate_to_json(GATE),
        "hpke_kat": rfc_text_kat(),
        "recipient_keys": {n: {"kid_hex": k["kid"].hex(), "ikm_hex": k["ikm"].hex(), "sk_hex": k["sk"].hex(),
                               "pk_hex": k["pk"].hex()} for n, k in KEYS.items()},
        "cases": [c1, c2, c3, c4],
        "reject": rejects,
        "dca": dca_vectors(),
    }


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    path = OUT / "payload_blob.json"
    path.write_text(json.dumps(build(), indent=2, ensure_ascii=True) + "\n")
    print(f"wrote {path}")


if __name__ == "__main__":
    main()
