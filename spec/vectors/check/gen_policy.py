#!/usr/bin/env python3
"""Writes the policy v1 vectors (spec/policy-v1.md, policy-v1.0).

spec/vectors/policy/{facts,mandate,render,state,engine,verify,archive,api}.json
and spec/vectors/profiles/bank-send/tia_transfer_facts.json. Deterministic:
every key, hash and signature is derived from fixed labels.

Usage: python3 spec/vectors/check/gen_policy.py [--out DIR]
"""

from __future__ import annotations

import sys

sys.dont_write_bytecode = True

import copy
import hashlib
import json
from pathlib import Path

import policy_v1 as P
import profile_bank_send as bs
from cbor_strict import Raw, encode
from edicta import TAG_AUTHORIZATION, TAG_AUTHORIZATION_SIG, action_hash, tagged

HERE = Path(__file__).resolve().parent
VECTORS = HERE.parent
FORMAT = "edicta-policy-vectors/v1"
# Each file carries the revision that last changed its bytes.
REVISION = "policy-v1.0"
REVISION_3 = "policy-v1.0"
REVISION_4 = "policy-v1.0"
REVISION_6 = "policy-v1.0"
REVISION_7 = "policy-v1.0"
REVISION_8 = "policy-v1.0"
REVISION_9 = "policy-v1.0"
T0 = 1791000000
GATE_ID = "gate-paper-1"


def sha(label: str) -> bytes:
    return hashlib.sha256(label.encode()).digest()


CORE_KEYS = json.loads((VECTORS / "keys.json").read_text())["keys"]
SEEDS = {n: bytes.fromhex(CORE_KEYS[n]["seed_hex"]) for n in ("agent1", "agent2", "gate1")}
SEEDS["p1"] = sha("edicta/policy/v1 test principal|p1")
SEEDS["p2"] = sha("edicta/policy/v1 test principal|p2")
PUB = {n: P.ed_pub(s) for n, s in SEEDS.items()}
A1, A2, G1 = PUB["agent1"], PUB["agent2"], PUB["gate1"]
AGENTS = sorted([A1, A2])

import principal_crypto as PC  # noqa: E402

# secp256k1 test principals (sig_type 2 and 3) and X25519 auditor keys.
SECP = {n: sha("edicta/policy/v1 test principal secp|" + n) for n in ("p1", "p2")}
SECP_PUB = {n: PC.pub_compressed(s) for n, s in SECP.items()}
ETH_ADDR = {n: PC.eth_address(PC.pub_point(s)) for n, s in SECP.items()}
HRP = "celestia"


def auditor_key(kid: bytes) -> tuple:
    import hpke_base
    return hpke_base.derive_key_pair(sha("edicta/policy/v1 test auditor|" + kid.decode()))


def auditor(name: str, label: str) -> dict:
    pk = auditor_key(name.encode())[1]
    return {"kid": P.auditor_kid(pk), "pubkey": pk, "label": label}


# Mandate order is ascending by the derived kid.
AUDITORS = sorted([auditor("auditor-1", "Alice"), auditor("auditor-2", "Bob")], key=lambda a: a["kid"])


def state_salt(label: str) -> bytes:
    return sha("edicta/policy/v1 test state salt|" + label)


def mid(label: str) -> bytes:
    return sha("edicta/policy/v1 test mandate_id|" + label)[:16]


def ch_of(label: str) -> bytes:
    return sha("edicta/policy/v1 test commitment|" + label)


# JSON conversion: uints as decimal strings, bytes as hex, recursively.

def js(x):
    if isinstance(x, bool) or x is None:
        return x
    if isinstance(x, int):
        return str(x)
    if isinstance(x, (bytes, bytearray)):
        return bytes(x).hex()
    if isinstance(x, dict):
        return {str(k): js(v) for k, v in x.items()}
    if isinstance(x, list):
        return [js(v) for v in x]
    return x


def F(amount: int, recipient="test:alice", asset="test:usd", scale=2, kind="transfer") -> dict:
    f = {"kind": kind, "asset": asset, "amount": P.amt(amount), "scale": scale}
    if recipient is not None:
        f["recipient"] = recipient
    return f


def raw_signed_mandate(seed: bytes, m: dict, sig: bytes | None = None) -> bytes:
    """Signed mandate bytes without validation (for rejects)."""
    canon = encode(P.to_cbor(m, P.S_MANDATE))
    if sig is None:
        sig = P.ed_sign(seed, P.signed_message("mandate-sig", P.mandate_hash(canon)))
    return encode({1: Raw(canon), 2: sig})


# Facts.

def gen_facts():
    cases = [
        ("facts_transfer", "A transfer with a recipient.", F(1500000, "cosmos:mocha-4:celestia1abc", "cosmos:mocha-4/utia", 6)),
        ("facts_no_recipient", "No recipient: key 5 absent.", F(250, None)),
        ("facts_zero", "Amount zero is h'00'.", F(0)),
        ("facts_amount_max", "Amount 2^256 - 1 (32 bytes).", F(P.MAX_AMOUNT, scale=0, asset="test:big")),
        ("facts_scale_255", "Scale 255, other kind token.", F(7, kind="swap-v2", scale=255)),
        ("facts_asset_128", "Asset of 128 bytes.", F(1, asset="a" * 128)),
    ]
    out = []
    for i, d, f in cases:
        out.append({"id": i, "description": d, "input": js(f), "cbor_hex": P.encode_facts(f).hex()})
    good = P.encode_facts(F(1500))
    base = P.to_cbor(F(1500), P.S_FACTS())

    def mut(**kw):
        m = dict(base)
        for k, v in kw.items():
            if v is None:
                m.pop(int(k[1:]), None)
            else:
                m[int(k[1:])] = v
        return encode(m)

    rejects = [
        ("facts_unknown_key", "Key 6.", mut(k6=1)),
        ("facts_missing_amount", "No key 3.", mut(k3=None)),
        ("facts_amount_nonminimal", "Amount with a leading zero byte.", mut(k3=b"\x00\x05")),
        ("facts_amount_33", "Amount of 33 bytes.", mut(k3=b"\x01" * 33)),
        ("facts_amount_empty", "Amount of 0 bytes.", mut(k3=b"")),
        ("facts_scale_256", "Scale 256.", mut(k4=256)),
        ("facts_scale_negative", "Scale -1 (major type 1).", mut(k4=-1)),
        ("facts_kind_upper", "Kind with an upper-case letter.", mut(k1="Transfer")),
        ("facts_kind_digit_first", "Kind starting with a digit.", mut(k1="1transfer")),
        ("facts_asset_space", "Asset with a space.", mut(k2="test usd")),
        ("facts_asset_129", "Asset of 129 bytes.", mut(k2="a" * 129)),
        ("facts_asset_nonascii", "Asset with U+00E9.", mut(k2="test:caf\u00e9")),
        ("facts_recipient_empty", "Recipient of 0 bytes.", mut(k5="")),
        ("facts_amount_tstr", "Amount as text.", mut(k3="1500")),
        ("facts_trailing", "A zero byte after the map.", good + b"\x00"),
        ("facts_unsorted", "Key 2 before key 1.", bytes.fromhex("a5") + encode(2) + encode("test:usd") + encode(1)
         + encode("transfer") + encode(3) + encode(P.amt(1500)) + encode(4) + encode(2) + encode(5) + encode("test:alice")),
        ("facts_indefinite", "Indefinite-length map.", b"\xbf" + good[1:] + b"\xff"),
        ("facts_float_scale", "Scale as a half float.", good.replace(bytes.fromhex("0402"), bytes.fromhex("04f94000"))),
        ("facts_too_large", "513 bytes (recipient padded), above the cap before parsing.",
         encode({1: "transfer", 2: "test:usd", 3: b"\x01", 4: 0, 5: "r" * 128, 6: "x" * 360})),
        ("facts_array", "An array instead of a map.", encode(["transfer"])),
    ]
    rej = []
    for i, d, b in rejects:
        try:
            P.decode_facts(b)
            raise AssertionError(f"{i} decodes")
        except P.PolicyError as e:
            rej.append({"id": i, "description": d, "cbor_hex": b.hex(), "expect_error": "ErrFactsInvalid",
                        "cause": e.cause})
    for c in out:
        assert P.decode_facts(bytes.fromhex(c["cbor_hex"])) is not None
    return {"cases": out, "reject": rej}


# Mandates.

def base_mandate(label="m_full", **over) -> dict:
    m = {"format": 1, "principal": PUB["p1"], "gate_id": GATE_ID, "agents": AGENTS, "not_before": T0 - 86400,
         "not_after": T0 + 30 * 86400,
         "assets": [{"asset": "test:usd", "scale": 2, "per_action_max": P.amt(5000),
                     "periods": [{"hours": 1, "max": P.amt(2000)}, {"hours": 24, "max": P.amt(10000)}],
                     "recipients": ["test:alice", "test:bob"]}],
         "count_limits": [{"hours": 1, "max_count": 5}], "mandate_id": mid(label), "version": 1,
         "max_decision_age": 1800, "min_spacing": 10, "kinds": ["transfer"]}
    m.update(over)
    return {k: v for k, v in m.items() if v is not None}


def mandate_inputs():
    full = base_mandate("m_full", assets=[
        {"asset": "test:eth", "scale": 18, "periods": [{"hours": 744, "max": P.amt(10 ** 18)}]},
        {"asset": "test:usd", "scale": 2, "per_action_max": P.amt(5000),
         "periods": [{"hours": 1, "max": P.amt(2000)}, {"hours": 24, "max": P.amt(10000)}],
         "recipients": ["test:alice", "test:bob"]}],
        count_limits=[{"hours": 1, "max_count": 5}, {"hours": 24, "max_count": 20}])
    minimal = {"format": 1, "principal": PUB["p1"], "gate_id": GATE_ID, "agents": [A1], "not_before": 1,
               "not_after": 2, "assets": [{"asset": "test:usd", "scale": 2, "per_action_max": P.amt(1)}],
               "mandate_id": bytes(16), "version": 1}
    v2 = copy.deepcopy(full)
    v2["version"] = 2
    v2["assets"][1]["per_action_max"] = P.amt(4000)
    big = {"format": 1, "principal": PUB["p2"], "gate_id": "gate:x/y.z_1-2", "agents": [A2], "not_before": T0,
           "not_after": P.MAX_RFC3339, "assets": [{"asset": "test:big", "scale": 0, "per_action_max": P.amt(P.MAX_AMOUNT)}],
           "mandate_id": mid("m_big"), "version": 7, "max_decision_age": 86400, "min_spacing": 2678400,
           "kinds": ["swap", "transfer"]}
    scale18 = {"format": 1, "principal": PUB["p1"], "gate_id": GATE_ID, "agents": AGENTS, "not_before": T0,
               "not_after": T0 + 3600,
               "assets": [{"asset": "eip155:1/erc20:0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", "scale": 18,
                           "per_action_max": P.amt(5), "periods": [{"hours": 1, "max": P.amt(1234567890123456789)},
                                                                    {"hours": 744, "max": P.amt(10 ** 20)}]}],
               "mandate_id": mid("m_scale18"), "version": 1}
    return [("m_full", "Every field; two assets, two count limits.", "p1", full),
            ("m_full_v2", "m_full version 2 with a lower per-action max: same mandate_id, same counter key.", "p1", v2),
            ("m_minimal", "Required fields only; mandate_id all zero; recipients any, kinds any, defaults.", "p1",
             minimal),
            ("m_big", "Principal p2; scale 0 with per-action max 2^256 - 1; bounds of every range.", "p2", big),
            ("m_scale18", "Scale 18 amounts and a 744 h window.", "p1", scale18)] + scheme_mandates(full)


def scheme_mandates(full: dict) -> list:
    """Draft.5 cases: one full mandate per secp256k1 scheme, fast-mode consent, private mode."""
    adr = dict(copy.deepcopy(full), principal=SECP_PUB["p1"], mandate_id=mid("m_adr036"), sig_type=2,
               principal_hrp=HRP)
    eth = dict(copy.deepcopy(full), principal=ETH_ADDR["p1"], mandate_id=mid("m_eip712"), sig_type=3)
    fast = dict(copy.deepcopy(full), mandate_id=mid("m_fast_mode"), fast_mode_max_delay=100)
    priv = dict(copy.deepcopy(full), mandate_id=mid("m_private"), auditors=AUDITORS, state_salt=state_salt("m_private"))
    return [("m_adr036", "m_full under Cosmos ADR-036 (sig_type 2): secp256k1 principal p1, HRP celestia; the "
             "signature is over the amino sign document whose data is the rendered text ending in the mandate hash.",
             "p1_secp", adr),
            ("m_eip712", "m_full under EIP-712 (sig_type 3): the principal is the Ethereum address of secp256k1 p1.",
             "p1_secp", eth),
            ("m_fast_mode", "m_full with fast_mode_max_delay 100 blocks (fast mode allowed).", "p1", fast),
            ("m_private", "m_full with two auditors (private mode): derived kids, labels, and the counter's "
             "state_salt.", "p1", priv)]


def seed_of(signer: str) -> bytes:
    return SECP[signer[:-5]] if signer.endswith("_secp") else SEEDS[signer]


def scheme_fields(m: dict, h: bytes) -> dict:
    st = m.get("sig_type")
    if st == 2:
        data = P.adr036_data(m, h)
        return {"adr036_signer": P.adr036_signer(m), "adr036_data": data,
                "signdoc": P.adr036_signdoc(data, P.adr036_signer(m)).decode()}
    if st == 3:
        return {"eip712_digest_hex": P.eip712_parts(m, h)["digest"].hex()}
    return {}


def gen_mandate():
    cases = []
    for i, d, signer, m in mandate_inputs():
        sm, h, sig = P.sign_mandate(seed_of(signer), m)
        canon = P.mandate_cbor(m)
        assert P.verify_mandate(sm)[1] == h
        cases.append({"id": i, "description": d, "signer": signer, "input": js(m), "mandate_cbor_hex": canon.hex(),
                      "mandate_hash_hex": h.hex(), "signed_message_hex": P.signed_message("mandate-sig", h).hex(),
                      "signature_hex": sig.hex(), "signed_mandate_hex": sm.hex(),
                      "counter_key_hex": P.counter_key_of(m).hex(), **scheme_fields(m, h)})
    base = base_mandate("m_reject")
    good = raw_signed_mandate(SEEDS["p1"], base)
    small_order = bytes([1]) + bytes(31)

    def m_(**kw):
        m = copy.deepcopy(base)
        for k, v in kw.items():
            if v is None:
                m.pop(k)
            else:
                m[k] = v
        return raw_signed_mandate(SEEDS["p1"], m)

    def asset(**kw):
        r = copy.deepcopy(base["assets"][0])
        for k, v in kw.items():
            if v is None:
                r.pop(k)
            else:
                r[k] = v
        return m_(assets=[r])

    flipped = bytearray(good)
    flipped[-1] ^= 1
    rejects = [
        ("sig_flipped", "Last signature byte flipped.", bytes(flipped), "ErrMandateSignature"),
        ("sig_other_principal", "Signed by p2, names p1.", raw_signed_mandate(SEEDS["p2"], base), "ErrMandateSignature"),
        ("sig_under_verdict_tag", "Signed over the mandate hash under the verdict signature tag.",
         raw_signed_mandate(SEEDS["p1"], base, P.ed_sign(SEEDS["p1"], P.signed_message(
             "verdict-sig", P.mandate_hash(encode(P.to_cbor(base, P.S_MANDATE)))))), "ErrMandateSignature"),
        ("principal_small_order", "Principal is a small-order point.", m_(principal=small_order), "ErrMandateInvalid"),
        ("principal_is_agent", "Principal listed as an agent.", m_(agents=sorted([A1, PUB["p1"]])), "ErrMandateInvalid"),
        ("agents_unsorted", "Agents descending.", m_(agents=sorted(AGENTS, reverse=True)), "ErrMandateInvalid"),
        ("agents_duplicate", "One agent twice.", m_(agents=[A1, A1]), "ErrMandateInvalid"),
        ("agents_empty", "No agents.", m_(agents=[]), "ErrMandateInvalid"),
        ("not_before_zero", "not_before 0.", m_(not_before=0), "ErrMandateInvalid"),
        ("not_after_equal", "not_after equals not_before.", m_(not_after=base["not_before"]), "ErrMandateInvalid"),
        ("not_after_beyond_9999", "not_after above 9999-12-31T23:59:59Z.", m_(not_after=P.MAX_RFC3339 + 1),
         "ErrMandateInvalid"),
        ("assets_unsorted", "Assets descending.", m_(assets=[base["assets"][0], {"asset": "test:aaa", "scale": 0,
                                                                                 "per_action_max": P.amt(1)}]),
         "ErrMandateInvalid"),
        ("asset_no_limit", "An asset rule with neither per_action_max nor periods.", asset(per_action_max=None,
                                                                                          periods=None),
         "ErrMandateInvalid"),
        ("per_action_max_zero", "per_action_max h'00'.", asset(per_action_max=b"\x00"), "ErrMandateInvalid"),
        ("per_action_max_nonminimal", "per_action_max h'0001'.", asset(per_action_max=b"\x00\x01"),
         "ErrMandateInvalid"),
        ("period_hours_0", "A period of 0 hours.", asset(periods=[{"hours": 0, "max": P.amt(1)}]), "ErrMandateInvalid"),
        ("period_hours_745", "A period of 745 hours.", asset(periods=[{"hours": 745, "max": P.amt(1)}]),
         "ErrMandateInvalid"),
        ("periods_unsorted", "24 h before 1 h.", asset(periods=list(reversed(base["assets"][0]["periods"]))),
         "ErrMandateInvalid"),
        ("periods_5", "Five periods.", asset(periods=[{"hours": h, "max": P.amt(1)} for h in range(1, 6)]),
         "ErrMandateInvalid"),
        ("recipients_unsorted", "Recipients descending.", asset(recipients=["test:bob", "test:alice"]),
         "ErrMandateInvalid"),
        ("recipients_empty", "Recipients key with no entry.", asset(recipients=[]), "ErrMandateInvalid"),
        ("scale_256", "Scale 256.", asset(scale=256), "ErrMandateInvalid"),
        ("count_max_0", "max_count 0.", m_(count_limits=[{"hours": 1, "max_count": 0}]), "ErrMandateInvalid"),
        ("count_max_above", "max_count 2^32 + 1.", m_(count_limits=[{"hours": 1, "max_count": (1 << 32) + 1}]),
         "ErrMandateInvalid"),
        ("max_decision_age_0", "max_decision_age 0.", m_(max_decision_age=0), "ErrMandateInvalid"),
        ("max_decision_age_86401", "max_decision_age 86401.", m_(max_decision_age=86401), "ErrMandateInvalid"),
        ("min_spacing_above", "min_spacing 2678401.", m_(min_spacing=2678401), "ErrMandateInvalid"),
        ("version_0", "version 0.", m_(version=0), "ErrMandateInvalid"),
        ("format_2", "format 2.", m_(format=2), "ErrMandateInvalid"),
        ("mandate_id_15", "mandate_id of 15 bytes.", m_(mandate_id=bytes(15)), "ErrMandateInvalid"),
        ("gate_id_space", "gate_id with a space.", m_(gate_id="gate 1"), "ErrMandateInvalid"),
        ("kinds_grammar", "A kind with an upper-case letter.", m_(kinds=["Transfer"]), "ErrMandateInvalid"),
        ("kinds_unsorted", "Kinds descending.", m_(kinds=["transfer", "swap"]), "ErrMandateInvalid"),
        ("unknown_key_14", "Mandate key 14 = 1. Before draft.5 the key was unknown; since draft.5 it is sig_type and "
         "the value 1 is refused (bytes unchanged, same error).",
         encode({1: Raw(encode({**P.to_cbor(base, P.S_MANDATE), 14: 1})), 2: bytes(64)}), "ErrMandateInvalid"),
        ("signature_63", "Signature of 63 bytes.", good[:-66] + encode(bytes(63)), "ErrMandateInvalid"),
        ("trailing", "A zero byte after the signed mandate.", good + b"\x00", "ErrMandateInvalid"),
        ("too_large", "16385 bytes, refused before parsing.", good + bytes(16385 - len(good)), "ErrMandateInvalid"),
    ]
    rejects += scheme_rejects(base)
    rej = []
    for row in rejects:
        i, d, b, want = row[:4]
        try:
            P.verify_mandate(b)
            raise AssertionError(f"{i} verifies")
        except P.PolicyError as e:
            assert e.sentinel == want, (i, e.sentinel, e.cause)
            r = {"id": i, "description": d, "signed_mandate_hex": b.hex(), "expect_error": want, "cause": e.cause}
            if len(row) > 4:
                r["rule"] = row[4]
            rej.append(r)
    keys = {n: {"seed_hex": SEEDS[n].hex(), "public_key_hex": PUB[n].hex(),
                "source": ("core keys.json" if n in CORE_KEYS else f"SHA-256(\"edicta/policy/v1 test principal|{n}\")")}
            for n in ("p1", "p2", "agent1", "agent2", "gate1")}
    for n in ("p1", "p2"):
        keys[n + "_secp"] = {"seed_hex": SECP[n].hex(), "public_key_compressed_hex": SECP_PUB[n].hex(),
                             "eth_address_hex": ETH_ADDR[n].hex(),
                             "cosmos_address": PC.cosmos_address(SECP_PUB[n], HRP),
                             "source": f"SHA-256(\"edicta/policy/v1 test principal secp|{n}\"), secp256k1 scalar"}
    for name in ("auditor-1", "auditor-2"):
        sk_, pk_ = auditor_key(name.encode())
        keys["auditor:" + name] = {"kid_hex": P.auditor_kid(pk_).hex(), "sk_hex": sk_.hex(), "pk_hex": pk_.hex(),
                                   "source": "DeriveKeyPair(SHA-256(\"edicta/policy/v1 test auditor|\" + name)), RFC "
                                             "9180 section 7.1.3; kid = SHA-256(tag(\"edicta/v1/auditor-kid\") || "
                                             "pk)[0..16]"}
    return {"keys": keys, "cases": cases, "reject": rej}


def not_on_curve_x() -> bytes:
    x = 1
    while PC.decompress(b"\x02" + x.to_bytes(32, "big")) is not None:
        x += 1
    return b"\x02" + x.to_bytes(32, "big")


def scheme_rejects(base: dict) -> list:
    """Draft.5 rejects: value rules of keys 14 to 17 and the principal, and one bad signature per scheme."""
    adr = dict(base, principal=SECP_PUB["p1"], sig_type=2, principal_hrp=HRP)
    eth = dict(base, principal=ETH_ADDR["p1"], sig_type=3)
    z64, z65 = bytes(64), bytes(65)

    def raw(m, sig):
        return encode({1: Raw(encode(P.to_cbor(m, P.S_MANDATE))), 2: sig})

    def without(m, key):
        return {k: v for k, v in m.items() if k != key}

    def signed(m, seed):
        return P.sign_mandate(seed, m)[0]

    def flip_last_sig_byte(b: bytes, n: int) -> bytes:
        x = bytearray(b)
        x[-1 if n == 64 else -2] ^= 1
        return bytes(x)

    good_adr = signed(adr, SECP["p1"])
    good_eth = signed(eth, SECP["p1"])
    sig_eth = good_eth[-65:]
    high_s = sig_eth[:32] + (PC.N - int.from_bytes(sig_eth[32:64], "big")).to_bytes(32, "big") + bytes([sig_eth[64] ^ 1])
    zero = {"kid": P.auditor_kid(bytes(32)), "pubkey": bytes(32), "label": "Zero"}
    kid_low = sorted([AUDITORS[0], zero], key=lambda a: a["kid"])
    ss = state_salt("m_reject")

    def aud(**kw):
        a = dict(AUDITORS[0])
        a.update(kw)
        return sorted([a, AUDITORS[1]], key=lambda x: x["kid"])

    pa = lambda auditors, **kw: raw(dict(base, auditors=auditors, state_salt=ss, **kw), z64)  # noqa: E731
    return [
        ("sig_type_1_present", "sig_type 1: Ed25519 has one encoding, the absent key.", raw(dict(base, sig_type=1), z64),
         "ErrMandateInvalid", "sig_type"),
        ("sig_type_4", "sig_type 4 (reserved).", raw(dict(base, sig_type=4), z64), "ErrMandateInvalid", "sig_type"),
        ("hrp_without_adr036", "principal_hrp on an Ed25519 mandate.", raw(dict(base, principal_hrp=HRP), z64),
         "ErrMandateInvalid", "principal_hrp"),
        ("adr036_without_hrp", "sig_type 2 without principal_hrp.", raw(without(adr, "principal_hrp"), z64),
         "ErrMandateInvalid", "principal_hrp"),
        ("hrp_uppercase", "principal_hrp with an upper-case letter (decoding charset).",
         raw(dict(adr, principal_hrp="Celestia"), z64), "ErrMandateInvalid", "principal_hrp"),
        ("principal_32_for_adr036", "sig_type 2 with a 32-byte principal.", raw(dict(adr, principal=PUB["p1"]), z64),
         "ErrMandateInvalid", "principal"),
        ("principal_not_on_curve", "sig_type 2 with a compressed key whose x has no point on secp256k1.",
         raw(dict(adr, principal=not_on_curve_x()), z64), "ErrMandateInvalid", "principal"),
        ("principal_prefix_04", "sig_type 2 with first byte 0x04.", raw(dict(adr, principal=b"\x04" + SECP_PUB["p1"][1:]),
                                                                        z64), "ErrMandateInvalid", "principal"),
        ("principal_21_for_eip712", "sig_type 3 with a 21-byte principal.",
         raw(dict(eth, principal=ETH_ADDR["p1"] + b"\x00"), z65), "ErrMandateInvalid", "principal"),
        ("principal_20_for_ed25519", "Ed25519 (sig_type absent) with a 20-byte principal.",
         raw(dict(base, principal=ETH_ADDR["p1"]), z64), "ErrMandateInvalid", "principal"),
        ("signature_64_for_eip712", "sig_type 3 with a 64-byte signature.", raw(eth, z64), "ErrMandateInvalid",
         "signature"),
        ("signature_65_for_ed25519", "Ed25519 with a 65-byte signature.", raw(base, z65), "ErrMandateInvalid",
         "signature"),
        ("fast_mode_max_delay_0", "fast_mode_max_delay 0: off has one encoding, the absent key.",
         raw(dict(base, fast_mode_max_delay=0), z64), "ErrMandateInvalid", "fast_mode_max_delay"),
        ("fast_mode_max_delay_1001", "fast_mode_max_delay 1001.", raw(dict(base, fast_mode_max_delay=1001), z64),
         "ErrMandateInvalid", "fast_mode_max_delay"),
        ("auditors_unsorted", "Auditors descending by kid.", raw(dict(base, auditors=list(reversed(AUDITORS))), z64),
         "ErrMandateInvalid", "auditors"),
        ("auditors_duplicate_kid", "One kid twice.", raw(dict(base, auditors=[AUDITORS[0], AUDITORS[0]]), z64),
         "ErrMandateInvalid", "auditors"),
        ("auditor_low_order", "An auditor key that is a low-order X25519 point (all zero).",
         raw(dict(base, auditors=kid_low), z64), "ErrMandateInvalid", "auditors"),
        ("auditors_17", "Seventeen auditors.", raw(dict(base, auditors=[
            dict(AUDITORS[0], label=f"A{i:02d}") for i in range(17)], state_salt=ss), z64),
         "ErrMandateInvalid", "auditors"),
        ("auditors_empty_array", "auditors present with no entry.", pa([]), "ErrMandateInvalid", "auditors"),
        ("auditor_kid_mismatch", "An auditor whose kid is not SHA-256(tag(edicta/v1/auditor-kid) || pubkey)[0..16].",
         pa(aud(kid=sha("edicta/policy/v1 test other kid")[:16])), "ErrMandateInvalid", "auditor_kid"),
        ("kid_15_bytes", "A kid of 15 bytes.", pa(aud(kid=AUDITORS[0]["kid"][:15])), "ErrMandateInvalid", "auditors"),
        ("kid_17_bytes", "A kid of 17 bytes.", pa(aud(kid=AUDITORS[0]["kid"] + b"\x00")), "ErrMandateInvalid",
         "auditors"),
        ("auditor_pubkey_31", "An auditor pubkey of 31 bytes.", pa(aud(pubkey=AUDITORS[0]["pubkey"][:31])),
         "ErrMandateInvalid", "auditors"),
        ("auditor_label_empty", "An empty label.", pa(aud(label="")), "ErrMandateInvalid", "auditors"),
        ("auditor_label_65", "A label of 65 bytes.", pa(aud(label="L" * 65)), "ErrMandateInvalid", "auditors"),
        ("auditor_label_quote", "A label with a double quote.", pa(aud(label='Al"ice')), "ErrMandateInvalid",
         "auditors"),
        ("auditor_label_backslash", "A label with a backslash.", pa(aud(label="Al\\ice")), "ErrMandateInvalid",
         "auditors"),
        ("auditor_label_leading_space", "A label with a leading space.", pa(aud(label=" Alice")),
         "ErrMandateInvalid", "auditor_label"),
        ("auditor_label_trailing_space", "A label with a trailing space.", pa(aud(label="Alice ")),
         "ErrMandateInvalid", "auditor_label"),
        ("auditor_label_non_ascii", "A label with a non-ASCII character (U+00E9).", pa(aud(label="Al\u00e9")),
         "ErrMandateInvalid", "auditors"),
        ("auditors_duplicate_label", "Two auditors with the same label.", pa(aud(label=AUDITORS[1]["label"])), "ErrMandateInvalid",
         "auditor_label_duplicate"),
        ("state_salt_missing_with_auditors", "auditors without state_salt.", raw(dict(base, auditors=AUDITORS), z64),
         "ErrMandateInvalid", "state_salt"),
        ("state_salt_without_auditors", "state_salt on a public mandate.", raw(dict(base, state_salt=ss), z64),
         "ErrMandateInvalid", "state_salt"),
        ("state_salt_31", "state_salt of 31 bytes.", raw(dict(base, auditors=AUDITORS, state_salt=ss[:31]), z64),
         "ErrMandateInvalid", "state_salt"),
        ("sig_type_0", "sig_type 0 (reserved).", raw(dict(base, sig_type=0), z64), "ErrMandateInvalid", "sig_type"),
        ("principal_hrp_17", "principal_hrp of 17 characters.", raw(dict(adr, principal_hrp="c" * 17), z64),
         "ErrMandateInvalid", "principal_hrp"),
        ("hrp_with_eip712", "principal_hrp on an EIP-712 mandate.", raw(dict(eth, principal_hrp=HRP), z65),
         "ErrMandateInvalid", "principal_hrp"),
        ("sig_bad_adr036", "sig_type 2, last signature byte flipped.", flip_last_sig_byte(good_adr, 64),
         "ErrMandateSignature", "signature"),
        ("sig_bad_eip712", "sig_type 3, last byte of s flipped.", flip_last_sig_byte(good_eth, 65),
         "ErrMandateSignature", "signature"),
        ("sig_high_s_eip712", "sig_type 3 with s replaced by n - s and v flipped (the same point, high s).",
         good_eth[:-65] + high_s, "ErrMandateSignature", "signature"),
        ("sig_v_0_eip712", "sig_type 3 with v = 0 (recovery id without the 27 offset).",
         good_eth[:-1] + bytes([sig_eth[64] - 27]), "ErrMandateSignature", "signature"),
        ("sig_eip712_other_key", "sig_type 3 signed by secp256k1 p2, names the address of p1.", signed_raw_eth(eth),
         "ErrMandateSignature", "signature"),
    ]


def signed_raw_eth(m: dict) -> bytes:
    h = P.mandate_hash(encode(P.to_cbor(m, P.S_MANDATE)))
    return encode({1: Raw(encode(P.to_cbor(m, P.S_MANDATE))), 2: PC.sign_eth(SECP["p2"], P.eip712_parts(m, h)["digest"])})


ETH = {"asset": "test:eth", "scale": 18, "periods": [{"hours": 744, "max": P.amt(10 ** 18)}]}


def two_assets(label, version, eth_scale=18, eth=True, extra=()):
    usd = copy.deepcopy(base_mandate(label)["assets"][0])
    assets = ([dict(ETH, scale=eth_scale)] if eth else []) + [usd] + list(extra)
    return base_mandate(label, version=version, assets=sorted(assets, key=lambda r: r["asset"].encode()))


def gen_adoption():
    btc = {"asset": "test:btc", "scale": 8, "per_action_max": P.amt(10 ** 6)}
    cases = [
        ("adopt_scale_change_unused", "Version 2 changes the scale of test:eth, which no allow ever used: refused, "
         "the cell keeps version 1.", [two_assets("ad1", 1), two_assets("ad1", 2, eth_scale=6)]),
        ("adopt_scale_change_after_drop", "Version 2 drops test:eth, version 3 lists it again at another scale: "
         "refused, the cell still knows test:eth.", [two_assets("ad2", 1), two_assets("ad2", 2, eth=False),
                                                     two_assets("ad2", 3, eth_scale=6)]),
        ("adopt_keep_scales_add_asset", "Version 2 keeps every scale and adds test:btc; a restart with version 2 "
         "uses the cell.", [two_assets("ad3", 1), two_assets("ad3", 2, extra=[btc]), two_assets("ad3", 2, extra=[btc])]),
        ("adopt_version_below_cell", "The cell holds version 2; version 1 is refused.",
         [two_assets("ad4", 2), two_assets("ad4", 1)]),
        ("adopt_same_version_other_hash", "Version 1 again with another per-action max: refused.",
         [two_assets("ad5", 1), base_mandate("ad5", assets=[dict(ETH), dict(base_mandate("ad5")["assets"][0],
                                                                       per_action_max=P.amt(4000))])]),
    ]
    cases = [(i, d, ms, None) for i, d, ms in cases]
    # A cell grown by earlier versions to 1012 assets; only the cell matters, so
    # those versions are elided and the start cell is given directly.
    full = [f"test:a{n:04d}" for n in range(1025)]
    rules = lambda names: [{"asset": a, "scale": 2, "per_action_max": P.amt(1000)} for a in names]  # noqa: E731
    start = {"version": 63, "mandate_hash": sha("edicta/policy/v1 test mandate|adopt_scales_full start"),
             "scales": {a: 2 for a in full[:1012]}}
    cases.append(("adopt_scales_full", "The cell holds 1012 assets. Version 64 adds 12 new ones and reaches the "
                  "bound of 1024: switched. Version 65 adds one more: refused, the cell keeps version 64. Another "
                  "version 65 that lists only known assets: switched.",
                  [base_mandate("ad6", version=64, assets=rules(full[1008:1024])),
                   base_mandate("ad6", version=65, assets=rules(full[1009:1025])),
                   base_mandate("ad6", version=65, assets=rules(full[0:16]))], start))
    cases.append(("state_salt_changed_on_successor", "A private mandate (auditors, state_salt) and its version 2 "
                  "with another state_salt: refused, since the public chain links of one counter cross versions and "
                  "both sides must blind with one salt.",
                  [private_mandate("ad7"), dict(private_mandate("ad7", version=2),
                                                state_salt=sha("edicta/policy/v1 test other state salt"))], None))
    out = []
    for i, d, ms, start in cases:
        cell, steps = start, []
        for m in ms:
            sm, mh, _ = P.sign_mandate(SEEDS["p1"], m)
            st = {"signed_mandate_hex": sm.hex(), "mandate_hash_hex": mh.hex()}
            try:
                act, cell = P.adopt(cell, m, mh)
                st["expect"] = act
            except P.PolicyError as e:
                st.update(expect="refuse", error="gate.ErrInvalidConfig", cause=e.cause)
            st["version_after"] = str(cell["version"])
            st["scales_after"] = {a: str(v) for a, v in sorted(cell["scales"].items())}
            if "state_salt" in cell:
                st["state_salt_after_hex"] = cell["state_salt"].hex()
            steps.append(st)
        c = {"id": i, "description": d}
        if start is not None:
            c["start"] = {"version": str(start["version"]), "mandate_hash_hex": start["mandate_hash"].hex(),
                          "scales": {a: str(v) for a, v in sorted(start["scales"].items())}}
        out.append({**c, "steps": steps})
    return out


def gen_render(mandate_file):
    out = []
    for c in mandate_file["cases"]:
        m = dict(next(x for x in mandate_inputs() if x[0] == c["id"])[3])
        out.append({"id": "render_" + c["id"], "mandate_ref": c["id"], "text": P.render(m)})
    extra = base_mandate("render_any", assets=[{"asset": "test:usd", "scale": 0, "periods": [{"hours": 1, "max": P.amt(9)}]}],
                         count_limits=None, max_decision_age=None, min_spacing=None, kinds=None)
    extra = {k: v for k, v in extra.items() if v is not None}
    out.append({"id": "render_recipients_any_scale0", "input": js(extra), "text": P.render(extra)})
    for c in out:
        if "mandate_ref" in c:
            mc = next(x for x in mandate_file["cases"] if x["id"] == c["mandate_ref"])
            if "adr036_data" in mc:
                c["adr036_data"] = mc["adr036_data"]
    two = private_mandate("render_two", auditors=sorted([auditor("auditor-1", "Auditor 1"),
                                                         auditor("auditor-2", "Auditor l")], key=lambda a: a["kid"]))
    out.append({"id": "render_m_private_two_auditors", "description": "Two auditor labels that differ in one character "
                "(1 and l): each line carries the full 128-bit fingerprint beside the unverified label.",
                "input": js(two), "text": P.render(two)})
    esc = dict(base_mandate("render_escape", assets=[{"asset": "test:<a&b>", "scale": 2, "per_action_max": P.amt(100),
                                                      "recipients": ["x&y", "x<y>"]}]),
               principal=SECP_PUB["p2"], sig_type=2, principal_hrp=HRP)
    h = P.mandate_hash(P.mandate_cbor(esc))
    data = P.adr036_data(esc, h)
    out.append({"id": "render_escape_adr036", "description": "Asset and recipients with <, > and &. The rendered "
                "text and D carry them as is; the amino sign document carries D only in base64, so the JSON escapes "
                "of section 6.2 never apply to D (they would apply only to a signer or other field holding those "
                "characters).", "input": js(esc), "text": P.render(esc), "adr036_data": data,
                "signdoc": P.adr036_signdoc(data, P.adr036_signer(esc)).decode()})
    return {"cases": out}


# State.

def B(index, count, *sums):
    return {"format": 1, "index": index, "count": count,
            "sums": sorted([{"asset": a, "scale": s, "sum": P.amt(v)} for a, s, v in sums],
                           key=lambda x: (x["asset"].encode(), x["scale"]))}


def gen_state():
    k0 = P.k(T0)
    b1 = B(k0, 1, ("test:usd", 2, 1000))
    b2 = B(k0 + 1, 3, ("test:usd", 2, 1500), ("test:eth", 18, 10 ** 18), ("test:usd", 6, 7))
    b3 = B(k0 + 2, 1, ("test:big", 0, P.MAX_AMOUNT))
    b64 = B(k0 + 3, 64, *[(f"test:p{i:02d}", 0, 1) for i in range(64)])
    buckets = [("bucket_one_sum", b1), ("bucket_three_sums", b2), ("bucket_max_sum", b3), ("bucket_64_pairs", b64)]
    cs1 = {"format": 1, "buckets": [{"index": k0, "hash": P.bucket_hash(b1)}]}
    cs3 = {"format": 1, "buckets": [{"index": b["index"], "hash": P.bucket_hash(b)} for b in (b1, b2, b3)]}
    cs767 = {"format": 1, "buckets": [{"index": (1 << 33) + i, "hash": sha(f"edicta/policy/v1 test ref|{i}")}
                                      for i in range(767)]}
    st1 = {"format": 1, "seq": 1, "last_t": T0 + 100, "last_th": T0 + 100, "closed_root": P.EMPTY_ROOT,
           "open": B(k0, 1, ("test:usd", 2, 1000))}
    st5 = {"format": 1, "seq": 5, "last_t": T0 + 3 * 3600 + 5, "last_th": T0 + 3 * 3600 + 1, "closed_root": P.closed_root(cs3),
           "open": B(k0 + 3, 1, ("test:usd", 2, 400))}
    stcov = copy.deepcopy(st5)
    stcov["open"]["sums"][0]["sum"] = P.amt(399)
    out = {"genesis": {"state": js(P.GENESIS), "state_cbor_hex": P.state_cbor(P.GENESIS).hex(),
                       "state_hash_hex": P.state_hash(P.GENESIS).hex(),
                       "empty_closed_set_cbor_hex": P.closed_cbor(P.EMPTY_CLOSED).hex(),
                       "empty_closed_root_hex": P.EMPTY_ROOT.hex()},
           "buckets": [{"id": i, "input": js(b), "cbor_hex": P.bucket_cbor(b).hex(), "bucket_hash_hex": P.bucket_hash(b).hex()}
                       for i, b in buckets],
           "closed_sets": [{"id": "closed_one", "input": js(cs1), "cbor_hex": P.closed_cbor(cs1).hex(),
                            "closed_root_hex": P.closed_root(cs1).hex()},
                           {"id": "closed_three", "input": js(cs3), "cbor_hex": P.closed_cbor(cs3).hex(),
                            "closed_root_hex": P.closed_root(cs3).hex()},
                           {"id": "closed_767_large_index", "description": "767 refs, indices 2^33 + i (9-byte heads), "
                            "hash i = SHA-256(\"edicta/policy/v1 test ref|\" + i): the largest ClosedSet.",
                            "pattern": "index 8589934592 + i, hash SHA-256(\"edicta/policy/v1 test ref|\" + decimal i), i = 0..766",
                            "cbor_size": str(len(P.closed_cbor(cs767))),
                            "cbor_sha256_hex": hashlib.sha256(P.closed_cbor(cs767)).hexdigest(),
                            "closed_root_hex": P.closed_root(cs767).hex()}],
           "states": [{"id": i, "input": js(s), "cbor_hex": P.state_cbor(s).hex(), "state_hash_hex": P.state_hash(s).hex()}
                      for i, s in (("state_seq1", st1), ("state_seq5", st5), ("state_seq5_open_399", stcov))],
           "coverage": {"description": "state_seq5 and state_seq5_open_399 differ only in one open-bucket sum "
                        "(400 versus 399); their hashes differ, so the state hash covers the open bucket.",
                        "a": "state_seq5", "b": "state_seq5_open_399"}}
    assert P.state_hash(st5) != P.state_hash(stcov)
    assert len(P.closed_cbor(cs767)) == 35289

    rej = []

    def rj(i, d, kind, b):
        fn = {"bucket": P.decode_bucket, "closed_set": P.decode_closed, "state": P.decode_state}[kind]
        try:
            fn(b)
            raise AssertionError(i)
        except P.PolicyError as e:
            assert e.sentinel == "ErrStateInvalid"
            rej.append({"id": i, "description": d, "structure": kind, "cbor_hex": b.hex(),
                        "expect_error": "ErrStateInvalid", "cause": e.cause})

    def braw(b):
        return encode(P.to_cbor(b, P.S_BUCKET))

    def sraw(s):
        return encode(P.to_cbor(s, P.S_STATE))

    x = copy.deepcopy(b1); x["count"] = 0; rj("bucket_count_0", "count 0.", "bucket", braw(x))
    x = copy.deepcopy(b2); x["sums"] = list(reversed(x["sums"])); rj("bucket_sums_unsorted", "Sums descending.", "bucket", braw(x))
    x = copy.deepcopy(b2); x["sums"] = [x["sums"][0], x["sums"][0]]; rj("bucket_sums_duplicate", "One pair twice.", "bucket", braw(x))
    x = copy.deepcopy(b1); x["sums"] = []; rj("bucket_sums_empty", "No sums.", "bucket", braw(x))
    x = copy.deepcopy(b1); x["sums"][0]["sum"] = b"\x00\x01"; rj("bucket_sum_nonminimal", "Sum h'0001'.", "bucket", braw(x))
    x = B(k0, 65, *[(f"test:p{i:02d}", 0, 1) for i in range(65)]); rj("bucket_65_pairs", "65 pairs.", "bucket", braw(x))
    x = copy.deepcopy(b1); x["format"] = 2; rj("bucket_format_2", "format 2.", "bucket", braw(x))
    rj("bucket_unknown_key", "Key 5.", "bucket", encode({**P.to_cbor(b1, P.S_BUCKET), 5: 0}))
    x = copy.deepcopy(cs3); x["buckets"] = list(reversed(x["buckets"]))
    rj("closed_unsorted", "Refs descending.", "closed_set", encode(P.to_cbor(x, P.S_CLOSED)))
    x = {"format": 1, "buckets": [{"index": i, "hash": bytes(32)} for i in range(768)]}
    rj("closed_768", "768 refs.", "closed_set", encode(P.to_cbor(x, P.S_CLOSED)))
    x = {"format": 1, "buckets": [{"index": 1, "hash": bytes(31)}]}
    rj("closed_hash_31", "A 31-byte hash.", "closed_set", encode(P.to_cbor(x, P.S_CLOSED)))
    x = dict(P.GENESIS); x["open"] = b1; rj("state_genesis_with_open", "seq 0 with an open bucket.", "state", sraw(x))
    x = dict(P.GENESIS); x["closed_root"] = P.closed_root(cs1); rj("state_genesis_other_root", "seq 0 with a non-empty closed root.", "state", sraw(x))
    x = dict(st1); x.pop("open"); rj("state_seq1_no_open", "seq 1 without the open bucket.", "state", sraw(x))
    x = dict(st1); x["last_th"] = x["last_t"] + 1; rj("state_last_th_after_last_t", "last_th > last_t.", "state", sraw(x))
    x = copy.deepcopy(st1); x["open"]["index"] += 1; rj("state_open_index", "open.index != k(last_t).", "state", sraw(x))
    x = dict(st1); x["seq"] = 1 << 63; rj("state_seq_2_63", "seq 2^63.", "state", sraw(x))
    out["reject"] = rej
    return out


# Engine.

def run_engine(m, start, steps):
    led = start or {"state": P.GENESIS, "set": P.EMPTY_CLOSED, "buckets": {}}
    out = []
    for s in steps:
        if "repeat" in s:
            n, t, dt, f = int(s["repeat"]), int(s["t_h_start"]), int(s["t_h_step"]), s["facts"]
            for j in range(n):
                r = P.evaluate(m, led, f, t + j * dt)
                assert "deny" not in r, (j, r)
                led = r["next"]
            o = {"repeat": str(n), "t_h_start": str(t), "t_h_step": str(dt), "facts": js(f),
                 "expect": {"allow_all": True, "state_hash_hex": P.state_hash(led["state"]).hex(),
                            "closed": str(len(led["set"]["buckets"])),
                            "oldest_closed_index": str(led["set"]["buckets"][0]["index"]) if led["set"]["buckets"] else None,
                            "closed_root_hex": led["state"]["closed_root"].hex()}}
            out.append(o)
            continue
        r = P.evaluate(m, led, s["facts"], s["t_h"])
        o = {"note": s.get("note"), "facts": js(s["facts"]), "t_h": str(s["t_h"])}
        if "deny" in r:
            e = {"deny": r["deny"]}
            if "cause" in r:
                e["cause"] = r["cause"]
        else:
            e = {"allow": True, "eval_time": str(r["eval_time"]), "rolled_over": r["closed_bucket"] is not None,
                 "closed": str(len(r["next"]["set"]["buckets"])), "new_state_hash_hex": r["new_hash"].hex(),
                 "new_state_cbor_hex": P.state_cbor(r["next"]["state"]).hex()}
            if r["closed_bucket"] is not None:
                e["closed_bucket_hash_hex"] = P.bucket_hash(r["closed_bucket"]).hex()
                e["closed_set_cbor_hex"] = P.closed_cbor(r["closed_set"]).hex()
            led = r["next"]
        if o["note"] is None:
            del o["note"]
        o["expect"] = e
        out.append(o)
    return out, led


def ledger_json(led):
    return {"state_cbor_hex": P.state_cbor(led["state"]).hex(),
            "closed_set_cbor_hex": P.closed_cbor(led["set"]).hex(),
            "buckets_cbor_hex": [P.bucket_cbor(led["buckets"][i]).hex() for i in sorted(led["buckets"])]}


def simple_mandate(**over):
    m = {"format": 1, "principal": PUB["p1"], "gate_id": GATE_ID, "agents": AGENTS, "not_before": T0 - 86400,
         "not_after": T0 + 60 * 86400, "assets": [{"asset": "test:usd", "scale": 2, "periods": [{"hours": 1, "max": P.amt(1000)}]}],
         "mandate_id": mid("engine"), "version": 1}
    m.update(over)
    return m


def gen_engine():
    k0 = P.k(T0)
    usd = lambda a: F(a, None)  # noqa: E731
    sc = []

    def add(i, d, m, steps, start=None):
        P.check_mandate(m)
        if start:
            P.check_ledger(start)
        out, led = run_engine(m, copy.deepcopy(start) if start else None, steps)
        x = {"id": i, "description": d, "mandate": js(m)}
        if start:
            x["start"] = ledger_json(start)
        x["steps"] = out
        x["final"] = {"state_cbor_hex": P.state_cbor(led["state"]).hex(), "state_hash_hex": P.state_hash(led["state"]).hex()}
        sc.append(x)

    add("period_edges", "1 h max 1000: equality allowed, +1 denied; a later window frees the headroom.",
        simple_mandate(), [{"facts": usd(600), "t_h": T0 + 10}, {"facts": usd(400), "t_h": T0 + 20},
                           {"facts": usd(1), "t_h": T0 + 30, "note": "1001 > 1000"},
                           {"facts": usd(1000), "t_h": T0 + 2 * 3600 + 5, "note": "window from k(T0 + 3606) = k0 + 1"}])
    add("bucket_rounding", "1 h max 100: a bucket partly inside the window counts fully; at t mod 3600 = 3599 the window "
        "is h buckets.", simple_mandate(assets=[{"asset": "test:usd", "scale": 2, "periods": [{"hours": 1, "max": P.amt(100)}]}]),
        [{"facts": usd(100), "t_h": T0 + 10},
         {"facts": usd(1), "t_h": T0 + 3600 + 3598, "note": "window starts at k(T0 + 3599) = k0: bucket k0 counts"},
         {"facts": usd(100), "t_h": T0 + 3600 + 3599, "note": "window starts at k(T0 + 3600) = k0 + 1"}])
    add("count_edges", "1 h count max 3.", simple_mandate(count_limits=[{"hours": 1, "max_count": 3}]),
        [{"facts": usd(1), "t_h": T0 + i} for i in (1, 2, 3)] + [{"facts": usd(1), "t_h": T0 + 4, "note": "4th"}])
    add("min_spacing", "min_spacing 60 measured on the last allowed T_H.", simple_mandate(min_spacing=60),
        [{"facts": usd(1), "t_h": T0 + 100}, {"facts": usd(1), "t_h": T0 + 159, "note": "59 s"},
         {"facts": usd(1), "t_h": T0 + 160, "note": "60 s"}, {"facts": usd(1), "t_h": T0 + 150, "note": "older than last_th"}])
    add("clamp", "Without min_spacing an older T_H is attributed at last_t (T_eff) and lands in the open bucket.",
        simple_mandate(), [{"facts": usd(500), "t_h": T0 + 7200 + 100}, {"facts": usd(400), "t_h": T0 + 50, "note": "T_eff = T0 + 7300"},
                           {"facts": usd(101), "t_h": T0 + 60, "note": "1001 in the window at T_eff"}])
    add("rollover", "Allows in three hours: each new hour closes the open bucket.", simple_mandate(),
        [{"facts": usd(100), "t_h": T0 + 10}, {"facts": usd(200), "t_h": T0 + 20}, {"facts": usd(300), "t_h": T0 + 3600 + 1},
         {"facts": usd(1), "t_h": T0 + 5 * 3600}])
    add("not_before", "T_H before not_before.", simple_mandate(not_before=T0 + 1000),
        [{"facts": usd(1), "t_h": T0 + 999}, {"facts": usd(1), "t_h": T0 + 1000}])
    add("multi_asset_window", "Two assets, 24 h window, per-asset sums.", simple_mandate(assets=[
        {"asset": "test:eth", "scale": 18, "periods": [{"hours": 24, "max": P.amt(10 ** 18)}]},
        {"asset": "test:usd", "scale": 2, "periods": [{"hours": 24, "max": P.amt(1000)}]}]),
        [{"facts": usd(900), "t_h": T0 + 1}, {"facts": F(10 ** 18, None, "test:eth", 18), "t_h": T0 + 3601},
         {"facts": usd(101), "t_h": T0 + 7201}, {"facts": usd(100), "t_h": T0 + 7202},
         {"facts": F(1, None, "test:eth", 18), "t_h": T0 + 24 * 3600, "note": "k0 + 1 still inside the 24 h window"},
         {"facts": F(1, None, "test:eth", 18), "t_h": T0 + 25 * 3600 + 3599, "note": "window starts at k0 + 2"}])
    add("retention_767", "800 allows one hour apart: 767 closed buckets retained, the oldest at k(T_eff) - 767.",
        simple_mandate(), [{"repeat": "800", "t_h_start": str(T0), "t_h_step": "3600", "facts": usd(1)},
                           {"facts": usd(999), "t_h": T0 + 800 * 3600 - 1, "note": "open bucket of the last hour holds 1"},
                           {"facts": usd(1000), "t_h": T0 + 801 * 3600 + 3599}])
    add("history_full_sum", "No period limit: the open sum would pass 2^256 - 1.", simple_mandate(assets=[
        {"asset": "test:big", "scale": 0, "per_action_max": P.amt(P.MAX_AMOUNT)}]),
        [{"facts": F(1 << 255, None, "test:big", 0), "t_h": T0 + 1}, {"facts": F((1 << 255) - 1, None, "test:big", 0), "t_h": T0 + 2},
         {"facts": F(1, None, "test:big", 0), "t_h": T0 + 3}, {"facts": F(1, None, "test:big", 0), "t_h": T0 + 3600,
                                                               "note": "a new hour has room again"}])
    full_count = {"state": {"format": 1, "seq": P.MAX_INT, "last_t": T0 + 5, "last_th": T0 + 5, "closed_root": P.EMPTY_ROOT,
                            "open": B(k0, P.MAX_INT, ("test:usd", 2, 1))}, "set": P.EMPTY_CLOSED, "buckets": {}}
    add("history_full_count", "Start: open count 2^63 - 1 (and seq): the count check comes first.",
        simple_mandate(), [{"facts": usd(1), "t_h": T0 + 6}], start=full_count)
    pairs = {"state": {"format": 1, "seq": 64, "last_t": T0 + 5, "last_th": T0 + 5, "closed_root": P.EMPTY_ROOT,
                       "open": B(k0, 64, *[(f"test:p{i:02d}", 0, 1) for i in range(64)])}, "set": P.EMPTY_CLOSED, "buckets": {}}
    add("history_full_pairs", "Start: 64 pairs in the open bucket; a 65th asset is refused, an existing one is not.",
        simple_mandate(assets=[{"asset": "test:p00", "scale": 0, "per_action_max": P.amt(10)},
                               {"asset": "test:usd", "scale": 2, "per_action_max": P.amt(10)}]),
        [{"facts": usd(1), "t_h": T0 + 6}, {"facts": F(2, None, "test:p00", 0), "t_h": T0 + 7}], start=pairs)
    seqfull = {"state": {"format": 1, "seq": P.MAX_INT, "last_t": T0 + 5, "last_th": T0 + 5, "closed_root": P.EMPTY_ROOT,
                         "open": B(k0, 1, ("test:usd", 2, 1))}, "set": P.EMPTY_CLOSED, "buckets": {}}
    add("history_full_seq", "Start: seq 2^63 - 1; a new hour resets the open count, so the seq check decides.",
        simple_mandate(), [{"facts": usd(1), "t_h": T0 + 3600 + 6}], start=seqfull)
    causes = {s2["expect"].get("cause") for s in sc for s2 in s["steps"]}
    assert {"sum", "count", "pairs", "seq"} <= causes, causes
    return {"note": "Steps are admitted facts (P1 to P8 passed); the engine runs P10 to P14 and Apply. The start ledger "
                    "is genesis unless start is given.", "scenarios": sc}


# Gate simulator for verify.json.

def private_randomness(label: str, n: int) -> dict:
    """Envelope randomness from a label, as the core payload vectors do; production draws it from a CSPRNG."""
    import hpke_base
    return {"salt": sha("edicta/policy/v1 test private salt|" + label),
            "dek": sha("edicta/policy/v1 test private dek|" + label),
            "aead_nonce": sha("edicta/policy/v1 test private aead nonce|" + label)[:12],
            "ikme": [sha(f"edicta/policy/v1 test private ephemeral|{label}|{i}") for i in range(n)],
            "sk_es": [hpke_base.derive_key_pair(sha(f"edicta/policy/v1 test private ephemeral|{label}|{i}"))[0]
                      for i in range(n)]}


def private_record(pk: int, plaintext: bytes, h: bytes, auditors: list) -> tuple:
    label = f"{pk}/{h.hex()}"
    rnd = private_randomness(label, len(auditors))
    env, trace = P.private_seal(plaintext, auditors, rnd["salt"], rnd["dek"], rnd["aead_nonce"], rnd["sk_es"])
    return P.record(15, plaintext_kind=pk, hash=h, envelope=env), env, rnd, trace


class Sim:
    def __init__(self, label, m=None, signer="p1", blind_salt=None):
        self.m = m or base_mandate(label)
        self.signer = signer
        self.sm, self.mh, _ = P.sign_mandate(seed_of(signer), self.m)
        self.led = {"state": P.GENESIS, "set": P.EMPTY_CLOSED, "buckets": {}}
        self.head = None
        self.recs = {}
        self.label = label
        # A dishonest gate may blind with another salt than its mandate's (vector state_salt_wrong).
        self.blind_salt = blind_salt
        self.put_mandate()
        self.put_struct(11, 3, P.closed_cbor(P.EMPTY_CLOSED), P.EMPTY_ROOT)

    @property
    def private(self):
        return "auditors" in self.m

    @property
    def salt(self):
        if not self.private:
            return None
        return self.blind_salt or self.m["state_salt"]

    def sh(self, st):
        return P.state_hash_p(st, self.salt)

    def put(self, rec):
        r = P.decode_record(rec)
        old = self.recs.get(r["path"])
        assert old is None or old == rec, r["path"]
        self.recs[r["path"]] = rec
        return r["path"]

    def put_private(self, pk, plaintext, h, key=None):
        return self.put(private_record(pk, plaintext, h if key is None else key, self.m["auditors"])[0])

    def put_mandate(self):
        if self.private:
            self.put_private(1, self.sm, self.mh)
        else:
            self.put(P.record(7, body=self.sm))

    def put_struct(self, kind, pk, body, h):
        if self.private:
            self.put_private(pk, body, h, P.blind_key(self.salt, h))
        else:
            self.put(P.record(kind, body=body))

    def adopt(self, m):
        self.m = m
        self.sm, self.mh, _ = P.sign_mandate(seed_of(self.signer), m)
        self.put_mandate()

    def decision(self, label, facts, agent=A1, valid_until=None, th=T0, v1=None):
        action = P.encode_facts(facts) if isinstance(facts, dict) else facts
        cl = self.label + "/" + label
        d = {"label": label, "commitment_hash": ch_of(cl), "agent_pubkey": agent,
             "action_type": P.TEST_ACTION_TYPE, "action": action,
             "valid_until": valid_until if valid_until is not None else th + 900, "gate_id": GATE_ID}
        d["action_salt"] = sha("edicta/policy/v1 test action salt|" + cl)
        d["action_hash"] = action_hash(P.TEST_ACTION_TYPE, d["action_salt"], action)
        d.update({"version": 1, "mandate_ref": self.mh, "mode": 1}, **(v1 or {}))
        d["pending"] = d["mode"] == 2
        return d

    def base_verdict(self, d, now):
        return {"format": 1, "gate_id": GATE_ID, "mandate_hash": self.mh, "commitment_hash": d["commitment_hash"],
                "action_hash": d["action_hash"], "agent_pubkey": d["agent_pubkey"], "decided_at": now}

    def state_read(self, v, st):
        v["prev_state"] = st
        if self.private:
            v["_prev_state_hash"] = self.sh(st)

    def sign(self, v, d=None, mutate_pub=None, mutate_pp=None, archive=True):
        """Signs v; in private mode first splits it into the private form and its PrivatePart, which is
        archived as kind 15 (4, private_hash). Returns (signed bytes, verdict hash, signed verdict)."""
        if self.private:
            pp_salt = sha("edicta/policy/v1 test private part salt|" + d["commitment_hash"].hex())
            pub, pp = P.split_verdict(v, pp_salt)
            if mutate_pp:
                mutate_pp(pp)
                pub["private_hash"] = P.thash("private-part", encode(P.to_cbor(pp, P.S_PRIVATE_PART)))
            if mutate_pub:
                mutate_pub(pub)
            if archive:
                ppb = encode(P.to_cbor(pp, P.S_PRIVATE_PART))
                self.put(private_record(4, ppb, pub["private_hash"], self.m["auditors"])[0])
            v = pub
        sv, vh = sign_unchecked(SEEDS["gate1"], v)
        return sv, vh, v

    def step(self, d, th, *, honest=True, facts=None, ledger=None, head=None, mutate=None, commit=True,
             archive=True, successor=True, next_ledger=None, mutate_pub=None, mutate_pp=None):
        now = th + 30
        reason, xid, f = P.admit(self.m, {P.TEST_ACTION_TYPE: P.TEST_EXTRACTOR}, d)
        if facts is not None:
            f, reason = facts, None
        if f is None and not honest:
            f = P.test_extract(d["action"])
        v = self.base_verdict(d, now)
        if reason and honest:
            v.update(outcome=2, reason=reason)
            if xid:
                v["extractor"] = xid
            if f is not None:
                v["facts"] = f
            sv, vh, sv_v = self.sign(v, d, archive=archive)
            if archive:
                self.put(P.record(9, body=sv))
            return sv, vh, sv_v
        led = ledger if ledger is not None else self.led
        r = P.evaluate(self.m, led, f, th)
        if "deny" in r:
            if honest:
                v.update(outcome=2, reason=r["deny"], extractor=xid, facts=f, anchor_time=th)
                v["prev_state"] = led["state"]
                if r["deny"] != "ErrOutsideMandate":
                    v["eval_time"] = r["eval_time"]
                sv, vh, sv_v = self.sign(v, d, archive=archive)
                if archive:
                    self.put(P.record(9, body=sv))
                return sv, vh, sv_v
            r = P.apply(led, {"asset": f["asset"], "scale": f["scale"], "amount": f["amount"], "t_h": th})
        hd = head if head is not None else self.head
        v.update(outcome=1, extractor=P.TEST_EXTRACTOR, facts=f, anchor_time=th, eval_time=r["eval_time"],
                 new_state_hash=self.sh(r["next"]["state"]))
        self.state_read(v, led["state"])
        if led["state"]["seq"] >= 1:
            v.update(prev_commitment_hash=hd[0], prev_verdict_hash=hd[1])
        if mutate:
            mutate(v, r)
        sv, vh, sv_v = self.sign(v, d, mutate_pub, mutate_pp, archive)
        if archive:
            if r["closed_bucket"] is not None:
                b = P.bucket_cbor(r["closed_bucket"])
                self.put_struct(10, 2, b, P.bucket_hash(r["closed_bucket"]))
                self.put_struct(11, 3, P.closed_cbor(r["closed_set"]), P.closed_root(r["closed_set"]))
            self.put(P.record(8, body=sv))
            if successor:
                self.put(P.record(12, gate_id=GATE_ID, counter_key=P.counter_key_of(self.m),
                                  state_hash=self.sh(led["state"]), commitment_hash=d["commitment_hash"]))
        if commit:
            self.led = next_ledger if next_ledger is not None else r["next"]
            self.head = (d["commitment_hash"], vh)
        return sv, vh, sv_v


def sign_unchecked(seed: bytes, v: dict) -> tuple:
    """Signs a verdict without the presence rule: dishonest-gate vectors sign verdicts the decoder may refuse."""
    canon = encode(P.to_cbor(v, P.S_VERDICT))
    h = P.thash("verdict", canon)
    return encode({1: P.to_cbor(v, P.S_VERDICT), 2: P.ed_sign(seed, P.signed_message("verdict-sig", h))}), h


PRINCIPALS = {"p1": PUB["p1"], "p2": PUB["p2"], "p1_cosmos": ("cosmos", PC.cosmos_address(SECP_PUB["p1"], HRP)),
              "p1_eth": ("eth", ETH_ADDR["p1"])}
SCHEMES = {"ed25519": None, "cosmos": 2, "eth": 3}
AUDITOR_SK = {n: auditor_key(n.encode())[0] for n in ("auditor-1", "auditor-2", "auditor-3")}


def principal_json(x) -> str:
    if isinstance(x, bytes):
        return x.hex()
    return f"{x[0]}:{x[1]}" if x[0] == "cosmos" else f"eth:0x{x[1].hex()}"


def decision_json(d: dict) -> dict:
    j = {"commitment_hash_hex": d["commitment_hash"].hex(), "agent_pubkey_hex": d["agent_pubkey"].hex(),
         "action_type": d["action_type"], "action_hex": d["action"].hex(), "action_hash_hex": d["action_hash"].hex(),
         "valid_until": str(d["valid_until"]), "gate_id": d["gate_id"]}
    if d.get("version") == 1:
        j["version"] = "1"
        j["action_salt_hex"] = d["action_salt"].hex()
        if d["mandate_ref"] is not None:
            j["mandate_ref_hex"] = d["mandate_ref"].hex()
        j["mode"] = str(d["mode"])
        if d["mode"] == 2:
            j.update(h0=str(d["h0"]), anchor_deadline=str(d["anchor_deadline"]))
    return j


def gen_verify():
    pool = {}
    cases = []
    sims = {}
    ppool = {}
    pcases = []

    def merge(sim, pl):
        for p, b in sim.recs.items():
            assert pl.get(p, b) == b, p
            pl[p] = b

    def case(i, desc, sim, d, th="same", *, full=False, steps=None, require=False, principals=("p1",),
             extractors=True, evidence=(), drop=(), corrupt=None, exp=None, schemes=None, auditors=(),
             private=False):
        out, pl = (pcases, ppool) if private else (cases, pool)
        merge(sim, pl)
        arch = sorted(p for p in sim.recs if p not in drop)
        cor = dict(corrupt or {})
        recs = {p: sim.recs[p] for p in arch}
        recs.update(cor)
        t_h = d["th"] if th == "same" else th
        ext = {P.TEST_ACTION_TYPE: P.TEST_EXTRACTOR} if extractors else {}
        inp = {"archive": P.Archive(recs), "decision": d, "t_h": t_h, "gate_pub": G1,
               "principals": [PRINCIPALS[x] for x in principals], "extractors": ext, "full": full,
               "max_walk_steps": steps, "evidence": list(evidence), "auditor_keys": [AUDITOR_SK[a] for a in auditors]}
        if schemes is not None:
            inp["schemes"] = tuple(SCHEMES[x] for x in schemes)
        res = P.verify_policy(inp)
        if exp:
            got = (res["policy"]["status"], res["policy"].get("rule") or res["policy"].get("reason"),
                   res["gate_integrity"]["status"], res["exit"])
            assert got == exp, (i, got, exp)
        c = {"id": i, "description": desc, "decision": decision_json(d)}
        if t_h is not None:
            c["t_h"] = str(t_h)
        c["config"] = {"require_policy": require, "policy_full": full, "max_walk_steps": str(steps) if steps is not None else None,
                       "principal_keys": [principal_json(PRINCIPALS[x]) for x in principals],
                       "extractors": {k: v for k, v in ext.items()}, "evidence": [e.hex() for e in evidence]}
        if schemes is not None:
            c["config"]["principal_schemes"] = list(schemes)
        if auditors:
            c["config"]["auditor_keys"] = [AUDITOR_SK[a].hex() for a in auditors]
        c["archive"] = arch
        if cor:
            c["corrupt"] = {p: b.hex() for p, b in cor.items()}
        c["expect"] = res
        out.append(c)

    def dec(sim, label, facts, th, **kw):
        d = sim.decision(label, facts, th=th, **kw)
        d["th"] = th
        return d

    # Honest chain A.
    A = Sim("A")
    a1 = dec(A, "a1", F(1000), T0 + 100); A.step(a1, a1["th"])
    a2 = dec(A, "a2", F(500, "test:bob"), T0 + 200); A.step(a2, a2["th"])
    ad = dec(A, "a_deny_4p", F(6000), T0 + 300); A.step(ad, ad["th"])
    a3 = dec(A, "a3", F(1500), T0 + 7300); A.step(a3, a3["th"])
    a4 = dec(A, "a4", F(400), T0 + 7400); A.step(a4, a4["th"])
    ad2 = dec(A, "a_deny_10p", F(200), T0 + 7450); A.step(ad2, ad2["th"])
    sims["A"] = A
    k0 = P.k(T0)
    b0_path = next(p for p in A.recs if p.startswith("policy-bucket/"))
    cs_path = next(p for p in A.recs if p.startswith("policy-closed/") and p != "policy-closed/" + P.EMPTY_ROOT.hex())
    allow = lambda d: f"policy-allow/{d['commitment_hash'].hex()}"  # noqa: E731

    case("pass_genesis", "First allow of a counter, from genesis; fast check only.", A, a1,
         exp=("pass", None, "not_checked", "0"))
    case("pass_fast_closed_bucket", "a4: the 24 h window needs the closed bucket of hour k0 from the archive.", A, a4,
         exp=("pass", None, "not_checked", "0"))
    case("pass_hour_rollover", "a3 rolled hour k0 over: Apply closes the open bucket, the new closed root covers it; "
         "full walk to genesis.", A, a3, full=True, exp=("pass", None, "ok", "0"))
    case("pass_chain_continuity", "a4, full walk a4 -> a3 -> a2 -> a1 -> genesis: every link, seq step, mandate and "
         "transition checks.", A, a4, full=True, exp=("pass", None, "ok", "0"))
    case("pass_depth_1", "a4, full walk capped at one step: a4 -> a3, and a3 is not genesis. The walk is truncated, "
         "so gate_integrity is unchecked (policy_walk_truncated) even though the cap is explicit; the policy check "
         "passes and the verdict stays valid.", A, a4, full=True, steps=1,
         exp=("pass", None, "unchecked", "0"))
    case("walk_truncated_cap_2", "a4, full walk capped at two steps: a4 -> a3 -> a2, and a2 is not genesis: "
         "last 3 of 4 verdicts checked, truncated.", A, a4, full=True, steps=2, exp=("pass", None, "unchecked", "0"))
    case("walk_cap_reaches_genesis", "a4, full walk capped at three steps: a4 -> a3 -> a2 -> a1, and a1 read "
         "genesis, so no further step is due and the walk is complete.", A, a4, full=True, steps=3,
         exp=("pass", None, "ok", "0"))
    nopol = dec(A, "a_no_policy_record", F(10), T0 + 7500)
    case("unchecked_verdict_unavailable", "require_policy and no policy_allow record for the decision.", A, nopol,
         require=True, exp=("unchecked", "policy_verdict_unavailable", "not_checked", "2"))
    bad = bytearray(A.recs[allow(a4)]); bad[-1] ^= 1
    case("unchecked_verdict_corrupt", "The allow record's gate signature does not verify.", A, a4,
         corrupt={allow(a4): bytes(bad)}, exp=("unchecked", "source_corrupt", "not_checked", "2"))
    case("unchecked_mandate_unavailable", "The mandate record is absent.", A, a4, drop=(f"mandate/{A.mh.hex()}",),
         exp=("unchecked", "policy_mandate_unavailable", "not_checked", "2"))
    case("unchecked_principal_untrusted", "The verifier trusts p2 only.", A, a4, principals=("p2",),
         exp=("unchecked", "policy_principal_untrusted", "not_checked", "2"))
    case("unchecked_no_extractor", "The verifier has no extractor for the action type.", A, a4, extractors=False,
         exp=("unchecked", "policy_no_extractor", "not_checked", "2"))
    case("unchecked_closed_set_missing", "The ClosedSet of a4's prev_state is absent.", A, a4, drop=(cs_path,),
         exp=("unchecked", "state_history_unavailable", "not_checked", "2"))
    case("unchecked_bucket_missing", "The closed bucket of hour k0 is absent.", A, a4, drop=(b0_path,),
         exp=("unchecked", "state_history_unavailable", "not_checked", "2"))
    ob = P.decode_bucket(P.decode_record(A.recs[b0_path])["body"])
    ob["sums"][0]["sum"] = P.amt(P.amt_int(ob["sums"][0]["sum"]) - 1)
    case("unchecked_bucket_corrupt", "The bucket record under hour k0's hash holds another bucket (one sum lower): its "
         "bytes do not hash to the key.", A, a4, corrupt={b0_path: P.record(10, body=P.bucket_cbor(ob))},
         exp=("unchecked", "source_corrupt", "not_checked", "2"))
    case("unchecked_t_h_not_verified", "Header trust did not pass: the T_H rules are blocked; the rest passes.", A, a4,
         th=None, exp=("unchecked", "blocked", "not_checked", "2"))
    case("walk_history_missing", "Full walk; a2's allow record is absent.", A, a4, full=True, drop=(allow(a2),),
         exp=("unchecked", "state_history_unavailable", "unchecked", "2"))
    bad = bytearray(A.recs[allow(a2)]); bad[-1] ^= 1
    case("walk_history_corrupt", "Full walk; a2's allow record has a bad gate signature.", A, a4, full=True,
         corrupt={allow(a2): bytes(bad)}, exp=("unchecked", "source_corrupt", "unchecked", "2"))

    # A dishonest gate: one fresh counter per case, the target is the cheat.
    def cheat(i, desc, rule, facts, th=T0 + 100, prior=(), m=None, d_over=None, honest_facts=None, mutate=None,
              t_h="same", exp_gi="not_checked", **kw):
        S = Sim("X-" + i, m=m)
        for j, (pf, pt) in enumerate(prior):
            S.step(dec(S, f"prior{j}", pf, pt), pt)
        d = dec(S, "cheat", facts, th, **(d_over or {}))
        S.step(d, th, honest=False, facts=honest_facts, mutate=mutate)
        case(i, desc, S, d, th=t_h, exp=("fail", rule, exp_gi, "1"), **kw)
        return S, d

    cheat("fail_amount_above_max", "Allowed 6000 above per_action_max 5000.", "ErrAmountAboveMax", F(6000))
    cheat("fail_recipient", "Recipient not in the allowlist.", "ErrRecipientNotAllowed", F(100, "test:mallory"))
    cheat("fail_recipient_absent", "No recipient while the asset has an allowlist.", "ErrRecipientNotAllowed", F(100, None))
    cheat("fail_kind", "Kind swap, mandate kinds = [transfer].", "ErrKindNotAllowed", F(100, kind="swap"))
    cheat("fail_asset_scale", "test:usd at scale 3, the mandate says 2.", "ErrAssetNotAllowed", F(100, scale=3))
    cheat("fail_agent_not_covered", "agent2 decides, the mandate lists agent1 only.", "ErrAgentNotCovered", F(100),
          m=base_mandate("X-fail_agent_not_covered", agents=[A1]), d_over={"agent": A2})
    cheat("fail_not_after", "valid_until one second after not_after.", "ErrOutsideMandate", F(100),
          d_over={"valid_until": T0 + 30 * 86400 + 1})
    cheat("fail_not_before", "Verified T_H before not_before.", "ErrOutsideMandate", F(100), th=T0 - 86400 - 1)
    cheat("fail_facts_mismatch", "The gate signed amount 100; the action bytes say 1000.", "facts_mismatch", F(1000),
          honest_facts=F(100))
    cheat("fail_period_limit", "Signed prev_state holds 1800 in the hour; 300 more passes the 1 h max 2000.",
          "ErrPeriodLimit", F(300), th=T0 + 200, prior=[(F(1800), T0 + 100)])
    cheat("fail_count_limit", "Count max 2 per hour; the third allow.", "ErrCountLimit", F(1), th=T0 + 300,
          prior=[(F(1), T0 + 100), (F(1), T0 + 200)],
          m=base_mandate("X-fail_count_limit", count_limits=[{"hours": 1, "max_count": 2}]))
    cheat("fail_min_spacing", "5 s after the last allow, min_spacing 10.", "ErrMinSpacing", F(1), th=T0 + 105,
          prior=[(F(1), T0 + 100)])

    def wrong_eval(v, r):
        v["eval_time"] = v["anchor_time"]
    cheat("fail_eval_time_mismatch", "An older T_H signed with eval_time = T_H instead of last_t.", "eval_time_mismatch",
          F(1), th=T0 + 50, prior=[(F(1), T0 + 7300)], m=base_mandate("X-fail_eval_time_mismatch", min_spacing=None),
          mutate=wrong_eval)

    def wrong_anchor(v, r):
        v["anchor_time"] += 60
        v["eval_time"] += 60
    cheat("fail_anchor_time_mismatch", "The verdict's anchor_time is 60 s after the verified T_H.", "anchor_time_mismatch",
          F(1), mutate=wrong_anchor)
    cheat("fail_mandate_gate_id", "The gate used a mandate bound to another gate.", "mandate_gate_id", F(1),
          m=base_mandate("X-fail_mandate_gate_id", gate_id="gate-other"))

    # Equivocation.
    C = Sim("C")
    c1 = dec(C, "c1", F(100), T0 + 100)
    g = copy.deepcopy(C.led)
    C.step(c1, c1["th"])
    c1x = dec(C, "c1x", F(1900), T0 + 110)
    svx, _, _ = C.step(c1x, c1x["th"], ledger=g, commit=False, archive=False)
    case("equivocation_fork_evidence", "c1 and c1x both allowed from genesis of one counter; c1x is evidence an agent "
         "received.", C, c1, evidence=[svx], exp=("unchecked", "blocked", "violated", "5"))
    case("fork_control_no_evidence", "Control: the same target without evidence passes.", C, c1,
         exp=("pass", None, "not_checked", "0"))

    D = Sim("D")
    gen0 = copy.deepcopy(D.led)
    d1x = dec(D, "d1x", F(1900), T0 + 90)
    D.step(d1x, d1x["th"], ledger=gen0, commit=False)
    d1 = dec(D, "d1", F(100), T0 + 100)
    D.step(d1, d1["th"], successor=False)
    d2 = dec(D, "d2", F(100), T0 + 200)
    D.step(d2, d2["th"])
    case("equivocation_fork_successor", "Full walk d2 -> d1 -> genesis; the successor record of genesis names d1x, an "
         "allow from the same genesis.", D, d2, full=True, exp=("unchecked", "blocked", "violated", "5"))

    E = Sim("E")
    e1 = dec(E, "e1", F(100), T0 + 100); E.step(e1, e1["th"])
    e2 = dec(E, "e2", F(100), T0 + 200)

    def unlink(v, r):
        v["prev_verdict_hash"] = sha("edicta/policy/v1 test unlinked")
    E.step(e2, e2["th"], mutate=unlink)
    case("equivocation_unlinked", "e2's prev_verdict_hash does not name e1's verdict.", E, e2, full=True,
         exp=("unchecked", "blocked", "violated", "5"))
    case("unlinked_fast_only", "Control: the fast check cannot see the broken link.", E, e2,
         exp=("pass", None, "not_checked", "0"))

    SI = Sim("SI")
    s1 = dec(SI, "s1", F(100), T0 + 100)

    def junk(v, r):
        v["new_state_hash"] = sha("edicta/policy/v1 test junk state")
    SI.step(s1, s1["th"], mutate=junk)
    case("equivocation_self_inconsistent", "new_state_hash is not Apply(prev_state, delta): found by the fast check.",
         SI, s1, exp=("unchecked", "blocked", "violated", "5"))

    U = Sim("U")
    f1 = dec(U, "f1", F(1500), T0 + 100); U.step(f1, f1["th"])
    f2 = dec(U, "f2", F(400), T0 + 200); U.step(f2, f2["th"])
    fake = copy.deepcopy(U.led)
    fake["state"]["open"]["sums"][0]["sum"] = P.amt(1000)
    f3 = dec(U, "f3", F(600), T0 + 300)
    U.step(f3, f3["th"], ledger=fake)
    case("understated_open_bucket_fast", "f3's prev_state shows 1000 in the hour instead of 1900; on it 600 more fits "
         "the 1 h max 2000. The fast check passes: the signed state is self-consistent.", U, f3,
         exp=("pass", None, "not_checked", "0"))
    case("understated_open_bucket_full", "The walk finds it: f2.new_state_hash != state_hash(f3.prev_state).", U, f3,
         full=True, exp=("unchecked", "blocked", "violated", "5"))

    V = Sim("V", m=base_mandate("V", version=2))
    g1 = dec(V, "g1", F(100), T0 + 100); V.step(g1, g1["th"])
    V.adopt(base_mandate("V", version=1))
    g2 = dec(V, "g2", F(100), T0 + 200); V.step(g2, g2["th"])
    case("equivocation_version_decrease", "g1 under version 2, then g2 under version 1 of the same mandate_id.", V, g2,
         full=True, exp=("unchecked", "blocked", "violated", "5"))

    # Asset scale across mandate versions: the cell keeps every scale an adopted version listed.
    W = Sim("W", m=two_assets("W", 1))
    w1 = dec(W, "w1", F(100), T0 + 100); W.step(w1, w1["th"])
    W.adopt(two_assets("W", 2, extra=[{"asset": "test:btc", "scale": 8, "per_action_max": P.amt(10 ** 6)}]))
    w2 = dec(W, "w2", F(100), T0 + 200); W.step(w2, w2["th"])
    case("pass_version_boundary_scales_kept", "w1 under version 1 spends test:usd only; version 2 keeps the scale of "
         "the unused test:eth and adds test:btc; full walk w2 -> w1 -> genesis finds no equivocation.", W, w2,
         full=True, exp=("pass", None, "ok", "0"))
    SC = Sim("SC", m=two_assets("SC", 1))
    x1 = dec(SC, "x1", F(100), T0 + 100); SC.step(x1, x1["th"])
    SC.adopt(two_assets("SC", 2, eth_scale=6))
    x2 = dec(SC, "x2", F(100), T0 + 200); SC.step(x2, x2["th"])
    case("equivocation_scale_change", "The gate adopted version 2 with test:eth at scale 6 (unused, 18 in version "
         "1), which adoption refuses; the walk x2 -> x1 reports it.", SC, x2, full=True,
         exp=("unchecked", "blocked", "violated", "5"))
    SR = Sim("SR", m=two_assets("SR", 1))
    y1 = dec(SR, "y1", F(100), T0 + 100); SR.step(y1, y1["th"])
    SR.adopt(two_assets("SR", 2, eth=False))
    y2 = dec(SR, "y2", F(100), T0 + 200); SR.step(y2, y2["th"])
    SR.adopt(two_assets("SR", 3, eth_scale=6))
    y3 = dec(SR, "y3", F(100), T0 + 300); SR.step(y3, y3["th"])
    case("equivocation_scale_change_after_drop", "Version 2 dropped test:eth, version 3 lists it at scale 6: no two "
         "consecutive mandates differ, but y1's and y3's do; evidence y1 and y3.", SR, y3, full=True,
         exp=("unchecked", "blocked", "violated", "5"))

    SG = Sim("SG")
    h1 = dec(SG, "h1", F(100), T0 + 100)
    real = P.apply(SG.led, P.delta_of({"facts": F(100), "anchor_time": h1["th"]}))
    skip = copy.deepcopy(real["next"])
    skip["state"]["seq"] += 1

    def gap(v, r):
        v["new_state_hash"] = P.state_hash(skip["state"])
    SG.step(h1, h1["th"], mutate=gap, next_ledger=skip)
    h2 = dec(SG, "h2", F(100), T0 + 200); SG.step(h2, h2["th"])
    case("equivocation_seq_gap", "h1 signed a new state with seq 2; h2 continues from it.", SG, h2, full=True,
         exp=("unchecked", "blocked", "violated", "5"))

    IE = Sim("IE")
    gi0 = copy.deepcopy(IE.led)
    i1 = dec(IE, "i1", F(6000), T0 + 100)
    IE.step(i1, i1["th"], honest=False)
    i1x = dec(IE, "i1x", F(100), T0 + 110)
    svix, _, _ = IE.step(i1x, i1x["th"], ledger=gi0, commit=False, archive=False)
    case("invalid_and_equivocation", "i1 is above per_action_max and also forks with i1x: fail stays fail (exit 1), "
         "gate_integrity is still violated.", IE, i1, evidence=[svix], exp=("fail", "ErrAmountAboveMax", "violated", "1"))

    archive_pool = dict(pool)
    draft5_cases(case, dec, cheat, sims)
    private_cases(case, dec, sims)

    ids = [c["id"] for c in cases + pcases]
    assert len(ids) == len(set(ids))
    head = {"gate": {"gate_id": GATE_ID, "gate_pubkey_hex": G1.hex()},
            "extractors": {P.TEST_ACTION_TYPE: P.TEST_EXTRACTOR}}
    return ({**head, "records": {p: pool[p].hex() for p in sorted(pool)}, "cases": cases}, archive_pool, sims,
            {**head, "records": {p: ppool[p].hex() for p in sorted(ppool)}, "cases": pcases})


def draft5_cases(case, dec, cheat, sims):
    """Policy-v1-draft.5 verifier cases: the verified decision is a v1 one (mandate_ref, mode, h0, deadline)."""
    MR = Sim("MR")
    sims["MR"] = MR
    r1 = dec(MR, "r1", F(100), T0 + 100, v1={}); MR.step(r1, r1["th"])
    case("mandate_ref_match", "v1 decision whose mandate_ref equals the allow verdict's mandate_hash; reported "
         "as match.", MR, r1, exp=("pass", None, "not_checked", "0"))
    r2 = dec(MR, "r2", F(100), T0 + 200, v1={"mandate_ref": sha("edicta/policy/v1 test other mandate")})
    MR.step(r2, r2["th"])
    case("mandate_ref_mismatch", "The agent committed to another mandate; the gate allowed under its own: both "
         "inputs are signed, so this is a fail.", MR, r2, exp=("fail", "mandate_ref_mismatch", "not_checked", "1"))
    r3 = dec(MR, "r3", F(100), T0 + 300, v1={"mandate_ref": None}); MR.step(r3, r3["th"])
    case("mandate_ref_absent", "v1 decision without mandate_ref: the gate skipped its own rule, which the envelope "
         "alone cannot prove; reported as absent, not a fail.", MR, r3, exp=("pass", None, "not_checked", "0"))
    pend = {"mode": 2, "h0": 1000, "anchor_deadline": 1050}
    cheat("fast_mode_not_allowed", "Fast-mode Authorization (pending reference) under a mandate without "
          "fast_mode_max_delay: P15.", "ErrFastModeNotAllowed", F(100), d_over={"v1": pend})
    fm = lambda label: base_mandate(label, fast_mode_max_delay=10)  # noqa: E731
    FX = Sim("FX", m=fm("FX"))
    x = dec(FX, "x1", F(100), T0 + 100, v1={"mode": 2, "h0": 1000, "anchor_deadline": 1011}); FX.step(x, x["th"])
    case("fast_mode_delay_exceeded", "anchor_deadline - h0 = 11 above the mandate's fast_mode_max_delay 10: the "
         "gate issued a deadline beyond the principal's bound.", FX, x, exp=("fail", "fast_mode_delay", "not_checked", "1"))
    FW = Sim("FW", m=fm("FW"))
    x = dec(FW, "w1", F(100), T0 + 100, v1={"mode": 2, "h0": 1000, "anchor_deadline": 1010}); FW.step(x, x["th"])
    case("fast_mode_within_bound", "anchor_deadline - h0 = 10, exactly the mandate's bound.", FW, x,
         exp=("pass", None, "not_checked", "0"))
    adr = base_mandate("PC", principal=SECP_PUB["p1"], sig_type=2, principal_hrp=HRP)
    PCo = Sim("PC", m=adr, signer="p1_secp")
    x = dec(PCo, "c1", F(100), T0 + 100, v1={}); PCo.step(x, x["th"])
    case("principal_scheme_unsupported", "ADR-036 mandate; this verifier build has Ed25519 and EIP-712 only.", PCo, x,
         principals=("p1_cosmos",), schemes=("ed25519", "eth"),
         exp=("unchecked", "principal_scheme_unsupported", "not_checked", "2"))
    case("principal_cosmos_pinned", "ADR-036 mandate; the verifier pins the principal by its bech32 address "
         "(--principal cosmos:<address>).", PCo, x, principals=("p1_cosmos",), exp=("pass", None, "not_checked", "0"))
    eth = base_mandate("PE", principal=ETH_ADDR["p1"], sig_type=3)
    PE = Sim("PE", m=eth, signer="p1_secp")
    x = dec(PE, "e1", F(100), T0 + 100, v1={}); PE.step(x, x["th"])
    case("principal_eth_pinned", "EIP-712 mandate; the verifier pins the principal by its address "
         "(--principal eth:0x<address>).", PE, x, principals=("p1_eth",), exp=("pass", None, "not_checked", "0"))
    case("principal_eth_not_cosmos", "EIP-712 mandate; the verifier pins only a Cosmos address of the same "
         "secp256k1 key: the comparison is per scheme.", PE, x, principals=("p1_cosmos",),
         exp=("unchecked", "policy_principal_untrusted", "not_checked", "2"))
    FN = Sim("FN", m=fm("FN"))
    x = dec(FN, "n1", F(100), T0 + 100, v1={"mode": 2, "h0": 1000, "anchor_deadline": 1005})
    case("fast_mode_no_policy_record", "A fast-mode Authorization (mode 2) makes the policy check required (core v1 "
         "10.1) although require_policy is off; the archive holds no policy_allow record: unchecked, never valid.",
         FN, x, exp=("unchecked", "policy_verdict_unavailable", "not_checked", "2"))
    x = dec(MR, "r4", F(100), T0 + 400, v1={})
    case("mandate_ref_without_verdict", "A strict-mode (mode 1) decision whose envelope carries mandate_ref, "
         "authorized by a gate that issued no verdict (for example a gate whose mandate was dropped and that skipped "
         "M0); require_policy is off. mandate_ref makes the policy check required (core v1 20.5): no policy_allow "
         "record, so unchecked, never valid.", MR, x, exp=("unchecked", "policy_verdict_unavailable", "not_checked", "2"))
    FT = Sim("FT", m=fm("FT"))
    x = dec(FT, "t1", F(100), T0 + 100, v1={"mode": 2, "h0": 1000, "anchor_deadline": 1005}); FT.step(x, x["th"])
    case("anchor_time_t_ref_pending", "Pending reference: the verdict's anchor_time is T_ref, the header time at h0, "
         "and matches the verified T_ref.", FT, x, exp=("pass", None, "not_checked", "0"))


def second_private_deny(PV, pd, dpp) -> dict:
    """A second private deny of the same decision under another reason, kept apart from the first by its
    private_hash segment. Synthetic verdict, not added to any archive pool: an honest gate reaches it, for example,
    with ErrMinSpacing and later ErrPeriodLimit on two attempts against different counter states."""
    now = pd["th"] + 600
    v = PV.base_verdict(pd, now)
    v.update(outcome=2, reason="ErrDecisionAge", extractor=dpp["extractor"], facts=dpp["facts"],
             anchor_time=pd["th"], gate_clock=1)
    pub, pp = P.split_verdict(v, sha("edicta/policy/v1 test private part salt|" + pd["commitment_hash"].hex() + "|2"))
    ppb = encode(P.to_cbor(pp, P.S_PRIVATE_PART))
    rec15 = private_record(4, ppb, pub["private_hash"], PV.m["auditors"])[0]
    sv, vh = sign_unchecked(SEEDS["gate1"], pub)
    rec9 = P.record(9, body=sv)
    return {"id": "private_deny_second_reason", "description": "A later attempt of the same decision denied for "
            "another reason (ErrDecisionAge, gate clock 600 s after T_ref; synthetic verdict). Kind 9 of a private "
            "deny is keyed (commitment_hash, private_hash), path policy-deny/<commitment_hash>/private-<private_hash>, "
            "so it does not conflict with the first deny, and the kind 15 PrivatePart it names stays reachable.",
            "reason": "ErrDecisionAge", "signed_verdict_hex": sv.hex(), "verdict_hash_hex": vh.hex(),
            "private_part_cbor_hex": ppb.hex(), "private_part_record_cbor_hex": rec15.hex(),
            "private_part_path": f"private/4/{pub['private_hash'].hex()}",
            "kind9_path": P.decode_record(rec9)["path"], "kind9_record_cbor_hex": rec9.hex()}


def same_reason_private_retry(PV, pd, dpp) -> dict:
    """A retry of the denied decision refused again for the same reason. The fresh PrivatePart salt gives a new
    private_hash, so the kind 9 key alone would not dedup it; the gate's local (commitment_hash, reason) index does."""
    now = pd["th"] + 60
    v = PV.base_verdict(pd, now)
    v.update(outcome=2, reason=dpp["reason"], extractor=dpp["extractor"], facts=dpp["facts"],
             anchor_time=pd["th"], gate_clock=1)
    pub, pp = P.split_verdict(v, sha("edicta/policy/v1 test private part salt|" + pd["commitment_hash"].hex() + "|3"))
    sv, vh = sign_unchecked(SEEDS["gate1"], pub)
    return {"id": "private_deny_same_reason_retry", "description": "A retry of the same decision 60 s after T_ref, "
            "refused again for the first deny's reason (" + dpp["reason"] + "). The gate signs and returns this fresh "
            "deny (new salt, so a new private_hash), but it already archived a private deny with this reason for "
            "this commitment_hash (gate-local index keyed (commitment_hash, reason)), so it writes no kind 9, no "
            "kind 15 PrivatePart. The ErrDenied marker write is repeated and is a no-op when the marker is present, so "
            "archive_writes (new records) is empty.",
            "reason": dpp["reason"], "signed_verdict_hex": sv.hex(), "verdict_hash_hex": vh.hex(),
            "private_hash_hex": pub["private_hash"].hex(),
            "dedup_key": {"commitment_hash": pd["commitment_hash"].hex(), "reason": dpp["reason"]},
            "archive_writes": []}


def private_mandate(label, **kw):
    return base_mandate(label, **{"auditors": AUDITORS, "state_salt": state_salt(label), **kw})


def private_cases(case, dec, sims):
    """Private mode (policy 9.5, 10.1, 13.2, 13.3): the cases of private.json."""
    pm = private_mandate
    PV = Sim("PV", m=pm("PV"))
    p1 = dec(PV, "p1", F(1000), T0 + 100, v1={}); PV.step(p1, p1["th"])
    p2 = dec(PV, "p2", F(500, "test:bob"), T0 + 200, v1={}); PV.step(p2, p2["th"])
    pd = dec(PV, "p_deny", F(6000), T0 + 300, v1={}); PV.step(pd, pd["th"])
    p3 = dec(PV, "p3", F(1500), T0 + 7300, v1={}); PV.step(p3, p3["th"])
    p4 = dec(PV, "p4", F(400), T0 + 7400, v1={}); PV.step(p4, p4["th"])
    sims["PV"] = PV
    sims["PV_targets"] = (p1, p4, pd, p3)
    k = ("auditor-2",)
    case("private_with_key_pass", "Private mandate; auditor-2's key opens the mandate, the PrivateParts, the "
         "closed bucket and the ClosedSets under their blinded keys; fast check and walk p4 -> genesis as in public "
         "mode, with the blinded state hashes.", PV, p4, full=True, auditors=k, private=True,
         exp=("pass", None, "ok", "0"))
    case("private_without_key", "No auditor key: step 1 (allow record, signature, binding, mandate_ref) runs; the "
         "rest is policy_private.", PV, p4, private=True, exp=("unchecked", "policy_private", "not_checked", "2"))
    case("private_wrong_key", "A key the envelopes do not list (auditor-3): nothing opens, policy_private.", PV, p4,
         auditors=("auditor-3",), private=True, exp=("unchecked", "policy_private", "not_checked", "2"))
    v4 = P.verify_verdict(P.decode_record(PV.recs[f"policy-allow/{p4['commitment_hash'].hex()}"])["body"], G1)[0]
    pp_path = f"private/4/{v4['private_hash'].hex()}"
    other_pp = {"format": 1, "salt": bytes(32), "extractor": P.TEST_EXTRACTOR, "facts": F(1), "anchor_time": T0,
                "eval_time": T0, "prev_state": P.GENESIS, "decided_at": T0}
    other = private_record(4, P.private_part_cbor(other_pp), v4["private_hash"], AUDITORS)[0]
    case("private_part_hash_differs", "The record under p4's private_hash opens to another PrivatePart: its hash "
         "differs from the key, source_corrupt.", PV, p4, auditors=k, corrupt={pp_path: other}, private=True,
         exp=("unchecked", "source_corrupt", "not_checked", "2"))
    case("private_walk_without_key", "Full walk without the key: L1 and L2 on public fields (keys 14 and 20, "
         "compared bytewise without the salt) down to the genesis hash; gate_integrity unchecked (policy_private), "
         "never ok.", PV, p4, full=True, private=True, exp=("unchecked", "policy_private", "unchecked", "2"))

    def cheat(i, desc, exp, facts=F(100), honest_facts=None, mutate=None, prior=(), mutate_pub=None, mutate_pp=None,
              blind_salt=None, **kw):
        S = Sim("PX-" + i, m=pm("PX-" + i), blind_salt=blind_salt)
        for j, (pf, pt) in enumerate(prior):
            S.step(dec(S, f"prior{j}", pf, pt, v1={}), pt)
        d = dec(S, "cheat", facts, T0 + 7300, v1={})
        S.step(d, d["th"], honest=False, facts=honest_facts, mutate=mutate, mutate_pub=mutate_pub, mutate_pp=mutate_pp)
        case(i, desc, S, d, private=True, exp=exp, **kw)

    cheat("private_without_key_facts_mismatch", "No key; the gate signed amount 100, the action bytes say 1000. The "
          "facts are in the PrivatePart, so without a key the comparison does not run: unchecked (policy_private).",
          ("unchecked", "policy_private", "not_checked", "2"), facts=F(1000), honest_facts=F(100))
    cheat("private_with_key_facts_mismatch", "The same with auditor-1's key: the merged verdict's facts differ from "
          "the re-extraction, fail.", ("fail", "facts_mismatch", "not_checked", "1"), facts=F(1000),
          honest_facts=F(100), auditors=("auditor-1",))

    def late(v, r):
        v["anchor_time"] += 60
        v["eval_time"] += 60
    cheat("private_without_key_anchor_time_mismatch", "No key; anchor_time 60 s after the verified T_ref, hidden in "
          "the PrivatePart: unchecked (policy_private).", ("unchecked", "policy_private", "not_checked", "2"),
          mutate=late)
    cheat("private_with_key_anchor_time_mismatch", "The same with a key: fail.",
          ("fail", "anchor_time_mismatch", "not_checked", "1"), mutate=late, auditors=k)

    def junk20(pub):
        pub["prev_state_hash"] = sha("edicta/policy/v1 test junk prev_state_hash")
    cheat("private_state_not_key_20", "The PrivatePart opens and hashes to private_hash, but its state does not hash "
          "to the signed prev_state_hash (key 20) under the mandate's state_salt.",
          ("unchecked", "blocked", "violated", "5"), mutate_pub=junk20, prior=[(F(100), T0 + 100)], auditors=k)
    cheat("state_salt_wrong", "The gate blinded the state hashes with another salt than the mandate's state_salt: "
          "with a key, state_hash_p(prev_state) differs from key 20.", ("unchecked", "blocked", "violated", "5"),
          prior=[(F(100), T0 + 100)], blind_salt=sha("edicta/policy/v1 test wrong state salt"), auditors=k)

    def add_reason(pp):
        pp["reason"] = "ErrAmountAboveMax"
    cheat("private_part_row_mismatch", "An allow whose PrivatePart, which hashes to the signed private_hash, also "
          "carries key 8 (a deny reason): the presence rule fails, so the gate signed a contradiction. The facts and "
          "state it does carry allow: policy pass, gate_integrity violated (gate_signed_inconsistent_private_part), "
          "exit 5.", ("pass", None, "violated", "5"), mutate_pp=add_reason, auditors=k)

    def drop_facts(pp):
        del pp["facts"]
    cheat("private_part_allow_missing_facts", "An allow whose PrivatePart lacks key 10 (facts): the verifier's own "
          "extraction of the action bytes stands in and allows: policy pass, gate_integrity violated "
          "(gate_signed_inconsistent_private_part), exit 5.", ("pass", None, "violated", "5"),
          mutate_pp=drop_facts, auditors=k)
    def drop_prev_state(pp):
        del pp["prev_state"]
    cheat("private_part_allow_missing_prev_state", "An allow whose PrivatePart lacks key 13 (prev_state): the facts "
          "and the per-action rules still run and pass, but the state read and the evaluation (steps 5 and 6) have "
          "no input: policy unchecked (blocked, naming gate_integrity), gate_integrity violated "
          "(gate_signed_inconsistent_private_part), exit 5.", ("unchecked", "blocked", "violated", "5"),
          mutate_pp=drop_prev_state, auditors=k)

    def drop_times(pp):
        del pp["anchor_time"]
        del pp["eval_time"]
    cheat("private_part_allow_missing_times", "An allow whose PrivatePart lacks keys 11 and 12 (anchor_time, "
          "eval_time): the verifier uses the verified T_ref and derives eval_time = max(T_ref, prev_state.last_t); "
          "evaluation on the signed state allows: policy pass, gate_integrity violated "
          "(gate_signed_inconsistent_private_part), exit 5.", ("pass", None, "violated", "5"),
          mutate_pp=drop_times, auditors=k)
    cheat("private_part_missing_facts_denies", "The gate allowed amount 6000 (above the per-action maximum) and left "
          "the facts out of the PrivatePart: the verifier's own extraction denies, so the gate contradicts itself in "
          "a way that changes the outcome: policy fail (ErrAmountAboveMax), decision invalid, gate_integrity "
          "violated.", ("fail", "ErrAmountAboveMax", "violated", "1"), facts=F(6000), mutate_pp=drop_facts,
          auditors=k)

    PF = Sim("PF", m=pm("PF"))
    x = dec(PF, "f1", F(100), T0 + 100, v1={})
    # Sign as a public-mode gate would, under the private mandate's hash.
    m_saved = PF.m
    PF.m = {kk: vv for kk, vv in PF.m.items() if kk not in ("auditors", "state_salt")}
    sv_pub, _, _ = PF.step(x, x["th"], archive=False, commit=False)
    PF.m = m_saved
    PF.put(P.record(8, body=sv_pub))
    case("verdict_form_mismatch", "The mandate has auditors but the allow verdict is in public form (prev_state and "
         "facts in clear).", PF, x, auditors=k, private=True, exp=("unchecked", "blocked", "violated", "5"))

    PK = Sim("PK", m=pm("PK"))
    g = copy.deepcopy(PK.led)
    q1 = dec(PK, "q1", F(100), T0 + 100, v1={}); PK.step(q1, q1["th"])
    q1x = dec(PK, "q1x", F(1900), T0 + 110, v1={})
    svx, _, _ = PK.step(q1x, q1x["th"], ledger=g, commit=False, archive=False)
    case("private_fork_without_key", "Two private-form allows with the same mandate_hash and the same "
         "prev_state_hash (genesis), different commitments; q1x is evidence. No key: the hash form of the fork rule.",
         PK, q1, evidence=[svx], private=True, exp=("unchecked", "blocked", "violated", "5"))

    CC = Sim("CC", m=pm("CC"))
    c1 = dec(CC, "c1", F(100), T0 + 100, v1={}); CC.step(c1, c1["th"])
    c2 = dec(CC, "c2", F(100), T0 + 200, v1={}); CC.step(c2, c2["th"])
    case("chain_continuity_without_salt", "Two consecutive private allows: without a key the walk compares c2's "
         "key 20 with c1's key 14 bytewise (L2) and reaches the genesis hash.", CC, c2, full=True, private=True,
         exp=("unchecked", "policy_private", "unchecked", "2"))
    CT = Sim("CT", m=pm("CT"))
    t1 = dec(CT, "t1", F(100), T0 + 100, v1={}); CT.step(t1, t1["th"])
    t2 = dec(CT, "t2", F(100), T0 + 200, v1={})

    def tamper20(pub):
        pub["prev_state_hash"] = sha("edicta/policy/v1 test tampered key 20")
    CT.step(t2, t2["th"], mutate_pub=tamper20)
    case("chain_continuity_tampered_without_salt", "As chain_continuity_without_salt, but t2's key 20 does not equal "
         "t1's key 14: L2 fails without any key, violated.", CT, t2, full=True, private=True,
         exp=("unchecked", "blocked", "violated", "5"))


def action_envelope_source():
    """The v1 decision whose action kind 15 plaintext 5 carries: core v1 valid.json v1_pending_fibre_mandate_ref."""
    import gen_vectors as gv
    gv.build()
    c, _, at, act, salt = gv.VALID["v1_pending_fibre_mandate_ref"]
    return "v1_pending_fibre_mandate_ref", at, salt, act, c["action"]["hash"]


def envelope_json(eid, pk, path, pt, key, rnd, trace, env, rec, extra=None):
    return {"id": eid, "plaintext_kind": str(pk), "path": path, "plaintext_cbor_hex": pt.hex(), "hash_hex": key.hex(),
            **(extra or {}), "salt_hex": rnd["salt"].hex(), "dek_hex": rnd["dek"].hex(),
            "aead_nonce_hex": rnd["aead_nonce"].hex(),
            "recipients": [{"kid_hex": a["kid"].hex(), "ikme_hex": rnd["ikme"][i].hex(),
                            "enc_hex": trace[i]["enc"].hex(), "wrapped_dek_hex": trace[i]["wrapped_dek"].hex()}
                           for i, a in enumerate(AUDITORS)],
            "envelope_hex": env.hex(), "record_cbor_hex": rec.hex()}


def gen_private(priv: dict, sims: dict) -> dict:
    """private.json: section 9.5 envelopes, the private form, blinding and the private-mode verifier cases."""
    PV = sims["PV"]
    salt = PV.m["state_salt"]
    names = ("auditor-1", "auditor-2", "auditor-3")
    keys = {}
    for n in names:
        pk_ = auditor_key(n.encode())[1]
        keys[n] = {"ikm_hex": sha("edicta/policy/v1 test auditor|" + n).hex(), "sk_hex": AUDITOR_SK[n].hex(),
                   "pk_hex": pk_.hex(), "kid_preimage_hex": (bytes([len(P.TAG_AUDITOR_KID)]) + P.TAG_AUDITOR_KID + pk_).hex(),
                   "kid_hex": P.auditor_kid(pk_).hex(), "fingerprint": P.fingerprint(P.auditor_kid(pk_))}
        lab = next((a["label"] for a in AUDITORS if a["pubkey"] == pk_), None)
        if lab:
            keys[n]["label"] = lab
    envs = []
    for pk in (1, 2, 3, 4):
        path = sorted(p for p in PV.recs if p.startswith(f"private/{pk}/"))[-1]
        r = P.decode_record(PV.recs[path])
        st, pt, _ = open_any(r, pk)
        h = P.plaintext_hash(pk, pt)
        key = r["key"]
        assert key == (P.blind_key(salt, h) if pk in (2, 3) else h)
        rec, env, rnd, trace = private_record(pk, pt, key, AUDITORS)
        assert rec == PV.recs[path]
        extra = {"plaintext_hash_hex": h.hex(), "state_salt_hex": salt.hex()} if pk in (2, 3) else None
        envs.append(envelope_json(f"envelope_{P.PLAINTEXT_KINDS[pk]}", pk, path, pt, key, rnd, trace, env, rec, extra))
    ref, at, asalt, act, ah = action_envelope_source()
    pt5 = asalt + act
    assert P.plaintext_hash(5, pt5, at) == ah
    rec5, env5, rnd5, trace5 = private_record(5, pt5, ah, AUDITORS)
    envs.append(envelope_json("envelope_action", 5, f"private/5/{ah.hex()}", pt5, ah, rnd5, trace5, env5, rec5,
                              {"action_type": at, "commitment_ref": f"spec/vectors/v1/valid.json#{ref}",
                               "action_salt_hex": asalt.hex(), "action_hex": act.hex()}))
    p1, p4, pd, p3 = sims["PV_targets"]

    def opened(sv):
        v, vh = P.verify_verdict(sv, G1)
        st, ppb, _ = P.private_open(P.decode_record(PV.recs[f"private/4/{v['private_hash'].hex()}"])["envelope"],
                                    [AUDITOR_SK["auditor-2"]], 4, v["private_hash"])
        return v, vh, ppb, P.decode_private_part(ppb)
    sv = P.decode_record(PV.recs[f"policy-allow/{p4['commitment_hash'].hex()}"])["body"]
    v, vh, ppb, pp = opened(sv)
    verdict = {"signed_verdict_hex": sv.hex(), "verdict_hash_hex": vh.hex(), "public_keys": sorted(
               str(k) for k, (nm, _, _, _) in P.S_VERDICT.items() if nm in v),
               "private_hash_hex": v["private_hash"].hex(), "prev_state_hash_hex": v["prev_state_hash"].hex(),
               "private_part_cbor_hex": ppb.hex(), "private_part": js(pp),
               "prev_state_cbor_hex": P.state_cbor(pp["prev_state"]).hex(),
               "merged_verdict": js(P.merge_verdict(v, pp))}
    deny_path = next(p for p in sorted(PV.recs) if p.startswith(f"policy-deny/{pd['commitment_hash'].hex()}/private-"))
    dsv = P.decode_record(PV.recs[deny_path])["body"]
    dv, dvh, dppb, dpp = opened(dsv)
    marker = encode({1: 0, 2: 5, 3: pd["commitment_hash"], 4: "ErrDenied", 5: GATE_ID, 6: pd["th"] + 30})
    deny = {"id": "private_deny_no_public_reason", "description": "A stage 4p deny (ErrAmountAboveMax, amount 6000 above "
            "5000) of a private mandate: the public part has exactly keys 1 to 7 and 19, so every private deny has the "
            "same public shape; kind 9 under the path segment private; the rejection marker name ErrDenied.",
            "signed_verdict_hex": dsv.hex(), "verdict_hash_hex": dvh.hex(),
            "public_keys": sorted(str(k) for k, (nm, _, _, _) in P.S_VERDICT.items() if nm in dv),
            "kind9_path": deny_path, "kind9_record_cbor_hex": PV.recs[deny_path].hex(),
            "marker_record_cbor_hex": marker.hex(), "marker_path": f"rejection/{pd['commitment_hash'].hex()}/ErrDenied",
            "with_key": {"id": "private_deny_with_key", "auditor": "auditor-2", "private_part_cbor_hex": dppb.hex(),
                         "private_part": js(dpp), "reason": dpp["reason"]},
            "second_deny": second_private_deny(PV, pd, dpp),
            "same_reason_retry": same_reason_private_retry(PV, pd, dpp)}
    assert sorted(deny["public_keys"], key=int) == ["1", "2", "3", "4", "5", "6", "7", "19"]
    base = envs[3]
    pt, h = bytes.fromhex(base["plaintext_cbor_hex"]), bytes.fromhex(base["hash_hex"])
    rnd = private_randomness("4/" + base["hash_hex"], 2)
    tampered = bytearray(bytes.fromhex(base["envelope_hex"])); tampered[-1] ^= 1
    from edicta_payload import payload_aad, hpke_info
    wrong_aad = P.private_seal(pt, AUDITORS, rnd["salt"], rnd["dek"], rnd["aead_nonce"], rnd["sk_es"], aead_aad=payload_aad())[0]
    wrong_info = P.private_seal(pt, AUDITORS, rnd["salt"], rnd["dek"], rnd["aead_nonce"], rnd["sk_es"], info=hpke_info())[0]

    def over(cap):
        n = cap - 400
        while len(P.private_seal(bytes(n), AUDITORS, rnd["salt"], rnd["dek"], rnd["aead_nonce"], rnd["sk_es"])[0]) <= cap:
            n += 1
        return P.private_seal(bytes(n), AUDITORS, rnd["salt"], rnd["dek"], rnd["aead_nonce"], rnd["sk_es"])[0]
    big = over(P.PRIVATE_CAP)
    big5 = over(P.PRIVATE_ACTION_CAP)
    rej = []
    for i, d, env, want, pk, hh in [
            ("envelope_cap_exceeded", "An envelope of 65,537 bytes for plaintext kind 4, one above its cap: refused "
             "before decoding.", big, "source_corrupt", 4, h),
            ("action_envelope_69633", "An envelope of 69,633 bytes for plaintext kind 5, one above the action cap.",
             big5, "source_corrupt", 5, ah),
            ("tampered_ciphertext", "The last ciphertext byte flipped: the DEK unwraps with a listed key, the AEAD "
             "fails.", bytes(tampered), "source_corrupt", 4, h),
            ("wrong_tag_aad", "Sealed with the core payload AEAD tag (edicta/v1/payload) as aad: the DEK unwraps, the "
             "AEAD fails.", wrong_aad, "source_corrupt", 4, h),
            ("wrong_tag_dek_info", "DEK wrapped with the core HPKE info (edicta/v1/payload-dek): no entry unwraps with "
             "the policy info, so nothing opens.", wrong_info, "policy_private", 4, h)]:
        st, cause, _ = P.private_open(env, [AUDITOR_SK["auditor-1"], AUDITOR_SK["auditor-2"]], pk, hh, at)
        got = {"corrupt": "source_corrupt", "private": "policy_private"}[st]
        assert got == want, (i, st, cause)
        rej.append({"id": i, "description": d, "plaintext_kind": str(pk), "hash_hex": hh.hex(),
                    "auditor_keys": ["auditor-1", "auditor-2"], "envelope_size": str(len(env)),
                    "envelope_hex": env.hex(), "expect": want})
    vrej = []
    g1 = P.verify_verdict(P.decode_record(PV.recs[f"policy-allow/{p1['commitment_hash'].hex()}"])["body"], G1)[0]
    rows = [
        ("verdict_mixed_forms", "Private form plus prev_state in clear (keys 13, 19, 20).", dict(v, prev_state=pp["prev_state"])),
        ("verdict_private_hash_only", "An allow with key 19 and without key 20.",
         {k: x for k, x in v.items() if k != "prev_state_hash"}),
        ("verdict_state_hash_only", "Key 20 without key 19 (public form with key 20).",
         {k: x for k, x in P.merge_verdict(v, pp).items()} | {"prev_state_hash": v["prev_state_hash"]}),
        ("verdict_genesis_with_chain_keys", "Private-form allow whose prev_state_hash is the genesis hash, with "
         "keys 15 and 16.", dict(g1, prev_commitment_hash=bytes(32), prev_verdict_hash=bytes(32))),
        ("verdict_later_without_chain_keys", "Private-form allow whose prev_state_hash is not the genesis hash, "
         "without keys 15 and 16.", {k: x for k, x in v.items() if k not in ("prev_commitment_hash", "prev_verdict_hash")}),
        ("private_form_with_reason", "Private-form deny with key 8 (reason) in clear.", dict(dv, reason="ErrAmountAboveMax")),
        ("private_form_with_facts", "Private-form allow with key 10 (facts) in clear.", dict(v, facts=pp["facts"])),
        ("private_form_with_anchor_time", "Private-form allow with key 11 in clear.", dict(v, anchor_time=pp["anchor_time"])),
        ("private_form_with_decided_at", "Private-form allow with key 17: decided_at is in the PrivatePart.",
         dict(v, decided_at=pp["decided_at"])),
        ("private_form_with_gate_clock", "Private-form deny with key 18.", dict(dv, gate_clock=1)),
        ("private_deny_with_key_20", "Private-form deny with key 20: a deny's state read is private.",
         dict(dv, prev_state_hash=v["prev_state_hash"])),
        ("private_allow_without_14", "Private-form allow without key 14.",
         {k: x for k, x in v.items() if k != "new_state_hash"}),
        ("public_form_without_decided_at", "Public form without key 17.",
         {k: x for k, x in P.merge_verdict(v, pp).items() if k != "decided_at"}),
    ]
    for i, d, vv in rows:
        b = encode({1: P.to_cbor(vv, P.S_VERDICT), 2: bytes(64)})
        try:
            P.decode_signed_verdict(b)
            raise AssertionError(i)
        except P.PolicyError as e:
            vrej.append({"id": i, "description": d, "signed_verdict_hex": b.hex(), "expect_error": "ErrVerdictInvalid",
                         "cause": e.cause})
    verdict["reject"] = vrej
    st3 = pp["prev_state"]
    ppa = {"format": 1, "salt": sha("edicta/policy/v1 test pp salt a"), **{k: x for k, x in pp.items()
                                                                          if k not in ("format", "salt")}}
    ppb2 = dict(ppa, salt=sha("edicta/policy/v1 test pp salt b"))
    bk = next(e for e in envs if e["plaintext_kind"] == "2")
    cl = next(e for e in envs if e["plaintext_kind"] == "3")
    blinding = [
        {"id": "state_hash_blind_vs_public", "description": "One State (p4's state read): the public state_hash and "
         "the blinded state_hash_p under the counter's state_salt.", "state_cbor_hex": P.state_cbor(st3).hex(),
         "state_salt_hex": salt.hex(), "state_hash_hex": P.state_hash(st3).hex(),
         "state_hash_p_preimage_hex": (P.tagged("state-blind") + salt + P.state_cbor(st3)).hex(),
         "state_hash_p_hex": P.state_hash_p(st3, salt).hex()},
        {"id": "state_hash_blind_genesis", "description": "Genesis keeps the public constant under blinding.",
         "state_cbor_hex": P.state_cbor(P.GENESIS).hex(), "state_salt_hex": salt.hex(),
         "state_hash_p_hex": P.state_hash_p(P.GENESIS, salt).hex(), "genesis_hash_hex": P.GENESIS_HASH.hex()},
        {"id": "blind_key_bucket", "description": "Kind 15 key of a closed bucket in private mode.",
         "bucket_hash_hex": bk["plaintext_hash_hex"], "state_salt_hex": salt.hex(),
         "blind_key_preimage_hex": (P.tagged("blind-key") + salt + bytes.fromhex(bk["plaintext_hash_hex"])).hex(),
         "key_hex": bk["hash_hex"], "path": bk["path"]},
        {"id": "blind_key_closed", "description": "Kind 15 key of a ClosedSet in private mode.",
         "closed_root_hex": cl["plaintext_hash_hex"], "state_salt_hex": salt.hex(), "key_hex": cl["hash_hex"],
         "path": cl["path"]},
        {"id": "private_part_salt", "description": "Equal PrivatePart content under two salts gives two "
         "private_hash values, so a public private_hash is no oracle for the content.",
         "private_part_a_cbor_hex": P.private_part_cbor(ppa).hex(), "private_hash_a_hex": P.private_hash(ppa).hex(),
         "private_part_b_cbor_hex": P.private_part_cbor(ppb2).hex(), "private_hash_b_hex": P.private_hash(ppb2).hex()},
    ]
    assert P.state_hash_p(P.GENESIS, salt) == P.GENESIS_HASH and P.private_hash(ppa) != P.private_hash(ppb2)
    return {"tags": {n: P.TAG[n].decode() for n in ("private-part", "private", "private-dek", "state-blind",
                                                   "blind-key")} | {"auditor-kid": P.TAG_AUDITOR_KID.decode()},
            "cap": str(P.PRIVATE_CAP), "action_cap": str(P.PRIVATE_ACTION_CAP), "auditor_keys": keys,
            "derivation": {
                "auditor_key": "(sk, pk) = DeriveKeyPair(SHA-256(\"edicta/policy/v1 test auditor|\" + name)), RFC 9180 "
                               "section 7.1.3; kid = SHA-256(tag(\"edicta/v1/auditor-kid\") || pk)[0..16]",
                "ephemeral_key": "skE = DeriveKeyPair(SHA-256(\"edicta/policy/v1 test private ephemeral|\" + label + "
                                 "\"|\" + index)).sk; index is the 0-based auditor position",
                "dek": "SHA-256(\"edicta/policy/v1 test private dek|\" + label)",
                "aead_nonce": "SHA-256(\"edicta/policy/v1 test private aead nonce|\" + label)[0:12]",
                "salt": "SHA-256(\"edicta/policy/v1 test private salt|\" + label)",
                "label": "decimal plaintext_kind + \"/\" + record key hex",
                "state_salt": "SHA-256(\"edicta/policy/v1 test state salt|\" + mandate label)",
                "private_part_salt": "SHA-256(\"edicta/policy/v1 test private part salt|\" + commitment_hash hex)",
                "note": "Production draws all of these from a CSPRNG. Rejects reuse the PrivatePart envelope's randomness."},
            "envelopes": envs, "private_verdict": verdict, "private_deny": deny, "blinding": blinding, "reject": rej,
            **priv}


def open_any(r, pk):
    """Opens a PV record with auditor-1 against the hash of its own plaintext (blinded keys need the plaintext)."""
    import hpke_base as hpke
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    import edicta_payload as pl
    b = pl.blob_decode(r["envelope"])
    sk = AUDITOR_SK["auditor-1"]
    for e in b.recipients:
        try:
            dek = hpke.setup_base_r(e.enc, sk, P.tagged("private-dek")).open(bytes([len(e.kid)]) + e.kid, e.wrapped_dek)
        except hpke.HPKEError:
            continue
        return "ok", ChaCha20Poly1305(dek).decrypt(b.aead_nonce, b.ciphertext, P.tagged("private"))[32:], e.kid
    raise AssertionError("auditor-1 cannot open")


def gen_archive(pool, ppool):
    cases = []
    seen = set()
    for p in sorted(pool):
        r = P.decode_record(pool[p])
        if r["kind"] in seen and r["kind"] != 9:
            continue
        seen.add(r["kind"])
        cases.append({"id": f"{P.KIND_NAMES[r['kind']]}_{len(cases)}", "kind": str(r["kind"]), "path": r["path"],
                      "key_hex": r["key"].hex(), "record_cbor_hex": pool[p].hex()})
        if len(cases) >= 7:
            break
    for pk in (1, 2, 3, 4):
        p = next(p for p in sorted(ppool) if p.startswith(f"private/{pk}/"))
        r = P.decode_record(ppool[p])
        cases.append({"id": f"private_blob_{P.PLAINTEXT_KINDS[pk]}", "kind": "15", "path": r["path"],
                      "key_hex": r["key"].hex(), "plaintext_kind": str(pk), "record_cbor_hex": ppool[p].hex()})
    _, at, asalt, act, ah = action_envelope_source()
    rec5 = private_record(5, asalt + act, ah, AUDITORS)[0]
    cases.append({"id": "private_blob_action", "kind": "15", "path": f"private/5/{ah.hex()}", "key_hex": ah.hex(),
                  "plaintext_kind": "5", "record_cbor_hex": rec5.hex()})
    pdeny = next(p for p in sorted(ppool) if p.startswith("policy-deny/") and "/private-" in p)
    r = P.decode_record(ppool[pdeny])
    cases.append({"id": "policy_deny_private", "kind": "9", "path": r["path"], "key_hex": r["key"].hex(),
                  "record_cbor_hex": ppool[pdeny].hex()})
    allow = next(pool[p] for p in sorted(pool) if p.startswith("policy-allow/"))
    deny = next(pool[p] for p in sorted(pool) if p.startswith("policy-deny/"))
    succ = next(pool[p] for p in sorted(pool) if p.startswith("policy-successor/"))
    body = lambda b: P.decode_record(b)["body"]  # noqa: E731
    sm = next(pool[p] for p in sorted(pool) if p.startswith("mandate/"))
    rej = [
        ("allow_holds_deny", "Kind 8 holding a deny verdict.", encode({1: 1, 2: 8, 3: body(deny)})),
        ("deny_holds_allow", "Kind 9 holding an allow verdict.", encode({1: 1, 2: 9, 3: body(allow)})),
        ("kind_6_reserved", "Kind 6 stays undefined.", encode({1: 1, 2: 6, 3: body(sm)})),
        ("kind_13", "Kind 13.", encode({1: 1, 2: 13, 3: body(sm)})),
        ("mandate_unknown_key", "Kind 7 with key 4.", encode({1: 1, 2: 7, 3: body(sm), 4: 0})),
        ("mandate_body_tstr", "Kind 7 body as text.", encode({1: 1, 2: 7, 3: "x"})),
        ("mandate_body_garbage", "Kind 7 body that is not a signed mandate.", encode({1: 1, 2: 7, 3: b"\xa0"})),
        ("bucket_body_noncanonical", "Kind 10 body with a non-minimal head.", encode({1: 1, 2: 10, 3: b"\xb8\x04" + P.decode_record(
            next(pool[p] for p in sorted(pool) if p.startswith("policy-bucket/")))["body"][1:]})),
        ("format_0", "format 0: archive records of the unsupported v0 drafts are refused at the header.", encode({1: 0, 2: 7, 3: body(sm)})),
        ("successor_gate_id_space", "Kind 12 gate_id with a space.", encode({**{k: v for k, v in [(1, 1), (2, 12)]},
                                                                            3: "gate 1", 4: bytes(32), 5: bytes(32), 6: bytes(32)})),
        ("successor_short_hash", "Kind 12 state_hash of 31 bytes.", encode({1: 1, 2: 12, 3: GATE_ID, 4: bytes(32),
                                                                           5: bytes(31), 6: bytes(32)})),
        ("successor_missing_commitment", "Kind 12 without key 6.", encode({1: 1, 2: 12, 3: GATE_ID, 4: bytes(32), 5: bytes(32)})),
        ("trailing", "A zero byte after a successor record.", succ + b"\x00"),
    ]
    priv = P.decode_record(next(ppool[p] for p in sorted(ppool) if p.startswith("private/4/")))
    pr = lambda kw: encode({1: 1, 2: 15, 3: 4, 4: priv["key"], 5: priv["envelope"], **kw})  # noqa: E731
    rej += [
        ("private_kind_6", "Kind 15 with plaintext_kind 6.", pr({3: 6})),
        ("private_envelope_65537", "Kind 15 plaintext_kind 4 with an envelope of 65,537 bytes (69,632 is the limit "
         "of plaintext kind 5 only).", pr({5: bytes(65537)})),
        ("private_kind_0", "Kind 15 with plaintext_kind 0.", pr({3: 0})),
        ("private_hash_31", "Kind 15 hash of 31 bytes.", pr({4: priv["key"][:31]})),
        ("private_envelope_empty", "Kind 15 with an empty envelope.", pr({5: b""})),
        ("private_envelope_tstr", "Kind 15 envelope as text.", pr({5: "x"})),
        ("private_missing_envelope", "Kind 15 without key 5.", encode({1: 1, 2: 15, 3: 4, 4: priv["key"]})),
        ("private_unknown_key", "Kind 15 with key 6.", pr({6: 0})),
        ("private_over_cap", "Kind 15 of 69,761 bytes.", None),
    ]
    head = encode({1: 1, 2: 15, 3: 5, 4: priv["key"]})
    filler = 69761 - (len(head) + 1 + 5)
    big = bytes([0xa4]) + head[1:] + bytes([0x05, 0x5a]) + filler.to_bytes(4, "big") + bytes(filler)
    assert len(big) == 69761
    rej[-1] = (rej[-1][0], rej[-1][1], big)
    out = []
    for i, d, b in rej:
        try:
            P.decode_record(b)
            raise AssertionError(i)
        except P.PolicyError as e:
            out.append({"id": i, "description": d, "record_cbor_hex": b.hex(), "expect_error": "archive.ErrCorrupt",
                        "cause": e.cause})
    pub_deny = next(p for p in sorted(pool) if p.startswith("policy-deny/"))
    pd_rec = P.decode_record(pool[pub_deny])
    pv_rec = P.decode_record(ppool[pdeny])
    reads = [
        {"id": "deny_private_under_reason_path", "description": "A private-form deny stored under a sentinel "
         "segment: the reader recomputes the segment (private iff key 19 is present).",
         "path": f"policy-deny/{pv_rec['key'].hex()}/ErrAmountAboveMax", "record_cbor_hex": ppool[pdeny].hex(),
         "expect_error": "archive.ErrCorrupt"},
        {"id": "deny_public_under_private_path", "description": "A public-form deny stored under the segment private.",
         "path": f"policy-deny/{pd_rec['key'].hex()}/{pdeny.rsplit('/', 1)[1]}", "record_cbor_hex": pool[pub_deny].hex(),
         "expect_error": "archive.ErrCorrupt"},
        {"id": "deny_private_own_path", "description": "Control: the private deny under its own path.",
         "path": pv_rec["path"], "record_cbor_hex": ppool[pdeny].hex(), "expect_error": None},
    ]
    for x in reads:
        assert (P.decode_record(bytes.fromhex(x["record_cbor_hex"]))["path"] == x["path"]) == (x["expect_error"] is None)
    return {"kinds": {str(k): {"name": n, "path": P.PATHS[k], "cap": str(P.REC_CAP[k])} for k, n in P.KIND_NAMES.items()},
            "reserved_kinds": ["6"], "marker_names": REASON_MARKERS + ["ErrDenied"],
            "marker_names_private_only": ["ErrDenied"], "cases": cases, "reject": out, "reads": reads}


REASON_MARKERS = ["ErrAgentNotCovered", "ErrFastModeNotAllowed", "ErrNoExtractor", "ErrFactsInvalid", "ErrOutsideMandate", "ErrKindNotAllowed",
                  "ErrAssetNotAllowed", "ErrRecipientNotAllowed", "ErrAmountAboveMax", "ErrDecisionAge", "ErrMinSpacing",
                  "ErrPeriodLimit", "ErrCountLimit", "ErrHistoryFull"]

API = [("403", "policy.ErrAgentNotCovered"), ("403", "policy.ErrNoExtractor"), ("403", "policy.ErrOutsideMandate"),
       ("403", "policy.ErrKindNotAllowed"), ("403", "policy.ErrAssetNotAllowed"), ("403", "policy.ErrRecipientNotAllowed"),
       ("403", "policy.ErrAmountAboveMax"), ("403", "policy.ErrMinSpacing"), ("403", "policy.ErrPeriodLimit"),
       ("403", "policy.ErrCountLimit"), ("403", "policy.ErrHistoryFull"), ("403", "policy.ErrFastModeNotAllowed"),
       ("410", "policy.ErrDecisionAge"),
       ("422", "policy.ErrFactsInvalid"), ("503", "ErrPolicyStateConflict")]


def gen_api(sims):
    A = sims["A"]
    deny4 = deny10 = allow = None
    for p, b in sorted(A.recs.items()):
        r = P.decode_record(b)
        if r["kind"] == 9 and r["reason"] == "ErrAmountAboveMax":
            deny4 = r["body"]
        if r["kind"] == 9 and r["reason"] == "ErrPeriodLimit":
            deny10 = r["body"]
    a1 = ch_of("A/a1")
    allow = P.decode_record(A.recs[f"policy-allow/{a1.hex()}"])["body"]
    v, _ = P.verify_verdict(allow, G1)
    auth = {1: 1, 2: v["commitment_hash"], 3: v["action_hash"], 4: GATE_ID, 5: T0 + 100 + 300, 6: 1, 7: 1}
    canon = encode(auth)
    ah = hashlib.sha256(tagged(TAG_AUTHORIZATION) + canon).digest()
    sig = P.ed_sign(SEEDS["gate1"], tagged(TAG_AUTHORIZATION_SIG) + ah)
    sa = encode({1: Raw(canon), 2: sig})

    def err(code, status, msg, retry, stored=None, verdict=None):
        m = {1: code, 2: msg, 3: retry}
        if stored is not None:
            m[4] = stored
        if verdict is not None:
            m[5] = verdict
        return encode(m)

    ex = [
        {"id": "authorize_allow", "status": "200", "description": "Allow: the SignedAuthorization (key 1, mode 1) and "
         "the allow verdict (key 5) of verify.json chain A, decision a1.", "response_cbor_hex": encode({1: sa, 5: allow}).hex(),
         "authorization_input": js(auth)},
        {"id": "authorize_deny_4p", "status": "403", "description": "Stage 4p deny with its signed verdict in key 5.",
         "response_cbor_hex": err("policy.ErrAmountAboveMax", 403, "policy: amount above the per-action maximum", 0,
                                  verdict=deny4).hex()},
        {"id": "authorize_deny_10p", "status": "403", "description": "Stage 10p deny with its signed verdict.",
         "response_cbor_hex": err("policy.ErrPeriodLimit", 403, "policy: rolling period limit", 0, verdict=deny10).hex()},
        {"id": "authorize_retry_stored", "status": "409", "description": "Same-commitment retry: stored Authorization "
         "(key 4) and stored verdict (key 5).", "response_cbor_hex": err("ErrNonceUsed", 409, "gate: nonce already used", 0,
                                                                          sa, allow).hex()},
        {"id": "authorize_state_conflict", "status": "503", "description": "Compare-and-swap conflict: retryable, no "
         "verdict.", "response_cbor_hex": err("ErrPolicyStateConflict", 503, "gate: policy state changed concurrently", 1).hex()},
    ]
    PV = sims["PV"]
    pdp = next(p for p in sorted(PV.recs) if p.startswith("policy-deny/") and "/private-" in p)
    ex.append({"id": "authorize_deny_private", "status": "403", "description": "Stage 4p deny at a private-mode gate: "
               "the caller still gets the sentinel in the error body, and key 5 holds the private-form verdict (keys 1 "
               "to 7 and 19), never the PrivatePart. HTTP answers are not archive data; protecting them is the "
               "caller's job.", "response_cbor_hex": err("policy.ErrAmountAboveMax", 403,
                                                         "policy: amount above the per-action maximum", 0,
                                                         verdict=P.decode_record(PV.recs[pdp])["body"]).hex()})
    return {"mapping": [{"status": s, "code": c, "retryable": "1" if s == "503" else "0"} for s, c in API],
            "match_rule": "after every core code of the same status", "examples": ex}


# tia-transfer facts (bank-send profile 2.4).

def tia_extract(action: bytes) -> dict:
    try:
        a = bs.action_decode(action)
        msg = bs.msg_decode(a["msg"], "celestia")
    except Exception as e:  # noqa: BLE001
        raise P.PolicyError("ErrFactsInvalid", getattr(e, "sentinel", "ErrMalformed"))
    if msg["denom"] != "utia":
        raise P.PolicyError("ErrFactsInvalid", "denom")
    f = {"kind": "transfer", "asset": f"cosmos:{a['chain_id']}/utia", "amount": P.amt(msg["amount"]), "scale": 6,
         "recipient": f"cosmos:{a['chain_id']}:{msg['to_address']}"}
    P.check_facts(f)
    return f


def gen_tia():
    act = json.loads((VECTORS / "profiles" / "bank-send" / "action.json").read_text())
    msgs = json.loads((VECTORS / "profiles" / "bank-send" / "msg_send.json").read_text())
    mcase = {c["id"]: c for c in msgs["cases"]}
    mrej = {c["id"]: c for c in msgs["reject"]}
    cases, rej = [], []
    for c in act["cases"]:
        b = bytes.fromhex(c["cbor_hex"])
        try:
            f = tia_extract(b)
            cases.append({"id": "tia_" + c["id"], "action_ref": c["id"], "action_hex": c["cbor_hex"], "facts": js(f),
                          "facts_cbor_hex": P.encode_facts(f).hex()})
        except P.PolicyError as e:
            rej.append({"id": "tia_" + c["id"], "action_ref": c["id"], "description": "Decodes as a bank-send action but "
                        "is refused by the extractor.", "action_hex": c["cbor_hex"], "expect_error": "ErrFactsInvalid",
                        "cause": e.cause})
    extra_ok = [("tia_max_amount", "mocha-4", "msg_max_amount"), ("tia_chain_upper", "Mocha-4.X_y", "msg_typical")]
    for i, chain, mref in extra_ok:
        b = bs.action_encode(chain, bytes.fromhex(mcase[mref]["msg_hex"]))
        f = tia_extract(b)
        cases.append({"id": i, "msg_ref": mref, "action_hex": b.hex(), "facts": js(f), "facts_cbor_hex": P.encode_facts(f).hex()})
    deny = [("deny_other_denom", "Denom ibc/...: only utia.", "mocha-4", "msg_ibc_denom", "cases"),
            ("deny_cosmos_hrp", "cosmos1 addresses: the extractor's HRP is celestia.", "cosmoshub-4", "msg_other_hrp", "cases"),
            ("deny_bad_checksum", "from_address checksum broken.", "mocha-4", "msg_from_bad_checksum", "reject"),
            ("deny_amount_zero", "Amount 0.", "mocha-4", "msg_amount_zero", "reject"),
            ("deny_amount_leading_zero", "Amount 01.", "mocha-4", "msg_amount_leading_zero", "reject"),
            ("deny_from_equals_to", "from == to.", "mocha-4", "msg_from_equals_to", "reject"),
            ("deny_msg_trailing", "Trailing byte in the msg.", "mocha-4", "msg_trailing_byte", "reject"),
            ("deny_msg_unknown_field", "Unknown protobuf field.", "mocha-4", "msg_unknown_field_bytes", "reject")]
    for i, d, chain, mref, where in deny:
        msg = bytes.fromhex((mcase if where == "cases" else mrej)[mref]["msg_hex"])
        b = bs.action_encode(chain, msg) if msg else bytes.fromhex("a201676d6f6368612d340240")
        try:
            tia_extract(b)
            raise AssertionError(i)
        except P.PolicyError as e:
            rej.append({"id": i, "msg_ref": mref, "description": d, "action_hex": b.hex(), "expect_error": "ErrFactsInvalid",
                        "cause": e.cause})
    good = bytes.fromhex(act["cases"][0]["cbor_hex"])
    for i, d, b in [("deny_action_trailing", "A zero byte after the action map.", good + b"\x00"),
                    ("deny_action_noncanonical", "chain_id length in a one-byte argument.",
                     bytes.fromhex(next(c for c in act["reject"] if c["id"] == "action_nonminimal_head")["cbor_hex"])),
                    ("deny_action_unknown_key", "Key 3 in the action.",
                     bytes.fromhex(next(c for c in act["reject"] if c["id"] == "action_unknown_key")["cbor_hex"])),
                    ("deny_chain_id_char", "chain_id with a slash.",
                     bytes.fromhex(next(c for c in act["reject"] if c["id"] == "action_chain_id_slash")["cbor_hex"]))]:
        try:
            tia_extract(b)
            raise AssertionError(i)
        except P.PolicyError as e:
            rej.append({"id": i, "description": d, "action_hex": b.hex(), "expect_error": "ErrFactsInvalid", "cause": e.cause})
    return {"format": "edicta-vectors/v0", "profile": "bank-send", "revision": "bank-send-v0-draft.8",
            "extractor": {"id": "celestia/tia-transfer/v1", "action_type": bs.ACTION_TYPE, "hrp": "celestia",
                          "denom": "utia", "scale": "6"}, "cases": cases, "reject": rej}


def header(extra: dict, revision: str = REVISION) -> dict:
    return {"format": FORMAT, "revision": revision, "generator": "spec/vectors/check/gen_policy.py", **extra}


def build() -> dict:
    """Returns {relative path: file content (str)}."""
    mand = gen_mandate()
    ver, pool, sims, priv = gen_verify()
    ppool = {p: bytes.fromhex(b) for p, b in priv["records"].items()}
    files = {
        "policy/facts.json": header({"test_extractor": {"id": P.TEST_EXTRACTOR, "action_type": P.TEST_ACTION_TYPE},
                                     **gen_facts()}),
        "policy/mandate.json": header({"tags": {n: t.decode() for n, t in P.TAG.items()}, **mand,
                                       "adoption": gen_adoption()}, REVISION_7),
        "policy/render.json": header(gen_render(mand), REVISION_7),
        "policy/state.json": header(gen_state()),
        "policy/engine.json": header(gen_engine()),
        "policy/verify.json": header(ver, REVISION_9),
        "policy/private.json": header(gen_private(priv, sims), REVISION_9),
        "policy/archive.json": header(gen_archive(pool, ppool), REVISION_9),
        "policy/api.json": header(gen_api(sims), REVISION_8),
        "profiles/bank-send/tia_transfer_facts.json": gen_tia(),
    }
    return {k: json.dumps(v, indent=2, ensure_ascii=True) + "\n" for k, v in files.items()}


def main() -> int:
    out = Path(sys.argv[sys.argv.index("--out") + 1]).resolve() if "--out" in sys.argv else VECTORS
    for rel, text in build().items():
        p = out / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
        print(f"wrote {p}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
