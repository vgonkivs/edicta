#!/usr/bin/env python3
"""Writes the policy v1 vectors (spec/policy-v1.md, policy-v1-draft.1).

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
from edicta_v0 import TAG_AUTHORIZATION, TAG_AUTHORIZATION_SIG, action_hash, tagged

HERE = Path(__file__).resolve().parent
VECTORS = HERE.parent
FORMAT = "edicta-policy-vectors/v1"
REVISION = "policy-v1-draft.1"
T0 = 1791000000
GATE_ID = "gate-paper-1"


def sha(label: str) -> bytes:
    return hashlib.sha256(label.encode()).digest()


CORE_KEYS = json.loads((VECTORS / "v0" / "keys.json").read_text())["keys"]
SEEDS = {n: bytes.fromhex(CORE_KEYS[n]["seed_hex"]) for n in ("agent1", "agent2", "gate1")}
SEEDS["p1"] = sha("edicta/policy/v1 test principal|p1")
SEEDS["p2"] = sha("edicta/policy/v1 test principal|p2")
PUB = {n: P.ed_pub(s) for n, s in SEEDS.items()}
A1, A2, G1 = PUB["agent1"], PUB["agent2"], PUB["gate1"]
AGENTS = sorted([A1, A2])


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
            ("m_scale18", "Scale 18 amounts and a 744 h window.", "p1", scale18)]


def gen_mandate():
    cases = []
    for i, d, signer, m in mandate_inputs():
        sm, h, sig = P.sign_mandate(SEEDS[signer], m)
        canon = P.mandate_cbor(m)
        assert P.verify_mandate(sm)[1] == h
        cases.append({"id": i, "description": d, "signer": signer, "input": js(m), "mandate_cbor_hex": canon.hex(),
                      "mandate_hash_hex": h.hex(), "signed_message_hex": P.signed_message("mandate-sig", h).hex(),
                      "signature_hex": sig.hex(), "signed_mandate_hex": sm.hex(),
                      "counter_key_hex": P.counter_key(m["principal"], m["mandate_id"]).hex()})
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
        ("unknown_key_14", "Mandate key 14.", encode({1: Raw(encode({**P.to_cbor(base, P.S_MANDATE), 14: 1})),
                                                      2: bytes(64)}), "ErrMandateInvalid"),
        ("signature_63", "Signature of 63 bytes.", good[:-66] + encode(bytes(63)), "ErrMandateInvalid"),
        ("trailing", "A zero byte after the signed mandate.", good + b"\x00", "ErrMandateInvalid"),
        ("too_large", "16385 bytes, refused before parsing.", good + bytes(16385 - len(good)), "ErrMandateInvalid"),
    ]
    rej = []
    for i, d, b, want in rejects:
        try:
            P.verify_mandate(b)
            raise AssertionError(f"{i} verifies")
        except P.PolicyError as e:
            assert e.sentinel == want, (i, e.sentinel, e.cause)
            rej.append({"id": i, "description": d, "signed_mandate_hex": b.hex(), "expect_error": want,
                        "cause": e.cause})
    keys = {n: {"seed_hex": SEEDS[n].hex(), "public_key_hex": PUB[n].hex(),
                "source": ("core keys.json" if n in CORE_KEYS else f"SHA-256(\"edicta/policy/v1 test principal|{n}\")")}
            for n in ("p1", "p2", "agent1", "agent2", "gate1")}
    return {"keys": keys, "cases": cases, "reject": rej}


def gen_render(mandate_file):
    out = []
    for c in mandate_file["cases"]:
        m = dict(next(x for x in mandate_inputs() if x[0] == c["id"])[3])
        out.append({"id": "render_" + c["id"], "mandate_ref": c["id"], "text": P.render(m)})
    extra = base_mandate("render_any", assets=[{"asset": "test:usd", "scale": 0, "periods": [{"hours": 1, "max": P.amt(9)}]}],
                         count_limits=None, max_decision_age=None, min_spacing=None, kinds=None)
    extra = {k: v for k, v in extra.items() if v is not None}
    out.append({"id": "render_recipients_any_scale0", "input": js(extra), "text": P.render(extra)})
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

class Sim:
    def __init__(self, label, m=None, signer="p1"):
        self.m = m or base_mandate(label)
        self.signer = signer
        self.sm, self.mh, _ = P.sign_mandate(SEEDS[signer], self.m)
        self.led = {"state": P.GENESIS, "set": P.EMPTY_CLOSED, "buckets": {}}
        self.head = None
        self.recs = {}
        self.label = label
        self.put(P.record(7, body=self.sm))
        self.put(P.record(11, body=P.closed_cbor(P.EMPTY_CLOSED)))

    def put(self, rec):
        r = P.decode_record(rec)
        old = self.recs.get(r["path"])
        assert old is None or old == rec, r["path"]
        self.recs[r["path"]] = rec
        return r["path"]

    def adopt(self, m):
        self.m = m
        self.sm, self.mh, _ = P.sign_mandate(SEEDS[self.signer], m)
        self.put(P.record(7, body=self.sm))

    def decision(self, label, facts, agent=A1, valid_until=None, th=T0):
        action = P.encode_facts(facts) if isinstance(facts, dict) else facts
        return {"label": label, "commitment_hash": ch_of(self.label + "/" + label), "agent_pubkey": agent,
                "action_type": P.TEST_ACTION_TYPE, "action": action, "action_hash": action_hash(P.TEST_ACTION_TYPE, action),
                "valid_until": valid_until if valid_until is not None else th + 900, "gate_id": GATE_ID}

    def base_verdict(self, d, now):
        return {"format": 1, "gate_id": GATE_ID, "mandate_hash": self.mh, "commitment_hash": d["commitment_hash"],
                "action_hash": d["action_hash"], "agent_pubkey": d["agent_pubkey"], "decided_at": now}

    def sign(self, v):
        return P.sign_verdict(SEEDS["gate1"], v)

    def step(self, d, th, *, honest=True, facts=None, ledger=None, head=None, mutate=None, commit=True,
             archive=True, successor=True, next_ledger=None):
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
            sv, vh = self.sign(v)
            if archive:
                self.put(P.record(9, body=sv))
            return sv, vh, v
        led = ledger if ledger is not None else self.led
        r = P.evaluate(self.m, led, f, th)
        if "deny" in r:
            if honest:
                v.update(outcome=2, reason=r["deny"], extractor=xid, facts=f, anchor_time=th, prev_state=led["state"])
                if r["deny"] != "ErrOutsideMandate":
                    v["eval_time"] = r["eval_time"]
                sv, vh = self.sign(v)
                if archive:
                    self.put(P.record(9, body=sv))
                return sv, vh, v
            r = P.apply(led, {"asset": f["asset"], "scale": f["scale"], "amount": f["amount"], "t_h": th})
        hd = head if head is not None else self.head
        v.update(outcome=1, extractor=P.TEST_EXTRACTOR, facts=f, anchor_time=th, eval_time=r["eval_time"],
                 prev_state=led["state"], new_state_hash=r["new_hash"])
        if led["state"]["seq"] >= 1:
            v.update(prev_commitment_hash=hd[0], prev_verdict_hash=hd[1])
        if mutate:
            mutate(v, r)
        sv, vh = self.sign(v)
        if archive:
            if r["closed_bucket"] is not None:
                self.put(P.record(10, body=P.bucket_cbor(r["closed_bucket"])))
                self.put(P.record(11, body=P.closed_cbor(r["closed_set"])))
            self.put(P.record(8, body=sv))
            if successor:
                self.put(P.record(12, gate_id=GATE_ID, counter_key=P.counter_key(self.m["principal"], self.m["mandate_id"]),
                                  state_hash=P.state_hash(led["state"]), commitment_hash=d["commitment_hash"]))
        if commit:
            self.led = next_ledger if next_ledger is not None else r["next"]
            self.head = (d["commitment_hash"], vh)
        return sv, vh, v


def gen_verify():
    pool = {}
    cases = []
    sims = {}

    def merge(sim):
        for p, b in sim.recs.items():
            assert pool.get(p, b) == b, p
            pool[p] = b

    def case(i, desc, sim, d, th="same", *, full=False, depth=None, require=False, principals=("p1",),
             extractors=True, evidence=(), drop=(), corrupt=None, exp=None):
        merge(sim)
        arch = sorted(p for p in sim.recs if p not in drop)
        cor = dict(corrupt or {})
        recs = {p: sim.recs[p] for p in arch}
        recs.update(cor)
        t_h = d["th"] if th == "same" else th
        ext = {P.TEST_ACTION_TYPE: P.TEST_EXTRACTOR} if extractors else {}
        res = P.verify_policy({"archive": P.Archive(recs), "decision": d, "t_h": t_h, "gate_pub": G1,
                               "principals": [PUB[x] for x in principals], "extractors": ext, "full": full,
                               "depth": depth, "evidence": list(evidence)})
        if exp:
            got = (res["policy"]["status"], res["policy"].get("rule") or res["policy"].get("reason"),
                   res["gate_integrity"]["status"], res["exit"])
            assert got == exp, (i, got, exp)
        c = {"id": i, "description": desc,
             "decision": {"commitment_hash_hex": d["commitment_hash"].hex(), "agent_pubkey_hex": d["agent_pubkey"].hex(),
                          "action_type": d["action_type"], "action_hex": d["action"].hex(),
                          "action_hash_hex": d["action_hash"].hex(), "valid_until": str(d["valid_until"]),
                          "gate_id": d["gate_id"]}}
        if t_h is not None:
            c["t_h"] = str(t_h)
        c["config"] = {"require_policy": require, "policy_full": full, "policy_depth": str(depth) if depth is not None else None,
                       "principal_keys": [PUB[x].hex() for x in principals], "extractors": {k: v for k, v in ext.items()},
                       "evidence": [e.hex() for e in evidence]}
        c["archive"] = arch
        if cor:
            c["corrupt"] = {p: b.hex() for p, b in cor.items()}
        c["expect"] = res
        cases.append(c)

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
    case("pass_depth_1", "a4, full walk limited to one hop.", A, a4, full=True, depth=1, exp=("pass", None, "ok", "0"))
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
              t_h="same", exp_gi="not_checked"):
        S = Sim("X-" + i, m=m)
        for j, (pf, pt) in enumerate(prior):
            S.step(dec(S, f"prior{j}", pf, pt), pt)
        d = dec(S, "cheat", facts, th, **(d_over or {}))
        S.step(d, th, honest=False, facts=honest_facts, mutate=mutate)
        case(i, desc, S, d, th=t_h, exp=("fail", rule, exp_gi, "1"))
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

    ids = [c["id"] for c in cases]
    assert len(ids) == len(set(ids))
    return {"gate": {"gate_id": GATE_ID, "gate_pubkey_hex": G1.hex()},
            "extractors": {P.TEST_ACTION_TYPE: P.TEST_EXTRACTOR},
            "records": {p: pool[p].hex() for p in sorted(pool)}, "cases": cases}, pool, sims


def gen_archive(pool):
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
    allow = next(pool[p] for p in sorted(pool) if p.startswith("policy-allow/"))
    deny = next(pool[p] for p in sorted(pool) if p.startswith("policy-deny/"))
    succ = next(pool[p] for p in sorted(pool) if p.startswith("policy-successor/"))
    body = lambda b: P.decode_record(b)["body"]  # noqa: E731
    sm = next(pool[p] for p in sorted(pool) if p.startswith("mandate/"))
    rej = [
        ("allow_holds_deny", "Kind 8 holding a deny verdict.", encode({1: 0, 2: 8, 3: body(deny)})),
        ("deny_holds_allow", "Kind 9 holding an allow verdict.", encode({1: 0, 2: 9, 3: body(allow)})),
        ("kind_6_reserved", "Kind 6 stays undefined.", encode({1: 0, 2: 6, 3: body(sm)})),
        ("kind_13", "Kind 13.", encode({1: 0, 2: 13, 3: body(sm)})),
        ("mandate_unknown_key", "Kind 7 with key 4.", encode({1: 0, 2: 7, 3: body(sm), 4: 0})),
        ("mandate_body_tstr", "Kind 7 body as text.", encode({1: 0, 2: 7, 3: "x"})),
        ("mandate_body_garbage", "Kind 7 body that is not a signed mandate.", encode({1: 0, 2: 7, 3: b"\xa0"})),
        ("bucket_body_noncanonical", "Kind 10 body with a non-minimal head.", encode({1: 0, 2: 10, 3: b"\xb8\x04" + P.decode_record(
            next(pool[p] for p in sorted(pool) if p.startswith("policy-bucket/")))["body"][1:]})),
        ("format_1", "format 1.", encode({1: 1, 2: 7, 3: body(sm)})),
        ("successor_gate_id_space", "Kind 12 gate_id with a space.", encode({**{k: v for k, v in [(1, 0), (2, 12)]},
                                                                            3: "gate 1", 4: bytes(32), 5: bytes(32), 6: bytes(32)})),
        ("successor_short_hash", "Kind 12 state_hash of 31 bytes.", encode({1: 0, 2: 12, 3: GATE_ID, 4: bytes(32),
                                                                           5: bytes(31), 6: bytes(32)})),
        ("successor_missing_commitment", "Kind 12 without key 6.", encode({1: 0, 2: 12, 3: GATE_ID, 4: bytes(32), 5: bytes(32)})),
        ("trailing", "A zero byte after a successor record.", succ + b"\x00"),
    ]
    out = []
    for i, d, b in rej:
        try:
            P.decode_record(b)
            raise AssertionError(i)
        except P.PolicyError as e:
            out.append({"id": i, "description": d, "record_cbor_hex": b.hex(), "expect_error": "archive.ErrCorrupt",
                        "cause": e.cause})
    return {"kinds": {str(k): {"name": n, "path": P.PATHS[k], "cap": str(P.REC_CAP[k])} for k, n in P.KIND_NAMES.items()},
            "reserved_kinds": ["6"], "marker_names": REASON_MARKERS, "cases": cases, "reject": out}


REASON_MARKERS = ["ErrAgentNotCovered", "ErrNoExtractor", "ErrFactsInvalid", "ErrOutsideMandate", "ErrKindNotAllowed",
                  "ErrAssetNotAllowed", "ErrRecipientNotAllowed", "ErrAmountAboveMax", "ErrDecisionAge", "ErrMinSpacing",
                  "ErrPeriodLimit", "ErrCountLimit", "ErrHistoryFull"]

API = [("403", "policy.ErrAgentNotCovered"), ("403", "policy.ErrNoExtractor"), ("403", "policy.ErrOutsideMandate"),
       ("403", "policy.ErrKindNotAllowed"), ("403", "policy.ErrAssetNotAllowed"), ("403", "policy.ErrRecipientNotAllowed"),
       ("403", "policy.ErrAmountAboveMax"), ("403", "policy.ErrMinSpacing"), ("403", "policy.ErrPeriodLimit"),
       ("403", "policy.ErrCountLimit"), ("403", "policy.ErrHistoryFull"), ("410", "policy.ErrDecisionAge"),
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
    auth = {1: 0, 2: v["commitment_hash"], 3: v["action_hash"], 4: GATE_ID, 5: T0 + 100 + 300, 6: 1}
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
        {"id": "authorize_allow", "status": "200", "description": "Allow: the SignedAuthorization (key 1) and the allow "
         "verdict (key 5) of verify.json chain A, decision a1.", "response_cbor_hex": encode({1: sa, 5: allow}).hex(),
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


def header(extra: dict) -> dict:
    return {"format": FORMAT, "revision": REVISION, "generator": "spec/vectors/check/gen_policy.py", **extra}


def build() -> dict:
    """Returns {relative path: file content (str)}."""
    mand = gen_mandate()
    ver, pool, sims = gen_verify()
    files = {
        "policy/facts.json": header({"test_extractor": {"id": P.TEST_EXTRACTOR, "action_type": P.TEST_ACTION_TYPE},
                                     **gen_facts()}),
        "policy/mandate.json": header({"tags": {n: t.decode() for n, t in P.TAG.items()}, **mand}),
        "policy/render.json": header(gen_render(mand)),
        "policy/state.json": header(gen_state()),
        "policy/engine.json": header(gen_engine()),
        "policy/verify.json": header(ver),
        "policy/archive.json": header(gen_archive(pool)),
        "policy/api.json": header(gen_api(sims)),
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
