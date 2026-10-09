#!/usr/bin/env python3
"""Generates the bank-send profile vectors that need no protobuf library. Deterministic.

Writes action.json, executor.json, timeout_height.json, price_trigger.json and
e2e.json. The MsgSend bytes are read from msg_send.json, which banksend-gen
writes with the real cosmos-sdk types, so run it first
(cd spec/vectors/tools/banksend-gen && go run .).

Usage: python3 spec/vectors/check/gen_profile_bank_send.py [--core DIR] [--out DIR]
Defaults: --core spec/vectors/v0; --out spec/vectors/profiles/bank-send.
"""

from __future__ import annotations

import sys

sys.dont_write_bytecode = True

import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import profile_bank_send as pf
from cbor_strict import Pairs, Raw, encode
from edicta_v0 import (AUTHORIZATION, AuthorizationCheck, Params, TAG_AUTHORIZATION_SIG, action_hash,
                       authorization_expires, authorization_hash, commitment_hash, signing_message, to_cbor,
                       verify_authorization, verify_for_gate)
from vecjson import authorization_to_json, commitment_to_json, gate_to_json, params_to_json

HERE = Path(__file__).resolve().parent
VECTORS = HERE.parent


def arg(name: str, default: Path) -> Path:
    if name in sys.argv:
        return Path(sys.argv[sys.argv.index(name) + 1]).resolve()
    return default


CORE = arg("--core", VECTORS / "historical" / "v0")
OUT = arg("--out", VECTORS / "profiles" / "bank-send")
FORMAT = "edicta-vectors/v0"
PROFILE = "bank-send"
PROFILE_REVISION = "bank-send-v0-draft.1"
# Files whose bytes or meaning changed in draft.2 carry it; the others keep draft.1.
PROFILE_REVISION_2 = "bank-send-v0-draft.2"
CORE_REVISION = "v0-draft.11"
T0 = 1791000000


def lab(s: str) -> bytes:
    return hashlib.sha256(s.encode()).digest()


def header(revision: str = PROFILE_REVISION) -> dict:
    return {"format": FORMAT, "profile": PROFILE, "revision": revision}


def write(name: str, obj: dict):
    path = OUT / name
    path.write_text(json.dumps(obj, indent=2, ensure_ascii=True) + "\n")
    print(f"wrote {path}")


MSGS: dict = {}
MSG_REJECTS: dict = {}


def load_msgs():
    f = json.loads((OUT / "msg_send.json").read_text())
    if f.get("revision") != PROFILE_REVISION:
        sys.exit("msg_send.json is from another profile revision; run banksend-gen first")
    for c in f["cases"]:
        MSGS[c["id"]] = c
    for c in f["reject"]:
        MSG_REJECTS[c["id"]] = bytes.fromhex(c["msg_hex"])


def msg(cid: str) -> bytes:
    return bytes.fromhex(MSGS[cid]["msg_hex"])


def domain_default() -> dict:
    return {"chain_id": "mocha-4", "hrp": "celestia", "denom": "utia",
            "sender": MSGS["msg_minimal"]["input"]["from_address"]}


# action.json

def action_vectors() -> dict:
    cases = []

    def add(cid, desc, chain_id, msg_ref=None, raw_msg=None):
        m = msg(msg_ref) if msg_ref else raw_msg
        b = pf.action_encode(chain_id, m)
        assert pf.action_decode(b) == {"chain_id": chain_id, "msg": m}
        c = {"id": cid, "description": desc}
        if msg_ref:
            c["msg_ref"] = msg_ref
        c.update({"input": {"chain_id": chain_id, "msg_hex": m.hex()}, "cbor_hex": b.hex(),
                  "action_hash_hex": action_hash(pf.ACTION_TYPE, b).hex()})
        cases.append(c)

    add("action_minimal_mocha", "msg_minimal for chain id mocha-4.", "mocha-4", "msg_minimal")
    add("action_typical_mainnet", "msg_typical for chain id celestia.", "celestia", "msg_typical")
    add("action_long_msg", "msg_denom_128 (msg longer than 23 bytes and 255 bytes: two-byte bstr head).",
        "edicta-devnet-1", "msg_denom_128")
    add("action_chain_id_50", "A 50-character chain id, the maximum.", "c" * 25 + "-" + "1" * 24, "msg_minimal")
    add("action_other_hrp", "msg_other_hrp on another Cosmos chain.", "cosmoshub-4", "msg_other_hrp")
    add("action_msg_1024_opaque", "A 1024-byte msg that is not a MsgSend: the action decodes (msg is opaque at this "
        "layer); the executor refuses it at the MsgSend check.", "mocha-4", raw_msg=bytes((7 * i + 3) & 0xFF for i in range(1024)))

    good = msg("msg_minimal")
    rej = []

    def r(cid, desc, b):
        try:
            pf.action_decode(b)
            raise AssertionError(cid)
        except pf.Reject as e:
            assert e.sentinel == "bankaction.ErrMalformed", cid
        rej.append({"id": cid, "description": desc, "cbor_hex": b.hex(), "expect_error": "bankaction.ErrMalformed"})

    r("action_empty", "Zero bytes.", b"")
    r("action_array", "A two-element array instead of a map.", encode(["mocha-4", good]))
    r("action_unknown_key", "Key 3 next to chain_id and msg.", encode({1: "mocha-4", 2: good, 3: 0}))
    r("action_missing_chain_id", "Only key 2.", encode({2: good}))
    r("action_missing_msg", "Only key 1.", encode({1: "mocha-4"}))
    r("action_chain_id_empty", "chain_id of 0 bytes.", encode({1: "", 2: good}))
    r("action_chain_id_51", "chain_id of 51 bytes.", encode({1: "c" * 51, 2: good}))
    r("action_chain_id_space", "chain_id with a space.", encode({1: "mocha 4", 2: good}))
    r("action_chain_id_slash", "chain_id with a slash.", encode({1: "mocha/4", 2: good}))
    r("action_chain_id_unicode", "chain_id with a non-ASCII letter (U+00E9).", encode({1: "moché-4", 2: good}))
    r("action_chain_id_bstr", "chain_id as a byte string.", encode({1: b"mocha-4", 2: good}))
    r("action_msg_tstr", "msg as a text string.", encode({1: "mocha-4", 2: "x"}))
    r("action_msg_empty", "msg of 0 bytes.", encode({1: "mocha-4", 2: b""}))
    r("action_msg_1025", "msg of 1025 bytes.", encode({1: "mocha-4", 2: bytes(1025)}))
    r("action_keys_unsorted", "Key 2 before key 1.", encode(Pairs(((2, good), (1, "mocha-4")))))
    r("action_duplicate_key", "Key 1 twice.", encode(Pairs(((1, "mocha-4"), (1, "mocha-4"), (2, good)))))
    r("action_nonminimal_head", "chain_id length in a one-byte argument (0x78 0x07).",
      b"\xa2\x01\x78\x07mocha-4" + encode(2) + encode(good))
    r("action_indefinite_map", "Indefinite-length map.", b"\xbf\x01" + encode("mocha-4") + b"\x02" + encode(good) + b"\xff")
    r("action_trailing_byte", "A zero byte after the map.", pf.action_encode("mocha-4", good) + b"\x00")
    r("action_tstr_key", "Text key \"chain_id\".", b"\xa2" + encode("chain_id") + encode("mocha-4") + b"\x02" + encode(good))
    r("action_null_msg", "msg is CBOR null.", b"\xa2\x01" + encode("mocha-4") + b"\x02\xf6")
    r("action_tagged_msg", "msg wrapped in tag 24 (encoded CBOR data item).",
      b"\xa2\x01" + encode("mocha-4") + b"\x02\xd8\x18" + encode(good))
    return dict(header(), action_type=pf.ACTION_TYPE, cases=cases, reject=rej)


# executor.json

def executor_vectors() -> dict:
    d = domain_default()
    to2 = MSGS["msg_typical"]["input"]["to_address"]
    other_sender = pf.bech32_encode("celestia", lab("edicta/v0 test bank other sender")[:20])
    cases = []

    def add(cid, desc, action: bytes, expect=None, domain=None, destinations=(), max_amount=0):
        dom = domain or d
        try:
            pf.executor_static_check(action, dom, list(destinations), max_amount)
            got = None
        except pf.Reject as e:
            got = e.sentinel
        assert got == expect, (cid, got, expect)
        c = {"id": cid, "description": desc, "domain": dom, "destinations": list(destinations),
             "max_amount": str(max_amount), "action_hex": action.hex()}
        if expect:
            c["expect_error"] = expect
        cases.append(c)

    A = pf.action_encode
    add("exec_ok_minimal", "action_minimal_mocha against its own domain.", A("mocha-4", msg("msg_minimal")))
    add("exec_ok_amount_at_limit", "Amount equal to max_amount is allowed.", A("mocha-4", msg("msg_typical")), max_amount=1000000)
    add("exec_risk_limit", "Amount one above max_amount.", A("mocha-4", msg("msg_typical")), "transfer.ErrRiskLimit", max_amount=999999)
    add("exec_destination_allowed", "to_address in the allowlist.", A("mocha-4", msg("msg_typical")), destinations=[to2])
    add("exec_destination_refused", "to_address not in the allowlist.", A("mocha-4", msg("msg_minimal")),
        "transfer.ErrDestination", destinations=[to2])
    add("exec_action_malformed", "Action bytes with a trailing byte.", A("mocha-4", msg("msg_minimal")) + b"\x00",
        "bankaction.ErrMalformed")
    add("exec_chain_mismatch", "Action for chain id celestia at a mocha-4 executor.", A("celestia", msg("msg_minimal")),
        "transfer.ErrChainMismatch")
    add("exec_chain_id_case", "Chain id Mocha-4: comparison is exact, no case folding.", A("Mocha-4", msg("msg_minimal")),
        "transfer.ErrChainMismatch")
    add("exec_chain_before_msg", "Wrong chain id and a malformed msg: the chain check comes first.",
        A("celestia", MSG_REJECTS["msg_duplicate_from"]), "transfer.ErrChainMismatch")
    add("exec_msg_malformed", "msg_duplicate_from inside a valid action.", A("mocha-4", MSG_REJECTS["msg_duplicate_from"]),
        "bankmsg.ErrMalformed")
    add("exec_msg_other_hrp", "msg_other_hrp (prefix cosmos) at a celestia executor.", A("mocha-4", msg("msg_other_hrp")),
        "bankmsg.ErrMalformed")
    add("exec_msg_opaque_1024", "action_msg_1024_opaque: decodes as an action, fails as a MsgSend.",
        A("mocha-4", bytes((7 * i + 3) & 0xFF for i in range(1024))), "bankmsg.ErrMalformed")
    add("exec_sender_mismatch", "from_address is not the executor's sender account.", A("mocha-4", msg("msg_minimal")),
        "transfer.ErrSenderMismatch", domain=dict(d, sender=other_sender))
    add("exec_denom_mismatch", "IBC denom at an executor whose denom is utia.", A("mocha-4", msg("msg_ibc_denom")),
        "transfer.ErrDenomMismatch")
    add("exec_sender_before_denom", "Wrong sender and wrong denom: the sender check comes first.",
        A("mocha-4", msg("msg_ibc_denom")), "transfer.ErrSenderMismatch", domain=dict(d, sender=other_sender))
    add("exec_denom_before_destination", "Wrong denom and a refused destination: the denom check comes first.",
        A("mocha-4", msg("msg_ibc_denom")), "transfer.ErrDenomMismatch", destinations=[to2])
    add("exec_destination_before_risk", "Refused destination and over the limit: the destination check comes first.",
        A("mocha-4", msg("msg_max_amount")), "transfer.ErrDestination", destinations=[to2], max_amount=1)
    return dict(header(), action_type=pf.ACTION_TYPE, cases=cases)


# timeout_height.json

def timeout_vectors() -> dict:
    s = 1_000_000_000
    intervals = []

    def iv(cid, desc, headers):
        tau = pf.block_interval_ms(headers)
        intervals.append({"id": cid, "description": desc,
                          "headers": [{"height": str(h), "time_ns": str(t)} for h, t in headers], "tau_ms": str(tau)})

    base = (T0 - 100) * s
    iv("tau_uniform", "Five headers six seconds apart.", [(100 + i, base + 6 * s * i) for i in range(5)])
    iv("tau_largest_interval", "Intervals 6.0 s, 11.2 s, 5.9 s: the largest is taken.",
       [(200, base), (201, base + 6 * s), (202, base + 17_200_000_000), (203, base + 23_100_000_000)])
    iv("tau_round_up", "An interval of 6 s plus 1 ns rounds up to 6001 ms.", [(300, base), (301, base + 6 * s + 1)])
    iv("tau_floor_one", "An interval of 1 ns gives the floor of 1 ms.", [(400, base), (401, base + 1)])

    cases = []

    def tc(cid, desc, H0=1_000_000, T=T0, tau=6000, expires=T0 + 300, skew=30, maxb=200, now=T0 + 5, expect=None):
        try:
            th = pf.timeout_height(H0, T, tau, expires, skew, maxb, now)
            got = None
        except pf.Reject as e:
            got, th = e.sentinel, None
        assert got == expect, (cid, got)
        c = {"id": cid, "description": desc, "head_height": str(H0), "head_time": str(T), "tau_ms": str(tau),
             "expires": str(expires), "skew_s": str(skew), "max_timeout_blocks": str(maxb), "now": str(now)}
        if expect:
            c["expect_error"] = expect
        else:
            c["timeout_height"] = str(th)
        cases.append(c)

    tc("th_typical", "270 s to expires - skew, budgeted at 2 x 6 s per block: 22 blocks.")
    tc("th_floor", "271 s: floor(271000 / 12000) = 22.", expires=T0 + 301)
    tc("th_capped", "2970 s would be 247 blocks; capped at max_timeout_blocks 200.", expires=T0 + 3000)
    tc("th_one_block", "Exactly 12 s left: one block.", expires=T0 + 42)
    tc("th_zero_blocks", "11 s left: no whole budgeted block fits, the send does not start.", expires=T0 + 41, now=T0 + 1,
       expect="transfer.ErrExpired")
    tc("th_head_after_end", "Head time already after expires - skew.", T=T0 + 280, expires=T0 + 300, now=T0 + 200,
       expect="transfer.ErrExpired")
    tc("th_now_at_expiry", "now + skew == expires: I6 forbids starting the send.", now=T0 + 270,
       expect="transfer.ErrExpired")
    tc("th_now_one_before_expiry", "now + skew == expires - 1, head older: still sends (70 s, 5 blocks).", now=T0 + 269,
       T=T0 + 200, expires=T0 + 300)
    tc("th_tau_rounding", "264 s: 22 blocks at tau 6000 ms, 21 at 6001 ms.", tau=6001, expires=T0 + 294)
    tc("th_max_blocks_1", "max_timeout_blocks 1.", maxb=1)
    tc("th_skew_zero", "skew_s 0: 300 s, 25 blocks.", skew=0)
    tc("th_large_height", "Head height 2^62.", H0=1 << 62)
    return dict(header(PROFILE_REVISION_2), slowdown_factor=str(pf.SLOWDOWN_FACTOR), max_timeout_blocks_limit=str(pf.MAX_TIMEOUT_BLOCKS_LIMIT), interval=intervals, cases=cases)


# price_trigger.json

def pt_base() -> dict:
    to1 = MSGS["msg_minimal"]["input"]["to_address"]
    return {
        "strategy_id": "tia-move-100bp",
        "asset": {"feed": "coingecko", "asset_id": "celestia", "quote": "USD"},
        "observations": [{"source": "coingecko", "price": 512300000, "observed_at": T0 - 10, "fetched_at": T0 - 5}],
        "baseline": {"price": 507200000, "set_at": T0 - 3600},
        "threshold_bp": 100,
        "direction": 1,
        "move_bp": 100,
        "branch": {"name": "up", "to_address": to1, "amount": 1, "denom": "utia"},
    }


def pt_to_json(p: dict) -> dict:
    def conv(v):
        if isinstance(v, dict):
            return {k: conv(x) for k, x in v.items()}
        if isinstance(v, list):
            return [conv(x) for x in v]
        return str(v) if isinstance(v, int) else v
    return conv(p)


def price_trigger_vectors() -> dict:
    cases = []

    def add(cid, desc, p):
        b = pf.pt_encode(p)
        assert pf.pt_decode(b) == p, cid
        cases.append({"id": cid, "description": desc, "input": pt_to_json(p), "cbor_hex": b.hex()})

    p = pt_base()
    add("pt_minimal", "One observation, up 100 bp, no reason.", p)
    add("pt_with_reason", "With a free-text reason containing U+00FC (UTF-8 is allowed in reason only).",
        dict(p, reason="Preis über Schwelle: +100 bp gegenüber Basis"))
    eight = [{"source": "coingecko" if i % 2 == 0 else "kraken", "price": 512300000 - i * 1000,
              "observed_at": T0 - 10 - 30 * i, "fetched_at": T0 - 5 - 30 * i} for i in range(8)]
    add("pt_eight_observations", "Eight observations, newest first, two sources.", dict(p, observations=eight))
    to2 = MSGS["msg_typical"]["input"]["to_address"]
    down = dict(p, observations=[dict(p["observations"][0], price=490000000)], direction=2, move_bp=339,
                branch={"name": "down", "to_address": to2, "amount": 1000000, "denom": "utia"})
    add("pt_down", "Down 339 bp to the down branch.", down)

    base_bytes = pf.pt_encode(p)
    rej = []

    def r(cid, desc, b):
        try:
            pf.pt_decode(b)
            raise AssertionError(cid)
        except pf.Reject as e:
            assert e.sentinel == "pricetrigger.ErrMalformed", (cid, e)
        rej.append({"id": cid, "description": desc, "cbor_hex": b.hex(), "expect_error": "pricetrigger.ErrMalformed"})

    def with_(**kw):
        return pf.pt_encode(dict(p, **kw))

    def raw_with(key, val_bytes):
        """Base body with the value of top-level key replaced by raw CBOR bytes."""
        m = pf.pt_cbor_map(p)
        m[key] = Raw(val_bytes)
        return encode(m)

    r("pt_float_threshold", "threshold_bp as a float16.", raw_with(5, b"\xf9\x56\x40"))
    r("pt_unknown_key", "Key 10.", encode(pf.pt_cbor_map(p) | {10: 0}))
    m = pf.pt_cbor_map(p)
    del m[8]
    r("pt_missing_branch", "No branch.", encode(m))
    r("pt_observations_empty", "Zero observations.", raw_with(3, b"\x80"))
    nine = [dict(eight[0], observed_at=T0 - 10 - i) for i in range(9)]
    r("pt_observations_9", "Nine observations.", with_(observations=nine))
    r("pt_observations_oldest_first", "Two observations, oldest first.", with_(observations=list(reversed(eight[:2]))))
    r("pt_observations_map", "observations as a map.", raw_with(3, encode({1: 1})))
    r("pt_price_zero", "Observation price 0.", with_(observations=[dict(p["observations"][0], price=0)]))
    r("pt_baseline_zero", "Baseline price 0.", with_(baseline={"price": 0, "set_at": T0}))
    r("pt_quote_lower", "Quote usd.", with_(asset=dict(p["asset"], quote="usd")))
    r("pt_asset_id_unicode", "asset_id with U+00E9.", with_(asset=dict(p["asset"], asset_id="célestia")))
    r("pt_threshold_0", "threshold_bp 0.", with_(threshold_bp=0))
    r("pt_threshold_10001", "threshold_bp 10001.", with_(threshold_bp=10001))
    r("pt_direction_3", "direction 3.", with_(direction=3))
    r("pt_move_2pow63", "move_bp 2^63.", with_(move_bp=1 << 63))
    r("pt_amount_zero", "branch amount 0.", with_(branch=dict(p["branch"], amount=0)))
    r("pt_to_address_upper", "branch to_address in upper case.", with_(branch=dict(p["branch"], to_address=p["branch"]["to_address"].upper())))
    r("pt_denom_digit_first", "branch denom 1tia.", with_(branch=dict(p["branch"], denom="1tia")))
    r("pt_reason_empty", "reason present and empty.", with_(reason=""))
    r("pt_reason_1025", "reason of 1025 bytes.", with_(reason="a" * 1025))
    r("pt_reason_invalid_utf8", "reason with an invalid UTF-8 byte.", raw_with(9, b"\x62\x61\xff"))
    r("pt_reason_bstr", "reason as a byte string.", raw_with(9, encode(b"why")))
    r("pt_nonminimal_uint", "threshold_bp 100 in a two-byte argument.", raw_with(5, b"\x19\x00\x64"))
    r("pt_trailing_byte", "A zero byte after the map.", base_bytes + b"\x00")
    r("pt_tagged_price", "move_bp wrapped in tag 2.", raw_with(7, b"\xc2\x41\x64"))

    cons = []

    def cc(cid, desc, ctx, msg_ref, issued_at, expect):
        m = pf.msg_decode(msg(msg_ref), "celestia")
        got = pf.pt_consistency(pf.pt_decode(pf.pt_encode(ctx)), m, issued_at)
        assert got == expect, (cid, got)
        cons.append({"id": cid, "description": desc, "context_cbor_hex": pf.pt_encode(ctx).hex(), "msg_ref": msg_ref,
                     "hrp": "celestia", "issued_at": str(issued_at), "expect_failed": expect})

    cc("ptc_consistent", "pt_minimal against msg_minimal.", p, "msg_minimal", T0, [])
    cc("ptc_down_consistent", "pt_down against msg_typical.", down, "msg_typical", T0, [])
    cc("ptc_move_wrong", "move_bp 101 although the exact value is 100.", dict(p, move_bp=101), "msg_minimal", T0, ["PT1"])
    cc("ptc_direction_wrong", "Price went up, direction says down.", dict(p, direction=2), "msg_minimal", T0, ["PT2"])
    cc("ptc_below_threshold", "threshold 101 with a move of 100.", dict(p, threshold_bp=101), "msg_minimal", T0, ["PT3"])
    cc("ptc_amount_differs", "Branch amount 2, authorized 1.", dict(p, branch=dict(p["branch"], amount=2)), "msg_minimal", T0, ["PT4"])
    cc("ptc_to_differs", "Branch names receiver 2, authorized receiver 1.", dict(p, branch=down["branch"] | {"amount": 1}),
       "msg_minimal", T0, ["PT4"])
    cc("ptc_fetched_after_issue", "Newest observation fetched after issued_at.", p, "msg_minimal", T0 - 6, ["PT5"])
    cc("ptc_several", "Wrong move, wrong direction and below threshold.", dict(p, move_bp=5, direction=2), "msg_minimal", T0,
       ["PT1", "PT2", "PT3"])
    return dict(header(), media_type=pf.MEDIA_TYPE_PRICE_TRIGGER, cases=cases, reject=rej, consistency=cons)


# e2e.json: commitment -> Authorization -> executor checks -> TxBody

def e2e_vectors() -> dict:
    keys = json.loads((CORE / "keys.json").read_text())["keys"]

    def sk(name):
        return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(keys[name]["seed_hex"]))

    gate = {"gate_id": "edictad-mocha-1", "action_types": [pf.ACTION_TYPE]}
    params = Params()
    action = pf.action_encode("mocha-4", msg("msg_minimal"))
    context = pf.pt_encode(pt_base())
    T_H = T0 + 30
    c = {
        "version": 0, "agent_id": "tia-transfer-agent", "agent_pubkey": bytes.fromhex(keys["agent1"]["public_key_hex"]),
        "nonce": lab("edicta/v0 test bank e2e nonce")[:16], "issued_at": T_H + 10, "valid_until": T_H + 10 + 900,
        "scope": {"gate_id": gate["gate_id"]},
        "action": {"type": pf.ACTION_TYPE, "hash": action_hash(pf.ACTION_TYPE, action)},
        "payload_ref": {"da": 2, "namespace": bytes(19) + b"edicta/d07", "commitment": lab("edicta/v0 test bank e2e share commitment"),
                        "height": 6543200, "signer": lab("edicta/v0 test recorder account")[:20]},
        "ciphertext_hash": lab("edicta/v0 test bank e2e blob"), "plaintext_hash": lab("edicta/v0 test bank e2e plaintext"),
        "payload_size": 1000,
    }
    canon = encode(to_cbor(c))
    ch = commitment_hash(canon)
    sig = sk("agent1").sign(signing_message(ch))
    env = encode({1: Raw(canon), 2: sig})
    now_gate = T0 + 60
    verify_for_gate(env, now_gate, gate, params)

    a = {"version": 0, "commitment_hash": ch, "action_hash": c["action"]["hash"], "gate_id": gate["gate_id"],
         "expires": authorization_expires(c["valid_until"], now_gate, 300), "path": 1}
    acanon = encode(to_cbor(a, AUTHORIZATION))
    asig = sk("gate1").sign(signing_message(authorization_hash(acanon), TAG_AUTHORIZATION_SIG))
    signed_auth = encode({1: Raw(acanon), 2: asig})
    now_exec = T0 + 65
    chk = AuthorizationCheck(bytes.fromhex(keys["gate1"]["public_key_hex"]), gate["gate_id"], pf.ACTION_TYPE, action, now_exec, 30)
    verify_authorization(signed_auth, chk)

    d = domain_default()
    pf.executor_static_check(action, d, [], 0)
    headers = [(6543250 + i, (T0 + 4 + 6 * i) * 1_000_000_000) for i in range(11)]
    tau = pf.block_interval_ms(headers)
    H0, Th = headers[-1][0], headers[-1][1] // 1_000_000_000
    th = pf.timeout_height(H0, Th, tau, a["expires"], 30, 200, now_exec)
    body = pf.body(msg("msg_minimal"), ch, th)
    assert pf.check_body(body, msg("msg_minimal"), ch) == th
    pt = pf.pt_decode(context)
    assert pf.pt_consistency(pt, pf.msg_decode(msg("msg_minimal"), "celestia"), c["issued_at"]) == []

    case = {
        "id": "e2e_minimal_mocha",
        "description": "agent1 commits to action_minimal_mocha; gate1 authorizes; the executor checks and builds the TxBody.",
        "gate": gate_to_json(gate), "params": params_to_json(params), "now_gate": str(now_gate),
        "commitment": {"input": commitment_to_json(c), "commitment_cbor_hex": canon.hex(), "commitment_hash_hex": ch.hex(),
                       "signer": "agent1", "envelope_hex": env.hex(),
                       "placeholders": {"payload_ref.commitment": "SHA-256 of a label, not a real share commitment",
                                        "ciphertext_hash": "SHA-256 of a label", "plaintext_hash": "SHA-256 of a label"}},
        "action_hex": action.hex(),
        "context": {"media_type": pf.MEDIA_TYPE_PRICE_TRIGGER, "cbor_hex": context.hex(), "expect_failed": []},
        "authorization": {"signer": "gate1", "authorized_at": str(now_gate), "max_authorization_ttl_s": "300",
                          "input": authorization_to_json(a), "signed_authorization_hex": signed_auth.hex()},
        "executor": {"now": str(now_exec), "skew_s": "30", "domain": d, "max_timeout_blocks": "200",
                     "headers": [{"height": str(h), "time_ns": str(t)} for h, t in headers], "tau_ms": str(tau),
                     "head_height": str(H0), "head_time": str(Th), "timeout_height": str(th),
                     "memo": ch.hex(), "body_hex": body.hex()},
    }
    return dict(header(PROFILE_REVISION_2), core_revision=CORE_REVISION, cases=[case])


def main():
    load_msgs()
    OUT.mkdir(parents=True, exist_ok=True)
    write("action.json", action_vectors())
    write("executor.json", executor_vectors())
    write("timeout_height.json", timeout_vectors())
    write("price_trigger.json", price_trigger_vectors())
    write("e2e.json", e2e_vectors())


if __name__ == "__main__":
    main()
