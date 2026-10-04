#!/usr/bin/env python3
"""Generates the dca-agent profile vectors. Deterministic: rerunning yields identical files.

Writes ibkr_order.json, dca_context.json and client_order_id.json. Core
commitment hashes are read from the core vector set, so run gen_vectors.py
first.

Usage: python3 spec/vectors/check/gen_profile_dca_agent.py [--core DIR] [--out DIR]
Defaults: --core spec/vectors/v0-next if present, else spec/vectors/v0 (it
must be a draft.9 set); --out spec/vectors/profiles/dca-agent.
"""

from __future__ import annotations

import sys

sys.dont_write_bytecode = True

import json
import struct
from pathlib import Path

from cbor_strict import Pairs, Raw, encode
from edicta_v0 import Reject, action_hash, to_cbor
from gen_payload_blob import DCA_MINIMAL, DCA_WITH_FILLS, T0, w
import profile_dca_agent as pf

HERE = Path(__file__).resolve().parent
VECTORS = HERE.parent


def arg(name: str, default: Path) -> Path:
    if name in sys.argv:
        return Path(sys.argv[sys.argv.index(name) + 1]).resolve()
    return default


CORE = arg("--core", VECTORS / "v0-next" if (VECTORS / "v0-next").is_dir() else VECTORS / "v0")
OUT = arg("--out", VECTORS / "profiles" / "dca-agent")
FORMAT = "edicta-vectors/v0"
PROFILE = "dca-agent"
PROFILE_REVISION = "dca-agent-v0-draft.1"
ACCOUNT = "DU1234567"

ORDER_MINIMAL = {"account": ACCOUNT, "conid": 265598, "side": 1, "qty": 100000, "order_type": 1,
                 "limit_price": 19050000000, "currency": "USD", "tif": 1}


def order_to_json(o: dict) -> dict:
    return {k: (str(v) if isinstance(v, int) else v) for k, v in o.items()}


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


def outcome(fn, *args):
    try:
        fn(*args)
    except Reject as e:
        return e.sentinel
    return None


def header() -> dict:
    return {"format": FORMAT, "profile": PROFILE, "revision": PROFILE_REVISION}


def ibkr_order_vectors(core_valid: dict, core_auth: dict) -> dict:
    cases = []

    def add(cid, desc, o, ref=None):
        b = pf.order_encode(o)
        assert pf.order_decode(b) == o
        pf.order_validate(o)
        case = {"id": cid, "description": desc, "input": order_to_json(o), "cbor_hex": b.hex(),
                "action_hash_hex": action_hash(pf.ACTION_TYPE_IBKR_ORDER_V0, b).hex(),
                "qty_decimal": pf.decimal(o["qty"], 4)}
        if "limit_price" in o:
            case["limit_price_decimal"] = pf.decimal(o["limit_price"], 8)
        if ref is not None:
            core = next(c for c in core_valid["cases"] if c["id"] == ref)
            assert core["action_hex"] == b.hex() and core["action_type"] == pf.ACTION_TYPE_IBKR_ORDER_V0
            case["core_commitment_ref"] = ref
        cases.append(case)

    add("order_minimal_lmt", "The action bytes of core vector minimal_lmt: BUY 10 shares at 190.50 USD, DAY.", ORDER_MINIMAL, "minimal_lmt")
    add("order_with_symbol", "Optional symbol present (informational; never used to route the order).",
        dict(ORDER_MINIMAL, conid=756733, symbol="SPY", qty=20000, limit_price=57250000000))
    add("order_sell_ioc", "SELL 1 share at 571.00, IOC.", dict(ORDER_MINIMAL, conid=756733, side=2, qty=10000, limit_price=57100000000, tif=3))
    add("order_gtc", "GTC limit order.", dict(ORDER_MINIMAL, tif=2))
    add("order_fractional", "qty 1 = 0.0001 share, limit_price 1 = 0.00000001: smallest units.", dict(ORDER_MINIMAL, qty=1, limit_price=1))
    add("order_max_ints", "conid, qty and limit_price at 2^63-1 (9-byte heads).",
        dict(ORDER_MINIMAL, conid=(1 << 63) - 1, qty=(1 << 63) - 1, limit_price=(1 << 63) - 1))

    base = to_cbor(ORDER_MINIMAL, pf.ORDER)
    good = pf.order_encode(ORDER_MINIMAL)
    malformed = []

    def bad(cid, desc, b):
        got = outcome(pf.order_decode, b)
        assert got == "ibkrorder.ErrMalformed", (cid, got)
        malformed.append({"id": cid, "description": desc, "cbor_hex": b.hex(), "expect_error": got})

    bad("order_unknown_key", "Extra key 10.", encode(w(base, 10, 0)))
    bad("order_missing_account", "Key 1 (account, the domain field) absent.", encode({k: v for k, v in base.items() if k != 1}))
    bad("order_missing_conid", "Key 2 (conid) absent.", encode({k: v for k, v in base.items() if k != 2}))
    bad("order_unsorted_keys", "Keys 1 and 2 swapped.", encode(Pairs(tuple([(2, base[2]), (1, base[1])] + [(k, base[k]) for k in sorted(base) if k > 2]))))
    bad("order_dup_key", "Key 9 twice.", encode(Pairs(tuple(sorted(base.items())) + ((9, 1),))))
    bad("order_float_qty", "qty as float64 10.0.", encode(w(base, 5, Raw(b"\xfb" + struct.pack(">d", 10.0)))))
    bad("order_nint_qty", "qty as the negative integer -100000.", encode(w(base, 5, -100000)))
    bad("order_tag_bignum_qty", "qty as tag 2 bignum h'0186a0'.", encode(w(base, 5, Raw(b"\xc2\x43\x01\x86\xa0"))))
    bad("order_null_symbol", "Optional symbol encoded as null instead of being absent.", encode(w(base, 3, Raw(b"\xf6"))))
    bad("order_nonminimal_conid", "conid in a 9-byte head; a lenient decoder reads the same order.",
        encode(w(base, 2, Raw(b"\x1b" + (265598).to_bytes(8, "big")))))
    bad("order_indefinite_map", "Order map with indefinite length.", b"\xbf" + good[1:] + b"\xff")
    bad("order_trailing_byte", "One zero byte after the order map.", good + b"\x00")
    bad("order_array", "The order as an array.", encode([ACCOUNT, 265598]))
    bad("order_deep_nesting", "symbol replaced by nested maps reaching depth 5.", encode(w(base, 3, {1: {1: {1: {1: 0}}}})))
    bad("order_account_empty", "account is the empty string.", encode(w(base, 1, "")))
    bad("order_account_33_chars", "account of 33 characters.", encode(w(base, 1, "D" * 33)))
    bad("order_account_unicode", "account contains U+03BF (Greek small omicron).", encode(w(base, 1, "DU12345ο7")))
    bad("order_currency_4_chars", "currency \"USDT\".", encode(w(base, 8, "USDT")))
    bad("order_currency_lowercase", "currency \"usd\".", encode(w(base, 8, "usd")))
    bad("order_symbol_control_char", "symbol \"AAPL\\n\".", encode(w(base, 3, "AAPL\n")))
    bad("order_account_bstr", "account as a byte string.", encode(w(base, 1, ACCOUNT.encode())))

    invalid = []

    def inv(cid, desc, o):
        b = pf.order_encode(o)
        pf.order_decode(b)
        got = outcome(pf.order_validate, o)
        assert got == "ibkrorder.ErrInvalid", (cid, got)
        invalid.append({"id": cid, "description": desc, "cbor_hex": b.hex(), "expect_error": got})

    inv("order_side_0", "side 0.", dict(ORDER_MINIMAL, side=0))
    inv("order_side_256", "side 256 (decodes at uint64 width, fails validation).", dict(ORDER_MINIMAL, side=256))
    inv("order_tif_9", "tif 9.", dict(ORDER_MINIMAL, tif=9))
    inv("order_type_3", "order_type 3.", dict(ORDER_MINIMAL, order_type=3))
    o = dict(ORDER_MINIMAL, order_type=2)
    o.pop("limit_price")
    inv("order_mkt", "order_type MKT (2) without limit_price: market orders are refused by the profile.", o)
    inv("order_qty_0", "qty 0.", dict(ORDER_MINIMAL, qty=0))
    inv("order_conid_0", "conid 0.", dict(ORDER_MINIMAL, conid=0))
    inv("order_limit_price_0", "limit_price 0.", dict(ORDER_MINIMAL, limit_price=0))
    o = dict(ORDER_MINIMAL)
    o.pop("limit_price")
    inv("order_lmt_no_price", "LMT order without limit_price.", o)
    inv("order_qty_2pow63", "qty = 2^63.", dict(ORDER_MINIMAL, qty=1 << 63))

    executor = []

    def ex(cid, desc, b: bytes, max_notional: int, account: str = ACCOUNT, auth_ref: str | None = None):
        got = outcome(pf.executor_static_check, b, account, max_notional)
        case = {"id": cid, "description": desc, "config": {"account": account, "max_notional": str(max_notional)},
                "cbor_hex": b.hex()}
        if auth_ref is not None:
            case["authorization_ref"] = auth_ref
        if got is not None:
            case["expect_error"] = got
        executor.append(case)
        return got

    notional = 100000 * 19050000000 // 10000
    assert ex("exec_minimal_from_authorization", "The bytes authorized by core vector auth_minimal_lmt_da, for the account they name.",
              good, 200000000000, auth_ref="auth_minimal_lmt_da") is None
    assert next(c for c in core_auth["cases"] if c["id"] == "auth_minimal_lmt_da")["check"]["action_hex"] == good.hex()
    assert ex("exec_notional_exact_equal", "qty * limit_price == max_notional * 10^4: accepted.", good, notional) is None
    assert ex("exec_notional_over", "qty * limit_price == max_notional * 10^4 + 10^4.", good, notional - 1) == "ibkr.ErrRiskLimit"
    wrap = pf.order_encode(dict(ORDER_MINIMAL, qty=1 << 32, limit_price=1 << 32))
    assert ex("exec_notional_uint64_wrap", "qty = limit_price = 2^32: the product 2^64 wraps to 0 in uint64 arithmetic and MUST still be refused.",
              wrap, 1) == "ibkr.ErrRiskLimit"
    assert ex("exec_risk_limit_disabled", "max_notional 0 disables the limit.", wrap, 0) is None
    assert ex("exec_account_mismatch", "The order names DU1234567; this executor serves DU7654321.", good, 0, account="DU7654321") == "ibkr.ErrAccountMismatch"
    assert ex("exec_account_before_risk", "Both the account and the risk limit fail; the account check comes first.",
              good, 1, account="DU7654321") == "ibkr.ErrAccountMismatch"
    assert ex("exec_invalid_before_account", "A MKT order for another account: validation comes before the account check.",
              bytes.fromhex(next(c for c in invalid if c["id"] == "order_mkt")["cbor_hex"]), 0, account="DU7654321") == "ibkrorder.ErrInvalid"
    assert ex("exec_malformed", "Bytes that are not a canonical order.", good + b"\x00", 0) == "ibkrorder.ErrMalformed"

    return dict(header(), action_type=pf.ACTION_TYPE_IBKR_ORDER_V0, cases=cases, malformed=malformed,
                invalid=invalid, executor=executor)


def dca_vectors() -> dict:
    """The DCA body vectors, moved unchanged from the draft.8 core payload_blob.json "dca" section."""
    cases = []
    for cid, d, desc in [("dca_minimal", DCA_MINIMAL, "No last_fills."),
                         ("dca_with_fills", DCA_WITH_FILLS, "Two fills from the previous periods.")]:
        b = pf.dca_encode(d)
        assert pf.dca_decode(b) == d
        cases.append({"id": cid, "description": desc, "input": dca_to_json(d), "cbor_hex": b.hex(),
                      "action_ref": "pb_one_recipient_dca"})
    base = pf.dca_to_cbor(DCA_MINIMAL)
    rejects = []

    def r(cid, desc, b):
        assert outcome(pf.dca_decode, b) == "dca.ErrMalformed", cid
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

    buy = {"account": ACCOUNT, "conid": 756733, "symbol": "SPY", "side": 1, "qty": 20000, "order_type": 1,
           "limit_price": 57250000000, "currency": "USD", "tif": 1}
    consistency = []

    def cons(cid, desc, d, o, failed):
        got = pf.dca_consistency(d, o)
        assert got == failed, (cid, got)
        consistency.append({"id": cid, "description": desc, "dca_cbor_hex": pf.dca_encode(d).hex(),
                            "order_cbor_hex": pf.order_encode(o).hex(), "expect_failed": failed})

    cons("dca_consistent", "dca_minimal and the order of pb_one_recipient_dca: every check holds.", DCA_MINIMAL, buy, [])
    cons("dca1_qty_differs", "The order buys 3 shares; the context says 2.", DCA_MINIMAL, dict(buy, qty=30000), ["DCA1"])
    cons("dca2_conid_differs", "The order is for conid 265598; the snapshot is for 756733.", DCA_MINIMAL, dict(buy, conid=265598), ["DCA2"])
    cons("dca3_currency_differs", "The order is in EUR; the budget in USD.", DCA_MINIMAL, dict(buy, currency="EUR"), ["DCA3"])
    over = w(DCA_MINIMAL, "budget", {"currency": "USD", "per_period": 120000000000, "spent": 120000000001})
    cons("dca4_spent_over_budget", "spent > per_period; DCA5 is not evaluated then.", over, buy, ["DCA4"])
    tight = w(DCA_MINIMAL, "budget", {"currency": "USD", "per_period": 120000000000, "spent": 120000000000 - 114500000000 + 1})
    cons("dca5_notional_over_remaining", "order notional 1145.00 exceeds the remaining budget by 10^-8.", tight, buy, ["DCA5"])
    exact = w(DCA_MINIMAL, "budget", {"currency": "USD", "per_period": 120000000000, "spent": 120000000000 - 114500000000})
    cons("dca5_notional_equal_remaining", "order notional equals the remaining budget exactly.", exact, buy, [])
    return dict(header(), media_type=pf.MEDIA_TYPE_DCA_V0, cases=cases, reject=rejects, consistency=consistency)


def client_order_id_vectors(core_valid: dict) -> dict:
    cases = []
    for v in core_valid["cases"]:
        hh = bytes.fromhex(v["commitment_hash_hex"])
        cases.append({"id": f"coid_{v['id']}", "commitment_ref": v["id"], "commitment_hash_hex": v["commitment_hash_hex"],
                      "client_order_id": pf.client_order_id(hh)})
    return dict(header(), core_revision=core_valid["revision"], cases=cases)


def write(name: str, obj: dict):
    path = OUT / name
    path.write_text(json.dumps(obj, indent=2, ensure_ascii=True) + "\n")
    print(f"wrote {path}")


def main():
    valid = json.loads((CORE / "valid.json").read_text())
    if valid.get("revision") != "v0-draft.9":
        sys.exit(f"{CORE} is not a v0-draft.9 vector set")
    auth = json.loads((CORE / "authorization.json").read_text())
    OUT.mkdir(parents=True, exist_ok=True)
    write("ibkr_order.json", ibkr_order_vectors(valid, auth))
    write("dca_context.json", dca_vectors())
    write("client_order_id.json", client_order_id_vectors(valid))


if __name__ == "__main__":
    main()
