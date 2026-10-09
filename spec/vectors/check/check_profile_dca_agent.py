#!/usr/bin/env python3
"""Verifies the dca-agent profile vectors (spec/vectors/profiles/dca-agent).

Checks the IBKR order format, the executor's static checks, the DCA context
media type and its consistency checks, and the client order ids. Cross-checks
against the core draft.9 set: the core IBKR actions are valid profile orders,
the authorized bytes pass the executor, and every DCA payload in
payload_blob.json is consistent with its action.

Usage: python3 spec/vectors/check/check_profile_dca_agent.py [--core DIR] [--dir DIR]
Defaults: --core spec/vectors/v1;
--dir spec/vectors/profiles/dca-agent.
"""

from __future__ import annotations

import sys

sys.dont_write_bytecode = True

import json
from pathlib import Path

import edicta as core
import profile_dca_agent as pf
from edicta import AuthorizationCheck, Reject, action_hash
from vecjson import action_from_case

HERE = Path(__file__).resolve().parent
VECTORS = HERE.parent


def arg(name: str, default: Path) -> Path:
    if name in sys.argv:
        return Path(sys.argv[sys.argv.index(name) + 1]).resolve()
    return default


CORE = arg("--core", VECTORS / "v1")
DIR = arg("--dir", VECTORS / "profiles" / "dca-agent")
FORMAT = "edicta-vectors/v0"
PROFILE_REVISION = "dca-agent-v0-draft.1"
REVISIONS = {"ibkr_order.json": "dca-agent-v0-draft.4", "client_order_id.json": "dca-agent-v0-draft.4"}


class Failure(Exception):
    pass


def expect(cond: bool, msg: str):
    if not cond:
        raise Failure(msg)


def outcome(fn, *args):
    try:
        fn(*args)
    except Reject as e:
        return e.sentinel
    return None


def load(d: Path, name: str) -> dict:
    obj = json.loads((d / name).read_text())
    expect(obj.get("format") == FORMAT, f"{name}: format")
    return obj


def order_from_json(j: dict) -> dict:
    return {k: (v if k in ("account", "symbol", "currency") else int(v)) for k, v in j.items()}


def dca_from_json(j: dict) -> dict:
    out = {}
    for name, val in j.items():
        if name == "last_fills":
            out[name] = [{k: int(v) for k, v in f.items()} for f in val]
        elif name == "strategy_id":
            out[name] = val
        else:
            out[name] = {k: (v if k in ("currency", "source") else int(v)) for k, v in val.items()}
    return out


def check_orders(f: dict, core_valid: dict, core_auth: dict) -> int:
    expect(f["action_type"] == pf.ACTION_TYPE_IBKR_ORDER_V0 and core.action_type_ok(f["action_type"]), "action type")
    for c in f["cases"]:
        cid = c["id"]
        o = order_from_json(c["input"])
        b = bytes.fromhex(c["cbor_hex"])
        expect(pf.order_encode(o) == b, f"{cid}: encoding")
        expect(pf.order_decode(b) == o, f"{cid}: decode round trip")
        pf.order_validate(o)
        expect(action_hash(f["action_type"], bytes.fromhex(c["action_salt_hex"]), b).hex() == c["action_hash_hex"],
               f"{cid}: action hash")
        expect(pf.decimal(o["qty"], 4) == c["qty_decimal"], f"{cid}: qty decimal")
        if "limit_price" in o:
            expect(pf.decimal(o["limit_price"], 8) == c["limit_price_decimal"], f"{cid}: limit_price decimal")
        if "core_commitment_ref" in c:
            ref = next(v for v in core_valid["cases"] if v["id"] == c["core_commitment_ref"])
            expect(ref["action_hex"] == c["cbor_hex"] and ref["input"]["action"]["hash"] == c["action_hash_hex"]
                   and ref["action_salt_hex"] == c["action_salt_hex"],
                   f"{cid}: not the action of core {c['core_commitment_ref']}")
    for r in f["malformed"]:
        expect(outcome(pf.order_decode, bytes.fromhex(r["cbor_hex"])) == r["expect_error"] == "ibkrorder.ErrMalformed", r["id"])
    for r in f["invalid"]:
        o = pf.order_decode(bytes.fromhex(r["cbor_hex"]))
        expect(outcome(pf.order_validate, o) == r["expect_error"] == "ibkrorder.ErrInvalid", r["id"])
    auth_by_id = {c["id"]: c for c in core_auth["cases"]}
    for x in f["executor"]:
        b = bytes.fromhex(x["cbor_hex"])
        cfg = x["config"]
        if "authorization_ref" in x:
            a = auth_by_id[x["authorization_ref"]]
            blk = a["check"]
            expect(bytes.fromhex(blk["action_hex"]) == b and blk["action_type"] == pf.ACTION_TYPE_IBKR_ORDER_V0,
                   f"{x['id']}: not the authorized bytes")
            core.verify_authorization(bytes.fromhex(a["signed_authorization_hex"]), AuthorizationCheck(
                bytes.fromhex(blk["gate_pubkey_hex"]), blk["gate_id"], blk["action_type"], b, int(blk["now"]),
                int(blk["skew_s"]), bytes.fromhex(blk["action_salt_hex"])))
        got = outcome(pf.executor_static_check, b, cfg["account"], int(cfg["max_notional"]))
        expect(got == x.get("expect_error"), f"{x['id']}: got {got}, want {x.get('expect_error')}")
    # Every IBKR action in the core set is a valid order of this profile.
    n = 0
    for v in core_valid["cases"]:
        if v["action_type"] == pf.ACTION_TYPE_IBKR_ORDER_V0:
            pf.order_validate(pf.order_decode(action_from_case(v)))
            n += 1
    expect(n > 0, "no IBKR actions in the core set")
    return n


def check_dca(f: dict, core_blob: dict) -> int:
    expect(f["media_type"] == pf.MEDIA_TYPE_DCA_V0, "media type")
    for c in f["cases"]:
        b = bytes.fromhex(c["cbor_hex"])
        d = pf.dca_decode(b)
        expect(pf.dca_encode(d) == b, f"{c['id']}: round trip")
        expect(d == dca_from_json(c["input"]), f"{c['id']}: input")
    for r in f["reject"]:
        expect(outcome(pf.dca_decode, bytes.fromhex(r["cbor_hex"])) == r["expect_error"] == "dca.ErrMalformed", r["id"])
    for c in f["consistency"]:
        d = pf.dca_decode(bytes.fromhex(c["dca_cbor_hex"]))
        o = pf.order_decode(bytes.fromhex(c["order_cbor_hex"]))
        expect(pf.dca_consistency(d, o) == c["expect_failed"], f"{c['id']}: consistency")
    expect({x for c in f["consistency"] for x in c["expect_failed"]} == set(pf.DCA_CHECKS), "every DCA check has a failing vector")
    # Replay of the core payloads that carry a DCA context: the context explains the authorized order.
    n = 0
    for c in core_blob["cases"]:
        p = c["payload"]
        if p["context"]["media_type"] != pf.MEDIA_TYPE_DCA_V0:
            continue
        expect(p["action"]["type"] == pf.ACTION_TYPE_IBKR_ORDER_V0, f"{c['id']}: DCA context with a non-IBKR action")
        d = pf.dca_decode(bytes.fromhex(p["context"]["data"]))
        o = pf.order_decode(bytes.fromhex(p["action"]["data"]))
        pf.order_validate(o)
        expect(not pf.dca_consistency(d, o), f"{c['id']}: DCA consistency")
        n += 1
    expect(n > 0, "no DCA payloads in the core set")
    return n


def check_coid(f: dict, core_valid: dict):
    hashes = {c["id"]: c["commitment_hash_hex"] for c in core_valid["cases"]}
    expect(f["core_revision"] == core_valid["revision"], "client_order_id.json was generated from another core revision")
    expect(len(f["cases"]) == len(core_valid["cases"]), "one client order id per core valid commitment")
    for c in f["cases"]:
        expect(c["commitment_hash_hex"] == hashes[c["commitment_ref"]], f"{c['id']}: hash")
        got = pf.client_order_id(bytes.fromhex(c["commitment_hash_hex"]))
        expect(got == c["client_order_id"] and len(got) == 64 and set(got) <= set("0123456789abcdef"), f"{c['id']}: id")


def main() -> int:
    try:
        core_valid = json.loads((CORE / "valid.json").read_text())
        expect(core_valid.get("revision") == "v1.0", f"{CORE} is not a v1.0 set")
        core_auth = json.loads((CORE / "authorization.json").read_text())
        core_blob = json.loads((CORE / "payload_blob.json").read_text())
        orders = load(DIR, "ibkr_order.json")
        dca = load(DIR, "dca_context.json")
        coid = load(DIR, "client_order_id.json")
        for name, f in (("ibkr_order.json", orders), ("dca_context.json", dca), ("client_order_id.json", coid)):
            expect(f["profile"] == "dca-agent" and f["revision"] == REVISIONS.get(name, PROFILE_REVISION),
                   f"{name}: profile header")
        n_core = check_orders(orders, core_valid, core_auth)
        n_dca = check_dca(dca, core_blob)
        check_coid(coid, core_valid)
        ids = [c["id"] for c in orders["cases"] + orders["malformed"] + orders["invalid"] + orders["executor"]
               + dca["cases"] + dca["reject"] + dca["consistency"] + coid["cases"]]
        expect(len(ids) == len(set(ids)), "duplicate ids")
    except (Failure, Reject) as e:
        print(f"FAIL (profile dca-agent): {e}", file=sys.stderr)
        return 1
    print(f"OK (profile dca-agent): {len(orders['cases'])} order, {len(orders['malformed'])} malformed, "
          f"{len(orders['invalid'])} invalid, {len(orders['executor'])} executor, {len(dca['cases'])} dca, "
          f"{len(dca['reject'])} dca reject, {len(dca['consistency'])} dca consistency, "
          f"{len(coid['cases'])} client order id; {n_core} core IBKR actions decode, {n_dca} core DCA payloads consistent")
    return 0


if __name__ == "__main__":
    sys.exit(main())
