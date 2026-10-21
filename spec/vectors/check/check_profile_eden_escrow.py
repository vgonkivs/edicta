#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Verifies the eden-escrow profile vectors (spec/vectors/profiles/eden-escrow) without go-ethereum.

Re-derives every expectation the Go generator wrote: the strict decoders (deposit calldata, action
CBOR, form T transaction, domain table) and the rule each reject fails first; the EIP-1559 signing
hash, facts, salted action hash; the signer's splice rule, RFC 6979 signatures (pure Python), payer recovery and
rail_ref; EE1 and EE3; the rebuild of served transactions (EE2); the receipt encoding and bloom;
EE7 and EE8; the header hash of the recorded block. The transactions root (a Merkle-Patricia trie)
is checked by the generator only.

Usage: python3 spec/vectors/check/check_profile_eden_escrow.py [--dir DIR]
"""

from __future__ import annotations

import sys

sys.dont_write_bytecode = True

import json
from pathlib import Path

import principal_crypto as pc
import profile_eden_escrow as ee
from edicta import action_hash
from policy_v1 import encode_facts

HERE = Path(__file__).resolve().parent
DEFAULT = HERE.parent / "profiles" / "eden-escrow"
REVISION = "eden-escrow-v1-draft.4"

fails: list[str] = []


def expect(cond: bool, what: str):
    if not cond:
        fails.append(what)


def refused(fn, *args):
    try:
        fn(*args)
    except ee.Refused as e:
        return e
    return None


def header(d: dict, name: str):
    expect(d.get("format") == "edicta-vectors/v0" and d.get("profile") == "eden-escrow"
           and d.get("revision") == REVISION, f"{name}: header")


def check_calls(d: dict):
    header(d, "deposit_call")
    expect(d["selector_hex"] == ee.SELECTOR_DEPOSIT.hex() == "b707d860", "selector")
    for c in d["cases"]:
        got = ee.decode_deposit_call(bytes.fromhex(c["data_hex"]))
        f = c["fields"]
        expect(got["payment_id"].hex() == f["payment_id_hex"] and "0x" + got["pay_to"].hex() == f["pay_to"]
               and "0x" + got["facilitator"].hex() == f["facilitator"]
               and str(got["expires_at"]) == f["expires_at"] and str(got["refund_after"]) == f["refund_after"]
               and got["tia_price_usd"].hex() == f["tia_price_usd_hex"], f"call {c['id']}")
    for r in d["reject"]:
        e = refused(ee.decode_deposit_call, bytes.fromhex(r["data_hex"]))
        expect(e is not None and e.sentinel == r["expect_error"] and e.rule == r["rule"],
               f"call reject {r['id']}: got {e and (e.sentinel, e.rule)}")
    return {c["id"]: c for c in d["cases"]}


def check_actions(d: dict, calls: dict):
    header(d, "action")
    ids = {x["build"]: x["id"] for x in d["extractors"]}
    expect(d["action_type"] == ee.ACTION_TYPE and ids == {"production": ee.EXTRACTOR_ID, "edictadev": ee.EXTRACTOR_DEV_ID},
           "action type, extractor IDs")
    expect(d["requirements_tag"].encode() == ee.REQUIREMENTS_TAG, "requirements tag")
    for x in d["extractors"]:
        rows = {}
        for r in x["rows"]:
            rows[int(r["chain_id"])] = bytes.fromhex(r["escrow"][2:])
            expect(r["code_hash"] == ee.CODE_HASH.hex(), f"row {r['chain_id']}: code hash")
        expect(rows == ee.ROWS[x["build"]], f"{x['id']}: rows")
    out = {}
    for c in d["cases"]:
        cid, inp = c["id"], c["input"]
        b = bytes.fromhex(c["cbor_hex"])
        a = ee.decode_action(b, c["build"])
        if c["build"] == "edictadev":
            e = refused(ee.decode_action, b, "production")
            expect(e is not None and e.rule == "ED1", f"{cid}: production build must refuse the dev row")
            expect(c["extractor_ids"] == [ee.EXTRACTOR_DEV_ID], f"{cid}: extractor ids")
        else:
            expect(c["extractor_ids"] == [ee.EXTRACTOR_ID, ee.EXTRACTOR_DEV_ID], f"{cid}: extractor ids")
        req = bytes.fromhex(inp["requirements_hex"])
        expect(a["tx"].hex() == c["tx_hex"], f"{cid}: tx")
        expect(ee.requirements_hash(req).hex() == c["requirements_hash_hex"] == a["requirements_hash"].hex(),
               f"{cid}: requirements_hash")
        expect(a["resource"] == inp["resource"], f"{cid}: resource")
        for k_json, k in (("chain_id", "chain_id"), ("nonce", "nonce"), ("max_priority_fee_per_gas", "tip"),
                          ("max_fee_per_gas", "fee"), ("gas_limit", "gas"), ("value", "value")):
            expect(str(a[k]) == inp[k_json], f"{cid}: {k_json}")
        expect("0x" + a["to"].hex() == inp["to"], f"{cid}: to")
        expect(a["data"].hex() == calls[inp["data_ref"]]["data_hex"], f"{cid}: data")
        expect(ee.sighash(a["tx"]).hex() == c["sighash_hex"], f"{cid}: sighash")
        salt = bytes.fromhex(c["action_salt_hex"])
        expect(action_hash(ee.ACTION_TYPE, salt, b).hex() == c["action_hash_hex"], f"{cid}: action_hash")
        f = ee.facts(a)
        fj = c["facts"]
        expect(f["kind"] == fj["kind"] and f["asset"] == fj["asset"] and f["amount"].hex() == fj["amount"]
               and str(f["scale"]) == fj["scale"] and f["recipient"] == fj["recipient"], f"{cid}: facts")
        expect(encode_facts(f).hex() == c["facts_cbor_hex"], f"{cid}: facts_cbor")
        out[cid] = a
    for r in d["reject"]:
        e = refused(ee.decode_action, bytes.fromhex(r["cbor_hex"]), r["build"])
        expect(e is not None and e.sentinel == r["expect_error"] and e.rule == r["rule"],
               f"action reject {r['id']}: got {e and (e.sentinel, e.rule, str(e))}")
        expect(r["extractor_expect_error"] == "ErrFactsInvalid", f"action reject {r['id']}: extractor")
        want_id = ee.EXTRACTOR_DEV_ID if r["build"] == "edictadev" else ee.EXTRACTOR_ID
        expect(r["extractor_id"] == want_id, f"action reject {r['id']}: extractor id")
    return out


def check_escrow_code(d: dict, live: dict):
    """The table constants from the recorded deployment: code hash, CREATE and CREATE2 addresses."""
    bs, tx = live["blockscout"], live["creation_tx"]["rpc_tx"]
    reads = {(r["url"], r["method"], (r["params"] or [""])[0].lower()): r["result"] for r in live["rpc_reads"]}
    main, test = "https://rpc.eden.gateway.fm/", "https://rpc.testnet.eden.gateway.fm/"
    runtime = bytes.fromhex(reads[(main, "eth_getCode", "0x" + ee.ESCROW_714.hex())][2:])
    init = bytes.fromhex(bs["creation_bytecode"][2:])
    expect(runtime == bytes.fromhex(bs["deployed_bytecode"][2:]), "rpc code equals verified deployed code")
    expect(pc.keccak256(runtime) == ee.CODE_HASH and d["runtime_code_hash"] == ee.CODE_HASH.hex(), "code hash")
    prefix = init[:len(init) - len(runtime)]
    expect(init.endswith(runtime) and prefix.hex() == d["constructor_prefix_hex"] and bs["constructor_args"] is None,
           "creation code = constructor prefix || runtime")
    i, sstore = 0, False
    while i < len(prefix):
        op = prefix[i]
        sstore |= op == 0x55
        i += 1 + (op - 0x5f if 0x60 <= op <= 0x7f else 0)
    expect(not sstore and d["constructor_writes_storage"] is False, "constructor writes no storage")
    expect(tx["to"] is None and tx["input"] == bs["creation_bytecode"], "creation tx")
    creator, nonce = bytes.fromhex(tx["from"][2:]), int(tx["nonce"], 16)
    expect(pc.keccak256(ee.rlp_enc_list([ee.rlp_enc_bytes(creator), ee.rlp_enc_int(nonce)]))[12:] == ee.ESCROW_714,
           "CREATE address")
    ih = pc.keccak256(init)
    expect(d["init_code_hash"] == ih.hex(), "init code hash")
    expect(pc.keccak256(b"\xff" + ee.DEPLOYER + bytes(32) + ih)[12:] == ee.ESCROW_COPY
           and d["create2"]["address"] == "0x" + ee.ESCROW_COPY.hex(), "CREATE2 address")
    expect(reads[(test, "eth_chainId", "")] == hex(3735928814) and reads[(main, "eth_chainId", "")] == hex(714), "chain ids")
    expect(d["recorded_code"]["testnet_create2"] == reads[(test, "eth_getCode", "0x" + ee.ESCROW_COPY.hex())],
           "recorded testnet code")


def check_signed(d: dict, actions: dict):
    header(d, "signed")
    k = d["keys"]["payer1"]
    priv = int(k["private_key_hex"], 16)
    addr = ee.address_of(priv)
    expect("0x" + addr.hex() == k["address"], "payer1 address")
    expect(int(d["secp256k1_n_hex"], 16) == pc.N, "n")
    for c in d["cases"]:
        a = actions[c["action_ref"]]
        y, r, s = int(c["y_parity"]), int(c["r_hex"], 16), int(c["s_hex"], 16)
        expect(ee.sign_rfc6979(priv, ee.sighash(a["tx"])) == (y, r, s), f"{c['id']}: RFC 6979 signature differs")
        signed = ee.splice(a["tx"], y, r, s)
        expect(signed.hex() == c["signed_hex"], f"{c['id']}: splice")
        expect(ee.rail_ref(signed) == c["rail_ref"], f"{c['id']}: rail_ref")
        expect("0x" + ee.exact_tx(signed, a["tx"]).hex() == c["payer"] == k["address"], f"{c['id']}: payer")
    for c in d["rail_ref"]:
        e = refused(ee.check_rail_ref, c["rail_ref"])
        got = "ok" if e is None else e.sentinel
        expect(got == c["expect"], f"rail_ref {c['id']}: {got}")
        expect(c.get("status") == (None if e is None else "unchecked"), f"rail_ref {c['id']}: status")
    for c in d["exact_tx"]:
        signed = bytes.fromhex(c["signed_hex"])
        expect(ee.rail_ref(signed) == c["rail_ref"], f"exact_tx {c['id']}: rail_ref")
        try:
            payer = ee.exact_tx(signed, actions[c["action_ref"]]["tx"])
            got = "pass"
        except ee.Refused as e:
            got, payer = e.sentinel, None
        expect(got == c["expect"], f"exact_tx {c['id']}: {got}")
        if got == "pass":
            expect("0x" + payer.hex() == c["payer"], f"exact_tx {c['id']}: payer")


def check_settlement(d: dict, actions: dict, live: dict):
    header(d, "settlement")
    ev = d["event"]
    expect(pc.keccak256(ev["signature"].encode()) == ee.TOPIC_DEPOSITED and ev["topic0_hex"] == ee.TOPIC_DEPOSITED.hex(),
           "deposited topic")
    rc = live["deposit"]["rpc_receipt"]
    expect(rc["logs"][0]["topics"][0] == "0x" + ev["topic0_hex"] and ev["f14_receipt_topic0_equal"] is True,
           "topic0 equals the recorded log")
    expect(pc.keccak256(ev["settled_signature"].encode()).hex() == ev["settled_topic0_hex"], "settled topic")
    for r in d["rebuild"]:
        b = ee.rebuild_type2(r["rpc_tx"])
        h = pc.keccak256(b).hex()
        expect(b.hex() == r["rebuilt_hex"] and h == r["rebuilt_hash"], f"rebuild {r['id']}")
        expect(("match" if h == r["rail_ref"] else "settlement_hash_mismatch") == r["expect"], f"rebuild {r['id']}: expect")
    raws = {live["deposit"]["hash"][2:]: live["deposit"]["raw_hex"], live["settle"]["hash"][2:]: live["settle"]["raw_hex"]}
    for r in d["rebuild"]:
        if r["expect"] == "match":
            expect(raws[r["rail_ref"]] == r["rebuilt_hex"], f"rebuild {r['id']}: Celestia bytes")
    expect(ee.receipt_consensus(rc).hex() == d["receipt"]["consensus_hex"], "receipt encoding")
    expect(ee.bloom(rc["logs"]).hex() == rc["logsBloom"][2:] and d["receipt"]["bloom_recomputed_equal"] is True, "bloom")
    for c in d["deposit_event"]:
        got = ee.deposit_event(int(c["status"]), c["logs"], actions[c["action_ref"]], bytes.fromhex(c["from"][2:]),
                               bytes.fromhex(c["escrow"][2:]), c["tx_hash"], c["block_hash"], c["transaction_index"])
        expect(got == c["expect"], f"deposit_event {c['id']}: {got}")
    blk = live["block_227899844"]["rpc_result"]
    hr = ee.header_rlp(blk)
    b = d["block"]
    expect(hr.hex() == b["header_rlp_hex"], "header rlp")
    expect(pc.keccak256(hr).hex() == b["header_hash"] == blk["hash"][2:] == b["served_hash"]
           and b["header_hash_equal"] is True, "header hash")
    txs = live["block_227899844"]["txs_raw_hex"]
    expect(["0x" + pc.keccak256(bytes.fromhex(t)).hex() for t in txs] == blk["transactions"], "block tx hashes")
    expect(b["transactions_root"] == b["served_transactions_root"] == blk["transactionsRoot"][2:]
           and b["transactions_root_equal"] is True, "transactions root (generator)")


def main() -> int:
    d = DEFAULT
    if "--dir" in sys.argv:
        d = Path(sys.argv[sys.argv.index("--dir") + 1])
    load = lambda n: json.loads((d / n).read_text())  # noqa: E731
    calls = check_calls(load("deposit_call.json"))
    actions = check_actions(load("action.json"), calls)
    check_escrow_code(load("action.json")["escrow_code"], load("live/escrow-code.json"))
    check_signed(load("signed.json"), actions)
    check_settlement(load("settlement.json"), actions, load("live/f14.json"))
    if fails:
        for f in fails:
            print(f"FAIL (eden-escrow): {f}", file=sys.stderr)
        return 1
    print("OK (eden-escrow): deposit calls, actions and rejects, signatures, rail_ref, EE3, EE2 rebuild, "
          "receipt, EE8, header hash, escrow code and table")
    return 0


if __name__ == "__main__":
    sys.exit(main())
