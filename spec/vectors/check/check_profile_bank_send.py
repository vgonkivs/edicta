#!/usr/bin/env python3
"""Verifies the bank-send profile vectors (spec/vectors/profiles/bank-send).

Independent of both generators: every expected byte string is rebuilt from
the case inputs with this checker's own hand-written protobuf, bech32 and CBOR.

- msg_send.json (written by banksend-gen from gogoproto): every MsgSend is
  re-encoded and strictly decoded here; every reject fails the strict decoder.
- tx.json (banksend-gen): every TxBody equals the profile's byte rule and
  parses back to its timeout_height; every body reject fails the on-chain
  body check; AuthInfo, SignDoc and TxRaw are re-encoded, the secp256k1
  public key and address are derived from the private key, the signature
  verifies over the SignDoc with a low S, and the tx hash is SHA-256(TxRaw).
- action.json, executor.json, timeout_height.json, price_trigger.json and
  e2e.json: every rule of the profile, including the core commitment and
  Authorization checks of the end-to-end case.

Usage: python3 spec/vectors/check/check_profile_bank_send.py [--dir DIR]
"""

from __future__ import annotations

import sys

sys.dont_write_bytecode = True

import hashlib
import json
from pathlib import Path

import profile_bank_send as pf
from edicta_v0 import (AuthorizationCheck, Reject, action_hash, check_rail_ref, commitment_hash, decode_signed,
                       verify_authorization, verify_for_gate)
from vecjson import gate_from_json, params_from_json

HERE = Path(__file__).resolve().parent
VECTORS = HERE.parent


def arg(name: str, default: Path) -> Path:
    if name in sys.argv:
        return Path(sys.argv[sys.argv.index(name) + 1]).resolve()
    return default


DIR = arg("--dir", VECTORS / "profiles" / "bank-send")
FORMAT = "edicta-vectors/v0"
REVISIONS = {"msg_send.json": "bank-send-v0-draft.1", "tx.json": "bank-send-v0-draft.1",
             "action.json": "bank-send-v0-draft.1", "executor.json": "bank-send-v0-draft.1",
             "timeout_height.json": "bank-send-v0-draft.2", "price_trigger.json": "bank-send-v0-draft.1",
             "e2e.json": "bank-send-v0-draft.2"}
FILES = ("msg_send.json", "tx.json", "action.json", "executor.json", "timeout_height.json", "price_trigger.json", "e2e.json")


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


def check_msgs(f: dict) -> dict:
    expect(f["type_url"] == pf.MSG_SEND_TYPE_URL, "type_url")
    msgs = {}
    for c in f["cases"]:
        i = c["input"]
        b = bytes.fromhex(c["msg_hex"])
        expect(pf.msg_encode(i["from_address"], i["to_address"], i["amount"]["denom"], i["amount"]["amount"]) == b,
               f"{c['id']}: MsgSend bytes differ from the hand encoding")
        m = pf.msg_decode(b, c["hrp"])
        expect(m["from"].hex() == c["from_hex"] and m["to"].hex() == c["to_hex"], f"{c['id']}: address bytes")
        expect(pf.bech32_encode(c["hrp"], m["from"]) == i["from_address"], f"{c['id']}: bech32 re-encoding")
        msgs[c["id"]] = b
    for c in f["reject"]:
        got = outcome(pf.msg_decode, bytes.fromhex(c["msg_hex"]), c["hrp"])
        expect(got == c["expect_error"] == "bankmsg.ErrMalformed", f"{c['id']}: got {got}")
        expect(isinstance(c["sdk_unmarshal_ok"], bool), f"{c['id']}: sdk_unmarshal_ok")
    return msgs


def check_tx(f: dict, msgs: dict):
    bodies = {}
    for c in f["body"]:
        h, th, m = bytes.fromhex(c["commitment_hash_hex"]), int(c["timeout_height"]), msgs[c["msg_ref"]]
        b = bytes.fromhex(c["body_hex"])
        expect(c["memo"] == pf.memo(h) and len(c["memo"]) == 64, f"{c['id']}: memo")
        expect(pf.body(m, h, th) == b, f"{c['id']}: gogoproto TxBody differs from the profile rule")
        expect(pf.check_body(b, m, h) == th, f"{c['id']}: timeout_height parse")
        bodies[c["id"]] = b
    for c in f["body_reject"]:
        got = outcome(pf.check_body, bytes.fromhex(c["body_hex"]), msgs[c["msg_ref"]], bytes.fromhex(c["commitment_hash_hex"]))
        expect(got == c["expect_error"] == "bankaction.ErrBodyMismatch", f"{c['id']}: got {got}")
    for c in f["signed"]:
        k = c["key"]
        priv = bytes.fromhex(k["priv_hex"])
        expect(priv == hashlib.sha256(k["label"].encode()).digest(), f"{c['id']}: key label")
        pub, addr = pf.secp256k1_pub_and_address(priv)
        expect(pub.hex() == k["pubkey_hex"] and addr.hex() == k["address_hex"], f"{c['id']}: public key or address")
        expect(pf.bech32_encode("celestia", addr) == k["address"], f"{c['id']}: bech32 address")
        body = bodies[c["body_ref"]]
        ai = pf.auth_info(pub, int(c["sequence"]), c["fee"]["denom"], c["fee"]["amount"], int(c["gas_limit"]))
        expect(ai.hex() == c["auth_info_hex"], f"{c['id']}: AuthInfo")
        sd = pf.sign_doc(body, ai, c["chain_id"], int(c["account_number"]))
        expect(sd.hex() == c["sign_doc_hex"], f"{c['id']}: SignDoc")
        sig = bytes.fromhex(c["signature_hex"])
        expect(pf.secp256k1_verify(pub, sd, sig), f"{c['id']}: signature")
        raw = pf.tx_raw(body, ai, sig)
        expect(raw.hex() == c["tx_raw_hex"], f"{c['id']}: TxRaw")
        th = hashlib.sha256(raw).hexdigest()
        expect(th == c["tx_hash_hex"] == c["rail_ref"], f"{c['id']}: tx hash / rail_ref")
        check_rail_ref(c["rail_ref"])


def check_actions(f: dict, msgs: dict) -> dict:
    expect(f["action_type"] == pf.ACTION_TYPE, "action_type")
    out = {}
    for c in f["cases"]:
        m = bytes.fromhex(c["input"]["msg_hex"])
        if "msg_ref" in c:
            expect(m == msgs[c["msg_ref"]], f"{c['id']}: msg_ref")
        b = bytes.fromhex(c["cbor_hex"])
        expect(pf.action_encode(c["input"]["chain_id"], m) == b, f"{c['id']}: encoding")
        expect(pf.action_decode(b) == {"chain_id": c["input"]["chain_id"], "msg": m}, f"{c['id']}: decoding")
        expect(action_hash(pf.ACTION_TYPE, b).hex() == c["action_hash_hex"], f"{c['id']}: action hash")
        out[c["id"]] = b
    for c in f["reject"]:
        got = outcome(pf.action_decode, bytes.fromhex(c["cbor_hex"]))
        expect(got == c["expect_error"] == "bankaction.ErrMalformed", f"{c['id']}: got {got}")
    return out


def check_executor(f: dict):
    for c in f["cases"]:
        got = outcome(pf.executor_static_check, bytes.fromhex(c["action_hex"]), c["domain"], c["destinations"],
                      int(c["max_amount"]))
        expect(got == c.get("expect_error"), f"{c['id']}: got {got}, want {c.get('expect_error')}")


def check_timeouts(f: dict):
    expect(int(f["max_timeout_blocks_limit"]) == pf.MAX_TIMEOUT_BLOCKS_LIMIT, "max_timeout_blocks_limit")
    expect(int(f["slowdown_factor"]) == pf.SLOWDOWN_FACTOR == 2, "slowdown_factor")
    for c in f["interval"]:
        hs = [(int(h["height"]), int(h["time_ns"])) for h in c["headers"]]
        expect(pf.block_interval_ms(hs) == int(c["tau_ms"]), f"{c['id']}: tau_ms")
    for c in f["cases"]:
        args = [int(c[k]) for k in ("head_height", "head_time", "tau_ms", "expires", "skew_s", "max_timeout_blocks", "now")]
        try:
            th, got = pf.timeout_height(*args), None
        except Reject as e:
            th, got = None, e.sentinel
        expect(got == c.get("expect_error"), f"{c['id']}: got {got}")
        if got is None:
            expect(th == int(c["timeout_height"]), f"{c['id']}: timeout_height {th}")


def pt_from_json(j):
    if isinstance(j, dict):
        return {k: (v if k in ("strategy_id", "feed", "asset_id", "quote", "source", "name", "to_address", "denom", "reason")
                    else pt_from_json(v)) for k, v in j.items()}
    if isinstance(j, list):
        return [pt_from_json(x) for x in j]
    return int(j)


def check_price_trigger(f: dict, msgs: dict, hrps: dict):
    expect(f["media_type"] == pf.MEDIA_TYPE_PRICE_TRIGGER, "media_type")
    for c in f["cases"]:
        p = pt_from_json(c["input"])
        b = bytes.fromhex(c["cbor_hex"])
        expect(pf.pt_encode(p) == b and pf.pt_decode(b) == p, f"{c['id']}: encoding")
    for c in f["reject"]:
        got = outcome(pf.pt_decode, bytes.fromhex(c["cbor_hex"]))
        expect(got == c["expect_error"] == "pricetrigger.ErrMalformed", f"{c['id']}: got {got}")
    for c in f["consistency"]:
        p = pf.pt_decode(bytes.fromhex(c["context_cbor_hex"]))
        m = pf.msg_decode(msgs[c["msg_ref"]], c["hrp"])
        got = pf.pt_consistency(p, m, int(c["issued_at"]))
        expect(got == c["expect_failed"], f"{c['id']}: got {got}")


def check_e2e(f: dict, actions: dict):
    for c in f["cases"]:
        gate, params = gate_from_json(c["gate"]), params_from_json(c["params"])
        cm = c["commitment"]
        env = bytes.fromhex(cm["envelope_hex"])
        verify_for_gate(env, int(c["now_gate"]), gate, params)
        signed, canon = decode_signed(env)
        expect(canon.hex() == cm["commitment_cbor_hex"], f"{c['id']}: commitment bytes")
        ch = commitment_hash(canon)
        expect(ch.hex() == cm["commitment_hash_hex"], f"{c['id']}: commitment hash")
        action = bytes.fromhex(c["action_hex"])
        expect(action == actions["action_minimal_mocha"], f"{c['id']}: action is action_minimal_mocha")
        com = signed["commitment"]
        expect(com["action"]["type"] == pf.ACTION_TYPE and com["action"]["hash"] == action_hash(pf.ACTION_TYPE, action),
               f"{c['id']}: committed action")
        a = c["authorization"]
        keys = json.loads((VECTORS / "historical" / "v0" / "keys.json").read_text())["keys"]
        ex = c["executor"]
        chk = AuthorizationCheck(bytes.fromhex(keys[a["signer"]]["public_key_hex"]), gate["gate_id"], pf.ACTION_TYPE, action,
                                 int(ex["now"]), int(ex["skew_s"]))
        sa, _ = verify_authorization(bytes.fromhex(a["signed_authorization_hex"]), chk)
        auth = sa["authorization"]
        expect(auth["commitment_hash"] == ch, f"{c['id']}: Authorization names the commitment")
        expect(auth["expires"] == min(com["valid_until"], int(a["authorized_at"]) + int(a["max_authorization_ttl_s"])),
               f"{c['id']}: expires")
        m = pf.executor_static_check(action, ex["domain"], [], 0)
        hs = [(int(h["height"]), int(h["time_ns"])) for h in ex["headers"]]
        tau = pf.block_interval_ms(hs)
        expect(tau == int(ex["tau_ms"]) and hs[-1][0] == int(ex["head_height"])
               and hs[-1][1] // 1_000_000_000 == int(ex["head_time"]), f"{c['id']}: head")
        th = pf.timeout_height(hs[-1][0], hs[-1][1] // 1_000_000_000, tau, auth["expires"], int(ex["skew_s"]),
                               int(ex["max_timeout_blocks"]), int(ex["now"]))
        expect(th == int(ex["timeout_height"]), f"{c['id']}: timeout_height")
        body = bytes.fromhex(ex["body_hex"])
        expect(ex["memo"] == ch.hex() and body == pf.body(m["msg"], ch, th), f"{c['id']}: body")
        expect(pf.check_body(body, m["msg"], ch) == th, f"{c['id']}: on-chain body check")
        ctx = c["context"]
        expect(ctx["media_type"] == pf.MEDIA_TYPE_PRICE_TRIGGER, f"{c['id']}: context media type")
        got = pf.pt_consistency(pf.pt_decode(bytes.fromhex(ctx["cbor_hex"])), m, com["issued_at"])
        expect(got == ctx["expect_failed"], f"{c['id']}: context consistency {got}")


def main() -> int:
    try:
        files = {}
        for name in FILES:
            f = json.loads((DIR / name).read_text())
            expect(f["format"] == FORMAT and f["profile"] == "bank-send" and f["revision"] == REVISIONS[name],
                   f"{name}: header")
            files[name] = f
        msgs = check_msgs(files["msg_send.json"])
        check_tx(files["tx.json"], msgs)
        actions = check_actions(files["action.json"], msgs)
        check_executor(files["executor.json"])
        check_timeouts(files["timeout_height.json"])
        check_price_trigger(files["price_trigger.json"], msgs, {})
        check_e2e(files["e2e.json"], actions)
        ids = []
        for name, f in files.items():
            for k in ("cases", "reject", "body", "body_reject", "signed", "interval", "consistency"):
                ids += [c["id"] for c in f.get(k, [])]
        expect(len(ids) == len(set(ids)), "duplicate ids")
    except (Failure, Reject) as e:
        print(f"FAIL (profile bank-send): {e}", file=sys.stderr)
        return 1
    m, t, a, ex, to, pt = (files[n] for n in FILES[:6])
    print(f"OK (profile bank-send): {len(m['cases'])} msg, {len(m['reject'])} msg reject, {len(t['body'])} body, "
          f"{len(t['body_reject'])} body reject, {len(t['signed'])} signed tx, {len(a['cases'])} action, "
          f"{len(a['reject'])} action reject, {len(ex['cases'])} executor, {len(to['interval'])} interval, "
          f"{len(to['cases'])} timeout, {len(pt['cases'])} price-trigger, {len(pt['reject'])} price-trigger reject, "
          f"{len(pt['consistency'])} consistency, {len(files['e2e.json']['cases'])} e2e")
    return 0


if __name__ == "__main__":
    sys.exit(main())
