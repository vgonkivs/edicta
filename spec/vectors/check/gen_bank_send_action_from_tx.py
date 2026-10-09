#!/usr/bin/env python3
"""Writes spec/vectors/profiles/bank-send/action_from_tx.json (bank-send-v0-draft.10, section 3.5). Deterministic.

ActionFromTx(tx, chain_id) on the signed transactions of tx.json, the action bytes it gives, and transactions it
refuses. The core v1 reveal path (core v1 10.7) accepts the bytes only if they hash to the committed action_hash
with the revealed salt.

Usage: python3 spec/vectors/check/gen_bank_send_action_from_tx.py [--out DIR]
"""

from __future__ import annotations

import sys

sys.dont_write_bytecode = True

import json
from pathlib import Path

import profile_bank_send as bs

VECTORS = Path(__file__).resolve().parent.parent
OUT = VECTORS / "profiles" / "bank-send"
TYPE_URL = b"/cosmos.bank.v1beta1.MsgSend"


class Refused(Exception):
    pass


def uvarint(b: bytes, i: int) -> tuple:
    out, shift, start = 0, 0, i
    while True:
        if i >= len(b):
            raise Refused("truncated varint")
        x = b[i]
        out |= (x & 0x7F) << shift
        i += 1
        if not x & 0x80:
            break
        shift += 7
    if i - start > 1 and b[i - 1] == 0:
        raise Refused("non-minimal varint")
    return out, i


def field(b: bytes, i: int, num: int) -> tuple:
    """A length-delimited field `num` at offset i: (value, next offset)."""
    tag, i = uvarint(b, i)
    if tag != (num << 3) | 2:
        raise Refused(f"field {num} expected")
    n, i = uvarint(b, i)
    if i + n > len(b):
        raise Refused("length exceeds input")
    return b[i:i + n], i + n


def txraw_body(tx: bytes) -> bytes:
    """AT1: strict TxRaw (BX3): body_bytes, auth_info_bytes once each, then at least one signature, nothing else."""
    body, i = field(tx, 0, 1)
    _, i = field(tx, i, 2)
    _, i = field(tx, i, 3)
    while i < len(tx):
        _, i = field(tx, i, 3)
    return body


def action_from_tx(tx: bytes, chain_id: str) -> bytes:
    body = txraw_body(tx)
    anyb, _ = field(body, 0, 1)
    url, j = field(anyb, 0, 1)
    if url != TYPE_URL:
        raise Refused("type_url")
    msg, j = field(anyb, j, 2)
    if j != len(anyb):
        raise Refused("trailing bytes in the Any")
    return bs.action_encode(chain_id, msg)


def build() -> dict:
    tx = json.loads((OUT / "tx.json").read_text())
    act = json.loads((OUT / "action.json").read_text())
    msgs = {c["id"]: c for c in json.loads((OUT / "msg_send.json").read_text())["cases"]}
    bodies = {c["id"]: c for c in tx["body"]}
    cases, reject = [], []
    for c in tx["signed"]:
        a = action_from_tx(bytes.fromhex(c["tx_raw_hex"]), c["chain_id"])
        msg_ref = bodies[c["body_ref"]]["msg_ref"]
        assert bs.action_decode(a)["msg"] == bytes.fromhex(msgs[msg_ref]["msg_hex"])
        ref = next((x["id"] for x in act["cases"] if x["cbor_hex"] == a.hex()), None)
        case = {"id": "aft_" + c["id"], "description": f"tx.json {c['id']}: msg spliced in the Any of message 0, "
                f"chain_id {c['chain_id']} from the checker's configuration.", "tx_ref": c["id"],
                "tx_raw_hex": c["tx_raw_hex"], "chain_id": c["chain_id"], "action_hex": a.hex()}
        if ref:
            case["action_ref"] = ref
        cases.append(case)
    good = bytes.fromhex(tx["signed"][0]["tx_raw_hex"])
    body = txraw_body(good)
    other_url = body.replace(TYPE_URL, b"/cosmos.bank.v1beta1.MsgBurn", 1)
    assert len(other_url) == len(body)

    def wrap(bd: bytes) -> bytes:
        rest = good[len(bytes([0x0a])) + len(enc_len(len(body))) + len(body):]
        return bytes([0x0a]) + enc_len(len(bd)) + bd + rest

    for i, d, t in [("aft_other_type_url", "Message 0 has another type URL (same length).", wrap(other_url)),
                    ("aft_trailing_byte", "A zero byte after the TxRaw.", good + b"\x00"),
                    ("aft_no_signature", "TxRaw without field 3.", good[:len(good) - len(sig_field(good))])]:
        try:
            action_from_tx(t, tx["signed"][0]["chain_id"])
            raise AssertionError(i)
        except Refused as e:
            reject.append({"id": i, "description": d, "tx_raw_hex": t.hex(), "chain_id": tx["signed"][0]["chain_id"],
                           "expect": "refused", "cause": str(e)})
    return {"format": "edicta-vectors/v0", "profile": "bank-send", "revision": "bank-send-v0-draft.10",
            "generator": "spec/vectors/check/gen_bank_send_action_from_tx.py",
            "description": "ActionFromTx of section 3.5: the action bytes reconstructed from a transaction (AT1 to "
            "AT3). Refused transactions give no bytes; the core reveal path is then unchecked.",
            "type_url": TYPE_URL.decode(), "cases": cases, "reject": reject}


def enc_len(n: int) -> bytes:
    out = b""
    while True:
        b = n & 0x7F
        n >>= 7
        out += bytes([b | (0x80 if n else 0)])
        if not n:
            return out


def sig_field(tx: bytes) -> bytes:
    """The last signature field of a TxRaw (tag, length, bytes)."""
    _, i = field(tx, 0, 1)
    _, i = field(tx, i, 2)
    start = i
    _, i = field(tx, i, 3)
    return tx[start:i]


def main() -> int:
    out = Path(sys.argv[sys.argv.index("--out") + 1]).resolve() if "--out" in sys.argv else OUT
    out.mkdir(parents=True, exist_ok=True)
    p = out / "action_from_tx.json"
    p.write_text(json.dumps(build(), indent=2, ensure_ascii=True) + "\n")
    print(f"wrote {p}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
