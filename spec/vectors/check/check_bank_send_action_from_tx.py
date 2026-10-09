#!/usr/bin/env python3
"""Verifies spec/vectors/profiles/bank-send/action_from_tx.json (bank-send-v0-draft.10, section 3.5).

Each case's action bytes are rebuilt here from tx.json (the body of the signed tx) and msg_send.json, as canonical
CBOR {1: chain_id, 2: msg}, without the generator's parser; every reject must start from a signed tx of tx.json;
the generator must reproduce the file byte for byte.

Usage: python3 spec/vectors/check/check_bank_send_action_from_tx.py
"""

from __future__ import annotations

import sys

sys.dont_write_bytecode = True

import json
from pathlib import Path

from cbor_strict import encode

DIR = Path(__file__).resolve().parent.parent / "profiles" / "bank-send"


def main() -> int:
    try:
        f = json.loads((DIR / "action_from_tx.json").read_text())
        tx = json.loads((DIR / "tx.json").read_text())
        msgs = {c["id"]: c for c in json.loads((DIR / "msg_send.json").read_text())["cases"]}
        acts = {c["id"]: c for c in json.loads((DIR / "action.json").read_text())["cases"]}
        signed = {c["id"]: c for c in tx["signed"]}
        bodies = {c["id"]: c for c in tx["body"]}
        assert f["revision"] == "bank-send-v0-draft.10" and f["type_url"] == "/cosmos.bank.v1beta1.MsgSend"
        for c in f["cases"]:
            s = signed[c["tx_ref"]]
            assert c["tx_raw_hex"] == s["tx_raw_hex"] and c["chain_id"] == s["chain_id"], c["id"]
            body = bytes.fromhex(bodies[s["body_ref"]]["body_hex"])
            raw = bytes.fromhex(s["tx_raw_hex"])
            assert raw[0] == 0x0A and body in raw[:len(body) + 4], f"{c['id']}: body is field 1 of the TxRaw"
            msg = bytes.fromhex(msgs[bodies[s["body_ref"]]["msg_ref"]]["msg_hex"])
            want = encode({1: s["chain_id"], 2: msg})
            assert c["action_hex"] == want.hex(), f"{c['id']}: reconstructed action"
            if "action_ref" in c:
                assert acts[c["action_ref"]]["cbor_hex"] == want.hex(), f"{c['id']}: action.json"
        assert any("action_ref" in c for c in f["cases"]), "one case equals an action.json case"
        for r in f["reject"]:
            assert r["expect"] == "refused" and r["chain_id"] == tx["signed"][0]["chain_id"], r["id"]
        import gen_bank_send_action_from_tx as gen
        assert json.dumps(gen.build(), indent=2, ensure_ascii=True) + "\n" == (DIR / "action_from_tx.json").read_text(), \
            "generator output differs"
    except (AssertionError, KeyError, ValueError) as e:
        print(f"FAIL (bank-send action_from_tx): {e}", file=sys.stderr)
        return 1
    print(f"OK (bank-send action_from_tx, bank-send-v0-draft.10): {len(f['cases'])} cases, {len(f['reject'])} reject; "
          f"generator output identical")
    return 0


if __name__ == "__main__":
    sys.exit(main())
