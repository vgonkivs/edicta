#!/usr/bin/env python3
"""Verifies spec/vectors/principal/*.json (policy-v1.0, section 6.2).

Uses the independent policy re-implementation of check_policy.py (not
policy_v1): strict decoding, value rules, rendering, the ADR-036 sign document
and the EIP-712 digest. The EIP-712 hash is also recomputed from the vector's
typed_data JSON with a generic encoder for the types it uses, so the JSON a
wallet is given and the digest the verifier checks cannot drift apart. ECDSA
signatures are re-derived with RFC 6979 and must match byte for byte. The
generator must reproduce every file.

Cross-language confirmation (go-ethereum, dcrd secp256k1):
spec/vectors/tools/principal-xcheck.

Usage: python3 spec/vectors/check/check_principal.py
"""

from __future__ import annotations

import sys

sys.dont_write_bytecode = True

import hashlib
import json
from pathlib import Path

import check_policy as C
import principal_crypto as pc

HERE = Path(__file__).resolve().parent
DIR = HERE.parent / "principal"
MANDATES = HERE.parent / "policy" / "mandate.json"
REVISION = "policy-v1.0"
REQUIRED = {
    "ed25519.json": {"s_not_reduced", "other_mandate_hash", "low_order_principal"},
    "adr036.json": {"high_s", "wrong_hrp", "principal_32_bytes", "not_on_curve", "other_mandate_hash",
                    "text_differs_one_byte", "last_line_not_hash", "d_without_empty_line", "d_trailing_lf",
                    "r_0", "s_0", "r_ge_n"},
    "eip712.json": {"v_0", "v_1", "high_s", "recovered_address_differs", "wrong_domain_name", "chain_id_present",
                    "r_0", "s_0", "r_ge_n"},
}


class Failure(Exception):
    pass


def expect(c, msg):
    if not c:
        raise Failure(msg)


def outcome(b: bytes) -> str:
    try:
        C.mandate_verify(b)
        return "accept"
    except C.Bad as e:
        return e.sentinel


def eip712_from_json(td: dict) -> bytes:
    """Generic EIP-712 hashStruct for string, bytesN and uintN fields, from the typed-data JSON."""
    k = pc.keccak256

    def type_string(name):
        return (name + "(" + ",".join(f"{f['type']} {f['name']}" for f in td["types"][name]) + ")").encode()

    def enc(name, obj):
        out = k(type_string(name))
        for f in td["types"][name]:
            t, v = f["type"], obj[f["name"]]
            if t == "string":
                out += k(v.encode())
            elif t.startswith("bytes"):
                b = bytes.fromhex(v[2:])
                expect(len(b) == int(t[5:]), f"typed_data {f['name']}: length")
                out += b + bytes(32 - len(b))
            elif t.startswith("uint"):
                out += int(v).to_bytes(32, "big")
            else:
                raise Failure(f"typed_data: unsupported type {t}")
        return k(out)

    return k(b"\x19\x01" + enc("EIP712Domain", td["domain"]) + enc(td["primaryType"], td["message"]))


def check_case(f: dict, mc: dict) -> tuple:
    case = f["case"]
    b = bytes.fromhex(case["signed_mandate_hex"])
    expect(outcome(b) == "accept", f"{f['scheme']}: valid mandate refused ({outcome(b)})")
    m, h = C.mandate_verify(b)
    expect(case["mandate_cbor_hex"] == mc["mandate_cbor_hex"] and case["mandate_hash_hex"] == h.hex()
           == mc["mandate_hash_hex"] and case["signed_mandate_hex"] == mc["signed_mandate_hex"],
           f"{f['scheme']}: not the mandate.json case {f['mandate_ref']}")
    expect(case["counter_key_hex"] == C.counter(m[2], m[9], m.get(14)).hex() == mc["counter_key_hex"],
           f"{f['scheme']}: counter key")
    return m, h, bytes.fromhex(case["signature_hex"])


def check_ed25519(f: dict, mc: dict):
    m, h, sig = check_case(f, mc)
    case = f["case"]
    expect(m.get(14) is None and case["signed_message_hex"] == (C.T_MANDATE_SIG + h).hex(), "ed25519: M")
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    priv = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(f["keys"]["p1"]["seed_hex"]))
    expect(priv.sign(C.T_MANDATE_SIG + h) == sig, "ed25519: not the RFC 8032 signature")


def check_adr036(f: dict, mc: dict):
    m, h, sig = check_case(f, mc)
    case = f["case"]
    seed = bytes.fromhex(f["keys"]["p1_secp"]["seed_hex"])
    expect(m.get(14) == 2 and m[2].hex() == case["principal_hex"] == pc.pub_compressed(seed).hex(), "adr036: key")
    expect(case["address"] == pc.cosmos_address(m[2], case["hrp"]) and case["hrp"] == m[15], "adr036: address")
    d = C.render(m) + "\n" + "mandate hash: " + h.hex()
    expect(case["rendered_text"] == d, "adr036: D")
    lines = d.split("\n")
    expect(lines[-1] == "mandate hash: " + h.hex() and lines[-2] == "" and lines[-3] != "", "adr036: D shape")
    doc = C.adr036_doc(m, h)
    expect(case["signdoc"].encode() == doc and case["digest_hex"] == hashlib.sha256(doc).hexdigest(), "adr036: doc")
    expect(pc.sign_cosmos(seed, doc) == sig, "adr036: not the RFC 6979 low-s signature")
    for r in f["reject"]:
        if "signed_data" in r:
            expect(r["signed_data"] != d, f"{r['id']}: signed the verifier's own D")
            expect(r["signed_signdoc"].encode() == C.adr036_doc(m, h, r["signed_data"]), f"{r['id']}: its doc")
            got = bytes.fromhex(r["signed_mandate_hex"])[-64:]
            expect(pc.verify_cosmos(m[2], r["signed_signdoc"].encode(), got), f"{r['id']}: a wallet signature")
    pc_ = f["case_private"]
    pb = bytes.fromhex(pc_["signed_mandate_hex"])
    expect(outcome(pb) == "accept", "adr036 private case refused")
    pm, ph = C.mandate_verify(pb)
    pd = C.render(pm) + "\n" + "mandate hash: " + ph.hex()
    expect(17 in pm and 18 in pm and pc_["rendered_text"] == pd and pc_["mandate_hash_hex"] == ph.hex()
           and "(label not verified) - key fingerprint: " in pd and "Labels are not verified" in pd,
           "adr036 private case: D with fingerprints")
    expect(pc_["signdoc"].encode() == C.adr036_doc(pm, ph) and pc.sign_cosmos(seed, C.adr036_doc(pm, ph)).hex()
           == pc_["signature_hex"], "adr036 private case: signature")
    by = {r["id"]: r for r in f["reject"]}
    for rid in ("r_0", "s_0", "r_ge_n"):
        rs = bytes.fromhex(by[rid]["signed_mandate_hex"])[-64:]
        r_, s_ = int.from_bytes(rs[:32], "big"), int.from_bytes(rs[32:], "big")
        expect(not (1 <= r_ < pc.N and 1 <= s_ < pc.N), rid)
    expect(by["d_trailing_lf"]["signed_data"] == d + "\n", "d_trailing_lf")
    expect(by["d_without_empty_line"]["signed_data"] == d.replace("\n\nmandate hash: ", "\nmandate hash: "),
           "d_without_empty_line")


def check_eip712(f: dict, mc: dict):
    m, h, sig = check_case(f, mc)
    case = f["case"]
    seed = bytes.fromhex(f["keys"]["p1_secp"]["seed_hex"])
    expect(m.get(14) == 3 and case["address"] == "0x" + m[2].hex()
           == "0x" + pc.eth_address(pc.pub_point(seed)).hex(), "eip712: address")
    k = pc.keccak256
    dom = k(k(b"EIP712Domain(string name,string version)") + k(b"Edicta Mandate") + k(b"1"))
    th = k(b"Mandate(bytes32 mandateHash,bytes16 mandateId,uint64 version,string gateId)")
    hs = k(th + h + m[9] + bytes(16) + m[10].to_bytes(32, "big") + k(m[3].encode()))
    dg = k(b"\x19\x01" + dom + hs)
    expect(case["domain_separator_hex"] == dom.hex() and case["type_hash_hex"] == th.hex()
           and case["hash_struct_hex"] == hs.hex() and case["digest_hex"] == dg.hex() == C.eip712_digest(m, h).hex(),
           "eip712: digest parts")
    td = case["typed_data"]
    expect(eip712_from_json(td) == dg, "eip712: typed_data JSON does not hash to the digest")
    expect(set(td["domain"]) == {"name", "version"}, "eip712: domain has extra fields")
    expect(pc.sign_eth(seed, dg) == sig and sig[64] in (27, 28), "eip712: not the RFC 6979 low-s signature")
    by = {r["id"]: r for r in f["reject"]}
    for cid in ("wrong_domain_name", "chain_id_present"):
        sd = bytes.fromhex(by[cid]["signed_digest_hex"])
        got = bytes.fromhex(by[cid]["signed_mandate_hex"])[-65:]
        expect(sd != dg and pc.verify_eth(m[2], sd, got), f"{cid}: a valid signature over its own digest")


def main() -> int:
    import gen_principal
    try:
        mand = {c["id"]: c for c in json.loads(MANDATES.read_text())["cases"]}
        built = gen_principal.build()
        n = 0
        for name, fn in (("ed25519.json", check_ed25519), ("adr036.json", check_adr036),
                         ("eip712.json", check_eip712)):
            text = (DIR / name).read_text()
            expect(text == built[name], f"{name}: generator output differs")
            f = json.loads(text)
            want = "policy-v1.0" if name == "ed25519.json" else REVISION
            expect(f["format"] == "edicta-policy-vectors/v1" and f["revision"] == want, f"{name}: header")
            fn(f, mand[f["mandate_ref"]])
            ids = {r["id"] for r in f["reject"]}
            expect(REQUIRED[name] <= ids, f"{name}: missing rejects {sorted(REQUIRED[name] - ids)}")
            for r in f["reject"]:
                got = outcome(bytes.fromhex(r["signed_mandate_hex"]))
                expect(got == r["expect_error"], f"{name} {r['id']}: got {got}, want {r['expect_error']}")
            n += len(f["reject"])
    except (Failure, C.Bad, C.Failure, KeyError) as e:
        print(f"FAIL (principal): {type(e).__name__}: {e}", file=sys.stderr)
        return 1
    print(f"OK (principal, {REVISION}): ed25519, adr036, eip712; {n} reject; RFC 6979 signatures reproduced; "
          "generator output identical")
    return 0


if __name__ == "__main__":
    sys.exit(main())
