#!/usr/bin/env python3
"""Writes spec/vectors/principal/{ed25519,adr036,eip712}.json (policy-v1.0, section 6.2). Deterministic:
Ed25519 per RFC 8032, ECDSA with RFC 6979 nonces.

The mandates are mandate.json cases m_full (Ed25519), m_adr036 and m_eip712.

Usage: python3 spec/vectors/check/gen_principal.py [--out DIR]
"""

from __future__ import annotations

import sys

sys.dont_write_bytecode = True

import copy
import hashlib
import json
from pathlib import Path

import gen_policy as G
import policy_v1 as P
import principal_crypto as PC
from cbor_strict import Raw, encode

OUT = Path(__file__).resolve().parent.parent / "principal"
FORMAT = "edicta-policy-vectors/v1"
REVISION = "policy-v1.0"


def mandate(cid: str) -> dict:
    return copy.deepcopy(next(m for i, _, _, m in G.mandate_inputs() if i == cid))


def raw(m: dict, sig: bytes) -> bytes:
    return encode({1: Raw(encode(P.to_cbor(m, P.S_MANDATE))), 2: sig})


def outcome(b: bytes) -> str:
    try:
        P.verify_mandate(b)
        return "accept"
    except P.PolicyError as e:
        return e.sentinel


def reject(rows: list) -> list:
    out = []
    for cid, desc, b, want, extra in rows:
        got = outcome(b)
        assert got == want, (cid, got, want)
        r = {"id": cid, "description": desc, "signed_mandate_hex": b.hex(), "expect_error": want}
        r.update(extra)
        out.append(r)
    return out


def head(revision: str = REVISION) -> dict:
    return {"format": FORMAT, "revision": revision, "generator": "spec/vectors/check/gen_principal.py"}


def ed25519_file() -> dict:
    m = mandate("m_full")
    sm, h, sig = P.sign_mandate(G.SEEDS["p1"], m)
    msg = P.signed_message("mandate-sig", h)
    s_big = (int.from_bytes(sig[32:], "little") + P_L).to_bytes(32, "little")
    other = dict(m, version=2)
    other_sig = P.ed_sign(G.SEEDS["p1"], P.signed_message("mandate-sig", P.mandate_hash(P.mandate_cbor(other))))
    rows = [
        ("s_not_reduced", "S + L in place of S (G2).", raw(m, sig[:32] + s_big), "ErrMandateSignature", {}),
        ("other_mandate_hash", "Signature of p1 over M of the same mandate with version 2.", raw(m, other_sig),
         "ErrMandateSignature", {}),
        ("low_order_principal", "Principal is the identity point (G0, a value rule).",
         raw(dict(m, principal=bytes([1]) + bytes(31)), sig), "ErrMandateInvalid", {}),
    ]
    # ed25519.json last changed at draft.6.
    return {**head("policy-v1.0"), "scheme": "ed25519 (sig_type absent)", "mandate_ref": "m_full",
            "keys": {"p1": {"seed_hex": G.SEEDS["p1"].hex(), "public_key_hex": G.PUB["p1"].hex()}},
            "case": {"principal_hex": m["principal"].hex(), "mandate_cbor_hex": P.mandate_cbor(m).hex(),
                     "mandate_hash_hex": h.hex(), "signed_message_hex": msg.hex(), "signature_hex": sig.hex(),
                     "signed_mandate_hex": sm.hex(), "counter_key_hex": P.counter_key_of(m).hex()},
            "reject": reject(rows)}


P_L = 2**252 + 27742317777372353535851937790883648493


def adr036_file() -> dict:
    m = mandate("m_adr036")
    sm, h, sig = P.sign_mandate(G.SECP["p1"], m)
    signer = P.adr036_signer(m)
    data = P.adr036_data(m, h)
    doc = P.adr036_signdoc(data, signer)
    text = P.render(m)

    def over(d: str, signer_: str = signer, seed: bytes = G.SECP["p1"]) -> tuple:
        return PC.sign_cosmos(seed, P.adr036_signdoc(d, signer_)), d

    hi = sig[:32] + (PC.N - int.from_bytes(sig[32:], "big")).to_bytes(32, "big")
    other = dict(m, version=2)
    oh = P.mandate_hash(P.mandate_cbor(other))
    lines = text.split("\n")
    i_ver = lines.index(f"version: {m['version']}")
    one_byte = "\n".join(lines[:i_ver] + [f"version: {m['version'] + 1}"] + lines[i_ver + 1:])
    variants = {
        "text_differs_one_byte": ("The wallet signed a text whose version line says 2 (one byte differs from the "
                                  "re-render).", one_byte + "\n" + "mandate hash: " + h.hex()),
        "last_line_not_hash": ("The wallet signed the rendered text alone, without the hash line.", text),
        "d_without_empty_line": ("D built from Render without its final LF: no empty line before the hash line.",
                                 text[:-1] + "\n" + "mandate hash: " + h.hex()),
        "d_trailing_lf": ("D followed by one LF.", data + "\n"),
        "other_mandate_hash": ("D ends with the hash of the same mandate at version 2.",
                               text + "\n" + "mandate hash: " + oh.hex()),
    }
    rows = [("high_s", "s replaced by n - s (the same signature, high s).", raw(m, hi), "ErrMandateSignature", {})]
    for cid, (desc, d) in variants.items():
        s2, _ = over(d)
        rows.append((cid, desc, raw(m, s2), "ErrMandateSignature",
                     {"signed_data": d, "signed_signdoc": P.adr036_signdoc(d, signer).decode()}))
    wrong_signer = PC.cosmos_address(m["principal"], "cosmos")
    s3, _ = over(data, wrong_signer)
    rows.append(("wrong_hrp", "Signed over the sign document whose signer is the same key under HRP cosmos.",
                 raw(m, s3), "ErrMandateSignature",
                 {"signed_signdoc": P.adr036_signdoc(data, wrong_signer).decode()}))
    rows.append(("principal_32_bytes", "sig_type 2 with the 32-byte Ed25519 key of p1 as principal.",
                 raw(dict(m, principal=G.PUB["p1"]), sig), "ErrMandateInvalid", {}))
    rows.append(("not_on_curve", "A compressed key whose x has no point on secp256k1.",
                 raw(dict(m, principal=G.not_on_curve_x()), sig), "ErrMandateInvalid", {}))
    s4 = PC.sign_cosmos(G.SECP["p2"], doc)
    rows.append(("other_key", "The exact sign document signed by secp256k1 p2.", raw(m, s4), "ErrMandateSignature", {}))
    rows += range_rows(m, sig, 64)
    pm = dict(m, mandate_id=G.mid("m_adr036_private"), auditors=G.AUDITORS, state_salt=G.state_salt("m_adr036_private"))
    psm, ph_, psig = P.sign_mandate(G.SECP["p1"], pm)
    pdata = P.adr036_data(pm, ph_)
    pdoc = P.adr036_signdoc(pdata, signer)
    private_case = {"description": "m_adr036 with two auditors and a state_salt (private mode): the wallet-signed D "
                    "carries one line per auditor with the unverified label and the full key fingerprint, and the "
                    "label note.", "mandate_cbor_hex": P.mandate_cbor(pm).hex(), "mandate_hash_hex": ph_.hex(),
                    "rendered_text": pdata, "signdoc": pdoc.decode(), "digest_hex": hashlib.sha256(pdoc).hexdigest(),
                    "signature_hex": psig.hex(), "signed_mandate_hex": psm.hex()}
    assert "(label not verified) - key fingerprint:" in pdata and outcome(psm) == "accept"
    return {**head(), "scheme": "cosmos adr-036 (sig_type 2)", "mandate_ref": "m_adr036",
            "keys": {"p1_secp": {"seed_hex": G.SECP["p1"].hex(), "public_key_compressed_hex": G.SECP_PUB["p1"].hex()},
                     "p2_secp": {"seed_hex": G.SECP["p2"].hex(), "public_key_compressed_hex": G.SECP_PUB["p2"].hex()}},
            "case": {"principal_hex": m["principal"].hex(), "hrp": m["principal_hrp"], "address": signer,
                     "mandate_cbor_hex": P.mandate_cbor(m).hex(), "mandate_hash_hex": h.hex(),
                     "rendered_text": data, "signdoc": doc.decode(), "digest_hex": hashlib.sha256(doc).hexdigest(),
                     "signature_hex": sig.hex(), "signed_mandate_hex": sm.hex(),
                     "counter_key_hex": P.counter_key_of(m).hex()},
            "case_private": private_case, "reject": reject(rows)}


def range_rows(m: dict, sig: bytes, n: int) -> list:
    """r and s outside [1, n-1] are refused before any verification or recovery (policy 6.2, sig_type 2 and 3)."""
    tail = sig[64:]
    nb = PC.N.to_bytes(32, "big")
    return [("r_0", "r = 0.", raw(m, bytes(32) + sig[32:64] + tail), "ErrMandateSignature", {}),
            ("s_0", "s = 0.", raw(m, sig[:32] + bytes(32) + tail), "ErrMandateSignature", {}),
            ("r_ge_n", "r = n, the group order (r >= n).", raw(m, nb + sig[32:64] + tail), "ErrMandateSignature", {})]


def eip712_digest_with(m: dict, h: bytes, name: bytes, chain_id: int | None) -> bytes:
    k = PC.keccak256
    if chain_id is None:
        dom = k(k(P.EIP712_DOMAIN_TYPE) + k(name) + k(P.EIP712_VERSION))
    else:
        dom = k(k(b"EIP712Domain(string name,string version,uint256 chainId)") + k(name) + k(P.EIP712_VERSION)
                + chain_id.to_bytes(32, "big"))
    return k(b"\x19\x01" + dom + P.eip712_parts(m, h)["hash_struct"])


def eip712_file() -> dict:
    m = mandate("m_eip712")
    sm, h, sig = P.sign_mandate(G.SECP["p1"], m)
    parts = P.eip712_parts(m, h)
    v = sig[64]
    hi = sig[:32] + (PC.N - int.from_bytes(sig[32:64], "big")).to_bytes(32, "big") + bytes([v ^ 1])
    rows = [
        ("v_0", "v = 0 (raw recovery id) in place of v = 27 or 28.", raw(m, sig[:64] + bytes([0])),
         "ErrMandateSignature", {}),
        ("v_1", "v = 1.", raw(m, sig[:64] + bytes([1])), "ErrMandateSignature", {}),
        ("high_s", "s replaced by n - s with v flipped: recovers the same address, refused for high s.", raw(m, hi),
         "ErrMandateSignature", {}),
        ("recovered_address_differs", "The digest signed by secp256k1 p2.", raw(m, PC.sign_eth(G.SECP["p2"],
                                                                                              parts["digest"])),
         "ErrMandateSignature", {}),
        ("wrong_domain_name", "Signed over the digest with domain name \"Edicta mandate\".",
         raw(m, PC.sign_eth(G.SECP["p1"], eip712_digest_with(m, h, b"Edicta mandate", None))), "ErrMandateSignature",
         {"signed_digest_hex": eip712_digest_with(m, h, b"Edicta mandate", None).hex()}),
        ("chain_id_present", "Signed over the digest of a domain that adds chainId = 1.",
         raw(m, PC.sign_eth(G.SECP["p1"], eip712_digest_with(m, h, P.EIP712_NAME, 1))), "ErrMandateSignature",
         {"signed_digest_hex": eip712_digest_with(m, h, P.EIP712_NAME, 1).hex()}),
    ] + range_rows(m, sig, 65)
    return {**head(), "scheme": "eip-712 (sig_type 3)", "mandate_ref": "m_eip712",
            "keys": {"p1_secp": {"seed_hex": G.SECP["p1"].hex(), "eth_address_hex": G.ETH_ADDR["p1"].hex()},
                     "p2_secp": {"seed_hex": G.SECP["p2"].hex(), "eth_address_hex": G.ETH_ADDR["p2"].hex()}},
            "case": {"address": "0x" + m["principal"].hex(), "mandate_cbor_hex": P.mandate_cbor(m).hex(),
                     "mandate_hash_hex": h.hex(), "typed_data": P.eip712_typed_data(m, h),
                     "domain_separator_hex": parts["domain_separator"].hex(), "type_hash_hex": parts["type_hash"].hex(),
                     "hash_struct_hex": parts["hash_struct"].hex(), "digest_hex": parts["digest"].hex(),
                     "signature_hex": sig.hex(), "signed_mandate_hex": sm.hex(),
                     "counter_key_hex": P.counter_key_of(m).hex()},
            "reject": reject(rows)}


def build() -> dict:
    files = {"ed25519.json": ed25519_file(), "adr036.json": adr036_file(), "eip712.json": eip712_file()}
    return {k: json.dumps(v, indent=2, ensure_ascii=True) + "\n" for k, v in files.items()}


def main() -> int:
    out = Path(sys.argv[sys.argv.index("--out") + 1]).resolve() if "--out" in sys.argv else OUT
    out.mkdir(parents=True, exist_ok=True)
    for name, text in build().items():
        (out / name).write_text(text)
        print(f"wrote {out / name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
