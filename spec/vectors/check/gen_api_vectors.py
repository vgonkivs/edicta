#!/usr/bin/env python3
"""Generates spec/vectors/api/publish_request.json (v0-draft.11). Deterministic.

Usage: python3 spec/vectors/check/gen_api_vectors.py [--core DIR] [--out DIR]
Defaults: --core spec/vectors/v0; --out spec/vectors/api.
"""

from __future__ import annotations

import sys

sys.dont_write_bytecode = True

import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import edicta_publish_v0 as pr
from cbor_strict import Pairs, Raw, encode
from edicta_v0 import Reject, commitment_hash, decode_signed, signing_message, tagged
from vecjson import commitment_from_json, pattern_bytes

HERE = Path(__file__).resolve().parent
VECTORS = HERE.parent


def arg(name: str, default: Path) -> Path:
    if name in sys.argv:
        return Path(sys.argv[sys.argv.index(name) + 1]).resolve()
    return default


CORE = arg("--core", VECTORS / "historical" / "v0")
OUT = arg("--out", VECTORS / "api")
FORMAT = "edicta-vectors/v0"
REVISION = "v0-draft.11"
T0 = 1791000000
NOW = T0 + 60
SKEW = 30
MAX_BLOB = 1 << 20
PATTERN = "affine-7-3"
ID64 = "agent-" + "x" * 58
GID = "edictad-1"


def main():
    keys = json.loads((CORE / "keys.json").read_text())["keys"]

    def sk(name):
        return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(keys[name]["seed_hex"]))

    def pk(name):
        return bytes.fromhex(keys[name]["public_key_hex"])

    allowlist = {"dca-agent-1": pk("agent1"), "tia-transfer-agent": pk("agent2"), ID64: pk("agent1")}
    gate_keys = [pk("gate1")]
    server = {"gate_id": GID, "now": str(NOW), "skew_s": str(SKEW), "max_blob_bytes": str(MAX_BLOB),
              "allowlist": {k: v.hex() for k, v in allowlist.items()}, "gate_keys": [k.hex() for k in gate_keys]}
    payload = json.loads((CORE / "payload.json").read_text())
    small_blob = bytes.fromhex(next(c for c in payload["cases"] if c["id"] == "ciphertext_hash_small_blob")["blob_hex"])

    cases = []

    def add(cid, desc, signer, agent_id, requested_at, blob):
        msg = pr.publish_message(GID, agent_id, requested_at, blob)
        sig = sk(signer).sign(msg)
        req = pr.encode_request(blob, agent_id, requested_at, sig)
        pr.verify_request(req, GID, NOW, SKEW, MAX_BLOB, allowlist, gate_keys)
        c = {"id": cid, "description": desc, "signer": signer, "agent_id": agent_id, "requested_at": str(requested_at)}
        if len(blob) > 1024:
            assert pattern_bytes(PATTERN, len(blob)) == blob
            c.update({"blob_pattern": PATTERN, "blob_size": str(len(blob))})
        else:
            c["blob_hex"] = blob.hex()
        c.update({"blob_sha256_hex": hashlib.sha256(blob).hexdigest(), "publish_message_hex": msg.hex(),
                  "signature_hex": sig.hex()})
        if len(blob) > 1024:
            c.update({"request_size": str(len(req)), "request_sha256_hex": hashlib.sha256(req).hexdigest()})
        else:
            c["request_cbor_hex"] = req.hex()
        cases.append(c)

    add("publish_small_blob", "The core ciphertext_hash_small_blob blob, signed by agent1 at now.", "agent1", "dca-agent-1",
        NOW, small_blob)
    add("publish_one_byte", "A 1-byte blob.", "agent1", "dca-agent-1", NOW - 10, b"\x00")
    add("publish_agent2", "agent2 under its own agent_id.", "agent2", "tia-transfer-agent", NOW + 5, small_blob)
    add("publish_window_edge_past", "requested_at = now - skew_s - 300, the oldest accepted.", "agent1", "dca-agent-1",
        NOW - SKEW - pr.PUBLISH_WINDOW_S, small_blob)
    add("publish_window_edge_future", "requested_at = now + skew_s + 300, the newest accepted.", "agent1", "dca-agent-1",
        NOW + SKEW + pr.PUBLISH_WINDOW_S, small_blob)
    add("publish_agent_id_64", "A 64-character agent_id, the longest.", "agent1", ID64, NOW, b"edicta")
    add("publish_max_blob", "A blob of exactly max_blob_bytes (1 MiB), given as a pattern.", "agent1", "dca-agent-1", NOW,
        pattern_bytes(PATTERN, MAX_BLOB))

    rej = []

    def r(cid, stage, rule, desc, req, expect, override=None):
        srv = dict(server, **(override or {}))
        al = {k: bytes.fromhex(v) for k, v in srv["allowlist"].items()}
        try:
            pr.verify_request(req, srv["gate_id"], int(srv["now"]), int(srv["skew_s"]), int(srv["max_blob_bytes"]), al,
                              [bytes.fromhex(k) for k in srv["gate_keys"]])
            raise AssertionError(cid)
        except Reject as e:
            assert e.sentinel == expect, (cid, e)
        v = {"id": cid, "stage": stage, "rule": rule, "description": desc, "request_cbor_hex": req.hex()}
        if override:
            v["server"] = override
        v["expect_error"] = expect
        rej.append(v)

    blob = small_blob
    aid = "dca-agent-1"

    def signed(agent_id=aid, at=NOW, b=blob, signer="agent1", msg=None):
        m = msg if msg is not None else pr.publish_message(GID, agent_id, at, b)
        return pr.encode_request(b, agent_id, at, sk(signer).sign(m))

    good = signed()
    sig = bytes.fromhex(good.hex())[-64:]

    r("pr_too_large", "D", "PR1", "max_blob_bytes 64 and a 65-byte blob.", signed(b=bytes(65)), "ErrTooLarge",
      {"max_blob_bytes": "64"})
    r("pr_trailing_byte", "D", "PR1", "A zero byte after the map.", good + b"\x00", "ErrTrailingData")
    r("pr_unknown_key", "D", "PR1", "Key 5 added.", encode({1: blob, 2: aid, 3: NOW, 4: sig, 5: 0}), "ErrUnknownKey")
    r("pr_missing_signature", "D", "PR1", "No key 4.", encode({1: blob, 2: aid, 3: NOW}), "ErrMissingField")
    r("pr_blob_empty", "D", "PR1", "Blob of 0 bytes.", signed(b=b""), "ErrFieldSize")
    r("pr_sig_63", "D", "PR1", "Signature of 63 bytes.", encode({1: blob, 2: aid, 3: NOW, 4: sig[:63]}), "ErrFieldSize")
    r("pr_agent_id_empty", "D", "PR1", "agent_id of 0 bytes.", encode({1: blob, 2: "", 3: NOW, 4: sig}), "ErrFieldSize")
    r("pr_agent_id_65", "D", "PR1", "agent_id of 65 bytes.", encode({1: blob, 2: "a" * 65, 3: NOW, 4: sig}), "ErrFieldSize")
    r("pr_agent_id_unicode", "D", "PR1", "agent_id with U+00E9.", encode({1: blob, 2: "dca-agént-1", 3: NOW, 4: sig}),
      "ErrInvalidString")
    r("pr_requested_at_float", "D", "PR1", "requested_at as a float64.",
      encode(Pairs(((1, blob), (2, aid), (3, Raw(b"\xfb" + bytes(8))), (4, sig)))), "ErrFloat")
    r("pr_keys_unsorted", "D", "PR1", "Key 2 before key 1.", encode(Pairs(((2, aid), (1, blob), (3, NOW), (4, sig)))),
      "ErrUnsortedMap")
    r("pr_requested_at_zero", "S", "PR2", "requested_at 0.", encode({1: blob, 2: aid, 3: 0, 4: sig}), "ErrZeroValue")
    r("pr_requested_at_2pow63", "S", "PR2", "requested_at 2^63.", encode({1: blob, 2: aid, 3: 1 << 63, 4: sig}), "ErrIntRange")
    r("pr_unknown_agent", "G", "PR3", "agent_id not in the allowlist, validly signed by agent1: same sentinel as a bad "
      "signature, so the endpoint is no allowlist oracle.", signed(agent_id="unknown-agent"), "edictaapi.ErrPublishSignature")
    r("pr_wrong_key", "G", "PR3", "agent1's id, signed by agent2.", signed(signer="agent2"), "edictaapi.ErrPublishSignature")
    r("pr_other_blob", "G", "PR3", "Signature over another blob.",
      pr.encode_request(blob, aid, NOW, sk("agent1").sign(pr.publish_message(GID, aid, NOW, b"\x00"))), "edictaapi.ErrPublishSignature")
    r("pr_other_requested_at", "G", "PR3", "Signature over requested_at - 1.",
      pr.encode_request(blob, aid, NOW, sk("agent1").sign(pr.publish_message(GID, aid, NOW - 1, blob))), "edictaapi.ErrPublishSignature")
    r("pr_other_agent_id", "G", "PR3", "agent2 signs for its own id, request names agent1's id with agent2 allowlisted there.",
      pr.encode_request(blob, aid, NOW, sk("agent2").sign(pr.publish_message(GID, "tia-transfer-agent", NOW, blob))),
      "edictaapi.ErrPublishSignature", {"allowlist": {aid: pk("agent2").hex()}})
    r("pr_other_gate_id", "G", "PR3", "Signed for gate_id other-edictad; this server's gate_id is edictad-1.",
      signed(msg=pr.publish_message("other-edictad", aid, NOW, blob)), "edictaapi.ErrPublishSignature")
    r("pr_no_gate_id", "G", "PR3", "Signed over the message without the gate_id field (the draft.10 layout).",
      signed(msg=tagged(pr.TAG_PUBLISH_REQUEST) + pr.publish_message(GID, aid, NOW, blob)[27 + len(GID):]),
      "edictaapi.ErrPublishSignature")
    r("pr_sig_untagged", "G", "PR3", "Signed without the tag.",
      signed(msg=pr.publish_message(GID, aid, NOW, blob)[26:]), "edictaapi.ErrPublishSignature")
    r("pr_sig_under_commitment_tag", "G", "PR3", "Signed under edicta/v0/sig over SHA-256 of the publish message.",
      signed(msg=signing_message(hashlib.sha256(pr.publish_message(GID, aid, NOW, blob)).digest())), "edictaapi.ErrPublishSignature")
    r("pr_sig_hashed_message", "G", "PR3", "Signed over SHA-256 of the publish message.",
      signed(msg=hashlib.sha256(pr.publish_message(GID, aid, NOW, blob)).digest()), "edictaapi.ErrPublishSignature")
    r("pr_sig_record_request_tag", "G", "PR3", "The same layout under edicta/v0/record-request.",
      signed(msg=tagged(b"edicta/v0/record-request") + pr.publish_message(GID, aid, NOW, blob)[26:]), "edictaapi.ErrPublishSignature")
    s_bad = sig[:32] + (int.from_bytes(sig[32:], "little") + 2**252 + 27742317777372353535851937790883648493).to_bytes(32, "little")
    r("pr_sig_noncanonical_s", "G", "PR3", "S + L in place of S.", encode({1: blob, 2: aid, 3: NOW, 4: s_bad}),
      "edictaapi.ErrPublishSignature")
    identity = (1).to_bytes(32, "little")
    r("pr_allowlisted_identity_key", "G", "PR3", "The allowlist maps the id to the identity point; R = identity, S = 0 "
      "verifies the plain equation for every message, so the key check must run.",
      encode({1: blob, 2: aid, 3: NOW, 4: identity + bytes(32)}), "edictaapi.ErrPublishSignature",
      {"allowlist": {aid: identity.hex()}})
    r("pr_gate_key", "L", "PR4", "The allowlisted key is the gate key and the request is signed with it.",
      signed(signer="gate1"), "ErrAgentKeyIsGateKey", {"allowlist": {aid: pk("gate1").hex()}})
    r("pr_stale_past", "W", "PR5", "requested_at one second older than the window.", signed(at=NOW - SKEW - pr.PUBLISH_WINDOW_S - 1),
      "edictaapi.ErrPublishStale")
    r("pr_stale_future", "W", "PR5", "requested_at one second newer than the window.", signed(at=NOW + SKEW + pr.PUBLISH_WINDOW_S + 1),
      "edictaapi.ErrPublishStale")
    r("pr_bad_sig_and_stale", "G", "PR3", "Wrong key and stale: the signature check comes first.",
      signed(at=NOW - 10000, signer="agent2"), "edictaapi.ErrPublishSignature")

    valid = json.loads((CORE / "valid.json").read_text())
    resp = []
    for cid, bt in (("minimal_lmt", T0 + 30),):
        cin = commitment_from_json(next(c for c in valid["cases"] if c["id"] == cid)["input"])
        ref = pr.payload_ref_cbor(cin["payload_ref"])
        env = bytes.fromhex(next(c for c in valid["cases"] if c["id"] == cid)["envelope_hex"])
        _, canon = decode_signed(env)
        assert ref in canon
        assert pr.decode_payload_ref(ref) == cin["payload_ref"]
        body = pr.encode_response(ref, bt, 0)
        resp.append({"id": f"response_{cid}", "description": f"The payload_ref of core vector {cid}, da = 2, so "
                     "retention_start is 0 and present.", "commitment_ref": cid, "payload_ref_cbor_hex": ref.hex(),
                     "block_time": str(bt), "retention_start": "0", "response_cbor_hex": body.hex()})

    out = {"format": FORMAT, "revision": REVISION,
           "tag": {"ascii": pr.TAG_PUBLISH_REQUEST.decode(), "tagged_hex": tagged(pr.TAG_PUBLISH_REQUEST).hex()},
           "publish_window_s": str(pr.PUBLISH_WINDOW_S), "request_overhead": str(pr.REQUEST_OVERHEAD),
           "patterns": {PATTERN: "byte i of the blob is (7*i + 3) mod 256, for i from 0"},
           "server": server, "cases": cases, "reject": rej, "response": resp}
    OUT.mkdir(parents=True, exist_ok=True)
    path = OUT / "publish_request.json"
    path.write_text(json.dumps(out, indent=2, ensure_ascii=True) + "\n")
    print(f"wrote {path}")


if __name__ == "__main__":
    main()
