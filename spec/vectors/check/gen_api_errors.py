#!/usr/bin/env python3
"""Generates spec/vectors/api/errors.json: the HTTP error mapping of core section 18
(v0-draft.17) with the additive codes of core v1 section 13 (v1-draft.2), and example
request and response bytes per endpoint. Deterministic.

Usage: python3 spec/vectors/check/gen_api_errors.py [--core DIR] [--out DIR]
Defaults: --core spec/vectors/v0; --out spec/vectors/api.
"""

from __future__ import annotations

import sys

sys.dont_write_bytecode = True

import hashlib
import json
from pathlib import Path

from cbor_strict import encode

HERE = Path(__file__).resolve().parent
VECTORS = HERE.parent


def arg(name: str, default: Path) -> Path:
    if name in sys.argv:
        return Path(sys.argv[sys.argv.index(name) + 1]).resolve()
    return default


CORE = arg("--core", VECTORS / "v0")
OUT = arg("--out", VECTORS / "api")
V1 = arg("--v1", VECTORS / "v1")
FORMAT = "edicta-vectors/v0"
REVISION = "v1-draft.2"

P, A, R, H = "/v0/publish", "/v0/authorize", "/v0/record", "/v0/health"
A1 = "/v1/authorize"
POSTS = [P, A, R]
ALL = [P, A, R, H]

STATUSES = {400: 0, 401: 0, 403: 0, 404: 0, 405: 0, 409: 0, 410: 0, 413: 0, 415: 0, 422: 0, 425: 1, 429: 1,
            500: 0, 502: 0, 503: 1, 504: 1}

STAGE_D = ["ErrMalformed", "ErrTrailingData", "ErrFloat", "ErrSimpleValue", "ErrTag", "ErrIndefiniteLength",
           "ErrNonMinimalInt", "ErrNestingTooDeep", "ErrUnsortedMap", "ErrDuplicateKey", "ErrKeyType", "ErrInvalidString",
           "ErrUnknownKey", "ErrWrongType", "ErrMissingField", "ErrFieldSize", "ErrNonCanonical"]

# (code, status, stored, endpoints, rules), in match order.
ERRORS = [
    ("ErrAnchorTooOld", 410, "none", [A], "8.5, K2"),
    ("ErrExpired", 410, "none", [A], "T2"),
    ("edictaapi.ErrPublishStale", 410, "none", [P], "PR5"),
    *[(c, 400, "none", POSTS, "stage D, wrapper decoding") for c in STAGE_D],
    ("ErrUnsupportedVersion", 400, "none", [A], "S1"),
    ("ErrIntRange", 400, "none", [P, A], "S2, PR2"),
    ("ErrInvalidEnum", 400, "none", [A], "S3"),
    ("ErrZeroValue", 400, "none", [P, A], "S6, PR2"),
    ("ErrPayloadTooLarge", 400, "none", [A], "S7"),
    ("ErrInvalidNamespace", 400, "none", [A], "S8"),
    ("ErrTimeOrder", 400, "none", [A], "S12"),
    ("ErrActionSize", 400, "none", [A], "A0"),
    ("edictaapi.ErrTokenInvalid", 401, "none", ALL, "18.1"),
    ("edictaapi.ErrPublishSignature", 401, "none", [P], "PR3"),
    ("ErrInvalidPublicKey", 403, "none", [A, R], "G0, RQ2"),
    ("ErrSignatureInvalid", 403, "none", [A, R], "G1, G2, RQ2"),
    ("ErrScopeMismatch", 403, "none", [A], "C1"),
    ("ErrActionTypeNotAllowed", 403, "none", [A], "C2"),
    ("ErrDANotAllowed", 403, "none", [A], "C3"),
    ("ErrAgentKeyIsGateKey", 403, "none", [A, P], "L0, PR4"),
    ("ErrAgentNotAllowed", 403, "none", [A], "L1"),
    ("ErrAgentKeyMismatch", 403, "none", [A], "L2"),
    ("ErrExecutorNotAllowed", 403, "none", [R], "RQ3"),
    ("ErrKeyRole", 403, "none", [R], "RQ4"),
    ("edictaapi.ErrRouteNotFound", 404, "none", ALL, "18.1"),
    ("edictaapi.ErrPublishDisabled", 404, "none", [P], "18.2"),
    ("edictaapi.ErrMethodNotAllowed", 405, "none", ALL, "18.1"),
    ("ErrNonceUsed", 409, "authorization", [A], "N1, retry rule 8.7"),
    ("ErrReceiptExists", 409, "receipt", [R], "RQ6"),
    ("ErrBeforeRegistryEpoch", 409, "none", [A], "E1"),
    ("ErrTooLarge", 413, "none", POSTS, "18.1, D0, PR1"),
    ("recorder.ErrTooLarge", 413, "none", [P], "Recorder limit"),
    ("ErrPayloadAboveCap", 413, "none", [A], "C4, Fibre payload limit"),
    ("edictaapi.ErrMediaType", 415, "none", POSTS, "18.1"),
    ("ErrActionMismatch", 422, "none", [A], "A1, retry rule 8.7"),
    ("ErrPayloadSizeMismatch", 422, "none", [A], "P1"),
    ("ErrPayloadHashMismatch", 422, "none", [A], "P2"),
    ("ErrDACommitmentMismatch", 422, "none", [A], "P3"),
    ("ErrArchiveRecomputeUnsupported", 422, "none", [A], "P3, K2 routing"),
    ("ErrIssuedBeforeAnchor", 422, "none", [A], "K1"),
    ("ErrTTLTooLong", 422, "none", [A], "S14"),
    ("ErrNotAuthorized", 422, "none", [R], "RQ5"),
    ("ErrNotYetValid", 425, "none", [A], "T1"),
    ("ErrAnchorNotFound", 425, "none", [A], "K0"),
    ("edictaapi.ErrQuotaExceeded", 429, "none", [P], "PR7"),
    ("recorder.ErrSignerMismatch", 502, "none", [P], "Recorder read-back"),
    ("recorder.ErrSubmitMismatch", 502, "none", [P], "Recorder Fibre submit result"),
    ("ErrPayloadUnavailable", 503, "none", [A], "8.5"),
    ("ErrRetentionUnavailable", 503, "none", [A], "K2"),
    ("ErrChainUnavailable", 503, "none", [P, A], "operational"),
    ("ErrAllowlistUnavailable", 503, "none", [P, A], "operational"),
    ("ErrRegistryUnavailable", 503, "none", [A, R], "operational"),
    ("ErrClockRegression", 503, "none", [A, R], "operational"),
    ("ErrClosed", 503, "none", ALL, "operational"),
    ("recorder.ErrOutcomeUnknown", 503, "none", [P], "PR6"),
    ("recorder.ErrNodeUnavailable", 503, "none", [P], "Recorder node read"),
    ("recorder.ErrTooManyPending", 503, "none", [P], "PR6, unresolved submissions"),
    ("recorder.ErrNotVisible", 503, "none", [P], "Recorder read-back"),
    ("ErrArchiveUnavailable", 503, "none", [A], "AR3, archive before authorize"),
    ("recorder.ErrArchiveUnavailable", 503, "none", [P], "Recorder archive write"),
    ("recorder.ErrEscrowInsufficient", 503, "none", [P], "Recorder Fibre escrow preflight"),
    ("edictaapi.ErrDeadline", 504, "none", ALL, "18.3"),
    ("edictaapi.ErrInternal", 500, "none", ALL, "18.3"),
]

# Core v1 section 13: these wrap no core sentinel and match after every existing code of their status, in
# this order. policy.ErrFastModeNotAllowed is matched with the policy codes (spec/vectors/policy/api.json).
V1_ERRORS = [
    ("ErrVersionNotAccepted", 403, "none", [A, A1], "core v1 V0"),
    ("ErrAnchorPending", 403, "none", [A, A1], "core v1 C5a"),
    ("ErrNamespaceNotAllowed", 403, "none", [A, A1], "core v1 C5b"),
    ("ErrMandateRefMissing", 403, "none", [A, A1], "core v1 M1"),
    ("ErrMandateMismatch", 403, "none", [A, A1], "core v1 M2"),
    ("ErrH0TooOld", 410, "none", [A, A1], "core v1 F5, B4"),
    ("ErrAnchorWindowClosed", 410, "none", [A, A1], "core v1 F5, F6, B4, B5"),
    ("ErrAnchorIntentInvalid", 422, "none", [A, A1], "core v1 F2, B2"),
    ("ErrCertInvalid", 422, "none", [A, A1], "core v1 F4"),
    ("ErrAnchorIntentUnavailable", 503, "none", [A, A1], "core v1 F1, B1"),
    ("ErrAnchorIntentRejected", 503, "none", [A, A1], "core v1 F6, B5"),
]
for _e in V1_ERRORS:
    _at = max(i for i, x in enumerate(ERRORS) if x[1] == _e[1])
    _run = [i for i in range(_at + 1, len(ERRORS)) if ERRORS[i][1] == _e[1]]
    ERRORS.insert((_run[-1] if _run else _at) + 1, _e)

REMOVED = "removed in draft.9; never reported"
CLIENT = "client side (SDK producer checks or payload opening); never crosses the API"
PROFILE = "dca-agent profile, executor side; never crosses the API"
NOT_API = {
    "ErrInvalidParams": "the gate's own parameters; reported as edictaapi.ErrInternal",
    "ErrFastModeRefused": "profile executors (core v1 6.3); never crosses the API",
    **{n: REMOVED for n in ["ErrUnsupportedActionKind", "ErrUnsupportedRail", "ErrUnsupportedOrderType", "ErrLimitPrice",
                            "ErrAccountMismatch", "ErrChainIDRule", "ErrDeadlineRange", "ErrPriceBound",
                            "ErrNotionalExceeded"]},
    **{n: CLIENT for n in ["blob.ErrTooLarge", "blob.ErrMalformed", "blob.ErrVersion", "blob.ErrRecipients",
                           "blob.ErrDuplicateKID", "blob.ErrNoRecipient", "blob.ErrUnwrap", "blob.ErrDecrypt",
                           "payload.ErrMalformed", "payload.ErrVersion", "payload.ErrTooLarge",
                           "sdk.ErrPlaintextHashMismatch", "sdk.ErrPayloadMismatch", "sdk.ErrDACommitmentMismatch",
                           "sdk.ErrDACheckUnavailable", "sdk.ErrInclusionUnverified", "sdk.ErrBlockTimeMismatch",
                           "sdk.ErrUnexpectedRef", "sdk.ErrPublishTimeout"]},
    **{n: PROFILE for n in ["dca.ErrMalformed", "ibkrorder.ErrMalformed", "ibkrorder.ErrInvalid",
                            "ibkr.ErrAccountMismatch", "ibkr.ErrRiskLimit"]},
}

MESSAGES = {
    "ErrNonceUsed": "gate: nonce already used",
    "ErrReceiptExists": "gate: receipt already recorded",
    "ErrActionMismatch": "commitment: action bytes do not match action.hash",
    "ErrTrailingData": "commitment: trailing data",
    "edictaapi.ErrQuotaExceeded": "edictaapi: quota exceeded for this agent",
    "edictaapi.ErrMediaType": "edictaapi: content type must be application/cbor",
    "ErrChainUnavailable": "gate: chain data unavailable",
    "ErrAnchorPending": "gate: pending payload reference and fast mode is off",
    "ErrVersionNotAccepted": "gate: commitment version not accepted",
}


def error_body(code: str, stored: bytes | None = None) -> bytes:
    status = next(e[1] for e in ERRORS if e[0] == code)
    m = {1: code, 2: MESSAGES[code], 3: STATUSES[status]}
    if stored is not None:
        m[4] = stored
    return encode(m)


def by_id(items, key):
    return {c["id"]: c for c in items[key]}


def main():
    valid = by_id(json.loads((CORE / "valid.json").read_text()), "cases")
    auth = by_id(json.loads((CORE / "authorization.json").read_text()), "cases")
    rcp = by_id(json.loads((CORE / "receipt.json").read_text()), "cases")
    keys = json.loads((CORE / "keys.json").read_text())["keys"]
    pub = json.loads((OUT / "publish_request.json").read_text())

    v = valid["minimal_lmt"]
    env, action = bytes.fromhex(v["envelope_hex"]), bytes.fromhex(v["action_hex"])
    sa = bytes.fromhex(auth["auth_minimal_lmt_da"]["signed_authorization_hex"])
    other = valid["ttl_exactly_max"]
    r = rcp["receipt_minimal_lmt"]
    ri = r["input"]
    pub_case = next(c for c in pub["cases"] if c["id"] == "publish_small_blob")
    pub_resp = next(c for c in pub["response"] if c["id"] == "response_minimal_lmt")
    assert hashlib.sha256(bytes.fromhex(pub_case["blob_hex"])).hexdigest() == v["input"]["ciphertext_hash"]

    authorize_req = encode({1: env, 2: action})
    examples = [
        {"id": "authorize_ok", "endpoint": A, "method": "POST", "description": "minimal_lmt with its action; the answer is "
         "the SignedAuthorization of core vector auth_minimal_lmt_da.", "commitment_ref": "minimal_lmt",
         "authorization_ref": "auth_minimal_lmt_da", "request_cbor_hex": authorize_req.hex(), "status": "200",
         "response_cbor_hex": encode({1: sa}).hex()},
        {"id": "authorize_retry_same_commitment", "endpoint": A, "method": "POST", "description": "The same request again "
         "after the nonce was consumed: the retry rule holds, so 409 carries the stored Authorization.",
         "commitment_ref": "minimal_lmt", "authorization_ref": "auth_minimal_lmt_da",
         "request_cbor_hex": authorize_req.hex(), "status": "409", "response_cbor_hex": error_body("ErrNonceUsed", sa).hex()},
        {"id": "authorize_nonce_used_other_commitment", "endpoint": A, "method": "POST", "description": "A "
         "commitment whose (agent_pubkey, nonce) registry entry holds another commitment_hash (state assumed): 409 "
         "without stored bytes.",
         "commitment_ref": other["id"], "request_cbor_hex": encode({1: bytes.fromhex(other["envelope_hex"]),
                                                                       2: bytes.fromhex(other["action_hex"])}).hex(),
         "status": "409", "response_cbor_hex": error_body("ErrNonceUsed").hex()},
        {"id": "authorize_action_mismatch", "endpoint": A, "method": "POST", "description": "minimal_lmt with one action "
         "byte flipped: stage A, 422, whether or not the nonce is used.", "commitment_ref": "minimal_lmt",
         "request_cbor_hex": encode({1: env, 2: action[:-1] + bytes([action[-1] ^ 1])}).hex(), "status": "422",
         "response_cbor_hex": error_body("ErrActionMismatch").hex()},
        {"id": "authorize_trailing_byte", "endpoint": A, "method": "POST", "description": "Wrapper followed by one zero "
         "byte: 400.", "request_cbor_hex": (authorize_req + b"\x00").hex(), "status": "400",
         "response_cbor_hex": error_body("ErrTrailingData").hex()},
        {"id": "authorize_chain_down", "endpoint": A, "method": "POST", "description": "The node is unreachable: 503, "
         "retryable, nothing consumed.", "commitment_ref": "minimal_lmt", "request_cbor_hex": authorize_req.hex(),
         "status": "503", "response_cbor_hex": error_body("ErrChainUnavailable").hex()},
        {"id": "record_ok", "endpoint": R, "method": "POST", "description": "The record request of core receipt vector "
         "receipt_minimal_lmt; the answer is that SignedReceipt.", "commitment_ref": "minimal_lmt",
         "receipt_ref": "receipt_minimal_lmt",
         "request_cbor_hex": encode({1: env, 2: ri["rail_ref"], 3: bytes.fromhex(ri["executor_pubkey"]),
                                     4: bytes.fromhex(ri["executor_signature"])}).hex(),
         "status": "200", "response_cbor_hex": encode({1: bytes.fromhex(r["signed_receipt_hex"])}).hex()},
        {"id": "record_exists", "endpoint": R, "method": "POST", "description": "The same record request again: 409 with "
         "the stored receipt.", "commitment_ref": "minimal_lmt", "receipt_ref": "receipt_minimal_lmt",
         "request_cbor_hex": encode({1: env, 2: ri["rail_ref"], 3: bytes.fromhex(ri["executor_pubkey"]),
                                     4: bytes.fromhex(ri["executor_signature"])}).hex(),
         "status": "409", "response_cbor_hex": error_body("ErrReceiptExists", bytes.fromhex(r["signed_receipt_hex"])).hex()},
        {"id": "publish_ok", "endpoint": P, "method": "POST", "description": "publish_request.json publish_small_blob (the "
         "minimal_lmt blob); the answer is response_minimal_lmt.", "publish_ref": "publish_small_blob",
         "response_ref": "response_minimal_lmt", "request_cbor_hex": pub_case["request_cbor_hex"], "status": "200",
         "response_cbor_hex": pub_resp["response_cbor_hex"]},
        {"id": "publish_quota", "endpoint": P, "method": "POST", "description": "Quota exhausted: 429, retryable, with a "
         "Retry-After header.", "publish_ref": "publish_small_blob", "request_cbor_hex": pub_case["request_cbor_hex"],
         "status": "429", "response_cbor_hex": error_body("edictaapi.ErrQuotaExceeded").hex()},
        {"id": "publish_wrong_media_type", "endpoint": P, "method": "POST", "description": "Content-Type application/json: "
         "415 before the body is read.", "content_type": "application/json",
         "request_cbor_hex": pub_case["request_cbor_hex"], "status": "415",
         "response_cbor_hex": error_body("edictaapi.ErrMediaType").hex()},
    ]
    ns = bytes(19) + b"edicta/d01"
    signer = hashlib.sha256(b"edicta/v0 test recorder account").digest()[:20]
    health = {1: 1, 2: "mocha-4", 3: 6543260, 4: 1791000064, 5: "gate-paper-1", 6: bytes.fromhex(keys["gate1"]["public_key_hex"]),
              7: signer, 8: ns, 9: [2]}
    examples.append({"id": "health_ok", "endpoint": H, "method": "GET", "description": "Recorder enabled, da = 2 only.",
                     "status": "200", "response_cbor_hex": encode(health).hex()})
    health_off = {k: x for k, x in health.items() if k not in (7, 8)}
    health_off[1] = 2
    health_off[9] = [1, 2]
    examples.append({"id": "health_degraded_no_recorder", "endpoint": H, "method": "GET", "description": "Degraded, "
                     "Recorder disabled (keys 7 and 8 absent), both DA types allowed.", "status": "200",
                     "response_cbor_hex": encode(health_off).hex()})

    v1valid = by_id(json.loads((V1 / "valid.json").read_text()), "cases")
    v1auth = by_id(json.loads((V1 / "authorization.json").read_text()), "cases")
    vb = v1valid["v1_minimal_included_blob"]
    v1_req = encode({1: bytes.fromhex(vb["envelope_hex"]), 2: bytes.fromhex(vb["action_hex"])})
    v1_resp = encode({1: bytes.fromhex(v1auth["auth_v1_strict_da"]["signed_authorization_hex"])})
    vp = v1valid["v1_pending_blob"]
    for path, ident, desc in ((A, "authorize_v1_on_v0_path", "A v1 envelope on /v0/authorize: the version comes "
                               "from the signed bytes, so the answer is the Authorization v1 of auth_v1_strict_da."),
                              (A1, "authorize_v1_alias", "The same request on the alias /v1/authorize: same handler, "
                               "same answer.")):
        examples.append({"id": ident, "endpoint": path, "method": "POST", "description": desc, "vectors": "v1",
                         "commitment_ref": "v1_minimal_included_blob", "authorization_ref": "auth_v1_strict_da",
                         "request_cbor_hex": v1_req.hex(), "status": "200", "response_cbor_hex": v1_resp.hex()})
    examples.append({"id": "authorize_v0_alias_version_not_accepted", "endpoint": A1, "method": "POST",
                     "description": "minimal_lmt (v0) on /v1/authorize at a gate with AcceptV0 false: 403.",
                     "commitment_ref": "minimal_lmt", "request_cbor_hex": authorize_req.hex(), "status": "403",
                     "response_cbor_hex": error_body("ErrVersionNotAccepted").hex()})
    examples.append({"id": "authorize_pending_fast_mode_off", "endpoint": A, "method": "POST", "description":
                     "v1_pending_blob at a gate whose FastMode is off: 403, nothing written.", "vectors": "v1",
                     "commitment_ref": "v1_pending_blob",
                     "request_cbor_hex": encode({1: bytes.fromhex(vp["envelope_hex"]),
                                                 2: bytes.fromhex(vp["action_hex"])}).hex(),
                     "status": "403", "response_cbor_hex": error_body("ErrAnchorPending").hex()})

    out = {"format": FORMAT, "revision": REVISION, "content_type": "application/cbor",
           "endpoints": {"publish": {"method": "POST", "path": P, "request_limit": "max_blob_bytes + 256"},
                         "authorize": {"method": "POST", "path": A, "request_limit": "67736"},
                         "authorize_v1_alias": {"method": "POST", "path": A1, "request_limit": "67736",
                                                "alias_of": A},
                         "record": {"method": "POST", "path": R, "request_limit": "2560"},
                         "health": {"method": "GET", "path": H}},
           "statuses": {str(k): {"retryable": str(x)} for k, x in STATUSES.items()},
           "errors": [{"code": c, "status": str(st), "retryable": str(STATUSES[st]), "stored": sto, "endpoints": eps,
                       "rules": rules} for c, st, sto, eps, rules in ERRORS],
           "not_api_visible": [{"name": n, "reason": why} for n, why in NOT_API.items()],
           "examples": examples}
    OUT.mkdir(parents=True, exist_ok=True)
    path = OUT / "errors.json"
    path.write_text(json.dumps(out, indent=2, ensure_ascii=True) + "\n")
    print(f"wrote {path}")


if __name__ == "__main__":
    main()
