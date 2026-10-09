#!/usr/bin/env python3
"""Writes spec/vectors/v1/archive.json and spec/vectors/v1/verify.json (v1-draft.2). Deterministic.

Records of kinds 13, 14 (small synthetic proof parts: the record layer never
verifies them; da/absence.json carries real ones), 15 (taken from
policy/private.json), decision and Authorization records of v1 decisions
with K2 input key 9, and the rejects of core v1 section 15. verify.json
gives the outcome of the authorization, anchor and retention_replay checks
for a v1 decision from archived records plus abstract evidence and absence
results (whose bytes are vectored in the core files and in da/absence.json).

Usage: python3 spec/vectors/check/gen_archive_v1.py [--out DIR]
"""

from __future__ import annotations

import sys

sys.dont_write_bytecode = True

import hashlib
import json
from pathlib import Path

import archive_v0 as a0
import archive_v1 as A
import edicta_v0 as v0
import edicta_v1 as v1
import gen_vectors as g
import gen_vectors_v1 as gv
from cbor_strict import encode
from edicta_v0 import Reject

VECTORS = Path(__file__).resolve().parent.parent
OUT = VECTORS / "v1"
if "--out" in sys.argv:
    OUT = Path(sys.argv[sys.argv.index("--out") + 1]).resolve()
FORMAT, REVISION = "edicta-vectors/v1", "v1-draft.2"
T0, NOW = g.T0, g.NOW
WINDOW = 3
T_REF = T0 - 12
CREATED = T0 - 20


def ph(label: str, size: int) -> bytes:
    return a0.placeholder("v1 " + label, size)


def js(x):
    if isinstance(x, bool) or x is None:
        return x
    if isinstance(x, int):
        return str(x)
    if isinstance(x, (bytes, bytearray)):
        return bytes(x).hex()
    if isinstance(x, dict):
        return {str(k): js(v) for k, v in x.items()}
    if isinstance(x, list):
        return [js(v) for v in x]
    return x


def valid(ref: str):
    c, canon, at, act = gv.VALID[ref]
    sig = gv.sign_v1(canon)[2]
    return c, gv.env(canon, sig), act


def auth(ref: str, mode: int, deadline: int | None, path: int = v0.PATH_DA, version: int = 1) -> bytes:
    a = gv.base_auth(ref, path, mode, deadline)
    if version == 0:
        a = {k: x for k, x in a.items() if k not in ("mode", "anchor_deadline")} | {"version": 0}
        canon = encode(v0.to_cbor(a, v0.AUTHORIZATION))
        return bytes.fromhex(gv.auth_fields(None, canon, "v0")["signed_authorization_hex"])
    return bytes.fromhex(gv.auth_fields(None, gv.auth_canon(a))["signed_authorization_hex"])


def k2_fibre(fast_window: int | None = None, block_time: int = T_REF) -> dict:
    k = {"da": 1, "checked_at": NOW, "block_time": block_time, "retention_latest_s": 14400,
         "retention_at_height_s": 14400, "retention_source": a0.SOURCE_DIRECT, "promise_created": CREATED}
    if fast_window is not None:
        k["fast_window"] = fast_window
    return k


def k2_blob(fast_window: int | None = None) -> dict:
    k = {"da": 2, "checked_at": NOW, "block_time": T_REF, "blob_retention_s": 14400}
    if fast_window is not None:
        k["fast_window"] = fast_window
    return k


def records() -> dict:
    """name -> (named record, description)."""
    out = {}
    pf, pf_env, pf_act = valid("v1_pending_fibre")
    pb, pb_env, pb_act = valid("v1_pending_blob")
    inc, inc_env, inc_act = valid("v1_minimal_included_fibre")
    h0f, h0b = pf["payload_ref"]["height"], pb["payload_ref"]["height"]
    out["decision_pending_fibre"] = ({"kind": 3, "envelope": pf_env, "action": pf_act},
                                     "Decision record of v1_pending_fibre (v1 envelope, decoded by its version).")
    out["decision_pending_blob"] = ({"kind": 3, "envelope": pb_env, "action": pb_act},
                                    "Decision record of v1_pending_blob.")
    out["decision_included_fibre"] = ({"kind": 3, "envelope": inc_env, "action": inc_act},
                                      "Decision record of v1_minimal_included_fibre.")
    out["authorization_fast_fibre"] = (
        {"kind": 4, "signed_authorization": auth("v1_pending_fibre", 2, h0f + WINDOW), "authorized_at": NOW,
         "k2": k2_fibre(WINDOW)},
        f"Authorization v1, mode 2, anchor_deadline h0 + {WINDOW}; K2 inputs with fast_window {WINDOW} and "
        "block_time = T_ref.")
    out["authorization_fast_blob"] = (
        {"kind": 4, "signed_authorization": auth("v1_pending_blob", 2, h0b + WINDOW), "authorized_at": NOW,
         "k2": k2_blob(WINDOW)}, "Authorization v1 for the pending blob reference, fast_window 3.")
    out["authorization_strict_fibre"] = (
        {"kind": 4, "signed_authorization": auth("v1_minimal_included_fibre", 1, None), "authorized_at": NOW,
         "k2": k2_fibre()}, "Authorization v1, mode 1 (included reference): K2 without key 9.")
    out["intent_fibre"] = (
        {"kind": 13, "da": 1, "commitment": pf["payload_ref"]["commitment"], "namespace": pf["payload_ref"]["namespace"],
         "ref_height": h0f, "tx": ph("intent fibre tx", 320), "created_at": CREATED},
        "Anchor intent, da = 1: tx is a placeholder (the record layer does not parse it); no signer key.")
    out["intent_blob"] = (
        {"kind": 13, "da": 2, "commitment": pb["payload_ref"]["commitment"], "namespace": pb["payload_ref"]["namespace"],
         "ref_height": h0b, "tx": ph("intent blob tx", 400), "signer": pb["payload_ref"]["signer"],
         "created_at": T0 - 5}, "Anchor intent, da = 2, with the signer (= payload_ref.signer).")
    out["absence_fibre_no_rows"] = (
        {"kind": 14, "da": 1, "commitment": pf["payload_ref"]["commitment"], "namespace": pf["payload_ref"]["namespace"],
         "height": h0f, "header": ph("absence header", 600), "dah": ph("absence dah", 1536), "namespace_data": b""},
        "Absence proof, da = 1: no row holds PFF_NS, so namespace_data is empty (size 0 is allowed).")
    out["absence_fibre_with_results"] = (
        {"kind": 14, "da": 1, "commitment": pf["payload_ref"]["commitment"], "namespace": pf["payload_ref"]["namespace"],
         "height": h0f + 1, "header": ph("absence header 2", 600), "dah": ph("absence dah 2", 1536),
         "namespace_data": ph("absence nsdata", 700), "results": ph("absence results", 256),
         "next_header": ph("absence next header", 600)},
        "Absence proof, da = 1, with a candidate: results and next_header present together.")
    out["absence_blob"] = (
        {"kind": 14, "da": 2, "commitment": pb["payload_ref"]["commitment"], "namespace": pb["payload_ref"]["namespace"],
         "height": h0b, "header": ph("absence blob header", 600), "dah": ph("absence blob dah", 1536),
         "namespace_data": ph("absence blob nsdata", 512)}, "Absence proof, da = 2 (results are not defined).")
    priv = json.loads((VECTORS / "policy" / "private.json").read_text())
    pp = next(e for e in priv["envelopes"] if e["plaintext_kind"] == "4")
    rec = A.decode_record(bytes.fromhex(pp["record_cbor_hex"]))
    out["private_part"] = (rec, "Kind 15 PrivatePart record, the same bytes as policy/private.json envelope_private_part.")
    for err in ("ErrMandateMismatch", "ErrH0TooOld", "ErrAnchorWindowClosed", "ErrFastModeNotAllowed"):
        out[f"rejection_{err}"] = ({"kind": 5, "commitment_hash": v1.commitment_hash_v1(gv.VALID["v1_pending_fibre"][1]),
                                    "error": err, "gate_id": g.GID, "rejected_at": NOW},
                                   f"Rejection marker {err} (core v1 11.3).")
    return out


def v0_reader(b: bytes) -> str:
    try:
        a0.decode_record(b)
        return "accepts"
    except Reject as e:
        return e.sentinel


def archive_vectors() -> tuple:
    recs = records()
    cases, by_name = [], {}
    for name, (r, desc) in recs.items():
        b = A.encode_record(r)
        assert A.decode_record(b) == r, name
        key = A.record_key(r)
        path = A.key_path(key)
        by_name[name] = (r, b, path)
        cases.append({"id": name, "description": desc, "kind": str(r["kind"]), "path": path, "input": js(r),
                      "record_cbor_hex": b.hex(), "v0_reader": v0_reader(b)})
    ik = lambda n: a0._to_int_keys({"format": 0, **by_name[n][0]}, A.schema_of(by_name[n][0]["kind"]))  # noqa: E731

    def mut(n, drop=(), k2=None, **kw):
        m = ik(n)
        for d in drop:
            m.pop(d)
        m.update({int(k[1:]): x for k, x in kw.items()})
        if k2 is not None:
            m[5] = k2
        return encode(m)

    k2f = ik("authorization_fast_fibre")[5]
    k2s = ik("authorization_strict_fibre")[5]
    over = ik("intent_fibre")
    over[7] = ph("intent over cap", 65600 - 120)
    while len(encode(over)) <= 65600:
        over[7] = over[7] + b"\x00"
    rej = [
        ("signer_on_fibre_intent", "Kind 13, da = 1 with key 8 (signer is defined for da = 2 only).",
         mut("intent_fibre", k8=b"\x01" * 20)),
        ("missing_signer_blob_intent", "Kind 13, da = 2 without key 8.", mut("intent_blob", drop=(8,))),
        ("intent_ref_height_0", "Kind 13 ref_height 0.", mut("intent_fibre", k6=0)),
        ("intent_created_at_0", "Kind 13 created_at 0.", mut("intent_fibre", k9=0)),
        ("intent_tx_empty", "Kind 13 with an empty tx.", mut("intent_fibre", k7=b"")),
        ("intent_da_3", "Kind 13 da = 3.", mut("intent_fibre", k3=3)),
        ("intent_over_cap", "Kind 13 of 65,601 bytes.", encode(over)),
        ("fast_window_on_strict", "Kind 4 with an Authorization in mode 1 and K2 key 9.",
         mut("authorization_strict_fibre", k2={**k2s, 9: 3})),
        ("fast_window_missing_on_fast", "Kind 4 with an Authorization in mode 2 and K2 without key 9.",
         mut("authorization_fast_fibre", k2={k: x for k, x in k2f.items() if k != 9})),
        ("fast_window_0", "K2 fast_window 0.", mut("authorization_fast_fibre", k2={**k2f, 9: 0})),
        ("fast_window_1001", "K2 fast_window 1001.", mut("authorization_fast_fibre", k2={**k2f, 9: 1001})),
        ("absence_next_header_without_results", "Kind 14 with next_header and no results.",
         mut("absence_fibre_with_results", drop=(10,))),
        ("absence_results_without_next_header", "Kind 14 with results and no next_header.",
         mut("absence_fibre_with_results", drop=(11,))),
        ("absence_results_on_blob", "Kind 14, da = 2, with results.", mut("absence_blob", k10=b"\x01", k11=b"\x01")),
        ("absence_height_0", "Kind 14 height 0.", mut("absence_blob", k6=0)),
        ("private_plaintext_kind_5", "Kind 15 plaintext_kind 5.", mut("private_part", k3=5)),
        ("rejection_not_a_marker", "Kind 5 with ErrVersionNotAccepted: a stage 1 refusal, never a marker.",
         mut("rejection_ErrH0TooOld", k4="ErrVersionNotAccepted")),
        ("kind_16_reserved", "Kind 16 (reserved for the batch record): undefined.", encode({1: 0, 2: 16, 3: b"\x01"})),
        ("kind_6_reserved", "Kind 6 stays undefined.", encode({1: 0, 2: 6, 3: b"\x01"})),
    ]
    out = []
    for i, d, b in rej:
        try:
            A.decode_record(b)
            raise AssertionError(i)
        except Reject as e:
            out.append({"id": i, "description": d, "record_cbor_hex": b.hex(), "expect_error": "archive.ErrCorrupt",
                        "cause": e.sentinel})
    # A reader recomputes the key from the record and refuses a record stored under another one.
    r, b, path = by_name["intent_fibre"]
    other = A.key_path((13, 1, r["commitment"], r["ref_height"] + 1))
    r2, b2, path2 = by_name["private_part"]
    reads = [{"id": "intent_key_mismatch", "description": "The intent of ref_height h0 stored under h0 + 1.",
              "path": other, "record_cbor_hex": b.hex(), "expect_error": "archive.ErrCorrupt"},
             {"id": "private_key_mismatch", "description": "A PrivatePart record stored under plaintext_kind 3.",
              "path": path2.replace("private/4/", "private/3/"), "record_cbor_hex": b2.hex(),
              "expect_error": "archive.ErrCorrupt"},
             {"id": "intent_key_match", "description": "Control: the same record under its own path.", "path": path,
              "record_cbor_hex": b.hex(), "expect_error": None}]
    for x in reads:
        got = A.key_path(A.record_key(A.decode_record(bytes.fromhex(x["record_cbor_hex"]))))
        assert (got == x["path"]) == (x["expect_error"] is None), x["id"]
    return {"format": FORMAT, "revision": REVISION, "generator": "spec/vectors/check/gen_archive_v1.py",
            "description": "Archive records of core v1 section 11. v0_reader is the result of the frozen v0 record "
            "decoder (decoding only: a v1 envelope with version 1 decodes there and is refused later at stage S).",
            "kinds": {str(k): {"name": A.KIND_NAMES[k], "cap": str(A.MAX_KIND_SIZE[k])} for k in (13, 14, 15)},
            "reserved_kinds": [str(k) for k in A.RESERVED_KINDS], "marker_names_added": list(A.VERDICTS_V1[len(a0.VERDICTS):]),
            "cases": cases, "reject": out, "reads": reads}, by_name


def verify_vectors(by_name: dict) -> dict:
    pf, pb = gv.VALID["v1_pending_fibre"][0], gv.VALID["v1_pending_blob"][0]
    h0 = pf["payload_ref"]["height"]
    d = h0 + WINDOW
    extra = {}

    def put(name, r):
        b = A.encode_record(r)
        extra[name] = (r, b, A.key_path(A.record_key(r)))
        return name

    put("authorization_fast_fibre_mode_1", {"kind": 4, "signed_authorization": auth("v1_pending_fibre", 1, None),
                                            "authorized_at": NOW})
    put("authorization_fast_fibre_deadline_1001", {"kind": 4, "authorized_at": NOW,
                                                   "signed_authorization": auth("v1_pending_fibre", 2, h0 + 1001)})
    put("authorization_fast_fibre_v0", {"kind": 4, "signed_authorization": auth("v1_pending_fibre", 0, None, version=0),
                                        "authorized_at": NOW})
    put("authorization_fast_fibre_window_2", {"kind": 4, "signed_authorization": auth("v1_pending_fibre", 2, d),
                                              "authorized_at": NOW, "k2": k2_fibre(WINDOW - 1)})
    allrec = {**by_name, **extra}
    cases = []

    def case(i, desc, decision, authorization, *, evidence=None, head=None, absence=None, needs_results=False,
             replay=False, refs=()):
        c = v1.decode_signed_v1(allrec[decision][0]["envelope"])[0]["commitment"]
        a = A.decode_authorization(allrec[authorization][0]["signed_authorization"])
        k2 = allrec[authorization][0].get("k2")
        h0_, pending = c["payload_ref"]["height"], v1.is_pending(c)
        head = head if head is not None else h0_ + WINDOW + 1
        absence = absence or {}
        rule = A.authorization_rules(c, a)
        exp = {"authorization": {"status": "fail", "rule": rule} if rule else {"status": "pass"}}
        report = {"version": "1"}
        if "mode" in a:
            report["mode"] = "fast" if a["mode"] == 2 else "strict"
        if pending:
            report["h0"] = str(h0_)
            if rule or a["version"] != 1:
                exp["anchor"] = {"status": "unchecked", "reason": "blocked", "blocked_by": "authorization"}
            else:
                report["anchor_deadline"] = str(a["anchor_deadline"])
                r = A.anchor_pending_rules(h0_, a["anchor_deadline"], evidence, head, absence, needs_results)
                exp["anchor"] = {k: (str(x) if isinstance(x, int) else x) for k, x in r.items()
                                 if k in ("status", "reason", "rule", "first_unproven")}
                for k in ("anchor_height", "publication"):
                    if k in r:
                        report[k] = str(r[k]) if isinstance(r[k], int) else r[k]
                if r.get("rule") == "anchor_absent":
                    report["intent_signer"] = (c["payload_ref"]["signer"].hex() if c["payload_ref"]["da"] == 2
                                               else "unknown")
        if replay:
            exp["retention_replay"] = A.replay_rules(c, a, k2)
        sts = [x["status"] for x in exp.values()]
        verdict, code = ("invalid", 1) if "fail" in sts else ("unchecked", 2) if "unchecked" in sts else ("valid", 0)
        exp |= {"report": report, "verdict": verdict, "exit": str(code)}
        j = {"id": i, "description": desc, "decision": decision, "authorization": authorization,
             "trusted_head": str(head)}
        if evidence is not None:
            j["evidence"] = {"height": str(evidence["height"]), "verifies": evidence["verifies"]}
        if absence:
            j["absence"] = [{"height": str(h), "result": absence[h]} for h in sorted(absence)]
        if needs_results:
            j["needs_results"] = True
        if replay:
            j["request"] = "replay"
        j["refs"] = list(refs)
        j["expect"] = exp
        cases.append(j)

    df, af = "decision_pending_fibre", "authorization_fast_fibre"
    proven = {h: "absent" for h in range(h0, d + 1)}
    case("fast_pass_in_window", "Evidence at H = h0 + 1, inside [h0, deadline].", df, af, evidence={"height": h0 + 1,
         "verifies": True})
    case("fast_pass_at_deadline", "Evidence at H = deadline, the last height of the window.", df, af,
         evidence={"height": d, "verifies": True})
    case("fast_h_below_h0", "Evidence at H = h0 - 1: a PFF cannot precede its reference height.", df, af,
         evidence={"height": h0 - 1, "verifies": True})
    case("fast_late_absence_proven", "Evidence at H = deadline + 1, and absence proven at every height of the window.",
         df, af, evidence={"height": d + 1, "verifies": True}, absence=proven, refs=["da/absence.json"])
    case("fast_late_absence_unproven", "Evidence at H = deadline + 1; no proof for height h0 + 2.", df, af,
         evidence={"height": d + 1, "verifies": True}, absence={h: x for h, x in proven.items() if h != h0 + 2})
    case("fast_pending", "No evidence; the trusted head is below the deadline: not decidable yet.", df, af,
         head=d - 1)
    case("fast_pending_results_needed", "No evidence; trusted head = deadline, but an AB5 results proof needs "
         "deadline + 1.", df, af, head=d, needs_results=True)
    case("fast_absent_proven", "No evidence; absence proven for every height of the window.", df, af, absence=proven,
         refs=["da/absence.json#window_three_heights_proven"])
    case("fast_absent_proven_blob", "da = 2: no evidence, absence proven over the window; the report names "
         "payload_ref.signer as the intent signer.", "decision_pending_blob", "authorization_fast_blob",
         absence={h: "absent" for h in range(pb["payload_ref"]["height"], pb["payload_ref"]["height"] + WINDOW + 1)})
    case("fast_absence_missing_height", "No evidence; the proof for height h0 + 1 is missing.", df, af,
         absence={h: x for h, x in proven.items() if h != h0 + 1}, refs=["da/absence.json#window_one_height_missing"])
    case("fast_absence_shows_present", "No evidence record, but the proof at h0 + 2 shows the anchor present (AB5): "
         "used as evidence, which the verifier cannot build in full here.", df, af,
         absence={**proven, h0 + 2: "present"}, refs=["da/absence.json#fibre_present"])
    case("fast_evidence_not_verifying", "Evidence that does not verify is a source problem; the rows for no usable "
         "evidence decide: absence proven, fail.", df, af, evidence={"height": h0 + 1, "verifies": False},
         absence=proven)
    case("auth_mode_mismatch", "Pending reference, Authorization v1 in mode 1 (A2).", df,
         "authorization_fast_fibre_mode_1")
    case("auth_deadline_over_1000", "anchor_deadline = h0 + 1001 (A3).", df, "authorization_fast_fibre_deadline_1001")
    case("auth_version_mismatch", "v1 decision, Authorization v0 (A1).", df, "authorization_fast_fibre_v0")
    case("auth_strict_included", "Control: included reference, Authorization v1 mode 1; the anchor check is core.",
         "decision_included_fibre", "authorization_strict_fibre")
    case("replay_fast_window_inconsistent", "replay: K2 fast_window 2, the Authorization's deadline is h0 + 3.", df,
         "authorization_fast_fibre_window_2", evidence={"height": h0 + 1, "verifies": True}, replay=True)
    case("replay_fast_window_consistent", "Control: replay with fast_window 3 = deadline - h0.", df, af,
         evidence={"height": h0 + 1, "verifies": True}, replay=True)
    used = sorted({c["decision"] for c in cases} | {c["authorization"] for c in cases})
    recs = {n: {"path": allrec[n][2], "record_cbor_hex": allrec[n][1].hex()} for n in used}
    return {"format": FORMAT, "revision": REVISION, "generator": "spec/vectors/check/gen_archive_v1.py",
            "description": "Verifier outcomes of core v1 10.1 to 10.3 for a v1 decision. decision and authorization "
            "name records (records: path and bytes; the archive.json case of the same name has the same bytes). evidence and absence are the "
            "results of verifying those proofs (bytes in the core evidence vectors and da/absence.json): a height "
            "of [h0, deadline] not listed has no proof. trusted_head is the height header trust reached. expect "
            "gives each check's outcome, the v1 report fields (10.6) and the verdict when every other check passes.",
            "window": str(WINDOW), "records": recs, "cases": cases}


def build() -> dict:
    gv.build()
    arch, by_name = archive_vectors()
    return {"archive.json": arch, "verify.json": verify_vectors(by_name)}


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    for name, obj in build().items():
        p = OUT / name
        p.write_text(json.dumps(obj, indent=2, ensure_ascii=True) + "\n")
        print(f"wrote {p}")


if __name__ == "__main__":
    main()
