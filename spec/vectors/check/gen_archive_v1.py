#!/usr/bin/env python3
"""Writes spec/vectors/v1/archive.json, verify.json and stage4m.json (v1.0). Deterministic.

Archive format 1 records of kinds 13, 14 (small synthetic proof parts: the
record layer never verifies them; da/absence.json carries real ones), 15
(taken from policy/private.json), 17 and 18, Authorization records with K2
input key 9, and their rejects. verify.json gives the outcome of the
authorization, anchor, retention_replay, decision and action checks from
archived records plus abstract evidence and absence results (whose bytes are
vectored in the core files and in da/absence.json). spec/vectors/archive/
(gen_archive.py) covers the payload, evidence and rejection kinds.
stage4m.json gives the gate's stage 4m outcome (core 8.8) and the archive
writes that follow it, per gate mandate and commitment mandate_ref.

Usage: python3 spec/vectors/check/gen_archive_v1.py [--out DIR]
"""

from __future__ import annotations

import sys

sys.dont_write_bytecode = True

import hashlib
import json
from pathlib import Path

import archive as A
import edicta as E
import gen_vectors as gv
from cbor_strict import encode
from edicta import Reject

VECTORS = Path(__file__).resolve().parent.parent
OUT = VECTORS / "v1"
if "--out" in sys.argv:
    OUT = Path(sys.argv[sys.argv.index("--out") + 1]).resolve()
FORMAT, REVISION = "edicta-vectors/v1", "v1.0"
T0, NOW = gv.T0, gv.NOW
WINDOW = 3
T_REF = T0 - 12
CREATED = T0 - 20
# Fast mode needs a mandate, so the fast-mode decisions name one.
PF, PB = "v1_pending_fibre_mandate_ref", "v1_pending_blob_mandate_ref"


def ph(label: str, size: int) -> bytes:
    return A.placeholder("v1 " + label, size)


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
    c, canon, at, act, salt = gv.VALID[ref]
    sig = gv.sign_commitment(canon)[2]
    return c, gv.env(canon, sig), act, salt


def receipt_bytes(ref: str, rail_ref: str) -> bytes:
    """A signed receipt for a decision, by gate1 for executor1."""
    out = gv.signed_receipt(gv.receipt_for(E.commitment_hash(gv.VALID[ref][1]), rail_ref))
    E.verify_receipt(out)
    return out


def auth(ref: str, mode: int, deadline: int | None, path: int = E.PATH_DA) -> bytes:
    a = gv.base_auth(ref, path, mode, deadline)
    return bytes.fromhex(gv.auth_fields(None, gv.auth_canon(a))["signed_authorization_hex"])


def k2_fibre(fast_window: int | None = None, block_time: int = T_REF) -> dict:
    k = {"da": 1, "checked_at": NOW, "block_time": block_time, "retention_latest_s": 14400,
         "retention_at_height_s": 14400, "retention_source": A.SOURCE_DIRECT, "promise_created": CREATED}
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
    pf, pf_env, pf_act, pf_salt = valid(PF)
    pb, pb_env, pb_act, pb_salt = valid(PB)
    inc, inc_env, inc_act, inc_salt = valid("v1_minimal_included_fibre")
    h0f, h0b = pf["payload_ref"]["height"], pb["payload_ref"]["height"]
    out["decision_pending_fibre"] = ({"kind": 17, "envelope": pf_env, "form": 1, "action": pf_act,
                                      "action_salt": pf_salt},
                                     f"Decision record (kind 17, form 1: public) of {PF}: the action bytes and the "
                                     "salt in clear.")
    out["decision_pending_blob"] = ({"kind": 17, "envelope": pb_env, "form": 1, "action": pb_act,
                                     "action_salt": pb_salt}, f"Decision record, form 1, of {PB}.")
    out["decision_included_fibre"] = ({"kind": 17, "envelope": inc_env, "form": 1, "action": inc_act,
                                       "action_salt": inc_salt},
                                      "Decision record, form 1, of v1_minimal_included_fibre.")
    out["reveal_pending_fibre"] = (
        {"kind": 18, "signed_receipt": receipt_bytes(PF, "a" * 64), "action_salt": pf_salt},
        f"Execution reveal (kind 18) of {PF}: the receipt gate1 issued for executor1's claim (rail_ref a 64-hex tx "
        "hash) and the salt. The gate writes it only for a form 2 decision with a public_execution profile; the record "
        "layer does not check that.")
    out["authorization_fast_fibre"] = (
        {"kind": 4, "signed_authorization": auth(PF, 2, h0f + WINDOW), "authorized_at": NOW,
         "k2": k2_fibre(WINDOW)},
        f"Authorization, mode 2, anchor_deadline h0 + {WINDOW}; K2 inputs with fast_window {WINDOW} and "
        "block_time = T_ref.")
    out["authorization_fast_blob"] = (
        {"kind": 4, "signed_authorization": auth(PB, 2, h0b + WINDOW), "authorized_at": NOW,
         "k2": k2_blob(WINDOW)}, "Authorization for the pending blob reference, fast_window 3.")
    out["authorization_strict_fibre"] = (
        {"kind": 4, "signed_authorization": auth("v1_minimal_included_fibre", 1, None), "authorized_at": NOW,
         "k2": k2_fibre()}, "Authorization, mode 1 (included reference): K2 without key 9.")
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
    pa = next(e for e in priv["envelopes"] if e["plaintext_kind"] == "5")
    assert pa["hash_hex"] == pf["action"]["hash"].hex(), "private.json envelope_action is not this decision's"
    out["private_action_fibre"] = (A.decode_record(bytes.fromhex(pa["record_cbor_hex"])),
                                   f"Kind 15 plaintext 5 (action): salt || action bytes of {PF}, encrypted to the "
                                   "mandate's auditors; the same bytes as policy/private.json envelope_action.")
    out["decision_private_fibre"] = ({"kind": 17, "envelope": pf_env, "form": 2},
                                     f"Decision record, form 2 (private), of {PF}: the envelope only; the action "
                                     "and the salt are in the kind 15 (5, action_hash) record, written first (AW4).")
    out["decision_pending_fibre_wrong_salt"] = (
        {"kind": 17, "envelope": pf_env, "form": 1, "action": pf_act, "action_salt": bytes([pf_salt[0] ^ 1]) + pf_salt[1:]},
        "A form 1 record whose salt has one bit flipped: it decodes (the record layer does not hash), and the "
        "verifier's action check finds it corrupt.")
    out["reveal_pending_fibre_wrong_salt"] = (
        {"kind": 18, "signed_receipt": receipt_bytes(PF, "a" * 64), "action_salt": bytes([pf_salt[0] ^ 1]) + pf_salt[1:]},
        "A reveal whose salt has one bit flipped: decodes; the verifier's reveal path finds it corrupt.")
    for err in ("ErrMandateRefMissing", "ErrH0TooOld", "ErrAnchorWindowClosed", "ErrFastModeNotAllowed"):
        out[f"rejection_{err}"] = ({"kind": 5, "commitment_hash": E.commitment_hash(gv.VALID[PF][1]),
                                    "error": err, "gate_id": gv.GID, "rejected_at": NOW},
                                   f"Rejection marker {err}.")
    return out


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
                      "record_cbor_hex": b.hex()})
    ik = lambda n: A._to_int_keys({"format": A.FORMAT, **by_name[n][0]}, A.schema_of(by_name[n][0]["kind"]))  # noqa: E731

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
        ("private_plaintext_kind_6", "Kind 15 plaintext_kind 6.", mut("private_part", k3=6)),
        ("private_envelope_empty", "Kind 15 with an empty envelope.", mut("private_part", k5=b"")),
        ("private_envelope_65537", "Kind 15 plaintext_kind 4 with a 65,537-byte envelope (the 69,632 limit is for "
         "plaintext kind 5 only).", mut("private_part", k5=ph("envelope 65537", 65537))),
        ("private_action_envelope_69633", "Kind 15 plaintext_kind 5 with a 69,633-byte envelope.",
         mut("private_part", k3=5, k5=ph("envelope 69633", 69633))),
        ("header_empty", "Kind 14 with an empty header.", mut("absence_blob", k7=b"")),
        ("decision_form1_missing_salt", "Kind 17 form 1 without action_salt.",
         mut("decision_pending_fibre", drop=(6,))),
        ("decision_form1_missing_action", "Kind 17 form 1 without action.",
         mut("decision_pending_fibre", drop=(5,))),
        ("decision_form2_with_action", "Kind 17 form 2 with the action and the salt.",
         mut("decision_pending_fibre", k4=2)),
        ("decision_salt_31", "Kind 17 action_salt of 31 bytes.",
         mut("decision_pending_fibre", k6=b"\x01" * 31)),
        ("decision_form_3", "Kind 17 form 3.", mut("decision_pending_fibre", k4=3)),
        ("kind_3_unassigned", "Kind 3 (the decision record of the v0 drafts) holding an envelope and action bytes: "
         "kind 3 is unassigned in format 1.",
         encode({1: 1, 2: 3, 3: ik("decision_pending_fibre")[3], 4: ik("decision_pending_fibre")[5]})),
        ("format_0_decision", "decision_pending_fibre under format 0: refused at the header.",
         encode({**ik("decision_pending_fibre"), 1: 0})),
        ("reveal_salt_33", "Kind 18 action_salt of 33 bytes.", mut("reveal_pending_fibre", k4=b"\x01" * 33)),
        ("reveal_receipt_garbage", "Kind 18 whose signed_receipt does not decode.",
         mut("reveal_pending_fibre", k3=b"\xa0")),
        ("rejection_not_a_marker", "Kind 5 with ErrAnchorPending: a stage 1 refusal, never a marker.",
         mut("rejection_ErrH0TooOld", k4="ErrAnchorPending")),
        ("rejection_mandate_mismatch_not_a_marker", "Kind 5 with ErrMandateMismatch: an M0 or M2 refusal writes no "
         "decision record and so no marker (core 8.8).", mut("rejection_ErrH0TooOld", k4="ErrMandateMismatch")),
        ("kind_16_reserved", "Kind 16 (reserved for the batch record): undefined.", encode({1: 1, 2: 16, 3: b"\x01"})),
        ("kind_6_reserved", "Kind 6 stays undefined.", encode({1: 1, 2: 6, 3: b"\x01"})),
        ("kind_19_undefined", "Kind 19: undefined.", encode({1: 1, 2: 19, 3: b"\x01"})),
    ]
    large_specs = [
        ("header_over_2p22", "Kind 14 header of 2^22 + 1 bytes (field limit).", "absence_blob", 7, "header big",
         (1 << 22) + 1),
        ("header_at_2p22", "Control: kind 14 header of exactly 2^22 bytes decodes.", "absence_blob", 7, "header big",
         1 << 22),
        ("namespace_data_over_2p24", "Kind 14 namespace_data of 2^24 + 1 bytes: the record exceeds the kind cap "
         "(16,777,216), which is checked before the fields.", "absence_blob", 9, "nsdata big", (1 << 24) + 1),
    ]
    large = []
    for i, d, base, field, label, size in large_specs:
        m = ik(base)
        m[field] = ph(label, size)
        b = encode(m)
        try:
            A.decode_record(b)
            cause = None
        except Reject as e:
            cause = e.sentinel
        large.append({"id": i, "description": d, "base_case": base, "field": str(field),
                      "placeholder_label": "v1 " + label, "field_size": str(size), "record_size": str(len(b)),
                      "record_sha256_hex": hashlib.sha256(b).hexdigest(),
                      "expect_error": "archive.ErrCorrupt" if cause else None, "cause": cause})
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
    r3, b3, path3 = by_name["absence_blob"]
    reads.append({"id": "absence_key_mismatch", "description": "An absence proof of height h stored under h + 1.",
                  "path": A.key_path((14, 2, r3["commitment"], r3["height"] + 1)), "record_cbor_hex": b3.hex(),
                  "expect_error": "archive.ErrCorrupt"})
    r4, b4, path4 = by_name["decision_pending_fibre"]
    other_c = E.commitment_hash(gv.VALID[PB][1]).hex()
    reads.append({"id": "decision_key_mismatch", "description": f"The kind 17 record of {PF} stored under the "
                  f"commitment hash of {PB}.", "path": f"decision/{other_c}", "record_cbor_hex": b4.hex(),
                  "expect_error": "archive.ErrCorrupt"})
    r5, b5, path5 = by_name["reveal_pending_fibre"]
    reads.append({"id": "reveal_key_mismatch", "description": "A reveal stored under another commitment hash.",
                  "path": f"reveal/{other_c}", "record_cbor_hex": b5.hex(), "expect_error": "archive.ErrCorrupt"})
    for x in reads:
        got = A.key_path(A.record_key(A.decode_record(bytes.fromhex(x["record_cbor_hex"]))))
        assert (got == x["path"]) == (x["expect_error"] is None), x["id"]
    return {"format": FORMAT, "revision": REVISION, "generator": "spec/vectors/check/gen_archive_v1.py",
            "description": "Archive records of format 1, kinds 13, 14, 15, 17, 18 and the Authorization with K2 "
            "input key 9.",
            "kinds": {str(k): {"name": A.KIND_NAMES[k], "cap": str(A.MAX_KIND_SIZE[k])} for k in (13, 14, 15, 17, 18)},
            "unassigned_kinds": [str(k) for k in A.UNASSIGNED_KINDS], "marker_names": sorted(A.VERDICTS),
            "large_note": "reject_large: the record is base_case with field replaced by the placeholder of "
            "placeholder_label and field_size (archive.placeholder), given by size and SHA-256 only.",
            "cases": cases, "reject": out, "reject_large": large, "reads": reads}, by_name


def verify_vectors(by_name: dict) -> dict:
    pf, pb = gv.VALID[PF][0], gv.VALID[PB][0]
    h0 = pf["payload_ref"]["height"]
    d = h0 + WINDOW
    extra = {}

    def put(name, r):
        b = A.encode_record(r)
        extra[name] = (r, b, A.key_path(A.record_key(r)))
        return name

    put("authorization_fast_fibre_mode_1", {"kind": 4, "signed_authorization": auth(PF, 1, None),
                                            "authorized_at": NOW})
    put("authorization_fast_fibre_deadline_1001", {"kind": 4, "authorized_at": NOW,
                                                   "signed_authorization": auth(PF, 2, h0 + 1001)})
    put("authorization_fast_fibre_window_2", {"kind": 4, "signed_authorization": auth(PF, 2, d),
                                              "authorized_at": NOW, "k2": k2_fibre(WINDOW - 1)})
    allrec = {**by_name, **extra}
    cases = []

    def case(i, desc, decision, authorization, *, evidence=None, head=None, absence=None, needs_results=False,
             replay=False, refs=()):
        c = A.decode_envelope(allrec[decision][0]["envelope"])[0]
        a = A.decode_authorization(allrec[authorization][0]["signed_authorization"])
        k2 = allrec[authorization][0].get("k2")
        h0_, pending = c["payload_ref"]["height"], E.is_pending(c)
        head = head if head is not None else h0_ + WINDOW + 1
        absence = absence or {}
        rule = A.authorization_rules(c, a)
        exp = {"authorization": {"status": "fail", "rule": rule} if rule else {"status": "pass"}}
        report = {"version": "1"}
        if "mode" in a:
            report["mode"] = "fast" if a["mode"] == 2 else "strict"
        if pending:
            report["h0"] = str(h0_)
            if rule:
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
    case("auth_mode_mismatch", "Pending reference, Authorization in mode 1 (AM1).", df,
         "authorization_fast_fibre_mode_1")
    case("auth_deadline_over_1000", "anchor_deadline = h0 + 1001 (AM2).", df, "authorization_fast_fibre_deadline_1001")
    case("auth_strict_included", "Control: included reference, Authorization mode 1; the anchor check is the "
         "included one.",
         "decision_included_fibre", "authorization_strict_fibre")
    case("replay_fast_window_inconsistent", "replay: K2 fast_window 2, the Authorization's deadline is h0 + 3.", df,
         "authorization_fast_fibre_window_2", evidence={"height": h0 + 1, "verifies": True}, replay=True)
    case("replay_fast_window_consistent", "Control: replay with fast_window 3 = deadline - h0.", df, af,
         evidence={"height": h0 + 1, "verifies": True}, replay=True)
    acases = action_cases(allrec)
    used = sorted({c["decision"] for c in cases} | {c["authorization"] for c in cases} |
                  {x for c in acases for x in (c["decision"], c.get("private_record"), c.get("reveal")) if x})
    recs = {n: {"path": allrec[n][2], "record_cbor_hex": allrec[n][1].hex()} for n in used}
    return {"format": FORMAT, "revision": REVISION, "generator": "spec/vectors/check/gen_archive_v1.py",
            "description": "Verifier outcomes of the authorization, anchor and retention_replay checks for a decision. decision and authorization "
            "name records (records: path and bytes; the archive.json case of the same name has the same bytes). evidence and absence are the "
            "results of verifying those proofs (bytes in the core evidence vectors and da/absence.json): a height "
            "of [h0, deadline] not listed has no proof. trusted_head is the height header trust reached. expect "
            "gives each check's outcome, the report fields and the verdict when every other check passes.",
            "window": str(WINDOW), "records": recs, "cases": cases,
            "action_description": "action_cases: the decision and action checks for a decision. "
            "decision, private_record (kind 15 plaintext 5) and reveal (kind 18) name records; auditor_key names a "
            "policy/private.json auditor key the verifier holds; checker gives the execution checker's profile flag "
            "public_execution and, when the reveal path runs, tx_action_hex = ActionFromTx(tx, chain_id) of the tx "
            "bound to the receipt's rail_ref; payload_salt_hex is the action_salt carried by the payload, and "
            "payload_o8 = fail says that payload failed O8 (O8 runs before the salt comparison, which then does not "
            "run).",
            "action_cases": acases}


def action_cases(allrec: dict) -> list:
    priv = json.loads((VECTORS / "policy" / "private.json").read_text())
    sk = {n: bytes.fromhex(k["sk_hex"]) for n, k in priv["auditor_keys"].items()}
    import policy_v1 as Pol
    c_pf, _, _, act, salt = gv.VALID[PF]
    broken = {k: x for k, x in allrec["decision_pending_fibre"][0].items() if k != "action_salt"}
    allrec["decision_corrupt"] = (None, encode(A.to_cbor(broken)), allrec["decision_pending_fibre"][2])
    out = []

    def case(i, desc, decision, private_record=None, key=None, reveal=None, checker=None, payload_salt=None,
             payload_o8=None):
        rec_b = allrec[decision][1]
        try:
            dec = A.decode_record(rec_b)
            exp = {"decision": {"status": "pass"}}
        except Reject:
            exp = {"decision": {"status": "unchecked", "reason": "source_corrupt"}}
            dec = None
        if dec is not None:
            opened = None
            if dec["form"] == 2 and private_record and key:
                pr = allrec[private_record][0]
                st, pt, _ = Pol.private_open(pr["envelope"], [sk[key]], 5, c_pf["action"]["hash"], c_pf["action"]["type"])
                opened = pt if st == "ok" else None
            rv = None
            if reveal and checker and checker["public_execution"]:
                rv = {"salt": allrec[reveal][0]["action_salt"], "action": bytes.fromhex(checker["tx_action_hex"])}
            # O8 runs first: a payload that fails it is a payload fail and gives no salt to compare.
            if payload_o8 == "fail":
                exp["payload"] = {"status": "fail", "rule": "O8"}
            r = A.action_rules(c_pf, dec, opened, dec["form"] == 2 and private_record is None, rv,
                               None if payload_o8 == "fail" else payload_salt)
            exp["action"] = {k: x for k, x in r.items() if k in ("status", "reason", "action_source")}
        j = {"id": i, "description": desc, "decision": decision}
        for k, x in (("private_record", private_record), ("auditor_key", key), ("reveal", reveal)):
            if x:
                j[k] = x
        if checker:
            j["checker"] = checker
        if payload_salt:
            j["payload_salt_hex"] = payload_salt.hex()
        if payload_o8:
            j["payload_o8"] = payload_o8
        j["expect"] = exp
        out.append(j)

    onchain = {"public_execution": True, "tx_action_hex": act.hex()}
    case("decision_v1_public_pass", "Form 1: ActionHash(type, key 6, key 5) equals action_hash.",
         "decision_pending_fibre")
    case("decision_v1_public_wrong_salt", "Form 1 with a wrong salt: unchecked, source_corrupt.",
         "decision_pending_fibre_wrong_salt")
    case("decision_v1_private_without_key", "Form 2, the kind 15 action record present, no auditor key: "
         "policy_private (exit 2).", "decision_private_fibre", "private_action_fibre")
    case("decision_v1_private_with_key", "Form 2 with auditor-1's key: kind 15 opens, the plaintext salt || bytes "
         "hashes to action_hash.", "decision_private_fibre", "private_action_fibre", "auditor-1")
    case("decision_v1_private_blob_missing", "Form 2 and no kind 15 (5, action_hash) record in any copy: "
         "decision_unavailable, naming it.", "decision_private_fibre")
    case("reveal_public_execution_pass", "Form 2, no key, a kind 18 reveal, and a public_execution checker whose "
         "ActionFromTx gives the committed bytes: pass by reveal.", "decision_private_fibre", "private_action_fibre",
         reveal="reveal_pending_fibre", checker=onchain)
    case("reveal_wrong_salt", "The reveal's salt is wrong: the tx bytes do not hash to action_hash with it: "
         "unchecked, source_corrupt.", "decision_private_fibre", "private_action_fibre",
         reveal="reveal_pending_fibre_wrong_salt", checker=onchain)
    case("reveal_tx_not_action", "The tx bound to rail_ref gives other action bytes (last byte flipped): a wrong "
         "salt and another tx cannot be told apart, source_corrupt.", "decision_private_fibre", "private_action_fibre",
         reveal="reveal_pending_fibre", checker={"public_execution": True,
                                                 "tx_action_hex": (act[:-1] + bytes([act[-1] ^ 1])).hex()})
    case("reveal_offchain_profile", "A reveal exists but the checker's profile has public_execution false "
         "(off-chain rail): the reveal path does not run, policy_private.", "decision_private_fibre",
         "private_action_fibre", reveal="reveal_pending_fibre", checker={"public_execution": False})
    case("payload_archive_salt_equal", "Control: the payload's action_salt (O8 passed) equals the form 1 salt.",
         "decision_pending_fibre", payload_salt=salt)
    case("payload_archive_salt_mismatch", "The payload's action_salt differs from the archive copy, which itself "
         "hashes correctly (stand-in for a collision; the rule is defence in depth): unchecked, source_corrupt, never "
         "an agent violation.", "decision_pending_fibre", payload_salt=bytes([salt[0] ^ 0x80]) + salt[1:])
    case("payload_o8_fails_before_salt_compare", "The payload's salt differs from the committed one, so O8 fails: a "
         "payload fail (the agent's signed payload contradicts its commitment). The comparison with the archive copy "
         "does not run, so the action check passes from the form 1 record.", "decision_pending_fibre",
         payload_salt=bytes([salt[0] ^ 0x80]) + salt[1:], payload_o8="fail")
    case("decision_record_corrupt", "The record under decision/<hex> is the form 1 record without its salt (it does "
         "not decode): the decision check is unchecked, source_corrupt.", "decision_corrupt")
    return out


def stage4m_outcome(gate_mandate: dict | None, ref: bytes | None, stored_same: bool) -> dict:
    """Core 8.8: the stage 4m result and the archive writes the gate makes after it."""
    if gate_mandate is None:
        rule = "M0" if ref is not None else None
    elif ref is None:
        rule = "M1"
    else:
        rule = "M2" if ref != gate_mandate["hash"] else None
    if rule is None:
        return {"rule": "none", "result": "continue", "next_stage": "4a" if gate_mandate is None else "4p",
                "verdict_signed": False, "writes": []}
    err = "ErrMandateRefMissing" if rule == "M1" else "ErrMandateMismatch"
    if stored_same:
        return {"rule": rule, "result": "ErrNonceUsed", "stored_authorization": True, "verdict_signed": False,
                "writes": []}
    writes = []
    if rule == "M1":
        writes = (["private_blob_action", "decision_form_2"] if gate_mandate["auditors"] else ["decision_form_1"])
        writes.append("marker:" + err)
    return {"rule": rule, "result": err, "verdict_signed": False, "writes": writes}


def stage4m_vectors() -> dict:
    m_full = gv.mandate_ref()
    other = hashlib.sha256(b"edicta/v1 test other mandate in force").digest()
    mandates = {"m_full": m_full, "other": other}
    cases = []

    def case(cid, desc, gate, commitment, stored_same=False):
        gm = None if gate is None else {"hash": mandates[gate[0]], "auditors": gate[1]}
        ref = gv.VALID[commitment][0].get("mandate_ref")
        c = {"id": cid, "description": desc,
             "gate_mandate": None if gate is None else {"mandate": gate[0], "auditors": gate[1]},
             "commitment_ref": commitment, "stored_entry_same_commitment": stored_same,
             "expect": stage4m_outcome(gm, ref, stored_same)}
        cases.append(c)

    case("no_mandate_no_ref", "Gate without a mandate, commitment without key 14: stage 4m passes; 4p and 10p do "
         "not exist, stage 4a writes form 1.", None, "v1_minimal_included_blob")
    case("m0_no_mandate_with_ref", "Gate without a mandate (dropped from its configuration), commitment naming "
         "m_full: M0 refuses; nothing is written, no verdict.", None, "v1_mandate_ref")
    case("m0_stored_retry", "As m0_no_mandate_with_ref, but the nonce entry holds this commitment (authorized "
         "before the mandate was dropped): the stored Authorization with ErrNonceUsed, nothing written.",
         None, "v1_mandate_ref", True)
    case("m1_public_no_ref", "Public mandate in force, commitment without key 14: M1; the commitment named no "
         "mandate, so stage 4a writes form 1 and the marker.", ("m_full", False), "v1_minimal_included_blob")
    case("m1_private_no_ref", "Private mandate in force, commitment without key 14: M1; stage 4a writes the "
         "kind 15 action record, then form 2, then the marker.", ("m_full", True), "v1_minimal_included_blob")
    case("m2_public_gate_other_ref", "Public mandate in force (another mandate_hash), commitment naming m_full "
         "(for example a private mandate before a switch to public mode): M2; no decision record, no kind 15, no "
         "marker, so the action bytes and the salt are never written in clear.", ("other", False), "v1_mandate_ref")
    case("m2_private_gate_other_ref", "Private mandate in force with its own auditors, commitment naming m_full: "
         "M2; nothing is encrypted to auditors the agent's principal did not choose, nothing is written.",
         ("other", True), "v1_mandate_ref")
    case("m2_stored_retry", "M2 on a commitment whose nonce entry holds it: the stored Authorization with "
         "ErrNonceUsed, nothing written.", ("other", False), "v1_mandate_ref", True)
    case("equal_ref_public", "mandate_ref equals the mandate in force: stage 4p runs next.", ("m_full", False),
         "v1_mandate_ref")
    case("equal_ref_private", "mandate_ref equals the private mandate in force: stage 4p runs next (stage 4a "
         "later writes form 2).", ("m_full", True), "v1_mandate_ref")
    return {"format": FORMAT, "revision": REVISION, "generator": "spec/vectors/check/gen_archive_v1.py",
            "description": "Gate stage 4m (core 8.8) and the archive writes after it. gate_mandate: null (no mandate) "
            "or the mandate in force (its name in mandates, auditors true for private mode). commitment_ref: a case "
            "of v1/valid.json; its key 14 is the agent's mandate_ref. stored_entry_same_commitment: the nonce entry "
            "of (agent_pubkey, nonce) holds this commitment_hash (the stored-retry check). expect.writes in order: "
            "private_blob_action (kind 15 (5, action_hash)), decision_form_1 or decision_form_2 (kind 17), "
            "marker:<name> (kind 5). No case signs a policy verdict.",
            "mandates": {k: v.hex() for k, v in mandates.items()},
            "mandate_sources": {"m_full": "spec/vectors/policy/mandate.json case m_full (mandate_hash)",
                                "other": "placeholder: SHA-256(\"edicta/v1 test other mandate in force\")"},
            "cases": cases}


def build() -> dict:
    gv.build()
    arch, by_name = archive_vectors()
    return {"archive.json": arch, "verify.json": verify_vectors(by_name), "stage4m.json": stage4m_vectors()}


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    for name, obj in build().items():
        p = OUT / name
        p.write_text(json.dumps(obj, indent=2, ensure_ascii=True) + "\n")
        print(f"wrote {p}")


if __name__ == "__main__":
    main()
