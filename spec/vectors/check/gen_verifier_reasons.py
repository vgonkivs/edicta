#!/usr/bin/env python3
"""Writes spec/vectors/verifier/reasons.json (v1-draft.5).

The machine-readable verifier reason enum and one case per
reason: the check it is reported on, the scenario as overrides of a valid,
authorized decision, the vectors that give concrete bytes for it, and the
expected check status, verdict and exit code. A second list holds the
boundary: verified data that proves a violation stays `fail`.

Execution reasons point at the cases of execution_outcomes.json, which hold
the full setup.

Usage: python3 spec/vectors/check/gen_verifier_reasons.py
"""

from __future__ import annotations

import sys

sys.dont_write_bytecode = True

import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
VECTORS = HERE.parent
OUT = VECTORS / "verifier" / "reasons.json"

# name, group, checks, meaning, advice
REASONS = [
    ("decision_unavailable", "archive", ["decision", "action"],
     "No decision record for the reference in any checked archive copy. On action: a private-form decision "
     "record whose kind 15 action record is absent.", "another archive copy"),
    ("payload_unavailable", "archive", ["payload"],
     "The payload record is missing in every checked copy. It signals a retention failure of the operator and "
     "can feed an external accountability policy. It is not a verdict on the decision.", "another archive copy"),
    ("evidence_unavailable", "archive", ["anchor"],
     "The evidence record is missing in every checked copy.", "another archive copy"),
    ("source_corrupt", "archive", ["decision", "envelope", "action", "authorization", "payload", "anchor",
                                   "receipt", "policy", "gate_integrity"],
     "Bytes from a source fail a check that a genuine copy passes: strict decoding, the key check, a hash or DA "
     "commitment against the commitment, a signature that the commitment hash does not cover, or an archived "
     "proof (da = 2 commitment proof, Fibre CV1 to CV8, the anchor proof).", "another copy"),
    ("chain_mismatch", "archive", ["header_trust", "anchor"],
     "An archived header at a needed height does not link to the trusted chain (HT3, HT5, OH6), or the archived "
     "evidence names another height than the decision.", "another archive copy, or check the trusted header"),
    ("da_unsupported", "configuration", ["anchor"],
     "The verifier has no anchor verifier for payload_ref.da.", "a verifier build that supports this da"),
    ("no_trusted_header", "header", ["header_trust"],
     "No trusted header file, explicit checkpoint or checkpoint source was given.", "supply a trusted header"),
    ("header_above_checkpoint", "header", ["header_trust", "execution"],
     "The checkpoint height T is below a needed height (OH4, EX5 (a)).", "retry later or with a newer checkpoint"),
    ("header_not_linking", "header", ["header_trust", "execution"],
     "An online header at a needed height does not link to the trusted chain, and no source gives one that "
     "does (OH6, EX5 (b)).", "another header source"),
    ("header_source_unavailable", "header", ["header_trust"],
     "No header or checkpoint source answered.", "another header source"),
    ("checkpoint_quorum", "header", ["header_trust"],
     "Fewer than quorum distinct sources agree on the checkpoint (OH5).", "more checkpoint sources"),
    ("header_disagreement", "header", ["header_trust", "execution"],
     "header disagreement with trusted chain: possible bad trusted header, hostile source, or fork (OH5, OH7, "
     "HT6, EX5 (d)).", "check the trusted header against an independent source"),
    ("blocked", "dependency", ["anchor_time", "header_trust", "execution", "retention_replay", "policy", "anchor"],
     "The check needs another check that did not pass; the report names that check.", "fix the named check"),
    ("receipt_mismatch", "input", ["receipt"],
     "A receipt that verifies but is not this decision's: another commitment_hash or gate_id, or a gate key "
     "that is not on record for gate_id.", "the receipt of this decision"),
    ("replay_inputs_missing", "archive", ["retention_replay"],
     "The Authorization record carries no K2 inputs (repaired from the registry).", "another archive copy"),
    ("replay_inconsistent", "archive", ["retention_replay"],
     "K2 recomputed from the recorded inputs disagrees with the Authorization's path, or promise_created matches "
     "no candidate. The K2 inputs are unsigned archive data, so a gate error and an altered record look the "
     "same.", "another archive copy"),
    ("timeout", "run", ["any"], "The run deadline cut the check short.", "retry with a longer --timeout"),
    ("no_checker", "execution", ["execution"], "No execution checker for action.type.", "a verifier with the profile"),
    ("chain_config", "execution", ["execution"], "BX0: the checker is configured for another chain.",
     "configure the action's chain"),
    ("tx_not_found", "execution", ["execution"], "BX1: no tx source knows the transaction.", "another tx source"),
    ("tx_source_unavailable", "execution", ["execution"], "BX1: the tx sources failed.", "another tx source"),
    ("tx_hash_mismatch", "execution", ["execution"], "BX2: the served bytes do not hash to rail_ref.",
     "another tx source"),
    ("tx_proof_invalid", "execution", ["execution"], "BX6: the inclusion proof does not verify.", "another tx source"),
    ("result_unproven", "execution", ["execution"],
     "The result code is not proven: no inclusion proof, or no source served block_results (RP1, RP2). It is "
     "attested by one source or confirmed only by agreeing sources, and neither gives pass (EX9).",
     "a tx source that serves inclusion proofs and a source that serves block_results"),
    ("results_root_mismatch", "execution", ["execution"], "RP4: the results do not hash to last_results_hash.",
     "another results source"),
    ("result_index_unbound", "execution", ["execution"], "RP5: nothing binds the tx's index in the results.",
     "a source that serves the block's txs (/block)"),
    ("result_header_unreachable", "execution", ["execution"], "RP4: the header at height + 1 is not trusted.",
     "retry later or with a newer checkpoint"),
    ("code_unproven", "execution", ["execution"], "A nonzero code that no result proof verifies (EX9).",
     "a source that serves block_results"),
    ("height_unproven", "execution", ["execution"], "A height at or below the anchor without a proof (EX4).",
     "a tx source that serves inclusion proofs"),
    ("cross_disagree", "execution", ["execution"], "Tx sources disagree and nothing verifies either (EX6).",
     "another tx source"),
    ("chain_unbound", "execution", ["execution"], "BX4: another chain id without proven inclusion.",
     "a tx source that serves inclusion proofs"),
    ("policy_verdict_unavailable", "policy", ["policy"],
     "No policy_allow record for an authorized decision while the policy check is required (RequirePolicy).",
     "another archive copy"),
    ("policy_mandate_unavailable", "policy", ["policy"], "The mandate record named by the verdict is missing.",
     "another archive copy"),
    ("policy_principal_untrusted", "configuration", ["policy"],
     "The mandate verifies, but its principal is not among the trusted principal keys.",
     "pin the principal key, if it is the intended one"),
    ("policy_no_extractor", "configuration", ["policy"],
     "The verifier has no extractor for action.type with the extractor ID the verdict names.",
     "a verifier with that extractor"),
    ("state_history_unavailable", "archive", ["policy", "gate_integrity"],
     "A closed set, a needed bucket, or a verdict or mandate the walk needs is missing.", "another archive copy"),
    ("gate_equivocation", "integrity", ["gate_integrity"],
     "Gate-signed verdicts contradict each other (fork, broken link, self-inconsistent transition, seq gap, version "
     "decrease or mandate change in one chain). The agent may be honest; the gate is at fault. Exit code 5.",
     "investigate the gate; the attached verdicts are the evidence"),
    ("gate_signed_inconsistent_private_part", "integrity", ["gate_integrity"],
     "A private-form verdict's PrivatePart opens and hashes to the gate-signed private_hash but breaks the presence "
     "rule of the verdict's outcome: the gate signed a contradiction. The policy check runs on what the verifier "
     "derives itself (its extractor's facts stand in for missing ones); a deny there is a policy fail, otherwise the "
     "decision verdict stays unchecked. Exit code 5.", "investigate the gate; the attached verdict is the evidence"),
    ("policy_walk_truncated", "integrity", ["gate_integrity"],
     "The policy walk took its step cap (default or explicit) before it reached genesis, with no finding. The older "
     "part of the gate's chain was not read, so gate_integrity is never ok here. The report gives the walked seq "
     "range and the step count. The policy check and the verdict do not change.",
     "raise --max-walk-steps above the target's seq"),
    ("anchor_pending", "header", ["anchor"],
     "Pending reference, no usable evidence, and the trusted header is below anchor_deadline (or anchor_deadline + 1 "
     "when a results proof is needed): not decidable yet.", "retry later or with a newer checkpoint"),
    ("absence_unproven", "archive", ["anchor"],
     "Pending reference, no evidence inside the window, and the absence proofs for [h0, anchor_deadline] are "
     "missing, incomplete or fail. Names the first height not proven.", "another archive copy or --absence-source"),
    ("policy_private", "configuration", ["policy", "gate_integrity", "action", "execution"],
     "The record needed is a private blob (kind 15) and no configured auditor key opens it. Names the first record. "
     "On action and execution: a private-form v1 decision record without a reveal that applies.",
     "an auditor key of the mandate"),
    ("principal_scheme_unsupported", "configuration", ["policy"],
     "The verifier build lacks the principal signature scheme the mandate names.",
     "a verifier build with that scheme"),
]

POLICY_CASE = {
    "policy_verdict_unavailable": ("unchecked_verdict_unavailable", "policy"),
    "policy_mandate_unavailable": ("unchecked_mandate_unavailable", "policy"),
    "policy_principal_untrusted": ("unchecked_principal_untrusted", "policy"),
    "policy_no_extractor": ("unchecked_no_extractor", "policy"),
    "state_history_unavailable": ("unchecked_bucket_missing", "policy"),
}

EXECUTION_CASE = {
    "header_above_checkpoint": "unchecked_header_above_checkpoint",
    "header_not_linking": "unchecked_header_not_linking",
    "header_disagreement": "unchecked_header_disagreement",
    "chain_config": "unchecked_chain_config",
    "tx_not_found": "unchecked_tx_not_found",
    "tx_source_unavailable": "unchecked_tx_source_unavailable",
    "tx_hash_mismatch": "unchecked_tx_hash_mismatch",
    "tx_proof_invalid": "unchecked_tx_proof_invalid",
    "result_unproven": "unchecked_result_unproven_single_source",
    "results_root_mismatch": "unchecked_result_root_mismatch",
    "result_index_unbound": "unchecked_result_index_unbound",
    "result_header_unreachable": "unchecked_result_header_unreachable",
    "code_unproven": "unchecked_code_unproven",
    "height_unproven": "unchecked_height_unproven",
    "cross_disagree": "unchecked_cross_disagree_code",
    "chain_unbound": "unchecked_chain_unbound",
}


def unchecked(check: str, reason: str, *, state="authorized", verdict="unchecked") -> dict:
    return {"check": check, "status": "unchecked", "reason": reason, "record_state": state, "verdict": verdict,
            "exit": str({"unchecked": 2, "not_authorized": 3}[verdict])}


def integrity_unchecked(reason: str) -> dict:
    """An integrity-only reason: the decision verdict is not affected."""
    return {"check": "gate_integrity", "status": "unchecked", "reason": reason, "record_state": "authorized",
            "verdict": "valid", "exit": "0"}


def violated() -> dict:
    return {"check": "gate_integrity", "status": "violated", "reason": "gate_equivocation", "record_state": "authorized",
            "verdict": "unchecked", "exit": "5"}


def violated_private_part() -> dict:
    return {"check": "gate_integrity", "status": "violated", "reason": "gate_signed_inconsistent_private_part",
            "record_state": "authorized", "verdict": "unchecked", "exit": "5"}


def failed(check: str, *, state="authorized") -> dict:
    return {"check": check, "status": "fail", "reason": None, "record_state": state, "verdict": "invalid",
            "exit": "1"}


def case(ident, description, setup, refs, ex, request=None):
    out = {"id": ident, "description": description, "setup": setup, "refs": refs, "expect": ex}
    if request:
        out["request"] = request
    return out


def build() -> dict:
    cases = [
        case("decision_absent", "No decision record under the reference. The record state is unknown, so the "
             "verdict is unchecked, not not_authorized.", {"decision": "absent"}, [],
             unchecked("decision", "decision_unavailable", state="unknown")),
        case("payload_absent", "The payload record is missing in the only archive copy.", {"payload": "absent"},
             [], unchecked("payload", "payload_unavailable")),
        case("evidence_absent", "The evidence record is missing.", {"evidence": "absent"}, [],
             unchecked("anchor", "evidence_unavailable")),
        case("payload_wrong_commitment", "The payload record decodes, but its blob does not recompute to "
             "payload_ref.commitment (P3).", {"payload": "record:payload_da2_wrong_commitment"},
             ["archive/records.json#payload_da2_wrong_commitment"], unchecked("payload", "source_corrupt")),
        case("payload_record_undecodable", "The payload record fails strict decoding.",
             {"payload": "reject:payload_unknown_key"}, ["archive/records.json#payload_unknown_key"],
             unchecked("payload", "source_corrupt")),
        case("action_bytes_altered", "The archived action bytes do not hash to action.hash.",
             {"action_bytes": "one byte flipped"}, [], unchecked("action", "source_corrupt")),
        case("agent_signature_altered", "The commitment hashes to the reference, but the agent signature in the "
             "copy does not verify. The signature is outside the commitment hash, so another copy may carry the "
             "genuine one.", {"envelope_signature": "one byte flipped"}, [], unchecked("envelope", "source_corrupt")),
        case("authorization_signature_altered", "The Authorization record's gate signature does not verify.",
             {"authorization": "signature one byte flipped"},
             ["v1/authorization.json#authorization_signed_by_other_gate"],
             unchecked("authorization", "source_corrupt")),
        case("evidence_other_height", "The evidence record names another height than payload_ref.height.",
             {"evidence": "record:evidence_da2_minimal_lmt_other_height"},
             ["archive/records.json#evidence_da2_minimal_lmt_other_height"], unchecked("anchor", "source_corrupt")),
        case("fibre_certificate_fails", "da = 1: the archived PFF certificate fails CV6.",
             {"evidence": "da1 with mutation sig_first_signature"}, ["da/fibre_cert.json#sig_first_signature"],
             unchecked("anchor", "source_corrupt")),
        case("fibre_anchor_proof_fails", "da = 1: the archived form-1 anchor proof fails NMT verification.",
             {"evidence": "da1 with mutation share_flip"}, ["da/fibre_anchor.json#share_flip"],
             unchecked("anchor", "source_corrupt")),
        case("receipt_signature_altered", "The given receipt's gate signature does not verify.",
             {"receipt": "receipt_wrong_hash_tag"}, ["v1/receipt.json#receipt_wrong_hash_tag"],
             unchecked("receipt", "source_corrupt")),
        case("archived_header_not_linking", "The archived header at payload_ref.height does not link to the "
             "trusted chain. Header trust is unchecked, and the anchor checked against that header is not "
             "trusted either.", {"archived_header": "not_linking"}, [],
             unchecked("header_trust", "chain_mismatch")),
        case("da_not_supported", "The verifier was built without an anchor verifier for the decision's da.",
             {"anchor_verifiers": "none for da"}, [], unchecked("anchor", "da_unsupported")),
        case("no_trusted_header", "No header file, checkpoint or checkpoint source.", {"trusted": "none"}, [],
             unchecked("header_trust", "no_trusted_header")),
        case("checkpoint_below_anchor", "The trusted header is below payload_ref.height.",
             {"trusted": "file below payload_ref.height"}, [], unchecked("header_trust", "header_above_checkpoint")),
        case("online_header_not_linking", "Agreed checkpoint; the headers source serves a header that does not "
             "link at a height between, and no other source is configured.",
             {"checkpoint_sources": 1, "headers_source": "breaks the chain"}, [],
             unchecked("header_trust", "header_not_linking")),
        case("header_sources_down", "The only checkpoint source does not answer.",
             {"checkpoint_sources": 1, "checkpoint_source": "unavailable"}, [],
             unchecked("header_trust", "header_source_unavailable")),
        case("checkpoint_quorum_short", "quorum 2, one source answers.",
             {"checkpoint_sources": 2, "quorum": 2, "answering": 1}, [],
             unchecked("header_trust", "checkpoint_quorum")),
        case("checkpoint_sources_disagree", "Two checkpoint sources give different hashes at T (OH5).",
             {"checkpoint_sources": 2, "hash_at_T": "differs"}, [],
             unchecked("header_trust", "header_disagreement")),
        case("cross_check_disagrees", "A header cross-check source gives another hash at payload_ref.height "
             "(OH7).", {"cross_check": "other hash at payload_ref.height"}, [],
             unchecked("header_trust", "header_disagreement")),
        case("anchor_time_blocked", "Header trust is unchecked, so K1 has no trusted T_H: anchor_time is "
             "blocked, even if the untrusted header would fail K1.", {"trusted": "none", "issued_at": "K1 fails"},
             ["v1/anchor.json#k1_one_second_early"], unchecked("anchor_time", "blocked")),
        case("receipt_other_decision", "A receipt that verifies but names another commitment_hash.",
             {"receipt": "valid, for another commitment"}, [], unchecked("receipt", "receipt_mismatch")),
        case("replay_no_k2", "replay: the Authorization record has no K2 inputs.",
             {"authorization": "record:authorization_minimal_lmt_da_repaired"},
             ["archive/records.json#authorization_minimal_lmt_da_repaired"],
             unchecked("retention_replay", "replay_inputs_missing"), request="replay"),
        case("replay_path_inconsistent", "replay: the recorded K2 inputs make K2 false, but the Authorization's "
             "path is 1.", {"authorization": "path 1, k2.block_time moved back past the window"}, [],
             unchecked("retention_replay", "replay_inconsistent"), request="replay"),
        case("run_timeout", "The run deadline expires during the execution step.",
             {"timeout": "expires during execution"}, [], unchecked("execution", "timeout"),
             request="verify --check-execution"),
        case("no_execution_checker", "Execution requested for an action type without a checker.",
             {"action_type": "no checker registered"}, [], unchecked("execution", "no_checker"),
             request="verify --check-execution"),
        case("execution_blocked", "Execution requested, but no receipt was given (EX2).", {"receipt": "none"}, [],
             unchecked("execution", "blocked"), request="verify --check-execution"),
    ]
    for reason, cid in EXECUTION_CASE.items():
        cases.append(case(f"execution_{reason}", "See the execution_outcomes.json case.", {},
                          [f"verifier/execution_outcomes.json#{cid}"],
                          unchecked("execution", reason),
                          request="verify --check-execution"))
    for reason, (cid, check) in POLICY_CASE.items():
        cases.append(case(f"policy_{reason}", "See the policy/verify.json case.", {},
                          [f"policy/verify.json#{cid}"], unchecked(check, reason)))
    cases.append(case("policy_walk_history_missing", "Full policy walk; a previous allow record is missing.", {},
                      ["policy/verify.json#walk_history_missing"], unchecked("gate_integrity", "state_history_unavailable")))
    cases.append(case("policy_bucket_corrupt", "A closed bucket record does not hash to its key.", {},
                      ["policy/verify.json#unchecked_bucket_corrupt"], unchecked("policy", "source_corrupt")))
    cases.append(case("policy_t_h_blocked", "Header trust did not pass, so the policy rules on T_H are blocked.", {},
                      ["policy/verify.json#unchecked_t_h_not_verified"], unchecked("policy", "blocked")))
    cases.append(case("policy_private_part_inconsistent", "With an auditor key, an allow's PrivatePart hashes to the "
                      "signed private_hash but carries a deny reason; the facts and state it carries allow.", {},
                      ["policy/private.json#private_part_row_mismatch"], violated_private_part()))
    cases.append(case("policy_gate_equivocation", "Two gate-signed allows from one state of one counter.", {},
                      ["policy/verify.json#equivocation_fork_evidence"], violated(), request="verify --policy-full"))
    cases.append(case("policy_walk_truncated", "Full policy walk capped at one step on a chain of four allows: "
                      "gate_integrity is unchecked, the policy check passes and the verdict stays valid.", {},
                      ["policy/verify.json#pass_depth_1"], integrity_unchecked("policy_walk_truncated"),
                      request="verify --policy-full --max-walk-steps 1"))
    cases += [
        case("anchor_pending", "Fast mode: no evidence yet and the trusted head is below the anchor deadline.", {},
             ["v1/verify.json#fast_pending"], unchecked("anchor", "anchor_pending")),
        case("absence_unproven", "Fast mode: no evidence, and the absence proof of one height of the window is "
             "missing.", {}, ["v1/verify.json#fast_absence_missing_height"], unchecked("anchor", "absence_unproven")),
        case("policy_private", "Private mandate and no auditor key: the rules cannot be checked.", {},
             ["policy/private.json#private_without_key"], unchecked("policy", "policy_private")),
        case("policy_private_walk", "Private mandate, full walk without an auditor key: L1 and L2 pass down to the "
             "genesis hash, gate_integrity stays unchecked.", {}, ["policy/private.json#private_walk_without_key"],
             unchecked("gate_integrity", "policy_private"), request="verify --policy-full"),
        case("policy_private_action", "Private-form v1 decision record, no auditor key, no reveal: the action check "
             "is unchecked.", {}, ["v1/verify.json#decision_v1_private_without_key"],
             unchecked("action", "policy_private")),
        case("decision_unavailable_private_action", "Private-form v1 decision record whose kind 15 action record is "
             "absent in every copy.", {}, ["v1/verify.json#decision_v1_private_blob_missing"],
             unchecked("action", "decision_unavailable")),
        case("policy_principal_scheme_unsupported", "The mandate's principal scheme is not in this verifier build.",
             {}, ["policy/verify.json#principal_scheme_unsupported"], unchecked("policy", "principal_scheme_unsupported")),
    ]
    boundary = [
        case("commitment_rule_broken", "The commitment hashes to the reference and breaks stage S (ttl above "
             "the limit). Every copy has these bytes: fail.", {"commitment": "reject:ttl_3601"},
             ["v1/reject.json#ttl_3601"], failed("envelope")),
        case("agent_key_small_order", "The committed agent_pubkey is of small order (G0): it is inside the "
             "commitment hash, so fail.", {"commitment": "reject:pubkey_order8_a"},
             ["v1/reject.json#pubkey_order8_a"], failed("envelope")),
        case("issued_before_anchor", "K1 against T_H of a header that passed header trust.",
             {"issued_at": "K1 fails"}, ["v1/anchor.json#k1_one_second_early"], failed("anchor_time")),
        case("payload_action_differs", "A recipient opens a payload whose bytes match the commitment, and the "
             "payload's action differs from the committed one (O8).", {"payload": "opened, action differs"},
             ["v1/payload_blob.json#pb_payload_action_differs"], failed("payload")),
        case("policy_amount_above_max", "The gate allowed an amount above the mandate's per-action maximum.", {},
             ["policy/verify.json#fail_amount_above_max"], failed("policy")),
        case("policy_period_limit_on_signed_state", "The gate-signed prev_state proves the allow broke a period limit.",
             {}, ["policy/verify.json#fail_period_limit"], failed("policy")),
        case("execution_body_mismatch", "The tx bytes hash to rail_ref and carry another body.", {},
             ["verifier/execution_outcomes.json#fail_body_mismatch"], failed("execution"),
             request="verify --check-execution"),
        case("anchor_absent", "Fast mode: absence proven for every height of [h0, anchor_deadline].", {},
             ["v1/verify.json#fast_absent_proven"], failed("anchor")),
        case("authorization_mode_mismatch", "A1: mode 1 for a pending reference.", {},
             ["v1/verify.json#auth_mode_mismatch"], failed("authorization")),
        case("authorization_deadline_over_1000", "A2: anchor_deadline above h0 + 1000.", {},
             ["v1/verify.json#auth_deadline_over_1000"], failed("authorization")),
        case("policy_private_part_inconsistent_denies", "A PrivatePart that hashes to private_hash lacks the facts; "
             "the verifier's own extraction denies the allowed action.", {},
             ["policy/private.json#private_part_missing_facts_denies"], failed("policy")),
        case("policy_mandate_ref_mismatch", "The envelope's mandate_ref differs from the allow verdict's mandate_hash.",
             {}, ["policy/verify.json#mandate_ref_mismatch"], failed("policy")),
        case("policy_fast_mode_not_allowed", "A fast-mode Authorization under a mandate without fast_mode_max_delay.",
             {}, ["policy/verify.json#fast_mode_not_allowed"], failed("policy")),
        case("policy_fast_mode_delay", "anchor_deadline - h0 above the mandate's fast_mode_max_delay.", {},
             ["policy/verify.json#fast_mode_delay_exceeded"], failed("policy")),
    ]
    return {
        "format": "edicta-vectors/v1",
        "revision": "v1-draft.5",
        "generator": "spec/vectors/check/gen_verifier_reasons.py",
        "description": (
            "The verifier reason enum and one case per reason. Each case starts from a valid, authorized "
            "decision with a trusted header and changes what setup says; refs give concrete bytes where a vector "
            "has them. expect gives the check that carries the reason, its status, the record state and the "
            "verdict with its exit code. boundary lists verified data that proves a violation and stays fail."),
        "reasons": [{"name": n, "group": g, "checks": c, "meaning": m, "advice": a} for n, g, c, m, a in REASONS],
        "cases": cases,
        "boundary": boundary,
    }


def main() -> int:
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(build(), indent=2, ensure_ascii=True) + "\n")
    print(f"wrote {OUT.relative_to(VECTORS.parent.parent)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
