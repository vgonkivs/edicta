#!/usr/bin/env python3
"""Writes spec/vectors/verifier/reasons.json (v0-draft.30).

The machine-readable reason enum of core section 20.1.1 and one case per
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
    ("decision_unavailable", "archive", ["decision"],
     "No decision record for the reference in any checked archive copy.", "another archive copy"),
    ("payload_unavailable", "archive", ["payload"],
     "The payload record is missing in every checked copy. It signals a retention failure of the operator and "
     "can feed an external accountability policy. It is not a verdict on the decision.", "another archive copy"),
    ("evidence_unavailable", "archive", ["anchor"],
     "The evidence record is missing in every checked copy.", "another archive copy"),
    ("source_corrupt", "archive", ["decision", "envelope", "action", "authorization", "payload", "anchor",
                                   "receipt", "policy", "gate_integrity"],
     "Bytes from a source fail a check that a genuine copy passes: strict decoding, the key check, a hash or DA "
     "commitment against the commitment, a signature that the commitment hash does not cover, or an archived "
     "proof (da = 2 commitment proof, Fibre CV1 to CV8, anchor proof forms 0 and 1).", "another copy"),
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
    ("blocked", "dependency", ["anchor_time", "header_trust", "execution", "retention_replay", "policy"],
     "The check needs another check that did not pass; the report names that check.", "fix the named check"),
    ("receipt_mismatch", "input", ["receipt"],
     "A receipt that verifies but is not this decision's: another commitment_hash or gate_id, or a gate key "
     "that is not on record for gate_id.", "the receipt of this decision"),
    ("replay_inputs_missing", "archive", ["retention_replay"],
     "The Authorization record carries no K2 inputs (repaired from the registry).", "another archive copy"),
    ("replay_unconfirmed", "archive", ["retention_replay"],
     "promise_created is earlier than the archived anchor's and the anchor proof is form 0, which shows no other "
     "candidate (19.2).", "an archive copy with a form-1 anchor proof"),
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
    ("policy_walk_truncated", "integrity", ["gate_integrity"],
     "The policy walk took its step cap (default or explicit) before it reached genesis, with no finding. The older "
     "part of the gate's chain was not read, so gate_integrity is never ok here. The report gives the walked seq "
     "range and the step count. The policy check and the verdict do not change.",
     "raise --max-walk-steps above the target's seq"),
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
             ["v0/authorization.json#authorization_signed_by_other_gate"],
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
             {"receipt": "receipt_wrong_hash_tag"}, ["v0/receipt.json#receipt_wrong_hash_tag"],
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
             ["v0/anchor.json#k1_one_second_early"], unchecked("anchor_time", "blocked")),
        case("receipt_other_decision", "A receipt that verifies but names another commitment_hash.",
             {"receipt": "valid, for another commitment"}, [], unchecked("receipt", "receipt_mismatch")),
        case("replay_no_k2", "replay: the Authorization record has no K2 inputs.",
             {"authorization": "record:authorization_minimal_lmt_da_repaired"},
             ["archive/records.json#authorization_minimal_lmt_da_repaired"],
             unchecked("retention_replay", "replay_inputs_missing"), request="replay"),
        case("replay_form0_earlier", "replay, da = 1: promise_created is earlier than the archived anchor's and "
             "the anchor proof is form 0.", {"evidence": "da1 form 0", "promise_created": "anchor - 1"}, [],
             unchecked("retention_replay", "replay_unconfirmed"), request="replay"),
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
    cases.append(case("policy_gate_equivocation", "Two gate-signed allows from one state of one counter.", {},
                      ["policy/verify.json#equivocation_fork_evidence"], violated(), request="verify --policy-full"))
    cases.append(case("policy_walk_truncated", "Full policy walk capped at one step on a chain of four allows: "
                      "gate_integrity is unchecked, the policy check passes and the verdict stays valid.", {},
                      ["policy/verify.json#pass_depth_1"], integrity_unchecked("policy_walk_truncated"),
                      request="verify --policy-full --max-walk-steps 1"))
    boundary = [
        case("commitment_rule_broken", "The commitment hashes to the reference and breaks stage S (ttl above "
             "the limit). Every copy has these bytes: fail.", {"commitment": "reject:ttl_3601"},
             ["v0/reject.json#ttl_3601"], failed("envelope")),
        case("agent_key_small_order", "The committed agent_pubkey is of small order (G0): it is inside the "
             "commitment hash, so fail.", {"commitment": "reject:pubkey_order8_a"},
             ["v0/reject.json#pubkey_order8_a"], failed("envelope")),
        case("issued_before_anchor", "K1 against T_H of a header that passed header trust.",
             {"issued_at": "K1 fails"}, ["v0/anchor.json#k1_one_second_early"], failed("anchor_time")),
        case("payload_action_differs", "A recipient opens a payload whose bytes match the commitment, and the "
             "payload's action differs from the committed one (O8).", {"payload": "opened, action differs"},
             ["v0/payload_blob.json#pb_payload_action_differs"], failed("payload")),
        case("policy_amount_above_max", "The gate allowed an amount above the mandate's per-action maximum.", {},
             ["policy/verify.json#fail_amount_above_max"], failed("policy")),
        case("policy_period_limit_on_signed_state", "The gate-signed prev_state proves the allow broke a period limit.",
             {}, ["policy/verify.json#fail_period_limit"], failed("policy")),
        case("execution_body_mismatch", "The tx bytes hash to rail_ref and carry another body.", {},
             ["verifier/execution_outcomes.json#fail_body_mismatch"], failed("execution"),
             request="verify --check-execution"),
    ]
    return {
        "format": "edicta-vectors/v0",
        "revision": "v0-draft.30",
        "generator": "spec/vectors/check/gen_verifier_reasons.py",
        "description": (
            "Reason enum of core 20.1.1 and one case per reason. Each case starts from a valid, authorized "
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
