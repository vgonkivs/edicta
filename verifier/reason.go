package verifier

import (
	"errors"
	"fmt"
)

// Reason says why a check is unchecked. The set is closed: a source problem
// always maps to one of these, and a new one is a protocol revision.
type Reason string

const (
	ReasonDecisionUnavailable     Reason = "decision_unavailable"
	ReasonPayloadUnavailable      Reason = "payload_unavailable"
	ReasonEvidenceUnavailable     Reason = "evidence_unavailable"
	ReasonSourceCorrupt           Reason = "source_corrupt"
	ReasonChainMismatch           Reason = "chain_mismatch"
	ReasonDAUnsupported           Reason = "da_unsupported"
	ReasonNoTrustedHeader         Reason = "no_trusted_header"
	ReasonHeaderAboveCheckpoint   Reason = "header_above_checkpoint"
	ReasonHeaderNotLinking        Reason = "header_not_linking"
	ReasonHeaderSourceUnavailable Reason = "header_source_unavailable"
	ReasonCheckpointQuorum        Reason = "checkpoint_quorum"
	ReasonHeaderDisagreement      Reason = "header_disagreement"
	ReasonBlocked                 Reason = "blocked"
	ReasonReceiptMismatch         Reason = "receipt_mismatch"
	ReasonReplayInputsMissing     Reason = "replay_inputs_missing"
	ReasonReplayUnconfirmed       Reason = "replay_unconfirmed"
	ReasonReplayInconsistent      Reason = "replay_inconsistent"
	ReasonTimeout                 Reason = "timeout"
	ReasonNoChecker               Reason = "no_checker"
	ReasonChainConfig             Reason = "chain_config"
	ReasonTxNotFound              Reason = "tx_not_found"
	ReasonTxSourceUnavailable     Reason = "tx_source_unavailable"
	ReasonTxHashMismatch          Reason = "tx_hash_mismatch"
	ReasonTxProofInvalid          Reason = "tx_proof_invalid"
	ReasonResultUnproven          Reason = "result_unproven"
	ReasonResultsRootMismatch     Reason = "results_root_mismatch"
	ReasonResultIndexUnbound      Reason = "result_index_unbound"
	ReasonResultHeaderUnreachable Reason = "result_header_unreachable"
	ReasonCodeUnproven            Reason = "code_unproven"
	ReasonHeightUnproven          Reason = "height_unproven"
	ReasonCrossDisagree           Reason = "cross_disagree"
	ReasonChainUnbound            Reason = "chain_unbound"
)

// DisagreementText is what the report says when header sources, or a header
// source and the trusted header, contradict each other.
const DisagreementText = "header disagreement with trusted chain: possible bad trusted header, hostile source, or fork"

// ReasonInfo is the closed table entry of one reason.
type ReasonInfo struct {
	Reason  Reason
	Checks  []string
	Meaning string
	Advice  string
}

var reasonTable = []ReasonInfo{
	{ReasonDecisionUnavailable, []string{"decision"}, "No decision record for the reference in any checked archive copy.", "another archive copy"},
	{ReasonPayloadUnavailable, []string{"payload"}, "The payload record is missing in every checked copy. It signals a retention failure of the operator and can feed an external accountability policy. It is not a verdict on the decision.", "another archive copy"},
	{ReasonEvidenceUnavailable, []string{"anchor"}, "The evidence record is missing in every checked copy.", "another archive copy"},
	{ReasonSourceCorrupt, []string{"decision", "envelope", "action", "authorization", "payload", "anchor", "receipt"}, "Bytes from a source fail a check that a genuine copy passes: strict decoding, the key check, a hash or DA commitment against the commitment, a signature that the commitment hash does not cover, or an archived proof (da = 2 commitment proof, Fibre CV1 to CV8, anchor proof forms 0 and 1).", "another copy"},
	{ReasonChainMismatch, []string{"header_trust", "anchor"}, "An archived header at a needed height does not link to the trusted chain (HT3, HT5, OH6), or the archived evidence names another height than the decision.", "another archive copy, or check the trusted header"},
	{ReasonDAUnsupported, []string{"anchor"}, "The verifier has no anchor verifier for payload_ref.da.", "a verifier build that supports this da"},
	{ReasonNoTrustedHeader, []string{"header_trust"}, "No trusted header file, explicit checkpoint or checkpoint source was given.", "supply a trusted header"},
	{ReasonHeaderAboveCheckpoint, []string{"header_trust", "execution"}, "The checkpoint height T is below a needed height (OH4, EX5 (a)).", "retry later or with a newer checkpoint"},
	{ReasonHeaderNotLinking, []string{"header_trust", "execution"}, "An online header at a needed height does not link to the trusted chain, and no source gives one that does (OH6, EX5 (b)).", "another header source"},
	{ReasonHeaderSourceUnavailable, []string{"header_trust"}, "No header or checkpoint source answered.", "another header source"},
	{ReasonCheckpointQuorum, []string{"header_trust"}, "Fewer than quorum distinct sources agree on the checkpoint (OH5).", "more checkpoint sources"},
	{ReasonHeaderDisagreement, []string{"header_trust", "execution"}, DisagreementText + " (OH5, OH7, HT6, EX5 (d)).", "check the trusted header against an independent source"},
	{ReasonBlocked, []string{"anchor_time", "header_trust", "execution", "retention_replay"}, "The check needs another check that did not pass; the report names that check.", "fix the named check"},
	{ReasonReceiptMismatch, []string{"receipt"}, "A receipt that verifies but is not this decision's: another commitment_hash or gate_id, or a gate key that is not on record for gate_id.", "the receipt of this decision"},
	{ReasonReplayInputsMissing, []string{"retention_replay"}, "The Authorization record carries no K2 inputs (repaired from the registry).", "another archive copy"},
	{ReasonReplayUnconfirmed, []string{"retention_replay"}, "promise_created is earlier than the archived anchor's and the anchor proof is form 0, which shows no other candidate (19.2).", "an archive copy with a form-1 anchor proof"},
	{ReasonReplayInconsistent, []string{"retention_replay"}, "K2 recomputed from the recorded inputs disagrees with the Authorization's path, or promise_created matches no candidate. The K2 inputs are unsigned archive data, so a gate error and an altered record look the same.", "another archive copy"},
	{ReasonTimeout, []string{"any"}, "The run deadline cut the check short.", "retry with a longer --timeout"},
	{ReasonNoChecker, []string{"execution"}, "No execution checker for action.type.", "a verifier with the profile"},
	{ReasonChainConfig, []string{"execution"}, "BX0: the checker is configured for another chain.", "configure the action's chain"},
	{ReasonTxNotFound, []string{"execution"}, "BX1: no tx source knows the transaction.", "another tx source"},
	{ReasonTxSourceUnavailable, []string{"execution"}, "BX1: the tx sources failed.", "another tx source"},
	{ReasonTxHashMismatch, []string{"execution"}, "BX2: the served bytes do not hash to rail_ref.", "another tx source"},
	{ReasonTxProofInvalid, []string{"execution"}, "BX6: the inclusion proof does not verify.", "another tx source"},
	{ReasonResultUnproven, []string{"execution"}, "The result code is attested by one source: no result proof and no cross confirmation (EX9).", "a source that serves block_results, or a cross tx source"},
	{ReasonResultsRootMismatch, []string{"execution"}, "RP4: the results do not hash to last_results_hash.", "another results source"},
	{ReasonResultIndexUnbound, []string{"execution"}, "RP5: nothing binds the tx's index in the results.", "a cross tx source"},
	{ReasonResultHeaderUnreachable, []string{"execution"}, "RP4: the header at height + 1 is not trusted.", "retry later or with a newer checkpoint"},
	{ReasonCodeUnproven, []string{"execution"}, "A nonzero code that no result proof verifies (EX9).", "a source that serves block_results"},
	{ReasonHeightUnproven, []string{"execution"}, "A height at or below the anchor without a proof (EX4).", "a tx source that serves inclusion proofs"},
	{ReasonCrossDisagree, []string{"execution"}, "Tx sources disagree and nothing verifies either (EX6).", "another tx source"},
	{ReasonChainUnbound, []string{"execution"}, "BX4: another chain id without proven inclusion.", "a tx source that serves inclusion proofs"},
}

// Reasons returns the closed table of 20.1.1, in order.
func Reasons() []ReasonInfo {
	out := make([]ReasonInfo, len(reasonTable))
	for i, r := range reasonTable {
		r.Checks = append([]string(nil), r.Checks...)
		out[i] = r
	}
	return out
}

// Info returns the table entry of r. The second value is false for a value
// outside the closed set.
func (r Reason) Info() (ReasonInfo, bool) {
	for _, e := range reasonTable {
		if e.Reason == r {
			e.Checks = append([]string(nil), e.Checks...)
			return e, true
		}
	}
	return ReasonInfo{}, false
}

// Advice is the one line that says what to try next.
func (r Reason) Advice() string {
	if e, ok := r.Info(); ok {
		return e.Advice
	}
	return ""
}

// Meaning is the one-sentence explanation of the reason.
func (r Reason) Meaning() string {
	if e, ok := r.Info(); ok {
		return e.Meaning
	}
	return ""
}

// ReasonError is an error that carries its machine-readable reason and the
// sources it blames, by normalized host or by the name of another check.
type ReasonError struct {
	Reason  Reason
	Sources []string
	Err     error
}

// Error is the message of the wrapped error; the report prints the reason
// and the sources on their own.
func (e *ReasonError) Error() string {
	if e.Err != nil {
		return e.Err.Error()
	}
	return string(e.Reason)
}

func (e *ReasonError) Unwrap() error { return e.Err }

// WithReason wraps err with a reason and the sources it names.
func WithReason(reason Reason, sources []string, err error) error {
	if err == nil {
		err = errors.New(string(reason))
	}
	return &ReasonError{Reason: reason, Sources: append([]string(nil), sources...), Err: err}
}

// Reasonf is WithReason over a formatted message.
func Reasonf(reason Reason, sources []string, format string, a ...any) error {
	return WithReason(reason, sources, fmt.Errorf(format, a...))
}

// ReasonOf finds the outermost reason in err's chain.
func ReasonOf(err error) (Reason, []string, bool) {
	var re *ReasonError
	if errors.As(err, &re) {
		return re.Reason, re.Sources, true
	}
	return "", nil, false
}
