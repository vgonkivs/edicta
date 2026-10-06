package archive

type ftype uint8

const (
	tUint ftype = iota
	tBstr
	tTstr
	tErrName
	tMap
)

type presence uint8

const (
	pReq presence = iota
	pOpt
	// pReq1 and pReq2 are required for that da and not defined for the other.
	pReq1
	pReq2
	// pOpt1 is optional for da = 1 and not defined for da = 2.
	pOpt1
	// pReq1Opt2 is required for da = 1 and optional for da = 2.
	pReq1Opt2
	// pTxIndex and pTxProof are defined only next to anchor_tx; the index is
	// required with it.
	pTxIndex
	pTxProof
)

type fdef struct {
	key    uint64
	name   string
	typ    ftype
	pres   presence
	lo, hi int
	sub    []fdef
}

const (
	maxOpaque = 1 << 22
	maxBlob   = 1 << 27

	maxEvidenceSize      = 1 << 25
	maxDecisionSize      = 69632
	maxAuthorizationSize = 512
	maxRejectionSize     = 256
)

var k2Schema = []fdef{
	{1, "da", tUint, pReq, 0, 0, nil},
	{2, "checked_at", tUint, pReq, 0, 0, nil},
	{3, "block_time", tUint, pReq, 0, 0, nil},
	{4, "blob_retention_s", tUint, pReq2, 0, 0, nil},
	{5, "retention_latest_s", tUint, pReq1, 0, 0, nil},
	{6, "retention_at_height_s", tUint, pReq1, 0, 0, nil},
	{7, "retention_source", tUint, pReq1, 0, 0, nil},
	{8, "promise_created", tUint, pOpt1, 0, 0, nil},
}

var commonSchema = []fdef{
	{1, "format", tUint, pReq, 0, 0, nil},
	{2, "kind", tUint, pReq, 0, 0, nil},
}

func schemaOf(k Kind) []fdef {
	var rest []fdef
	switch k {
	case KindPayload:
		rest = []fdef{
			{3, "da", tUint, pReq, 0, 0, nil},
			{4, "commitment", tBstr, pReq, 32, 32, nil},
			{5, "namespace", tBstr, pReq2, 29, 29, nil},
			{6, "signer", tBstr, pReq2, 20, 20, nil},
			{7, "blob", tBstr, pReq, 1, maxBlob, nil},
			{8, "intent_height", tUint, pReq, 0, 0, nil},
		}
	case KindEvidence:
		rest = []fdef{
			{3, "da", tUint, pReq, 0, 0, nil},
			{4, "commitment", tBstr, pReq, 32, 32, nil},
			{5, "namespace", tBstr, pReq, 29, 29, nil},
			{6, "height", tUint, pReq, 0, 0, nil},
			{7, "header", tBstr, pReq, 1, maxOpaque, nil},
			{8, "anchor_tx", tBstr, pReq1Opt2, 1, maxOpaque, nil},
			{9, "anchor_tx_index", tUint, pTxIndex, 0, 0, nil},
			{10, "anchor_tx_proof", tBstr, pTxProof, 1, maxOpaque, nil},
			{11, "blob_proof", tBstr, pReq2, 1, maxOpaque, nil},
			{12, "tx_code", tUint, pReq1, 0, 0, nil},
			{13, "system_blob", tBstr, pReq1, 1, maxOpaque, nil},
			{14, "system_blob_proof", tBstr, pReq1, 1, maxOpaque, nil},
			{15, "promise_height", tUint, pReq1, 0, 0, nil},
			{16, "promise_header", tBstr, pReq1, 1, maxOpaque, nil},
			{17, "historical_info", tBstr, pReq1, 1, maxOpaque, nil},
			{18, "promise_valset", tBstr, pReq1, 1, maxOpaque, nil},
		}
	case KindDecision:
		rest = []fdef{
			{3, "envelope", tBstr, pReq, 1, 2176, nil},
			{4, "action", tBstr, pReq, 1, 1 << 16, nil},
		}
	case KindAuthorization:
		rest = []fdef{
			{3, "signed_authorization", tBstr, pReq, 1, 256, nil},
			{4, "authorized_at", tUint, pReq, 0, 0, nil},
			{5, "k2", tMap, pOpt, 0, 0, k2Schema},
		}
	case KindRejection:
		rest = []fdef{
			{3, "commitment_hash", tBstr, pReq, 32, 32, nil},
			{4, "error", tErrName, pReq, 4, 64, nil},
			{5, "gate_id", tTstr, pReq, 1, 64, nil},
			{6, "rejected_at", tUint, pReq, 0, 0, nil},
		}
	}
	return append(append([]fdef(nil), commonSchema...), rest...)
}

func maxSizeOf(k Kind) int {
	switch k {
	case KindEvidence:
		return maxEvidenceSize
	case KindDecision:
		return maxDecisionSize
	case KindAuthorization:
		return maxAuthorizationSize
	case KindRejection:
		return maxRejectionSize
	}
	return MaxRecordSize
}

// verdicts are the only error names a rejection marker may carry.
var verdicts = map[string]bool{
	"ErrActionMismatch":              true,
	"ErrAnchorNotFound":              true,
	"ErrAnchorTooOld":                true,
	"ErrArchiveRecomputeUnsupported": true,
	"ErrDACommitmentMismatch":        true,
	"ErrExpired":                     true,
	"ErrIssuedBeforeAnchor":          true,
	"ErrNonceUsed":                   true,
	"ErrNotYetValid":                 true,
	"ErrPayloadHashMismatch":         true,
	"ErrPayloadSizeMismatch":         true,
	"ErrPayloadUnavailable":          true,
	"ErrRetentionUnavailable":        true,
}

func isIDChar(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' ||
		c == '.' || c == '_' || c == ':' || c == '/' || c == '-'
}

func isNameChar(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9'
}
