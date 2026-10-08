package policy

import "errors"

// ErrDenied is the umbrella every policy deny wraps.
var ErrDenied = errors.New("policy: denied")

type denyError struct{ msg string }

func (e *denyError) Error() string        { return e.msg }
func (e *denyError) Is(target error) bool { return target == ErrDenied }

func deny(msg string) error { return &denyError{msg: msg} }

// Deny sentinels, one per rule that can refuse an action.
var (
	ErrAgentNotCovered     = deny("policy: agent not covered by the mandate")
	ErrNoExtractor         = deny("policy: no extractor for the action type")
	ErrFactsInvalid        = deny("policy: facts could not be extracted or are invalid")
	ErrOutsideMandate      = deny("policy: outside the mandate validity")
	ErrKindNotAllowed      = deny("policy: kind not allowed")
	ErrAssetNotAllowed     = deny("policy: asset not allowed")
	ErrRecipientNotAllowed = deny("policy: recipient not allowed")
	ErrAmountAboveMax      = deny("policy: amount above the per-action maximum")
	ErrDecisionAge         = deny("policy: anchor older than the maximum decision age")
	ErrMinSpacing          = deny("policy: too soon after the last allowed action")
	ErrPeriodLimit         = deny("policy: rolling period limit")
	ErrCountLimit          = deny("policy: rolling count limit")
	ErrHistoryFull         = deny("policy: history capacity reached")
)

// Structural sentinels.
var (
	ErrMandateInvalid   = errors.New("policy: invalid mandate")
	ErrMandateSignature = errors.New("policy: mandate signature invalid")
	ErrVerdictInvalid   = errors.New("policy: invalid verdict")
	ErrVerdictSignature = errors.New("policy: verdict signature invalid")
	ErrStateInvalid     = errors.New("policy: invalid state")
	ErrCounterInvalid   = errors.New("policy: invalid counter cell")
	ErrScaleChanged     = errors.New("policy: asset scale differs from the one the counter recorded")
	ErrScalesFull       = errors.New("policy: counter scale map is full")
)

// DenyReasons lists the bare names of the deny sentinels in the order the checks run.
var DenyReasons = []string{
	"ErrAgentNotCovered", "ErrNoExtractor", "ErrFactsInvalid", "ErrOutsideMandate", "ErrKindNotAllowed",
	"ErrAssetNotAllowed", "ErrRecipientNotAllowed", "ErrAmountAboveMax", "ErrDecisionAge", "ErrMinSpacing",
	"ErrPeriodLimit", "ErrCountLimit", "ErrHistoryFull",
}

var denyByName = map[string]error{
	"ErrAgentNotCovered": ErrAgentNotCovered, "ErrNoExtractor": ErrNoExtractor, "ErrFactsInvalid": ErrFactsInvalid,
	"ErrOutsideMandate": ErrOutsideMandate, "ErrKindNotAllowed": ErrKindNotAllowed, "ErrAssetNotAllowed": ErrAssetNotAllowed,
	"ErrRecipientNotAllowed": ErrRecipientNotAllowed, "ErrAmountAboveMax": ErrAmountAboveMax, "ErrDecisionAge": ErrDecisionAge,
	"ErrMinSpacing": ErrMinSpacing, "ErrPeriodLimit": ErrPeriodLimit, "ErrCountLimit": ErrCountLimit, "ErrHistoryFull": ErrHistoryFull,
}

// DenySentinel returns the sentinel for a bare reason name.
func DenySentinel(name string) (error, bool) {
	e, ok := denyByName[name]
	return e, ok
}

// ReasonOf returns the bare reason name of a deny error, or "" if err is not
// one of the thirteen denies.
func ReasonOf(err error) string {
	for _, n := range DenyReasons {
		if errors.Is(err, denyByName[n]) {
			return n
		}
	}
	return ""
}

// HistoryFullError says which capacity bound was hit; it matches ErrHistoryFull.
type HistoryFullError struct{ Cause string } // "sum", "count", "pairs" or "seq"

func (e *HistoryFullError) Error() string { return "policy: history capacity reached: " + e.Cause }
func (e *HistoryFullError) Is(target error) bool {
	return target == ErrHistoryFull || target == ErrDenied
}
