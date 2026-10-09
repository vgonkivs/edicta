package archive

import (
	"errors"
	"strings"
)

var errBadKey = errors.New("archive: not a canonical key")

func isLowerHex32(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// ParseKey reports the kind of a canonical record path. It accepts exactly
// the paths KeyPath produces, so a server can refuse every other string
// before it touches storage.
func ParseKey(path string) (Kind, error) {
	parts := strings.Split(path, "/")
	switch parts[0] {
	case "payload", "evidence":
		if len(parts) != 3 || (parts[1] != "1" && parts[1] != "2") || !isLowerHex32(parts[2]) {
			return 0, errBadKey
		}
		if parts[0] == "payload" {
			return KindPayload, nil
		}
		return KindEvidence, nil
	case "decision", "authorization", "reveal":
		if len(parts) != 2 || !isLowerHex32(parts[1]) {
			return 0, errBadKey
		}
		switch parts[0] {
		case "decision":
			return KindDecision, nil
		case "reveal":
			return KindReveal, nil
		}
		return KindAuthorization, nil
	case "rejection":
		if len(parts) != 3 || !isLowerHex32(parts[1]) || !IsVerdict(parts[2]) {
			return 0, errBadKey
		}
		return KindRejection, nil
	case "mandate", "policy-allow", "policy-bucket", "policy-closed", "policy-successor":
		if len(parts) != 2 || !isLowerHex32(parts[1]) {
			return 0, errBadKey
		}
		for k, dir := range policyDirs {
			if dir == parts[0] {
				return k, nil
			}
		}
	case "intent", "absence":
		if !parseHeightKey(parts) {
			return 0, errBadKey
		}
		if parts[0] == "intent" {
			return KindAnchorIntent, nil
		}
		return KindAbsenceProof, nil
	case "policy-deny":
		if len(parts) != 3 || !isLowerHex32(parts[1]) || !IsPolicyDeny(parts[2]) {
			return 0, errBadKey
		}
		return KindPolicyDeny, nil
	}
	return 0, errBadKey
}
