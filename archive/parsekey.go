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
	case "decision", "authorization":
		if len(parts) != 2 || !isLowerHex32(parts[1]) {
			return 0, errBadKey
		}
		if parts[0] == "decision" {
			return KindDecision, nil
		}
		return KindAuthorization, nil
	case "rejection":
		if len(parts) != 3 || !isLowerHex32(parts[1]) || !IsVerdict(parts[2]) {
			return 0, errBadKey
		}
		return KindRejection, nil
	}
	return 0, errBadKey
}
