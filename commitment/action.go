package commitment

import (
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
)

// ValidMediaType reports whether s is a lower-case media type of the form
// name "/" name, with no parameters, no whitespace and at most max bytes.
func ValidMediaType(s string, max int) bool {
	if len(s) < 3 || len(s) > max {
		return false
	}
	slash := -1
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '/' {
			if slash >= 0 {
				return false
			}
			slash = i
		}
	}
	if slash < 1 || slash == len(s)-1 {
		return false
	}
	return mediaName(s[:slash]) && mediaName(s[slash+1:])
}

func mediaName(n string) bool {
	for i := 0; i < len(n); i++ {
		c := n[i]
		alnum := c >= 'a' && c <= 'z' || c >= '0' && c <= '9'
		if i == 0 {
			if !alnum {
				return false
			}
			continue
		}
		switch c {
		case '!', '#', '$', '&', '^', '_', '.', '+', '-':
		default:
			if !alnum {
				return false
			}
		}
	}
	return len(n) > 0
}

func validActionType(s string) bool { return ValidMediaType(s, MaxActionTypeSize) }

// ActionHash is H(tag || uint8(len(type)) || type || action). The type is
// inside the preimage so bytes committed under one type never match under
// another.
func ActionHash(actionType string, action []byte) (Hash, error) {
	if len(action) < 1 || len(action) > MaxActionSize {
		return Hash{}, fmt.Errorf("%w: %d bytes", ErrActionSize, len(action))
	}
	if !validActionType(actionType) {
		return Hash{}, fmt.Errorf("%w: action type", ErrInvalidString)
	}
	typ := append([]byte{byte(len(actionType))}, actionType...)
	return sha256.Sum256(tagged(TagAction, typ, action)), nil
}

// ActionHashFor is the action hash of a commitment or Authorization of the
// given version. Every caller that binds action bytes to a version goes
// through it, so the v1 preimage can change in this one place; today both
// versions use ActionHash.
func ActionHashFor(version uint64, actionType string, action []byte) (Hash, error) {
	return ActionHash(actionType, action)
}

// CheckAction requires the supplied bytes to be exactly the committed ones.
func CheckAction(c *Commitment, action []byte) error {
	if c == nil {
		return fmt.Errorf("%w: nil commitment", ErrActionMismatch)
	}
	h, err := ActionHashFor(c.Version, c.Action.Type, action)
	if err != nil {
		if len(action) < 1 || len(action) > MaxActionSize {
			return err
		}
		return fmt.Errorf("%w: %v", ErrActionMismatch, err)
	}
	if subtle.ConstantTimeCompare(h[:], c.Action.Hash) != 1 {
		return ErrActionMismatch
	}
	return nil
}
