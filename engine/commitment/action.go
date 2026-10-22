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

// ActionHash is H(tag || uint8(len(type)) || type || salt || action). The
// type is inside the preimage so bytes committed under one type never match
// under another; the fixed-width salt keeps the public hash from being a
// dictionary oracle for low-entropy actions.
func ActionHash(actionType string, salt, action []byte) (Hash, error) {
	if len(action) < 1 || len(action) > MaxActionSize {
		return Hash{}, fmt.Errorf("%w: %d bytes", ErrActionSize, len(action))
	}
	if err := CheckActionSalt(salt); err != nil {
		return Hash{}, err
	}
	if !validActionType(actionType) {
		return Hash{}, fmt.Errorf("%w: action type", ErrInvalidString)
	}
	typ := append([]byte{byte(len(actionType))}, actionType...)
	return sha256.Sum256(tagged(TagAction, typ, salt, action)), nil
}

// CheckActionSalt requires a present salt of exactly ActionSaltSize bytes.
// A missing salt is an integration fault and so a separate error from a
// salt of the wrong length.
func CheckActionSalt(salt []byte) error {
	switch len(salt) {
	case 0:
		return fmt.Errorf("%w: action salt", ErrMissingField)
	case ActionSaltSize:
		return nil
	default:
		return fmt.Errorf("%w: action salt of %d bytes", ErrFieldSize, len(salt))
	}
}

// CheckAction requires the supplied bytes and salt to hash, under the
// committed type, to the committed action hash.
func CheckAction(c *Commitment, action, salt []byte) error {
	if c == nil {
		return fmt.Errorf("%w: nil commitment", ErrActionMismatch)
	}
	return matchActionHash(c.Action.Type, salt, action, c.Action.Hash)
}

// matchActionHash runs the size, salt and hash rules in their normative
// order. A type the grammar refuses cannot hash to anything committed, so
// it is a mismatch.
func matchActionHash(actionType string, salt, action, committed []byte) error {
	if len(action) < 1 || len(action) > MaxActionSize {
		return fmt.Errorf("%w: %d bytes", ErrActionSize, len(action))
	}
	if err := CheckActionSalt(salt); err != nil {
		return err
	}
	h, err := ActionHash(actionType, salt, action)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrActionMismatch, err)
	}
	if subtle.ConstantTimeCompare(h[:], committed) != 1 {
		return ErrActionMismatch
	}
	return nil
}
