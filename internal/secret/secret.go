package secret

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
)

const redacted = "[redacted]"

// ErrPermissions means a secret file is readable by group or others.
var ErrPermissions = errors.New("secret: file mode wider than 0600")

// ErrEmpty means a secret file has no content.
var ErrEmpty = errors.New("secret: empty")

// Secret holds secret bytes. The bytes live behind a pointer to an unexported
// struct, so reflection-based printing of a copy, a slice, a map or an
// enclosing struct shows an address at most. The zero value is no secret.
type Secret struct{ box *box }

type box struct{ b []byte }

// New copies b.
func New(b []byte) Secret { return Secret{box: &box{b: bytes.Clone(b)}} }

// FromFile reads a secret from path. The file must not be readable by group
// or others, and one trailing newline is trimmed. Errors never contain file
// content.
func FromFile(path string) (Secret, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return Secret{}, fmt.Errorf("secret: stat %q: %w", path, err)
	}
	if !fi.Mode().IsRegular() {
		return Secret{}, fmt.Errorf("secret: %q is not a regular file", path)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return Secret{}, fmt.Errorf("%w: %q", ErrPermissions, path)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return Secret{}, fmt.Errorf("secret: read %q: %w", path, err)
	}
	b = bytes.TrimSuffix(bytes.TrimSuffix(b, []byte("\n")), []byte("\r"))
	if len(b) == 0 {
		return Secret{}, fmt.Errorf("%w: %q", ErrEmpty, path)
	}
	return Secret{box: &box{b: b}}, nil
}

// Reveal returns a copy of the secret bytes. It is the only way out.
func (s Secret) Reveal() []byte {
	if s.box == nil {
		return nil
	}
	return bytes.Clone(s.box.b)
}

// RevealString returns the secret as a string.
func (s Secret) RevealString() string { return strings.Clone(string(s.Reveal())) }

// IsSet reports whether the secret has any bytes.
func (s Secret) IsSet() bool { return s.box != nil && len(s.box.b) > 0 }

// Zero overwrites the bytes; the secret reads as empty afterwards.
func (s Secret) Zero() {
	if s.box != nil {
		clear(s.box.b)
		s.box.b = nil
	}
}

func (Secret) String() string               { return redacted }
func (Secret) GoString() string             { return redacted }
func (Secret) MarshalJSON() ([]byte, error) { return []byte(`"` + redacted + `"`), nil }
func (Secret) MarshalText() ([]byte, error) { return []byte(redacted), nil }
func (Secret) LogValue() slog.Value         { return slog.StringValue(redacted) }

// Format makes every fmt verb print "[redacted]".
func (Secret) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte(redacted)) }
