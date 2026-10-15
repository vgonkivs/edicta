package clearerr

import (
	"slices"
	"strconv"
	"strings"
)

// RedactURL cuts an endpoint down to scheme://host[:port], or host[:port]
// when it has no scheme. Paid RPC providers put the API key in the path, the
// query or the userinfo, so only the authority without userinfo may be
// printed.
func RedactURL(raw string) string {
	scheme, rest, found := strings.Cut(raw, "://")
	if !found {
		scheme, rest = "", raw
	}
	if i := strings.IndexAny(rest, "/?#"); i >= 0 {
		rest = rest[:i]
	}
	if i := strings.LastIndex(rest, "@"); i >= 0 {
		rest = rest[i+1:]
	}
	if !found {
		return rest
	}
	return scheme + "://" + rest
}

// RedactText applies RedactURL to every scheme://... URL inside s.
func RedactText(s string) string {
	var b strings.Builder
	for {
		i := strings.Index(s, "://")
		if i < 0 {
			b.WriteString(s)
			return b.String()
		}
		start := i
		for start > 0 && isSchemeByte(s[start-1]) {
			start--
		}
		end := i + 3
		for end < len(s) && !isURLEnd(s[end]) {
			end++
		}
		// Punctuation that closes the sentence is not part of the URL.
		stop := end
		for stop > i+3 && strings.IndexByte(".,;:!?)", s[stop-1]) >= 0 {
			stop--
		}
		b.WriteString(s[:start])
		b.WriteString(RedactURL(s[start:stop]))
		s = s[stop:]
	}
}

func isSchemeByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '+' || c == '-' || c == '.'
}

func isURLEnd(c byte) bool {
	switch c {
	case ' ', '\t', '\n', '\r', '"', '\'', '`', '<', '>':
		return true
	}
	return false
}

// RedactEndpoints cuts every occurrence of each of raws in s by RedactURL.
// Unlike RedactText it also finds endpoints written without a scheme.
func RedactEndpoints(s string, raws ...string) string {
	// Longest first, so an endpoint that prefixes another is not cut halfway.
	raws = slices.Clone(raws)
	slices.SortFunc(raws, func(a, b string) int { return len(b) - len(a) })
	for _, r := range raws {
		red := RedactURL(r)
		if r == "" || red == r {
			continue
		}
		s = strings.ReplaceAll(s, strconv.Quote(r), strconv.Quote(red))
		s = strings.ReplaceAll(s, r, red)
	}
	return s
}

// RedactErr returns err with its text passed through RedactEndpoints and
// RedactText. errors.Is and errors.As still reach the original chain.
func RedactErr(err error, raws ...string) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	out := RedactText(RedactEndpoints(msg, raws...))
	if out == msg {
		return err
	}
	return &redacted{msg: out, err: err}
}

type redacted struct {
	msg string
	err error
}

func (e *redacted) Error() string { return e.msg }
func (e *redacted) Unwrap() error { return e.err }
