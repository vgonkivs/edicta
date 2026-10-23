// Package secret holds secret bytes read from files. A Secret prints as
// "[redacted]" under every fmt verb, slog and JSON; the value leaves it only
// through the explicit Reveal method.
package secret
