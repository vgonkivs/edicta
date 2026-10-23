// Package clearerr holds the one message for each failure seen in live runs:
// it names the cause and the fix. doctor and init use it to turn raw dial,
// TLS, node and facilitator errors into something a person can act on.
package clearerr

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
)

// Error is a message that names a cause and a fix. Cause is the underlying
// error, if any, for errors.Is and errors.As.
type Error struct {
	// Kind is a stable machine label of the failure.
	Kind  string
	Msg   string
	Cause error
}

func (e *Error) Error() string { return e.Msg }
func (e *Error) Unwrap() error { return e.Cause }

// Kinds of Error.
const (
	KindScheme     = "scheme"
	KindTLS        = "tls"
	KindFee        = "fee"
	KindPassphrase = "passphrase"
	KindChain      = "chain"
	KindEscrow     = "escrow"
	KindFacilitate = "facilitator"
)

// KindOf returns the Kind of err, or "" if err holds no Error.
func KindOf(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Kind
	}
	return ""
}

// Scheme is an endpoint written with the wrong scheme for what answers there.
func Scheme(endpoint, got, serverSpeaks, fix string) error {
	return &Error{Kind: KindScheme, Msg: fmt.Sprintf("endpoint %s: scheme %s but server speaks %s; use %s", RedactURL(endpoint), got, serverSpeaks, RedactText(fix))}
}

// TLS is a failed TLS handshake.
func TLS(endpoint string, reason error) error {
	return &Error{
		Kind:  KindTLS,
		Msg:   fmt.Sprintf("endpoint %s: TLS: %s; check the certificate or set tls = false for a local node", RedactURL(endpoint), RedactText(reasonText(reason))),
		Cause: reason,
	}
}

// FeeTooLow is a transaction fee under the node's minimum gas price. price is
// the node's price in utia per gas, as text.
func FeeTooLow(price string) error {
	return &Error{Kind: KindFee, Msg: fmt.Sprintf("fee below the node's minimum gas price %s utia/gas; doctor reads it from the node", price)}
}

// KeyringPassphrase is a passphrase file that does not unlock the key.
func KeyringPassphrase(file, key string) error {
	return &Error{Kind: KindPassphrase, Msg: fmt.Sprintf("keyring passphrase file %s does not open %s", file, key)}
}

// WrongChain is a node on another chain than the config expects.
func WrongChain(endpoint, got, want string) error {
	return &Error{Kind: KindChain, Msg: fmt.Sprintf("node at %s is chain %s, config expects %s", RedactURL(endpoint), got, want)}
}

// EscrowLow is a Fibre escrow under the headroom of one upload.
func EscrowLow(have, headroom uint64) error {
	return &Error{Kind: KindEscrow, Msg: fmt.Sprintf("escrow %d utia below headroom %d (one upload of max_blob_bytes)", have, headroom)}
}

// Facilitator is a payment the facilitator refused: its invalidReason as it
// sent it, then the profile check that applies, if there is one.
func Facilitator(invalidReason, profileCheck string) error {
	msg := fmt.Sprintf("facilitator refused the payment: %s", RedactText(invalidReason))
	if profileCheck != "" {
		msg += "; " + profileCheck
	}
	return &Error{Kind: KindFacilitate, Msg: msg}
}

// Dial turns the error of a connection attempt to endpoint into the matching
// message. scheme is the one the config used (http, https, or "" for a
// host:port with tls decided by the flag), and tlsOn what the config
// expects. An error it does not recognise is returned with its URLs and
// endpoint redacted.
func Dial(endpoint, scheme string, tlsOn bool, err error) error {
	if err == nil {
		return nil
	}
	raw := endpoint
	endpoint = RedactURL(endpoint)
	s := err.Error()
	var (
		unknownAuth x509.UnknownAuthorityError
		hostErr     x509.HostnameError
		certInvalid x509.CertificateInvalidError
		recHdr      tls.RecordHeaderError
	)
	switch {
	case strings.Contains(s, "server gave HTTP response to HTTPS client"):
		return Scheme(endpoint, "https", "http", "http://"+bare(endpoint))
	case strings.Contains(s, "first record does not look like a TLS handshake"), errors.As(err, &recHdr):
		if scheme == "https" {
			return Scheme(endpoint, "https", "http", "http://"+bare(endpoint))
		}
		return Scheme(endpoint, schemeOrTLS(scheme, tlsOn), "plain text", "tls = false")
	case strings.Contains(s, "HTTP request to an HTTPS server"):
		return Scheme(endpoint, "http", "https", "https://"+bare(endpoint))
	case errors.As(err, &unknownAuth), errors.As(err, &hostErr), errors.As(err, &certInvalid),
		strings.Contains(s, "x509:"), strings.Contains(s, "tls:"), strings.Contains(s, "remote error: tls"):
		return TLS(endpoint, err)
	}
	return RedactErr(err, raw)
}

func schemeOrTLS(scheme string, tlsOn bool) string {
	if scheme != "" {
		return scheme
	}
	if tlsOn {
		return "tls"
	}
	return "plain"
}

func bare(endpoint string) string {
	if _, rest, ok := strings.Cut(endpoint, "://"); ok {
		return rest
	}
	return endpoint
}

// reasonText is the short reason of a TLS failure.
func reasonText(err error) string {
	if err == nil {
		return "handshake failed"
	}
	s := err.Error()
	// Drop the "Get \"url\": " prefix net/http puts in front.
	if i := strings.LastIndex(s, "\": "); i >= 0 {
		s = s[i+3:]
	}
	return s
}

// IsFeeTooLow reports whether a broadcast error says the fee was under the
// node's minimum gas price.
func IsFeeTooLow(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "insufficient fee") || strings.Contains(s, "insufficient minimum gas price") ||
		strings.Contains(s, "below the minimum gas price") || strings.Contains(s, "minimum global fee")
}
