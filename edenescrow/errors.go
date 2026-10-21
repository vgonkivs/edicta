// SPDX-License-Identifier: Apache-2.0

package edenescrow

import (
	"errors"
	"fmt"
)

var (
	// ErrMalformed is any format failure of the action, its transaction or
	// the deposit calldata.
	ErrMalformed = errors.New("edenescrow: malformed")
	// ErrUnknownDomain is a well-formed transaction whose chain is not a row
	// of the table, or whose recipient is not that row's escrow.
	ErrUnknownDomain = errors.New("edenescrow: unknown chain or escrow")
	// ErrSignature is a signature outside the accepted ranges (y_parity 0 or
	// 1, 1 <= r < n, 1 <= s <= n/2) or one from which no key recovers.
	ErrSignature = errors.New("edenescrow: invalid signature")
	// ErrSignedMismatch is signed transaction bytes that are not the action's
	// transaction with one valid signature spliced in.
	ErrSignedMismatch = errors.New("edenescrow: signed transaction is not the authorized one")
	// ErrRequirements is a payment-required statement that does not decode,
	// does not bind to the action or quotes another deposit than the
	// action's.
	ErrRequirements = errors.New("edenescrow: payment requirements do not match the action")
)

// ruleError names the decoder rule that refused the input, so that tests
// can check the rule order the shared vectors record.
type ruleError struct {
	sentinel error
	rule     string
	msg      string
}

func (e *ruleError) Error() string { return fmt.Sprintf("%v: %s (rule %s)", e.sentinel, e.msg, e.rule) }

func (e *ruleError) Unwrap() error { return e.sentinel }

func malformed(rule, format string, a ...any) error {
	return &ruleError{sentinel: ErrMalformed, rule: rule, msg: fmt.Sprintf(format, a...)}
}

func requirements(rule, format string, a ...any) error {
	return &ruleError{sentinel: ErrRequirements, rule: rule, msg: fmt.Sprintf(format, a...)}
}

func unknownDomain(format string, a ...any) error {
	return &ruleError{sentinel: ErrUnknownDomain, rule: "ED1", msg: fmt.Sprintf(format, a...)}
}
