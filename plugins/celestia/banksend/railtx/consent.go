package railtx

import (
	"errors"
	"sync/atomic"
)

// ErrNotStarted means a broadcast was attempted before the caller armed the
// Consent.
var ErrNotStarted = errors.New("railtx: nothing is broadcast before the user starts the demo")

// Consent is the switch every consent-gated broadcast path checks. The zero
// value is unarmed. The owner of the user dialog arms it once, after the user
// has said go; nothing in this package arms it, and there is no way to unarm.
type Consent struct{ armed atomic.Bool }

// Arm allows broadcasts from every sender holding this Consent.
func (c *Consent) Arm() { c.armed.Store(true) }

// Check returns ErrNotStarted until Arm has been called. A nil Consent is
// never armed.
func (c *Consent) Check() error {
	if c == nil || !c.armed.Load() {
		return ErrNotStarted
	}
	return nil
}
