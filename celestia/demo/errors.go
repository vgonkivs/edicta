package demo

import (
	"context"
	"errors"

	"github.com/vgonkivs/edicta/edictaapi"
)

var (
	ErrFunderAddressMismatch   = errors.New("demo: --address differs from the funder key's address")
	ErrSameAccount             = errors.New("demo: funder, recorder and executor must be distinct accounts")
	ErrFundTimeout             = errors.New("demo: funds did not arrive in time")
	ErrShortfallAboveMax       = errors.New("demo: a needed send exceeds the per-send funding maximum")
	ErrOperatorQuit            = errors.New("demo: stopped by the operator")
	ErrAttemptUnexpected       = errors.New("demo: a cheating attempt did not end as expected")
	ErrRailLocked              = errors.New("demo: this rail broadcasts nothing now")
	ErrTrustRootUnavailable    = errors.New("demo: no trust root from an independent channel")
	ErrTrustRootNotIndependent = errors.New("demo: the trust-root source is on a data RPC host")
	ErrTrustedHeaderTooLow     = errors.New("demo: the trusted header is below the needed height")
	ErrClockSkew               = errors.New("demo: local clock differs from chain time")
	ErrNoTerminal              = errors.New("demo: the start needs an Enter on a terminal")
	ErrConfig                  = errors.New("demo: invalid configuration")
	ErrFundingCap              = errors.New("demo: lifetime funding cap reached")
	ErrFibreRefused            = errors.New("demo: the demo runs celestia_blob only")
	ErrHomeLocked              = errors.New("demo: another demo holds the home directory")
)

// Process exit codes of the demo.
const (
	ExitOK           = 0
	ExitWrong        = 1
	ExitInconclusive = 2
	ExitNotAuth      = 3
	ExitUsage        = 4
	ExitInterrupted  = 130
)

type codedError struct {
	code int
	err  error
}

func (e *codedError) Error() string { return e.err.Error() }
func (e *codedError) Unwrap() error { return e.err }

func coded(code int, err error) error { return &codedError{code: code, err: err} }

func asAPIError(err error) *edictaapi.Error {
	var ae *edictaapi.Error
	if errors.As(err, &ae) {
		return ae
	}
	return nil
}

// errName is the API error code, or the error text, or "no error".
func errName(err error, _ string) string {
	switch ae := asAPIError(err); {
	case err == nil:
		return "no error"
	case ae != nil:
		return ae.Code
	}
	return err.Error()
}

// ExitCodeOf is the process exit code an error from New or Run stands for.
func ExitCodeOf(err error) int {
	var ce *codedError
	switch {
	case err == nil:
		return ExitOK
	case errors.Is(err, context.Canceled):
		return ExitInterrupted
	case errors.As(err, &ce):
		return ce.code
	case errors.Is(err, ErrConfig), errors.Is(err, ErrNoTerminal):
		return ExitUsage
	}
	return ExitInconclusive
}
