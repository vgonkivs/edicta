// SPDX-License-Identifier: Apache-2.0

package commitcmd

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/vgonkivs/edicta/edictaapi"
	"github.com/vgonkivs/edicta/sdk"
)

// Failure is the one error type Commit returns. Exit is the CLI exit code,
// Status the HTTP status of the serve route.
type Failure struct {
	Exit      int
	Status    int
	Code      string
	Message   string
	Retryable bool
	// Stored is the Authorization the gate already issued, on a nonce replay.
	Stored []byte
	// PolicyVerdict is the signed deny verdict of a policy refusal.
	PolicyVerdict []byte
}

func (f *Failure) Error() string { return fmt.Sprintf("%s: %s", f.Code, f.Message) }

// HTTPStatus is the status the serve route answers with.
func (f *Failure) HTTPStatus() int {
	if f.Status != 0 {
		return f.Status
	}
	switch f.Exit {
	case ExitUsage:
		return http.StatusBadRequest
	case ExitUnavailable:
		return http.StatusServiceUnavailable
	}
	return http.StatusUnprocessableEntity
}

func usagef(format string, a ...any) *Failure {
	return &Failure{Exit: ExitUsage, Code: "usage", Message: fmt.Sprintf(format, a...)}
}

// classify maps an error of the publish, build or authorize path to a Failure.
// A gate refusal is exit 3 with the server's code; anything that may succeed
// on a later try is exit 6.
func classify(err error) *Failure {
	var f *Failure
	if errors.As(err, &f) {
		return f
	}
	var ae *edictaapi.Error
	if errors.As(err, &ae) {
		out := &Failure{Exit: ExitRefused, Status: ae.Status, Code: ae.Code, Message: ae.Message,
			Retryable: ae.Retryable, Stored: ae.Stored, PolicyVerdict: ae.PolicyVerdict}
		if ae.Retryable {
			out.Exit = ExitUnavailable
		}
		return out
	}
	switch {
	case errors.Is(err, sdk.ErrInvalidConfig):
		return &Failure{Exit: ExitUsage, Code: "usage", Message: err.Error()}
	case errors.Is(err, sdk.ErrInclusionUnverified), errors.Is(err, sdk.ErrPublishTimeout),
		errors.Is(err, sdk.ErrClockBehindAnchor), errors.Is(err, context.DeadlineExceeded),
		errors.Is(err, context.Canceled):
		return &Failure{Exit: ExitUnavailable, Code: "source_unavailable", Message: err.Error(), Retryable: true}
	case errors.Is(err, sdk.ErrDACommitmentMismatch), errors.Is(err, sdk.ErrUnexpectedRef),
		errors.Is(err, sdk.ErrPublishResult), errors.Is(err, sdk.ErrValidityWindow),
		errors.Is(err, sdk.ErrBlockTimeMismatch), errors.Is(err, sdk.ErrDACheckUnavailable):
		return &Failure{Exit: ExitRefused, Code: "publication_refused", Message: err.Error()}
	}
	return &Failure{Exit: ExitUnavailable, Code: "source_unavailable", Message: err.Error(), Retryable: true}
}
