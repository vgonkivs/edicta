package doctor

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/vgonkivs/edicta/celestia/config"
)

// ErrNotAvailable is what a probe returns when the thing it asks about does
// not exist in this build or is not running.
var ErrNotAvailable = errors.New("doctor: not available")

func errNoProbe(what string) error {
	return fmt.Errorf("%w: no %s probe in this run", ErrNotAvailable, what)
}

// Checks returns every check of the stack in the order doctor prints them.
// cfgCheck is the result of loading the config, which the caller owns.
func Checks(env *Env, cfgCheck Check) []Check {
	return []Check{
		cfgCheck,
		endpointsCheck{env},
		chainCheck{env},
		fibreCheck{env},
		feesCheck{env},
		keyringCheck{env},
		clockCheck{env},
		archiveCheck{env},
		gateCheck{env},
		signerCheck{env},
		settlementCheck{env},
		facilitatorCheck{env},
		balancesCheck{env},
	}
}

// PreflightChecks are the checks that need only the [network] section: the
// endpoints answer, and the Celestia and settlement chains are the ones the
// presets name. They run before anything is written.
func PreflightChecks(env *Env) []Check {
	return []Check{endpointsCheck{env}, chainCheck{env}, settlementCheck{env}}
}

// ConfigCheck reports the outcome of loading and validating the config file.
type ConfigCheck struct {
	// Err is the load or validation error; nil when the config is valid.
	Err error
	// Drift lists presets whose version differs from this binary's.
	Drift []string
	// Presets is a one-line description of the presets in use.
	Presets string
}

func (ConfigCheck) Name() string { return "config" }

func (k ConfigCheck) Run(context.Context, config.Config) Result {
	if k.Err != nil {
		return fail(k.Err.Error(), "fix the key named in the message in edicta.toml; unknown keys are refused so typos show up here")
	}
	if len(k.Drift) > 0 {
		return warn(strings.Join(k.Drift, "; "), "review the changed preset values, then set the preset versions in [network] to the new ones")
	}
	return ok("%s", k.Presets)
}
