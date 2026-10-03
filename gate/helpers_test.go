package gate_test

import (
	"crypto/sha256"

	"github.com/vgonkivs/prior/gate/registry/memreg"

	"github.com/vgonkivs/prior/commitment"
	"github.com/vgonkivs/prior/test/gatefix"
)

func sha256sum(b []byte) [32]byte { return sha256.Sum256(b) }

// routeArchive stages chain data so that the retention window rule fails by
// exactly one second: the DA path must not be used.
func routeArchive(e *gatefix.Env, c *commitment.Commitment) {
	th := c.ValidUntil + 600 - 14400 - 1
	e.StageChain(c, th, th)
}

func newMemRegErr(epoch uint64) (*memreg.Registry, error) { return memreg.New(epoch) }
