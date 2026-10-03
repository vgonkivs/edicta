package commitment

import (
	"fmt"
	"math"
)

const (
	maxTTLCap     = 3600
	maxSkew       = 300
	maxUint63     = math.MaxInt64
	retentionDiv  = 4
	defaultSkewS  = 30
	defaultRetent = 14400
)

// Params are read from chain state by the gate at check time.
type Params struct {
	FibreRetentionS uint64
	BlobRetentionS  uint64
	SkewS           uint64
}

// DefaultParams uses a conservative blob retention until the Celestia pin is
// confirmed.
func DefaultParams() Params {
	return Params{FibreRetentionS: defaultRetent, BlobRetentionS: defaultRetent, SkewS: defaultSkewS}
}

func (p Params) Validate() error {
	if p.FibreRetentionS < 1 || p.FibreRetentionS > maxUint63 {
		return fmt.Errorf("%w: fibre_retention_s %d", ErrInvalidParams, p.FibreRetentionS)
	}
	if p.BlobRetentionS < 1 || p.BlobRetentionS > maxUint63 {
		return fmt.Errorf("%w: blob_retention_s %d", ErrInvalidParams, p.BlobRetentionS)
	}
	if p.SkewS > maxSkew {
		return fmt.Errorf("%w: skew_s %d", ErrInvalidParams, p.SkewS)
	}
	return nil
}

// MaxTTL is min(3600, floor(retention/4)). An unknown da yields 0 so that
// nothing passes by accident; stage S rejects such a da earlier.
func (p Params) MaxTTL(da DA) uint64 {
	var r uint64
	switch da {
	case DAFibre:
		r = p.FibreRetentionS
	case DACelestiaBlob:
		r = p.BlobRetentionS
	default:
		return 0
	}
	return min(maxTTLCap, r/retentionDiv)
}
