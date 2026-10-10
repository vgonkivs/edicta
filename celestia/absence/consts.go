// Package absence verifies proofs that an anchor is not included at a
// height, and windows of them, against hashes that header trust already
// established. VerifyHeight and VerifyWindow are pure; Fetcher and Chain
// read archived and online proofs through interfaces and hand them to the
// pure check. Every failure of a proof means "not proven", never "absent":
// a hostile source can withhold, but it cannot make an included anchor look
// absent without breaking SHA-256 or the NMT.
package absence

const (
	// PinnedAppVersion is the only app version whose square rules (Fibre txs
	// last, in PFF namespace order, in PFF_NS) let a height prove absence.
	// The protocol pins it rather than importing appconsts, so an upgrade
	// cannot silently widen what proves absence.
	PinnedAppVersion = 10

	// SubtreeRootThreshold is the share commitment threshold the app passes
	// to CreateCommitment.
	SubtreeRootThreshold = 64

	// MaxWindow bounds anchor_deadline - h0: no gate configuration allows
	// more, and it bounds the work of one window.
	MaxWindow = 1000

	pffTypeURL = "/celestia.fibre.v1.MsgPayForFibre"
)

const (
	commitmentSize = 32
	namespaceSize  = 29
	signerSize     = 20
)

// namespaceOK accepts a version-0 user blob namespace: 18 zero bytes after
// the version and a non-zero sub-id prefix, which excludes the reserved
// range.
func namespaceOK(ns []byte) bool {
	if len(ns) != namespaceSize || ns[0] != 0 {
		return false
	}
	for _, c := range ns[1:19] {
		if c != 0 {
			return false
		}
	}
	for _, c := range ns[19:28] {
		if c != 0 {
			return true
		}
	}
	return false
}
