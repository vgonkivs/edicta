// Package absence verifies proofs that an anchor is not included at a
// height, and windows of them, against hashes that header trust already
// established. It does no I/O: fetching the proofs and the trusted hashes is
// the caller's job. Every failure of a proof means "not proven", never
// "absent": a hostile source can withhold, but it cannot make an included
// anchor look absent without breaking SHA-256 or the NMT.
package absence

// Wire numbers and pins in one place: the archive kind numbering and the
// pinned app version may move between protocol drafts.
const (
	// RecordFormat is the archive record format of the kind 14 record.
	RecordFormat = 0
	// KindAbsenceProof is the archive kind of an absence proof record.
	KindAbsenceProof = 14

	// DAFibre and DACelestiaBlob are the payload_ref.da values.
	DAFibre        = 1
	DACelestiaBlob = 2

	// PathPrefix is the first path segment of a kind 14 record.
	PathPrefix = "absence"

	// PinnedAppVersion is the only app version whose square rules (Fibre txs
	// last, in PFF namespace order) let a result index be bound by the tail
	// rule. The protocol pins it rather than importing appconsts, so an
	// upgrade cannot silently widen what proves absence.
	PinnedAppVersion = 10

	// SubtreeRootThreshold is the share commitment threshold the app passes
	// to CreateCommitment.
	SubtreeRootThreshold = 64

	// MaxWindow bounds anchor_deadline - h0: no gate configuration allows
	// more, and it bounds the work of one window.
	MaxWindow = 1000
)

// Field sizes of the kind 14 record.
const (
	MaxRecordSize        = 1 << 24
	maxArchiveRecordSize = 1<<27 + 4096
	maxProofPart         = 1 << 22
	maxNamespaceData     = 1 << 24
	commitmentSize       = 32
	namespaceSize        = 29
	signerSize           = 20
)

// Record keys of kind 14.
const (
	keyFormat        = 1
	keyKind          = 2
	keyDA            = 3
	keyCommitment    = 4
	keyNamespace     = 5
	keyHeight        = 6
	keyHeader        = 7
	keyDAH           = 8
	keyNamespaceData = 9
	keyResults       = 10
	keyNextHeader    = 11
)
