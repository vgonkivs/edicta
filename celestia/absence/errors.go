package absence

import (
	"errors"
	"fmt"
)

// Invalid arguments: the caller's mistake, not a property of a proof.
var (
	ErrQuery  = errors.New("absence: invalid query")
	ErrWindow = errors.New("absence: invalid window")
)

// Why a height is not proven. Outcome.Err wraps one of these.
var (
	// ErrNoProof: no record for the height.
	ErrNoProof = errors.New("absence: no proof for this height")
	// ErrRecordMismatch: the record is about another query or height.
	ErrRecordMismatch = errors.New("absence: record is not about this query and height")
	// ErrHeader: the signed header does not decode, names another height,
	// is not the trusted one, or its commit is for another block.
	ErrHeader = errors.New("absence: header not tied to the trusted chain")
	// ErrDAH: the DAH does not decode, is invalid, or does not hash to the
	// header's data hash.
	ErrDAH = errors.New("absence: data availability header does not verify")
	// ErrNamespaceData: the namespace data does not decode or is not a
	// complete namespace proof against the DAH.
	ErrNamespaceData = errors.New("absence: namespace data does not verify")
	// ErrShares: the shares of the namespace do not reassemble (PFF txs) or
	// do not parse (blobs).
	ErrShares = errors.New("absence: namespace shares do not parse")
	// ErrOtherAppVersion: the header's app version is not the pinned one,
	// and only a candidate with every result code 0 can be proven there.
	ErrOtherAppVersion = errors.New("absence: app version is not the pinned one")
	// ErrResultUnproven: a candidate exists and its result code is not
	// proven.
	ErrResultUnproven = errors.New("absence: candidate result code not proven")
)

// ErrResultsMissing: a candidate exists and the record holds no results
// proof; fetching the results of the height may prove it.
var ErrResultsMissing = fmt.Errorf("%w: no results proof", ErrResultUnproven)
