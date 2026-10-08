package policy

import (
	"fmt"
	"regexp"
)

// Extractor turns the exact action bytes of one action type into facts. It is
// pure and deterministic and accepts only canonical bytes, so one byte string
// is never read as two actions.
type Extractor interface {
	ID() string
	ActionType() string
	Extract(action []byte) (Facts, error)
}

var extractorID = regexp.MustCompile(`^[a-z0-9][a-z0-9./-]*$`)

// Extractors is an immutable registry keyed by action type.
type Extractors struct {
	byType map[string]Extractor
}

// NewExtractors builds the registry. A duplicate action type or ID, or a
// malformed ID, is an error.
func NewExtractors(xs ...Extractor) (*Extractors, error) {
	r := &Extractors{byType: make(map[string]Extractor, len(xs))}
	ids := make(map[string]struct{}, len(xs))
	for _, x := range xs {
		if x == nil {
			return nil, fmt.Errorf("policy: nil extractor")
		}
		id, t := x.ID(), x.ActionType()
		if len(id) < 1 || len(id) > 64 || !extractorID.MatchString(id) {
			return nil, fmt.Errorf("policy: extractor id %q is malformed", id)
		}
		if t == "" {
			return nil, fmt.Errorf("policy: extractor %q has no action type", id)
		}
		if _, dup := r.byType[t]; dup {
			return nil, fmt.Errorf("policy: duplicate extractor for action type %q", t)
		}
		if _, dup := ids[id]; dup {
			return nil, fmt.Errorf("policy: duplicate extractor id %q", id)
		}
		ids[id] = struct{}{}
		r.byType[t] = x
	}
	return r, nil
}

// Has reports whether an extractor serves the action type.
func (r *Extractors) Has(actionType string) bool {
	if r == nil {
		return false
	}
	_, ok := r.byType[actionType]
	return ok
}

// ID returns the extractor ID serving an action type.
func (r *Extractors) ID(actionType string) (string, bool) {
	if r == nil {
		return "", false
	}
	x, ok := r.byType[actionType]
	if !ok {
		return "", false
	}
	return x.ID(), true
}

// Extract returns ErrNoExtractor, or ErrFactsInvalid for an extractor error, a
// recovered panic or facts that fail Validate. The ID is returned whenever an
// extractor exists.
func (r *Extractors) Extract(actionType string, action []byte) (id string, f Facts, err error) {
	if r == nil {
		return "", Facts{}, ErrNoExtractor
	}
	x, ok := r.byType[actionType]
	if !ok {
		return "", Facts{}, ErrNoExtractor
	}
	id = x.ID()
	defer func() {
		if p := recover(); p != nil {
			f, err = Facts{}, fmt.Errorf("%w: extractor panicked: %v", ErrFactsInvalid, p)
		}
	}()
	f, err = x.Extract(action)
	if err != nil {
		return id, Facts{}, fmt.Errorf("%w: %w", ErrFactsInvalid, err)
	}
	if err := f.Validate(); err != nil {
		return id, Facts{}, fmt.Errorf("%w: %w", ErrFactsInvalid, err)
	}
	return id, f, nil
}
