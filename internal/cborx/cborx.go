// SPDX-License-Identifier: Apache-2.0

// Package cborx builds the CBOR codec modes the typed formats share: a
// strict decoder that refuses everything a canonical encoder never emits, and
// the RFC 8949 core deterministic encoder.
package cborx

import "github.com/fxamacker/cbor/v2"

// Limits bound the shape a strict decoder accepts.
type Limits struct {
	MaxNestedLevels  int
	MaxArrayElements int
	MaxMapPairs      int
}

// StrictDecMode refuses duplicate map keys, indefinite lengths, tags,
// invalid UTF-8 and unknown struct fields, within l.
func StrictDecMode(l Limits) (cbor.DecMode, error) {
	return cbor.DecOptions{
		DupMapKey:         cbor.DupMapKeyEnforcedAPF,
		IndefLength:       cbor.IndefLengthForbidden,
		TagsMd:            cbor.TagsForbidden,
		UTF8:              cbor.UTF8RejectInvalid,
		ExtraReturnErrors: cbor.ExtraDecErrorUnknownField,
		MaxNestedLevels:   l.MaxNestedLevels,
		MaxArrayElements:  l.MaxArrayElements,
		MaxMapPairs:       l.MaxMapPairs,
	}.DecMode()
}

// CanonicalEncMode is core deterministic encoding without indefinite
// lengths. nilContainersAsEmpty makes a nil slice or map encode as an empty
// one instead of null.
func CanonicalEncMode(nilContainersAsEmpty bool) (cbor.EncMode, error) {
	o := cbor.CoreDetEncOptions()
	o.IndefLength = cbor.IndefLengthForbidden
	if nilContainersAsEmpty {
		o.NilContainers = cbor.NilContainerAsEmpty
	}
	return o.EncMode()
}
