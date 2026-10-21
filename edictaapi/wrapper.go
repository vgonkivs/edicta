// SPDX-License-Identifier: Apache-2.0

package edictaapi

import (
	"bytes"
	"net/http"
)

// The wrapper codec below lets another Edicta service (edicta-signer) serve
// its own routes under the transport rules of the core API: the same strict
// CBOR decoder, the same JSON conversion, the same error body. A route
// declares its wrapper map as a Schema.

// FieldKind is the CBOR type of a wrapper field.
type FieldKind uint8

const (
	KindUint FieldKind = iota
	KindBytes
	KindText
)

// Field is one entry of a wrapper map. For bytes and text, Min and Max bound
// the length; a Max of zero means no bound beyond the body limit. Charset,
// when set, must accept every byte.
type Field struct {
	Key      uint64
	Name     string
	Kind     FieldKind
	Min, Max uint64
	Charset  func(byte) bool
	Required bool
}

// Schema is the field set of one wrapper map.
type Schema struct{ fs []fspec }

// NewSchema builds a schema from its fields.
func NewSchema(fields ...Field) Schema {
	fs := make([]fspec, len(fields))
	for i, f := range fields {
		max := f.Max
		if max == 0 {
			max = unbounded
		}
		kind := fUint
		switch f.Kind {
		case KindBytes:
			kind = fBytes
		case KindText:
			kind = fText
		}
		fs[i] = fspec{key: f.Key, name: f.Name, kind: kind, min: f.Min, max: max, charset: f.Charset, required: f.Required}
	}
	return Schema{fs: fs}
}

// ErrorSchema is the error body of the core API.
var ErrorSchema = Schema{fs: jsonErrorBody}

// Fields is a decoded wrapper map.
type Fields struct{ m map[uint64]*node }

// DecodeWrapper decodes b as one canonical wrapper map of s with the strict
// decoder of the core routes.
func DecodeWrapper(b []byte, s Schema) (Fields, error) {
	m, err := decodeFields(b, s.fs)
	if err != nil {
		return Fields{}, err
	}
	return Fields{m: m}, nil
}

// Has reports whether key is present.
func (f Fields) Has(key uint64) bool { return f.m[key] != nil }

// Bytes returns a copy of a byte string field, nil when absent.
func (f Fields) Bytes(key uint64) []byte {
	if n := f.m[key]; n != nil && n.major == majBstr {
		return bytes.Clone(n.b)
	}
	return nil
}

// Text returns a text field, empty when absent.
func (f Fields) Text(key uint64) string {
	if n := f.m[key]; n != nil && n.major == majTstr {
		return string(n.b)
	}
	return ""
}

// Uint returns a uint field.
func (f Fields) Uint(key uint64) (uint64, bool) {
	if n := f.m[key]; n != nil && n.major == majUint {
		return n.u, true
	}
	return 0, false
}

// Item is one entry of an encoded wrapper map.
type Item struct{ kv kv }

func BytesItem(key uint64, b []byte) Item { return Item{kv{key: key, kind: fBytes, b: b}} }
func TextItem(key uint64, s string) Item  { return Item{kv{key: key, kind: fText, s: s}} }
func UintItem(key uint64, u uint64) Item  { return Item{kv{key: key, kind: fUint, u: u}} }

// EncodeWrapper returns the canonical CBOR map of items, given in ascending
// key order.
func EncodeWrapper(items ...Item) []byte {
	kvs := make([]kv, len(items))
	for i, it := range items {
		kvs[i] = it.kv
	}
	return encodeMap(kvs...)
}

// JSONToWrapper converts a JSON request body to the canonical CBOR wrapper
// map of s. The result still goes through DecodeWrapper.
func JSONToWrapper(body []byte, s Schema) ([]byte, error) { return jsonToCBOR(body, s.fs) }

// WrapperToJSON renders a wrapper map with the field names of s; an integer
// above 2^53-1 is an error, never a rounded number.
func WrapperToJSON(b []byte, s Schema) ([]byte, error) { return cborToJSON(b, s.fs) }

// JSONBodyLimit is the JSON body limit of a route whose CBOR limit is
// limit: the base64 expansion plus room for the member names.
func JSONBodyLimit(limit uint64) uint64 { return jsonLimit(limit) }

// ResponseIsJSON decides the media type of a response, errors included: a
// GET follows Accept, any other method its request's Content-Type.
func ResponseIsJSON(r *http.Request) bool { return responseIsJSON(r) }

// ErrorBody is the CBOR error body of the core API without stored results.
func ErrorBody(code, msg string, retryable bool) []byte {
	return errorResponse(500, code, msg, retryable, nil, nil, 0).body
}
