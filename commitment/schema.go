package commitment

import (
	"fmt"
	"slices"
)

type fieldKind int

const (
	kUint fieldKind = iota
	kBytes
	kText
	kMap
)

func (k fieldKind) major() byte {
	return [...]byte{majUint, majBstr, majTstr, majMap}[k]
}

type field struct {
	key      uint64
	name     string
	kind     fieldKind
	min, max int // byte length for kBytes and kText
	charset  func(byte) bool
	// grammar checks the whole string after the charset.
	grammar  func(string) bool
	required bool
	// onlyIf and requiredIf make a key depend on already visited siblings.
	onlyIf     func(seen map[uint64]*node) bool
	requiredIf func(seen map[uint64]*node) bool
	sub        []field
}

func isID(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' ||
		c == '.' || c == '_' || c == ':' || c == '/' || c == '-'
}

var (
	scopeSchema = []field{
		{key: 1, name: "gate_id", kind: kText, min: 1, max: 64, charset: isID, required: true},
	}
	actionSchema = []field{
		{key: 3, name: "type", kind: kText, min: 3, max: MaxActionTypeSize, grammar: validActionType, required: true},
		{key: 4, name: "hash", kind: kBytes, min: 32, max: 32, required: true},
	}
	payloadRefSchema = []field{
		{key: 1, name: "da", kind: kUint, required: true},
		{key: 2, name: "namespace", kind: kBytes, min: 29, max: 29, required: true},
		{key: 3, name: "commitment", kind: kBytes, min: 32, max: 32, required: true},
		{key: 4, name: "height", kind: kUint, required: true},
		{key: 5, name: "signer", kind: kBytes, min: 20, max: 20, onlyIf: notFibre, requiredIf: isBlob},
	}
	commitmentSchema = []field{
		{key: 1, name: "version", kind: kUint, required: true},
		{key: 2, name: "agent_id", kind: kText, min: 1, max: 64, charset: isID, required: true},
		{key: 3, name: "agent_pubkey", kind: kBytes, min: 32, max: 32, required: true},
		{key: 4, name: "nonce", kind: kBytes, min: 16, max: 16, required: true},
		{key: 5, name: "issued_at", kind: kUint, required: true},
		{key: 6, name: "valid_until", kind: kUint, required: true},
		{key: 7, name: "scope", kind: kMap, required: true, sub: scopeSchema},
		{key: 8, name: "action", kind: kMap, required: true, sub: actionSchema},
		{key: 10, name: "payload_ref", kind: kMap, required: true, sub: payloadRefSchema},
		{key: 11, name: "ciphertext_hash", kind: kBytes, min: 32, max: 32, required: true},
		{key: 12, name: "plaintext_hash", kind: kBytes, min: 32, max: 32, required: true},
		{key: 13, name: "payload_size", kind: kUint, required: true},
	}

	// The v1 schemas add only keys; da = 3, payload_ref keys 7 and 8 and
	// commitment key 15 stay reserved and are refused like any unknown key.
	payloadRefSchemaV1 = append(slices.Clone(payloadRefSchema),
		field{key: 6, name: "anchor", kind: kUint})
	commitmentSchemaV1 = append(withSub(commitmentSchema, 10, payloadRefSchemaV1),
		field{key: 14, name: "mandate_ref", kind: kBytes, min: 32, max: 32})
)

// withSub returns a copy of schema whose map field key has sub as its schema.
func withSub(schema []field, key uint64, sub []field) []field {
	out := slices.Clone(schema)
	for i := range out {
		if out[i].key == key {
			out[i].sub = sub
		}
	}
	return out
}

// schemaVersion is the version a map's key 1 selects: 1 only for the uint 1,
// otherwise 0, so every other value takes the frozen v0 path and gets its v0
// outcome.
func schemaVersion(n *node) uint64 {
	for _, e := range n.entries {
		if e.key == 1 && e.val.major == majUint && e.val.u == VersionV1 {
			return VersionV1
		}
	}
	return VersionV0
}

// da is key 1 and is visited before key 5, so seen already holds it. Other da
// values are rejected later by static validation.
func daIs(seen map[uint64]*node, da DA) bool {
	n := seen[1]
	return n != nil && n.major == majUint && n.u == uint64(da)
}

func notFibre(seen map[uint64]*node) bool { return !daIs(seen, DAFibre) }
func isBlob(seen map[uint64]*node) bool   { return daIs(seen, DACelestiaBlob) }

// checkMap applies the rule order to one map: keys ascending, for
// each key its field checks, then recursion; the map-level checks run after.
func checkMap(n *node, schema []field, path string) error {
	seen := make(map[uint64]*node, len(n.entries))
	for _, e := range n.entries {
		var f *field
		for i := range schema {
			if schema[i].key == e.key {
				f = &schema[i]
				break
			}
		}
		if f != nil && f.onlyIf != nil && !f.onlyIf(seen) {
			f = nil
		}
		if f == nil {
			return fmt.Errorf("%w: %s key %d", ErrUnknownKey, path, e.key)
		}
		v := e.val
		name := path + "." + f.name
		if v.major != f.kind.major() {
			return fmt.Errorf("%w: %s has major type %d", ErrWrongType, name, v.major)
		}
		switch f.kind {
		case kBytes, kText:
			if len(v.b) < f.min || len(v.b) > f.max {
				return fmt.Errorf("%w: %s length %d", ErrFieldSize, name, len(v.b))
			}
			if f.charset != nil {
				for _, c := range v.b {
					if !f.charset(c) {
						return fmt.Errorf("%w: %s byte 0x%02x outside charset", ErrInvalidString, name, c)
					}
				}
			}
			if f.grammar != nil && !f.grammar(string(v.b)) {
				return fmt.Errorf("%w: %s is not a media type", ErrInvalidString, name)
			}
		case kMap:
			if err := checkMap(v, f.sub, name); err != nil {
				return err
			}
		}
		seen[e.key] = v
	}
	for _, f := range schema {
		if seen[f.key] == nil && (f.required || f.requiredIf != nil && f.requiredIf(seen)) {
			return fmt.Errorf("%w: %s.%s", ErrMissingField, path, f.name)
		}
	}
	return nil
}
