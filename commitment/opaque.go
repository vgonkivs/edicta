// SPDX-License-Identifier: Apache-2.0

package commitment

// UndefinedDA reads an envelope for a verifier whose revision defines only
// some da values. When the envelope is well formed (one commitment, one
// 64-byte signature, nothing else) and its commitment is UndefinedDACommitment,
// it returns the da. Any other input returns ok == false and the strict
// decoders give their own verdict.
func UndefinedDA(env []byte, defined func(DA) bool) (da DA, ok bool) {
	raw, err := EnvelopeCommitment(env)
	if err != nil || defined == nil {
		return 0, false
	}
	root, err := scanTop(env, 1)
	if err != nil || root.major != majMap || len(root.entries) != 2 {
		return 0, false
	}
	var sn *node
	for _, e := range root.entries {
		if e.key == 2 {
			sn = e.val
		}
	}
	if sn == nil || sn.major != majBstr || len(sn.b) != 64 {
		return 0, false
	}
	return UndefinedDACommitment(raw, defined)
}

// UndefinedDACommitment reads bare commitment bytes the same way. It returns
// the da when every field outside payload_ref passes the strict key, type and
// size checks, the version and the integer ranges pass, and payload_ref is a
// canonical map whose da entry is a uint that defined rejects. The other keys
// of payload_ref are opaque there: a later revision may give that da other
// keys and sizes, so the strict checks of payload_ref are not applied to them.
// A nil defined, or any other input, returns ok == false.
func UndefinedDACommitment(raw []byte, defined func(DA) bool) (da DA, ok bool) {
	if defined == nil || len(raw) > MaxCommitmentSize {
		return 0, false
	}
	cn, err := scanTop(raw, 2)
	if err != nil || cn.major != majMap {
		return 0, false
	}
	if err := checkMap(cn, opaqueRefSchema, "commitment"); err != nil {
		return 0, false
	}
	m := byKey(cn)
	if m[1].u != Version {
		return 0, false
	}
	ref := byKey(m[10])
	d := ref[1]
	if d == nil || d.major != majUint {
		return 0, false
	}
	for _, n := range []*node{m[1], m[5], m[6], m[13], d} {
		if n != nil && n.major == majUint && n.u > maxUint63 {
			return 0, false
		}
	}
	if defined(DA(d.u)) {
		return 0, false
	}
	return DA(d.u), true
}

var opaqueRefSchema = func() []field {
	s := make([]field, len(commitmentSchema))
	copy(s, commitmentSchema)
	for i := range s {
		if s[i].key == 10 {
			s[i].opaque = true
		}
	}
	return s
}()
