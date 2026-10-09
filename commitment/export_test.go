package commitment

// FrozenV0Reader is the v0 reader as frozen before v1 existed: the v0 schema
// whatever the version, then the v0 version rule.
func FrozenV0Reader(b []byte) (*SignedCommitment, error) {
	s, err := decodeSigned(b, false)
	if err != nil {
		return nil, err
	}
	if s.Commitment.Version != VersionV0 {
		return nil, ErrUnsupportedVersion
	}
	return s, nil
}

// FrozenV0AuthorizationReader decodes an Authorization with the v0 schema
// only, as an executor built before v1 does.
func FrozenV0AuthorizationReader(b []byte) (*SignedAuthorization, Hash, error) {
	return decodeSignedAuthorization(b, false)
}

// FrozenV0VerifyAuthorization runs the frozen v0 executor's decoding and
// static rules.
func FrozenV0VerifyAuthorization(b []byte) error {
	s, _, err := decodeSignedAuthorization(b, false)
	if err != nil {
		return err
	}
	return ValidateAuthorization(&s.Authorization, []uint64{VersionV0})
}
