package attacks_test

import "crypto/sha256"

func sha(b []byte) [32]byte { return sha256.Sum256(b) }
