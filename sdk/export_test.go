package sdk

// The commitment assembler is not part of the public API: it takes a nonce and
// a plaintext hash, which only the builder may choose. The tests reach it
// through these aliases.
type Input = input

var BuildCommitment = buildCommitment
