// Package edictad wires the gate, the optional Recorder and the HTTP API into
// one daemon. It holds everything the command needs except process plumbing, so
// startup, refusals and shutdown run in tests against fakes.
//
// Nothing about a network is compiled in: the chain id and every endpoint come
// from the configuration or are discovered, and the compatibility check runs
// on every start with no way to skip it.
package edictad
