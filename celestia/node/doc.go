// Package node is the seam between Edicta and a Celestia node. It holds narrow
// interfaces over exactly what the Recorder, the gate chain client, inclusion
// verification and the rail transaction code need: headers, blob get and
// proof, blob submit, the consensus state and transaction path, x/fibre
// params and the chain id. It is the only package that imports celestia-node's
// api/client, cosmos-sdk and the gRPC stubs, so everything else stays testable
// against nodefake.
//
// Nothing about a network is compiled in: chain id, denom, address prefix and
// app version are discovered and cross-checked by Check at startup.
package node
