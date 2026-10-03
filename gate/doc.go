// Package gate admits or refuses an action request that carries a signed
// DecisionCommitment. Nothing is executed unless every check passes, and an
// order is sent to the rail at most once per (agent key, nonce).
package gate
