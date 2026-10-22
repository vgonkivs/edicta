// Package gate verifies a signed DecisionCommitment and authorizes the
// committed action. It never executes anything: it signs an Authorization,
// consumes the nonce, and an executor acts only on a valid Authorization.
package gate
