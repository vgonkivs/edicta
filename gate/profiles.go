package gate

// publicExecution is the compiled profile registry: for each action type a
// profile defines, whether its executed transaction is public. It is code,
// not configuration, so that an operator cannot mark an off-chain type public
// and make its low-entropy action bytes testable against the public action
// hash through a reveal.
var publicExecution = map[string]bool{
	"application/vnd.edicta.ibkr.order.v0+cbor":       false,
	"application/vnd.edicta.cosmos.bank-send.v0+cbor": true,
}

// PublicExecution reports whether a compiled profile registers actionType
// with public execution. A type no profile registers is not public.
func PublicExecution(actionType string) bool { return publicExecution[actionType] }
