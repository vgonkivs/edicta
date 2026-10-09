package gate

// ProfileRegistry says, for each action type a compiled profile defines,
// whether its executed transaction is public. The core imports no profile:
// the integrator's build fills the registry from the profiles it ships and
// passes it to the constructor. It is code, not operator configuration, so
// that an operator cannot mark an off-chain type public and make its
// low-entropy action bytes testable against the public action hash through a
// reveal.
type ProfileRegistry interface {
	// PublicExecution reports whether actionType is registered with public
	// execution; a type no profile registers is not public.
	PublicExecution(actionType string) bool
}

// ProfileSet is a ProfileRegistry built from a fixed table.
type ProfileSet map[string]bool

func (p ProfileSet) PublicExecution(actionType string) bool { return p[actionType] }
