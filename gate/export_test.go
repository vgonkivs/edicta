package gate

import "github.com/vgonkivs/edicta/commitment"

// The crash hooks and the order mutator are unexported fields of Gate that
// production code never sets. A hook that returns an error makes Admit
// return at once without writing anything more. The mutator runs on the
// order built from action.params, before the action check, and models a bug
// or a tampered builder.

func (g *Gate) SetAfterReserve(f func() error)  { g.afterReserve = f }
func (g *Gate) SetAfterExecute(f func() error)  { g.afterExecute = f }
func (g *Gate) SetBeforeResolve(f func() error) { g.beforeResolve = f }
func (g *Gate) SetMutateOrder(f func(*commitment.IBKROrderV0)) {
	g.mutateOrder = f
}
