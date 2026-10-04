package gate

// The crash hooks are unexported fields of Gate that production code never
// sets. A hook that returns an error makes Admit return at once without
// writing anything more.

func (g *Gate) SetAfterReserve(f func() error)  { g.afterReserve = f }
func (g *Gate) SetAfterExecute(f func() error)  { g.afterExecute = f }
func (g *Gate) SetBeforeResolve(f func() error) { g.beforeResolve = f }
