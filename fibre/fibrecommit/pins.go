package fibrecommit

//go:generate go run ./internal/genpins

// pinnedModule is a module of the build the vectors were produced under. For a
// replaced module, version and sum are those of the replace target.
type pinnedModule struct {
	path        string
	version     string
	sum         string
	replacePath string
}
