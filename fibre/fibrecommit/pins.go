package fibrecommit

//go:generate go run ./internal/genpins

// pinnedModule is a strict-tier module of the build the vectors were produced
// under: exact version and h1 sum, and it must be linked. For a replaced
// module, version and sum are those of the replace target. The list in
// pins_gen.go is generated; bumping any of these modules means re-running the
// vector generator and getting human sign-off.
type pinnedModule struct {
	path        string
	version     string
	sum         string
	replacePath string
}
