package verifycli

// Defaults are the values a configuration file supplies for flags the user
// did not pass. A flag given on the command line always wins, and a group of
// defaults is dropped when it would contradict how the user chose to trust
// the chain: checkpoint sources apply only with a headers source.
type Defaults struct {
	GateKeys      string
	ArchiveDir    string
	ArchiveURL    string
	HeadersRPC    string
	CheckpointRPC []string
	CrossCheckRPC []string
	ExcludeHosts  []string
	TxRPC         []string
	Quorum        int
}

// DefaultsLoader reads the defaults of the file at path; an empty path means
// the default location, where a missing file is not an error.
type DefaultsLoader func(path string) (Defaults, error)

func (f *flags) applyDefaults(d Defaults, given map[string]bool) {
	if !given["archive"] && !given["archive-url"] {
		switch {
		case d.ArchiveDir != "":
			f.archiveDir = d.ArchiveDir
		case d.ArchiveURL != "":
			f.archiveURL = d.ArchiveURL
		}
	}
	if !given["exclude-host"] {
		f.excludeHosts = append([]string(nil), d.ExcludeHosts...)
	}
	// The trust anchor is the user's choice: a trusted file or an explicit
	// checkpoint turns the configured checkpoint sources off.
	if !given["trusted"] && !given["checkpoint"] && !given["checkpoint-rpc"] && (given["headers-rpc"] || d.HeadersRPC != "") {
		f.checkpointRPC = append([]string(nil), d.CheckpointRPC...)
		if len(f.checkpointRPC) > 0 && !given["checkpoint-quorum"] && d.Quorum > 0 {
			f.quorum = d.Quorum
		}
	}
	online := f.checkpoint != "" || len(f.checkpointRPC) > 0
	if !given["headers-rpc"] && (online || f.checkExec || f.absenceSource != "") {
		f.headersRPC = d.HeadersRPC
	}
	if !given["cross-check"] && (online || f.checkExec) {
		f.crossRPC = append([]string(nil), d.CrossCheckRPC...)
	}
	if !given["tx-rpc"] && f.checkExec {
		f.txRPC = append([]string(nil), d.TxRPC...)
	}
}
