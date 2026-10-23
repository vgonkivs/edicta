package main

import (
	"errors"
	"io/fs"
	"strings"

	"github.com/vgonkivs/edicta/config"
	"github.com/vgonkivs/edicta/services/cli/verifycli"
)

// verifyDefaults reads the defaults of verify and replay from edicta.toml. An
// explicit --config must exist; the default file is skipped when absent.
func verifyDefaults(path string) (verifycli.Defaults, error) {
	explicit := path != ""
	if !explicit {
		p, err := config.DefaultPath()
		if err != nil {
			return verifycli.Defaults{}, nil
		}
		path = p
	}
	c, err := config.LoadValid(path, nil, config.Builtin{})
	if err != nil {
		if !explicit && errors.Is(err, fs.ErrNotExist) {
			return verifycli.Defaults{}, nil
		}
		return verifycli.Defaults{}, err
	}
	d := verifycli.Defaults{ArchiveDir: c.Archive.Dir, ArchiveURL: c.Archive.URL}
	if s := c.Signer; s != nil {
		d.GateKeys = strings.Join(s.PinnedGateKeys, ",")
	}
	if v := c.Verify; v != nil {
		d.HeadersRPC = v.HeadersRPC
		d.CheckpointRPC = v.CheckpointRPC
		d.CrossCheckRPC = v.CrossCheckRPC
		d.ExcludeHosts = v.ExcludeHosts
		d.Quorum = int(v.Quorum)
		if v.TxRPC != "" {
			d.TxRPC = []string{v.TxRPC}
		}
	}
	return d, nil
}
