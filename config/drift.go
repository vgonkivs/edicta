package config

import "fmt"

// PresetVersions are the versions of the presets a config names, as this
// binary knows them.
type PresetVersions struct {
	Celestia, Settlement uint32
}

// Versions returns the preset versions this binary has for the networks the
// config names; a network without data (custom, none) is zero.
func (c Config) Versions(p Presets) (PresetVersions, error) {
	if p == nil {
		p = Builtin{}
	}
	cp, err := p.Celestia(c.Network.Celestia)
	if err != nil {
		return PresetVersions{}, err
	}
	sp, err := p.Settlement(c.Network.Settlement)
	if err != nil {
		return PresetVersions{}, err
	}
	return PresetVersions{Celestia: cp.Version, Settlement: sp.Version}, nil
}

// Drift lists, one line each, the presets whose version in this binary
// differs from the one the file was written against. A file with no recorded
// version has nothing to compare.
func (c Config) Drift(p Presets) ([]string, error) {
	v, err := c.Versions(p)
	if err != nil {
		return nil, err
	}
	var out []string
	if w := c.Network.CelestiaPresetVersion; w != 0 && v.Celestia != 0 && w != v.Celestia {
		out = append(out, fmt.Sprintf("preset %s: file written against version %d, this binary has version %d", c.Network.Celestia, w, v.Celestia))
	}
	if w := c.Network.SettlementPresetVersion; w != 0 && v.Settlement != 0 && w != v.Settlement {
		out = append(out, fmt.Sprintf("preset %s: file written against version %d, this binary has version %d", c.Network.Settlement, w, v.Settlement))
	}
	return out, nil
}
