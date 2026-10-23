package doctor

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/vgonkivs/edicta/celestia/clearerr"
	"github.com/vgonkivs/edicta/celestia/edictad"
	"github.com/vgonkivs/edicta/config"
	"github.com/vgonkivs/edicta/internal/keyfile"
	"github.com/vgonkivs/edicta/internal/secret"
)

type keyringCheck struct{ env *Env }

func (keyringCheck) Name() string { return "keyring" }

func (k keyringCheck) Run(ctx context.Context, c config.Config) Result {
	type kr struct{ label, dir, name, pass string }
	var rings []kr
	if r := c.Recorder; r != nil {
		rings = append(rings, kr{"recorder", r.KeyringDir, r.KeyName, r.PassphraseFile})
	}
	if p := c.Publisher; p != nil {
		rings = append(rings, kr{"publisher", p.KeyringDir, p.KeyName, p.PassphraseFile})
	}
	if len(rings) == 0 {
		return ok("no Celestia keyring configured")
	}
	var bad, fixes, good []string
	for _, r := range rings {
		if _, err := secret.FromFile(r.pass); err != nil {
			bad = append(bad, fmt.Sprintf("%s passphrase file: %v", r.label, err))
			fixes = append(fixes, "make the passphrase file exist with mode 0600 and a non-empty line")
			continue
		}
		addr, err := k.env.accountOf(ctx, r.dir, r.name, r.pass)
		if err != nil {
			bad = append(bad, fmt.Sprintf("%s: %v", r.label, err))
			fixes = append(fixes, "point passphrase_file at the file the keyring was created with, or recreate the key")
			continue
		}
		good = append(good, fmt.Sprintf("%s %s", r.label, addr))
	}
	if len(bad) > 0 {
		return fail(strings.Join(bad, "; "), strings.Join(uniq(fixes), "; "))
	}
	return ok("opens without a prompt: %s", strings.Join(good, ", "))
}

type keyDirsCheck struct{}

func (keyDirsCheck) Name() string { return "keydirs" }

// Run applies init's rule to every directory that holds key material: a
// directory another user can write lets them delete or swap a key whose
// address was already funded, whatever the mode of the key file.
func (keyDirsCheck) Run(_ context.Context, c config.Config) Result {
	var dirs []string
	add := func(d string) {
		if d == "" || d == "." {
			return
		}
		d = filepath.Clean(d)
		if !slices.Contains(dirs, d) {
			dirs = append(dirs, d)
		}
	}
	keyFile := func(p string) {
		if p != "" {
			add(filepath.Dir(p))
		}
	}
	keyring := func(dir, pass string) {
		if dir != "" {
			add(dir)
			add(filepath.Dir(dir))
		}
		keyFile(pass)
	}
	if c.Agent != nil {
		keyFile(c.Agent.KeyFile)
	}
	if c.Gate != nil {
		keyFile(c.Gate.KeyFile)
	}
	if c.Signer != nil {
		keyFile(c.Signer.PayerKeyFile)
	}
	if r := c.Recorder; r != nil {
		keyring(r.KeyringDir, r.PassphraseFile)
	}
	if p := c.Publisher; p != nil {
		keyring(p.KeyringDir, p.PassphraseFile)
	}
	if len(dirs) == 0 {
		return ok("no key directory configured")
	}
	var bad []string
	checked := 0
	for _, d := range dirs {
		// A missing directory is reported by the check of the key in it.
		resolved, err := filepath.EvalSymlinks(d)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err == nil {
			err = keyfile.CheckDir(resolved)
		}
		if err != nil {
			bad = append(bad, err.Error())
			continue
		}
		checked++
	}
	if len(bad) > 0 {
		return fail(strings.Join(bad, "; "), "make every directory that holds keys yours and mode 0700 (chmod 700 DIR); a directory others can write lets them delete or replace a key")
	}
	return ok("%d key directories are yours and closed to others", checked)
}

// MaxClockOffset is the largest offset doctor accepts.
const MaxClockOffset = time.Second

type clockCheck struct{ env *Env }

func (clockCheck) Name() string { return "clock" }

func (k clockCheck) Run(ctx context.Context, _ config.Config) Result {
	var (
		answered int
		bad      []string
		notes    []string
	)
	for _, s := range k.env.Clocks {
		off, err := s.Offset(ctx)
		if err != nil {
			notes = append(notes, fmt.Sprintf("%s: %v", s.Name(), err))
			continue
		}
		answered++
		if off > MaxClockOffset || off < -MaxClockOffset {
			bad = append(bad, fmt.Sprintf("%s says the clock is off by %s", s.Name(), off.Round(time.Millisecond)))
		}
	}
	switch {
	case len(bad) > 0:
		return fail(strings.Join(bad, "; "), "sync the system clock (NTP); the gate refuses decisions and anchors when its clock drifts")
	case answered == 0:
		return fail("no time source answered: "+strings.Join(notes, "; "), "check the network; the clock cannot be verified offline")
	case answered == 1:
		return warn("only one time source answered: "+strings.Join(notes, "; "), "check access to the second time source")
	}
	return ok("offset below %s against %d sources", MaxClockOffset, answered)
}

type archiveCheck struct{ env *Env }

func (archiveCheck) Name() string { return "archive" }

func (k archiveCheck) Run(ctx context.Context, c config.Config) Result {
	a := c.Archive
	if a.Dir == "" && a.URL == "" {
		return ok("no archive configured")
	}
	var bad, fixes []string
	if a.Dir != "" {
		if err := writable(a.Dir); err != nil {
			bad = append(bad, fmt.Sprintf("archive.dir %s: %v", a.Dir, err))
			fixes = append(fixes, "create the directory or fix its permissions; the gate writes the archive before it signs")
		}
		if c.Capture != nil && c.Capture.Dir != "" && edictad.DirsOverlap(a.Dir, c.Capture.Dir) {
			bad = append(bad, fmt.Sprintf("archive.dir %s and capture.dir %s are one directory or one lies inside the other", a.Dir, c.Capture.Dir))
			fixes = append(fixes, "give the archive and the capture store separate directories: captures are not archive records")
		}
	}
	if len(bad) > 0 {
		return fail(strings.Join(bad, "; "), strings.Join(uniq(fixes), "; "))
	}
	var notes []string
	if k.env.Net != nil {
		for _, u := range append([]string{a.URL}, a.MirrorURLs...) {
			if u == "" {
				continue
			}
			resp, err := k.env.Net.HTTPGet(ctx, u)
			if err != nil || resp.Status >= 500 {
				notes = append(notes, fmt.Sprintf("%s did not answer", clearerr.RedactURL(u)))
			}
		}
	}
	if len(notes) > 0 {
		return warn(strings.Join(notes, "; "), "archive mirrors only matter when the primary is down; fix them to keep the redundancy")
	}
	if a.Dir != "" {
		return ok("archive.dir %s is writable", a.Dir)
	}
	return ok("archive.url answers")
}

// writable proves a file can be created in dir, or in the nearest existing
// parent when dir is not there yet. It creates nothing that stays.
func writable(dir string) error {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	cur := abs
	for {
		fi, err := os.Stat(cur)
		if err == nil {
			if !fi.IsDir() {
				return fmt.Errorf("%s is not a directory", cur)
			}
			break
		}
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return err
		}
		cur = parent
	}
	f, err := os.CreateTemp(cur, ".doctor-*")
	if err != nil {
		return err
	}
	name := f.Name()
	_ = f.Close()
	if err := os.Remove(name); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("cannot remove %s: %w", filepath.Base(name), err)
	}
	return nil
}
