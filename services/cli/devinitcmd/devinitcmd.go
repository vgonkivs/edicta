// SPDX-License-Identifier: Apache-2.0

//go:build edictadev

// Package devinitcmd is edicta dev init, the one-shot of the local docker
// compose stack. It creates the DEV keys, the dev mandate and the dev
// configuration files, and the Eden dev genesis. It exists only in builds with
// the edictadev tag, and it never overwrites anything, so a second run reuses
// what the first made.
package devinitcmd

import (
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/vgonkivs/edicta/internal/keyfile"
	"github.com/vgonkivs/edicta/services/cli/initcmd"
)

// Main runs the one-shot. args is the command line as in os.Args; args[0] is
// not used. It returns 0, or 1 after printing the error.
func Main(args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 {
		args = args[1:]
	}
	if err := run(args, stdout, stderr); err != nil {
		fmt.Fprintln(stderr, "edicta-devinit:", err)
		return 1
	}
	return 0
}

func run(args []string, out, errOut io.Writer) error {
	fs := flag.NewFlagSet("edicta-devinit", flag.ContinueOnError)
	fs.SetOutput(errOut)
	home := fs.String("home", "", "the dev home directory (required)")
	escrowAddr := fs.String("escrow-address", "", "CREATE2 address of NativeEscrow in the Eden genesis")
	escrowCode := fs.String("escrow-code-file", "", "file with the NativeEscrow runtime code, hex; absent keeps the slot a placeholder")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	var slot escrowSlot
	if *escrowCode != "" {
		b, err := os.ReadFile(*escrowCode)
		if err != nil {
			return fmt.Errorf("escrow code: %w", err)
		}
		if slot.Code, err = hex.DecodeString(strings.TrimPrefix(strings.TrimSpace(string(b)), "0x")); err != nil || len(slot.Code) == 0 {
			return errors.New("escrow code file is not non-empty hex")
		}
		slot.Address = *escrowAddr
	} else if *escrowAddr != "" {
		return errors.New("-escrow-address needs -escrow-code-file")
	}

	res, err := initcmd.RunDev(initcmd.DevConfig{Home: *home})
	if err != nil {
		return err
	}
	gdir := filepath.Join(res.Home, "genesis")
	if err := keyfile.MkdirSync(gdir); err != nil {
		return err
	}
	spec, err := buildEdenGenesis(initcmd.DevEdenChainID, res.Payer.Address, res.Facilitator.Address, slot)
	if err != nil {
		return err
	}
	genesis, err := writeOnce(filepath.Join(gdir, "eden-genesis.json"), spec)
	if err != nil {
		return err
	}
	jwtHex, err := newJWT()
	if err != nil {
		return err
	}
	jwtFile, err := writeOnce(filepath.Join(gdir, "jwt.hex"), jwtHex)
	if err != nil {
		return err
	}

	escrowNote := "NativeEscrow: PLACEHOLDER, no runtime code in the Eden genesis yet"
	if slot.Address != "" {
		escrowNote = "NativeEscrow: runtime code at " + slot.Address
	}
	fmt.Fprintf(out, "DEV ONLY: do not use these keys on any public chain\n")
	fmt.Fprintf(out, "home            %s\n", res.Home)
	fmt.Fprintf(out, "celestia chain  %s\n", initcmd.DevCelestiaChainID)
	fmt.Fprintf(out, "eden chain id   %d\n", initcmd.DevEdenChainID)
	fmt.Fprintf(out, "recorder        %s\n", res.Recorder.Address)
	fmt.Fprintf(out, "funder          %s\n", res.Funder.Address)
	fmt.Fprintf(out, "payer           %s\n", res.Payer.Address)
	fmt.Fprintf(out, "facilitator     %s\n", res.Facilitator.Address)
	fmt.Fprintf(out, "mandate hash    %s\n", res.MandateHash)
	fmt.Fprintf(out, "eden genesis    %s (%s)\n", genesis.path, genesis.status)
	fmt.Fprintf(out, "jwt secret      %s (%s)\n", jwtFile.path, jwtFile.status)
	fmt.Fprintln(out, escrowNote)
	return nil
}

type written struct{ path, status string }

// writeOnce writes data unless the file is there, and says which it did.
func writeOnce(path string, data []byte) (written, error) {
	switch err := keyfile.WriteNew(path, data); {
	case err == nil:
		return written{path, "created"}, nil
	case errors.Is(err, keyfile.ErrExists):
		return written{path, "exists"}, nil
	default:
		return written{path, ""}, err
	}
}

func newJWT() ([]byte, error) {
	b, err := keyfile.RandomBytes(32)
	if err != nil {
		return nil, err
	}
	return []byte(hex.EncodeToString(b) + "\n"), nil
}
