package fsarchive_test

import (
	"encoding/hex"

	"github.com/vgonkivs/edicta/archive/fsarchive"
	"github.com/vgonkivs/edicta/test/archivefix"
)

func hexOf(b []byte) string { return hex.EncodeToString(b) }

func fsarchiveOpen(dir string, fx *archivefix.Fixture, opts ...fsarchive.Option) (*fsarchive.Store, error) {
	return fsarchive.Open(dir, committers(fx), opts...)
}
