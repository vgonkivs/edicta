package httparchive_test

import (
	"github.com/vgonkivs/edicta/engine/archive"
	"github.com/vgonkivs/edicta/engine/archive/fsarchive"
	"github.com/vgonkivs/edicta/engine/archive/httparchive"
	"github.com/vgonkivs/edicta/engine/verifier"
)

var (
	_ httparchive.RawSource   = (*fsarchive.Store)(nil)
	_ verifier.Reader         = (*httparchive.Client)(nil)
	_ archive.PayloadStreamer = (*httparchive.Client)(nil)
)
