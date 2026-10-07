package httparchive_test

import (
	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/archive/fsarchive"
	"github.com/vgonkivs/edicta/archive/httparchive"
	"github.com/vgonkivs/edicta/verifier"
)

var (
	_ httparchive.RawSource   = (*fsarchive.Store)(nil)
	_ verifier.Reader         = (*httparchive.Client)(nil)
	_ archive.PayloadStreamer = (*httparchive.Client)(nil)
)
