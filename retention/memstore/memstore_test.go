package memstore_test

import (
	"testing"

	"github.com/vgonkivs/edicta/retention"
	"github.com/vgonkivs/edicta/retention/memstore"
	"github.com/vgonkivs/edicta/test/retentionstore"
)

var _ retention.Store = memstore.New()

func TestConformance(t *testing.T) {
	retentionstore.Run(t, func(t *testing.T) *retentionstore.Handle {
		var st retention.Store = memstore.New()
		return &retentionstore.Handle{Store: st, Reopen: func() retention.Store { return st }}
	})
}
