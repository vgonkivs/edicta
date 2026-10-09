package archive

import (
	"context"

	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/gate"
)

// NewIntentSource serves the gate's stage K-fast from r. The reader checks
// the key of what it returns, so the record is the one the reference names.
func NewIntentSource(r IntentReader) gate.IntentSource { return intentSource{r: r} }

type intentSource struct{ r IntentReader }

func (s intentSource) Intent(ctx context.Context, da commitment.DA, commit []byte, refHeight uint64) (*gate.AnchorIntent, error) {
	rec, err := s.r.Intent(ctx, da, commit, refHeight)
	if err != nil {
		return nil, err
	}
	return &gate.AnchorIntent{
		DA: rec.DA, Commitment: rec.Commitment, Namespace: rec.Namespace, RefHeight: rec.RefHeight,
		Tx: rec.Tx, Signer: rec.Signer, CreatedAt: rec.CreatedAt,
	}, nil
}
