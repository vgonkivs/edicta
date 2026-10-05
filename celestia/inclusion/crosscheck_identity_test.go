package inclusion_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/celestia/inclusion"
)

// Sources with the same non-empty ID are one provider, however many Reader
// instances they hold; an empty ID falls back to the Reader instance.

func TestCrossCheckCountsProvidersByIdentity(t *testing.T) {
	a1 := inclusion.Source{Name: "a1", ID: "node-a", Headers: headerNode(t, nil)}
	a2 := inclusion.Source{Name: "a2", ID: "node-a", Headers: headerNode(t, nil)}
	b := inclusion.Source{Name: "b", ID: "node-b", Headers: headerNode(t, nil)}

	_, _, err := crossRig(t, a1, a2)
	require.ErrorIs(t, err, inclusion.ErrConfig, "the same provider listed twice counts once")

	_, _, err = crossRig(t, a1, b)
	require.NoError(t, err)
	_, _, err = crossRig(t, a1, a2, b)
	require.NoError(t, err, "two distinct providers remain")
}
