package verifier_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/engine/archive"
	"github.com/vgonkivs/edicta/engine/verifier"
	"github.com/vgonkivs/edicta/test/execresultfix"
	"github.com/vgonkivs/edicta/test/gatefix"
)

// readingChecker asks for the archived execution results the way a rail
// checker does, then answers with the rig's facts.
type readingChecker struct {
	*fakeChecker
	chainID string
	railRef [32]byte
	got     []verifier.ArchivedResult
	err     error
}

func (c *readingChecker) CheckExecution(ctx context.Context, in verifier.ExecutionInput) (verifier.ExecutionFacts, error) {
	if in.Archived != nil {
		c.got, c.err = in.Archived.ExecutionResults(ctx, c.chainID, c.railRef)
		if c.err != nil {
			return verifier.ExecutionFacts{}, c.err
		}
	}
	return c.fakeChecker.CheckExecution(ctx, in)
}

// copyReader is one archive copy.
type copyReader struct {
	rec   *archive.ExecutionResultRecord
	err   error
	asked int
}

func (c *copyReader) ExecutionResult(_ context.Context, chainID string, railRef []byte) (*archive.ExecutionResultRecord, error) {
	c.asked++
	if c.err != nil {
		return nil, c.err
	}
	if c.rec == nil || c.rec.ChainID != chainID || string(c.rec.RailRef) != string(railRef) {
		return nil, archive.ErrNotFound
	}
	return c.rec, nil
}

func archivedRig(t *testing.T) (*execRig, *readingChecker, execresultfix.Record) {
	t.Helper()
	e := newExecRig(t, newParts(t), nil)
	r := execresultfix.Load(t).Records[0]
	chk := &readingChecker{fakeChecker: e.chk, chainID: r.Key.ChainID, railRef: r.Key.RailRefBytes(t)}
	e.deps.Executions = map[string]verifier.ExecutionChecker{gatefix.ActionType: chk}
	return e, chk, r
}

func TestArchivedResultsReachTheChecker(t *testing.T) {
	e, chk, r := archivedRig(t)
	_, err := e.store.Put(context.Background(), r.Build(t))
	require.NoError(t, err)

	rep := e.run(t)
	passed(t, rep, verifier.CheckExecution)
	require.NoError(t, chk.err)
	require.Len(t, chk.got, 1)
	assert.Equal(t, "archive", chk.got[0].Copy)
	assert.Equal(t, r.Build(t), chk.got[0].Record)
	require.Len(t, chk.calls, 1)
	assert.Same(t, e.trust, chk.calls[0].Trust, "the checker ties the records to the verifier's own header trust")
}

func TestArchivedResultsOfEveryCopy(t *testing.T) {
	e, chk, r := archivedRig(t)
	rec := r.Build(t)
	_, err := e.store.Put(context.Background(), rec)
	require.NoError(t, err)

	// The same key with other bytes: a squat in one copy must not hide the
	// record of another.
	other := *rec
	other.Result = []byte{0x08, 0x0d}
	same := &copyReader{rec: r.Build(t)}
	differs := &copyReader{rec: &other}
	broken := &copyReader{err: fmt.Errorf("%w: %w", archive.ErrCorrupt, errors.New("strict decoding"))}
	absent := &copyReader{}
	e.deps.ResultCopies = []verifier.ResultCopy{
		{Name: "mirror", Reader: same}, {Name: "squatted", Reader: differs},
		{Name: "broken", Reader: broken}, {Name: "older", Reader: absent},
	}
	rep := e.run(t)
	passed(t, rep, verifier.CheckExecution)
	require.NoError(t, chk.err)

	var copies []string
	for _, g := range chk.got {
		copies = append(copies, g.Copy)
	}
	assert.Equal(t, []string{"archive", "squatted", "broken"}, copies, "copy order, equal bytes once, absent copies left out")
	assert.Nil(t, chk.got[2].Record)
	require.ErrorIs(t, chk.got[2].Err, archive.ErrCorrupt)
	for _, c := range []*copyReader{same, differs, broken, absent} {
		assert.Equal(t, 1, c.asked)
	}
}

func TestArchivedResultFaultStopsTheVerification(t *testing.T) {
	e, _, _ := archivedRig(t)
	fault := errors.New("archive answered 500")
	e.deps.ResultCopies = []verifier.ResultCopy{{Name: "mirror", Reader: &copyReader{err: fault}}}
	_, err := e.rig.verifier(t).Verify(context.Background(), e.p.hash,
		verifier.WithReceipt(validReceipt(t, e.p)), verifier.WithExecutionCheck())
	require.ErrorIs(t, err, fault)
}

func TestArchivedResultsAbsentEverywhere(t *testing.T) {
	e, chk, _ := archivedRig(t)
	rep := e.run(t)
	passed(t, rep, verifier.CheckExecution)
	require.NoError(t, chk.err)
	assert.Empty(t, chk.got)
}

func TestArchivedResultsWithoutACopy(t *testing.T) {
	e, _, _ := archivedRig(t)
	e.deps.Archive = plainReader{e.store}
	rep := e.run(t)
	passed(t, rep, verifier.CheckExecution)
	require.Len(t, e.chk.calls, 1)
	assert.Nil(t, e.chk.calls[0].Archived)
	assert.Nil(t, e.chk.calls[0].Trust)
}

// plainReader hides every optional reader of the archive.
type plainReader struct{ verifier.Reader }

func TestResultCopiesAreValidated(t *testing.T) {
	e, _, _ := archivedRig(t)
	ok := &copyReader{}
	for name, copies := range map[string][]verifier.ResultCopy{
		"no reader":     {{Name: "a"}},
		"no name":       {{Name: " ", Reader: ok}},
		"archive":       {{Name: "archive", Reader: ok}},
		"repeated name": {{Name: "a", Reader: ok}, {Name: "a", Reader: ok}},
	} {
		t.Run(name, func(t *testing.T) {
			d := e.deps
			d.ResultCopies = copies
			_, err := verifier.New(d)
			require.ErrorIs(t, err, verifier.ErrInvalidConfig)
		})
	}
}
