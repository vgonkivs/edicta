package archive

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/gate"
)

type gateSource struct{ r Store }

// NewGateSource serves the gate's archive path from the payload records of r.
// It ignores the namespace and signer of the reference: the gate's recompute
// with the reference fails on any difference. When r is a PayloadStreamer
// the record is read as a stream and never decoded whole. A record that is
// unreadable or damaged is reported as gate.ErrArchiveUnavailable, never as a
// missing blob.
func NewGateSource(r Store) gate.BlobSource {
	return gateSource{r}
}

func (s gateSource) Fetch(ctx context.Context, ref commitment.PayloadRef, maxSize uint64) ([]byte, error) {
	var (
		b   []byte
		err error
	)
	if st, ok := s.r.(PayloadStreamer); ok {
		b, err = fetchStream(ctx, st, ref, maxSize)
	} else {
		b, err = fetchDecoded(ctx, s.r, ref, maxSize)
	}
	return b, sourceFault(ctx, err)
}

func fetchDecoded(ctx context.Context, r Store, ref commitment.PayloadRef, maxSize uint64) ([]byte, error) {
	p, err := r.Payload(ctx, ref.DA, ref.Commitment)
	if errors.Is(err, ErrNotFound) {
		return nil, fmt.Errorf("%w: %w", gate.ErrBlobNotFound, err)
	}
	if err != nil {
		return nil, err
	}
	if maxSize < uint64(len(p.Blob)) {
		return p.Blob[:maxSize+1], nil
	}
	return p.Blob, nil
}

// sourceFault leaves success, an absent blob and a finished caller context
// as they are and reports every other failure as an archive fault.
func sourceFault(ctx context.Context, err error) error {
	switch {
	case err == nil, errors.Is(err, gate.ErrBlobNotFound), errors.Is(err, gate.ErrArchiveUnavailable), ctx.Err() != nil:
		return err
	}
	return fmt.Errorf("%w: %w", gate.ErrArchiveUnavailable, err)
}

// ErrNoStreamer means the store cannot stream payload records.
var ErrNoStreamer = errors.New("archive: store does not stream payload records")

type streamSource struct{ st PayloadStreamer }

// NewStreamGateSource is NewGateSource for a store that must stream: the
// record is never decoded whole.
func NewStreamGateSource(r Store) (gate.BlobSource, error) {
	st, ok := r.(PayloadStreamer)
	if !ok {
		return nil, ErrNoStreamer
	}
	return streamSource{st}, nil
}

func (s streamSource) Fetch(ctx context.Context, ref commitment.PayloadRef, maxSize uint64) ([]byte, error) {
	b, err := fetchStream(ctx, s.st, ref, maxSize)
	return b, sourceFault(ctx, err)
}

const readChunk = 64 << 10

func fetchStream(ctx context.Context, st PayloadStreamer, ref commitment.PayloadRef, maxSize uint64) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	rc, err := st.PayloadReader(ctx, ref.DA, ref.Commitment)
	if errors.Is(err, ErrNotFound) {
		return nil, fmt.Errorf("%w: %w", gate.ErrBlobNotFound, err)
	}
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	n, err := readPayloadHead(rc, ref)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrCorrupt, err)
	}
	want := n
	if maxSize < want {
		want = maxSize + 1
	}
	out := make([]byte, want)
	for off := uint64(0); off < want; {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		end := min(off+readChunk, want)
		if _, err := io.ReadFull(rc, out[off:end]); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return nil, fmt.Errorf("%w: blob is shorter than its length", ErrCorrupt)
			}
			return nil, fmt.Errorf("archive: read payload: %w", err)
		}
		off = end
	}
	if want == n {
		if err := checkTail(rc); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrCorrupt, err)
		}
	}
	return out, nil
}

// checkTail checks what follows the blob: the intent height and nothing else.
func checkTail(r io.Reader) error {
	t, err := io.ReadAll(io.LimitReader(r, 11))
	if err != nil {
		return fmt.Errorf("record tail: %w", err)
	}
	if len(t) < 2 || t[0] != 8 || t[1]>>5 != majUint {
		return errors.New("record tail is not the intent height")
	}
	var v uint64
	w := 0
	switch ai := t[1] & 31; {
	case ai < 24:
		v = uint64(ai)
	case ai > 27:
		return errors.New("intent height encoding")
	default:
		w = 1 << (ai - 24)
		if len(t) != 2+w {
			return errors.New("record has bytes after the intent height")
		}
		for _, x := range t[2:] {
			v = v<<8 | uint64(x)
		}
		if v < 24 || w > 1 && v>>(4*w) == 0 {
			return errors.New("intent height not in shortest form")
		}
	}
	if w == 0 && len(t) != 2 {
		return errors.New("record has bytes after the intent height")
	}
	if v == 0 {
		return errors.New("intent height is zero")
	}
	return nil
}

// readPayloadHead consumes the canonical payload record up to the first blob
// byte, checks the fixed leading keys against ref and returns the blob length.
func readPayloadHead(r io.Reader, ref commitment.PayloadRef) (uint64, error) {
	var b [9]byte
	one := func() (byte, error) {
		_, err := io.ReadFull(r, b[:1])
		return b[0], err
	}
	expect := func(want ...byte) error {
		got := make([]byte, len(want))
		if _, err := io.ReadFull(r, got); err != nil {
			return fmt.Errorf("record header: %w", err)
		}
		for i := range want {
			if got[i] != want[i] {
				return fmt.Errorf("record header differs at byte %d", i)
			}
		}
		return nil
	}
	bstr := func(key byte, n byte) ([]byte, error) {
		head := []byte{key, 0x58, n}
		if n < 24 {
			head = []byte{key, 0x40 | n}
		}
		if err := expect(head...); err != nil {
			return nil, err
		}
		v := make([]byte, n)
		if _, err := io.ReadFull(r, v); err != nil {
			return nil, fmt.Errorf("record header: %w", err)
		}
		return v, nil
	}

	pairs := byte(6)
	if ref.DA == commitment.DACelestiaBlob {
		pairs = 8
	}
	if err := expect(0xa0|pairs, 1, format, 2, byte(KindPayload), 3, byte(ref.DA)); err != nil {
		return 0, err
	}
	c, err := bstr(4, 32)
	if err != nil {
		return 0, err
	}
	if string(c) != string(ref.Commitment) {
		return 0, errors.New("record carries another commitment")
	}
	if ref.DA == commitment.DACelestiaBlob {
		if _, err := bstr(5, 29); err != nil {
			return 0, err
		}
		if _, err := bstr(6, 20); err != nil {
			return 0, err
		}
	}
	if err := expect(7); err != nil {
		return 0, err
	}
	head, err := one()
	if err != nil {
		return 0, fmt.Errorf("record header: %w", err)
	}
	if head>>5 != majBstr {
		return 0, errors.New("blob is not a byte string")
	}
	var n uint64
	switch ai := head & 31; {
	case ai < 24:
		n = uint64(ai)
	case ai > 27:
		return 0, errors.New("blob length encoding")
	default:
		w := 1 << (ai - 24)
		if _, err := io.ReadFull(r, b[:w]); err != nil {
			return 0, fmt.Errorf("record header: %w", err)
		}
		for _, v := range b[:w] {
			n = n<<8 | uint64(v)
		}
		if n < 24 || w > 1 && n < 1<<(4*w) {
			return 0, errors.New("blob length not shortest form")
		}
	}
	if n < 1 || n > maxBlob {
		return 0, fmt.Errorf("%w: blob of %d bytes", commitment.ErrFieldSize, n)
	}
	return n, nil
}
