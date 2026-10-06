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
// the record is read as a stream and never decoded whole.
func NewGateSource(r Store) gate.BlobSource {
	return gateSource{r}
}

func (s gateSource) Fetch(ctx context.Context, ref commitment.PayloadRef, maxSize uint64) ([]byte, error) {
	if st, ok := s.r.(PayloadStreamer); ok {
		return fetchStream(ctx, st, ref, maxSize)
	}
	p, err := s.r.Payload(ctx, ref.DA, ref.Commitment)
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
	return out, nil
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
	if err := expect(0xa0|pairs, 1, 0, 2, byte(KindPayload), 3, byte(ref.DA)); err != nil {
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
