// Package fibrecommit recomputes the Fibre blob commitment with celestia-app's
// own encoder, so the value that the gate compares is the one validators sign.
package fibrecommit

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/celestiaorg/celestia-app/v10/fibre"

	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/gate"
)

const (
	// PinnedAppVersion is the only celestia-app release whose encoder the
	// test vectors were generated with.
	PinnedAppVersion = "v10.4.0-mocha"

	// MaxDataSize is the largest blob the pinned encoder accepts.
	MaxDataSize = 1<<27 - 5

	// DefaultMaxDataSize is the cap Edicta applies unless configured otherwise.
	DefaultMaxDataSize = 16 << 20
)

// ErrTooLarge means the data is above the configured cap. It is not a
// commitment mismatch: nothing was computed.
var ErrTooLarge = errors.New("fibrecommit: data above the configured cap")

var errWrongDA = errors.New("fibrecommit: reference is not a Fibre reference")

// Committer implements gate.DACommitter for da = 1.
type Committer struct {
	max uint64
}

// New returns a Committer refusing data above maxDataSize, which must be in
// [1, MaxDataSize].
func New(maxDataSize uint64) (*Committer, error) {
	if maxDataSize == 0 || maxDataSize > MaxDataSize {
		return nil, fmt.Errorf("fibrecommit: max data size %d outside [1, %d]", maxDataSize, uint64(MaxDataSize))
	}
	return &Committer{max: maxDataSize}, nil
}

// MaxDataSize returns the configured cap.
func (c *Committer) MaxDataSize() uint64 { return c.max }

// Check recomputes the commitment of blob and compares it with ref.Commitment.
// The size is checked first so an oversize input never reaches the encoder.
func (c *Committer) Check(ref commitment.PayloadRef, blob []byte) error {
	if uint64(len(blob)) > c.max {
		return fmt.Errorf("%w: %d bytes, cap %d", ErrTooLarge, len(blob), c.max)
	}
	if ref.DA != commitment.DAFibre {
		return fmt.Errorf("%w: da %d", errWrongDA, ref.DA)
	}
	if len(ref.Commitment) != fibre.CommitmentSize {
		return fmt.Errorf("%w: commitment is %d bytes", gate.ErrDACommitmentMismatch, len(ref.Commitment))
	}
	if len(blob) == 0 {
		return fmt.Errorf("%w: empty blob", gate.ErrDACommitmentMismatch)
	}
	got, err := Commitment(blob)
	if err != nil {
		return fmt.Errorf("%w: %w", gate.ErrDACommitmentMismatch, err)
	}
	if !bytes.Equal(got[:], ref.Commitment) {
		return gate.ErrDACommitmentMismatch
	}
	return nil
}

// Commitment returns the Fibre commitment of data. data is not modified.
func Commitment(data []byte) ([32]byte, error) {
	var out [32]byte
	if len(data) == 0 {
		return out, errors.New("fibrecommit: empty data")
	}
	if uint64(len(data)) > MaxDataSize {
		return out, fmt.Errorf("%w: %d bytes exceed the encoder limit", ErrTooLarge, len(data))
	}
	// NewBlob keeps its input as row storage.
	b, err := fibre.NewBlob(bytes.Clone(data), fibre.DefaultBlobConfigV0())
	if err != nil {
		return out, fmt.Errorf("fibrecommit: encode: %w", err)
	}
	defer b.Free()
	c := b.ID().Commitment()
	copy(out[:], c[:])
	return out, nil
}

// UploadSize returns the padded upload size for dataLen bytes, the value
// carried as blob_size in the payment promise.
func UploadSize(dataLen uint64) (uint64, error) {
	if dataLen == 0 {
		return 0, errors.New("fibrecommit: empty data")
	}
	if dataLen > MaxDataSize {
		return 0, fmt.Errorf("%w: %d bytes exceed the encoder limit", ErrTooLarge, dataLen)
	}
	return uint64(fibre.DefaultBlobConfigV0().UploadSize(int(dataLen))), nil
}

// BlobID returns the version-0 Fibre blob ID for a commitment.
func BlobID(c [32]byte) [33]byte {
	var id [33]byte
	copy(id[1:], c[:])
	return id
}
