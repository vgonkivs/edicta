package commitment_test

import (
	"crypto/sha256"
	"testing"

	"github.com/vgonkivs/prior/commitment"
)

func TestPayloadVectors(t *testing.T) {
	var pf payloadFile
	loadJSON(t, "payload.json", &pf)
	vf := loadValid(t)
	minimal := toCommitment(t, validCaseByID(t, vf, "minimal_lmt").Input)

	for _, pc := range pf.Cases {
		switch pc.ID {
		case "ciphertext_hash_small_blob":
			t.Run(pc.ID, func(t *testing.T) {
				blob := mustHex(t, pc.BlobHex)
				want := mustHex(t, pc.CiphertextHashHex)
				sum := sha256.Sum256(blob)
				if string(sum[:]) != string(want) {
					t.Fatalf("SHA-256(blob) %x, want %x", sum, want)
				}
				if uint64(len(blob)) != u64(t, pc.PayloadSize) {
					t.Fatalf("len(blob) %d, want %s", len(blob), pc.PayloadSize)
				}
				if string(minimal.CiphertextHash) != string(want) || minimal.PayloadSize != uint64(len(blob)) {
					t.Fatal("minimal_lmt does not commit to this blob")
				}
				if err := commitment.CheckPayload(minimal, blob); err != nil {
					t.Fatalf("CheckPayload: %v", err)
				}
			})
		case "plaintext_hash_basic":
			t.Run(pc.ID, func(t *testing.T) {
				var salt [32]byte
				copy(salt[:], mustHex(t, pc.SaltHex))
				if len(mustHex(t, pc.SaltHex)) != 32 {
					t.Fatal("vector salt is not 32 bytes")
				}
				h := commitment.PlaintextHash(salt, mustHex(t, pc.PlaintextHex))
				want := mustHex(t, pc.PlaintextHashHex)
				if string(h[:]) != string(want) {
					t.Fatalf("PlaintextHash %x, want %x", h[:], want)
				}
				if string(minimal.PlaintextHash) != string(want) {
					t.Fatal("minimal_lmt does not commit to this plaintext hash")
				}
			})
		default:
			t.Errorf("unexpected payload case %q", pc.ID)
		}
	}
}

func TestPayloadRejectVectors(t *testing.T) {
	var pf payloadFile
	loadJSON(t, "payload.json", &pf)
	if len(pf.Reject) == 0 {
		t.Fatal("no payload reject vectors loaded")
	}
	for _, pc := range pf.Reject {
		t.Run(pc.ID, func(t *testing.T) {
			c := &commitment.Commitment{
				PayloadSize:    u64(t, pc.PayloadSize),
				CiphertextHash: mustHex(t, pc.CiphertextHashHex),
			}
			err := commitment.CheckPayload(c, mustHex(t, pc.BlobHex))
			assertSentinel(t, err, pc.ExpectError)
		})
	}
}

func TestPlaintextHashSaltBoundary(t *testing.T) {
	var salt [32]byte
	salt[0] = 1
	a := commitment.PlaintextHash(salt, []byte("buy"))
	b := commitment.PlaintextHash(salt, []byte("buy"))
	if a != b {
		t.Fatal("PlaintextHash is not deterministic")
	}
	var other [32]byte
	if commitment.PlaintextHash(other, []byte("buy")) == a {
		t.Fatal("different salt must change the hash")
	}
	want := sha256.Sum256(append(append([]byte{}, salt[:]...), "buy"...))
	if [32]byte(a) != want {
		t.Fatal("PlaintextHash must be SHA-256(salt || plaintext) with no tag")
	}
}

func TestCheckPayloadOrder(t *testing.T) {
	blob := []byte("0123456789")
	sum := sha256.Sum256(blob)
	tests := []struct {
		name string
		size uint64
		hash []byte
		blob []byte
		want string
	}{
		{"ok", 10, sum[:], blob, ""},
		{"size checked before hash", 11, make([]byte, 32), blob, "ErrPayloadSizeMismatch"},
		{"longer blob", 10, sum[:], append(append([]byte{}, blob...), 0), "ErrPayloadSizeMismatch"},
		{"empty blob", 10, sum[:], nil, "ErrPayloadSizeMismatch"},
		{"hash mismatch", 10, make([]byte, 32), blob, "ErrPayloadHashMismatch"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &commitment.Commitment{PayloadSize: tt.size, CiphertextHash: tt.hash}
			err := commitment.CheckPayload(c, tt.blob)
			if tt.want == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			assertSentinel(t, err, tt.want)
		})
	}
}
