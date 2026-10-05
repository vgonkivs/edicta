package fibrecommit

import (
	"encoding/hex"
	"errors"
	"fmt"
	"runtime/debug"

	"github.com/celestiaorg/celestia-app/v10/fibre"
)

// selfTestCases are copied from fibre_commit.json: the live Mocha blob, the
// padding boundary around 262144 and a row size above 128. Blobs follow the
// vector file's affine pattern: byte i is 7*i+3 mod 256.
var selfTestCases = []struct {
	name       string
	size       int
	commitment [32]byte
	uploadSize uint64
	live       bool
}{
	{"fibre_live_mocha_popsmin1", 1, mustHex32("0af738097b64a00bff6820c48a3ae26160b8054c9a9b79bd3cac2100d1833b2e"), 262144, true},
	{"fibre_size_262139", 262139, mustHex32("c2f52f72723d3a23dca37e165297dcab888be28078578b12c0976b5ef08a939e"), 262144, false},
	{"fibre_size_262140", 262140, mustHex32("f8ffcc4de8e10dd63b214cef0048b1c7aba8ee08614d538b6817da2a8b4c3087"), 524288, false},
	{"fibre_size_524284", 524284, mustHex32("6fee93b1c2540bbe58943ef43baf1eb566604095aebc140a74c6fb3c017d228f"), 786432, false},
}

func mustHex32(s string) [32]byte {
	var out [32]byte
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != len(out) {
		return out
	}
	copy(out[:], b)
	return out
}

func selfTestBlob(size int, live bool) []byte {
	if live {
		return []byte{0x65}
	}
	b := make([]byte, size)
	for i := range b {
		b[i] = byte(7*i + 3)
	}
	return b
}

// SelfTest recomputes the known answers and checks the encoder limits, so a
// drifted encoder is caught at startup instead of as mass rejections.
func SelfTest() error {
	for _, c := range selfTestCases {
		blob := selfTestBlob(c.size, c.live)
		got, err := Commitment(blob)
		if err != nil {
			return fmt.Errorf("fibrecommit self-test %s: %w", c.name, err)
		}
		if got != c.commitment {
			return fmt.Errorf("fibrecommit self-test %s: commitment %x, want %x", c.name, got, c.commitment)
		}
		up, err := UploadSize(uint64(len(blob)))
		if err != nil {
			return fmt.Errorf("fibrecommit self-test %s: %w", c.name, err)
		}
		if up != c.uploadSize {
			return fmt.Errorf("fibrecommit self-test %s: upload size %d, want %d", c.name, up, c.uploadSize)
		}
	}
	if lim := fibre.DefaultBlobConfigV0().MaxDataSize; lim != MaxDataSize {
		return fmt.Errorf("fibrecommit self-test: encoder limit %d, want %d", lim, MaxDataSize)
	}
	return nil
}

const appModule = "github.com/celestiaorg/celestia-app/v10"

// pinnedReplaces are the replace targets the vectors were produced under.
// Only modules outside pinnedModules are optional; those in it must all be
// present and match.
var pinnedReplaces = map[string]string{
	"cosmossdk.io/api":                            "github.com/celestiaorg/cosmos-sdk/api@v0.7.6",
	"cosmossdk.io/log":                            "github.com/celestiaorg/cosmos-sdk/log@v1.3.0",
	"cosmossdk.io/store":                          "github.com/celestiaorg/cosmos-sdk/store@v1.1.3-celestia.1",
	"cosmossdk.io/x/tx":                           "github.com/celestiaorg/cosmos-sdk/x/tx@v0.13.9",
	"cosmossdk.io/x/upgrade":                      "github.com/celestiaorg/cosmos-sdk/x/upgrade@v0.2.0",
	"github.com/bcp-innovations/hyperlane-cosmos": "github.com/celestiaorg/hyperlane-cosmos@v1.3.0",
	"github.com/cometbft/cometbft":                "github.com/celestiaorg/celestia-core@v0.42.0",
	"github.com/cosmos/cosmos-sdk":                "github.com/celestiaorg/cosmos-sdk@v0.52.8",
	"github.com/cosmos/ibc-go/v8":                 "github.com/celestiaorg/ibc-go/v8@v8.7.2",
	"github.com/cosmos/ledger-cosmos-go":          "github.com/cosmos/ledger-cosmos-go@v0.16.0",
	"github.com/etclabscore/go-jsonschema-walk":   "github.com/LexLuthr/go-jsonschema-walk@v1.0.0",
	"github.com/gogo/protobuf":                    "github.com/regen-network/protobuf@v1.3.3-alpha.regen.1",
	"github.com/syndtr/goleveldb":                 "github.com/syndtr/goleveldb@v1.0.1-0.20210819022825-2ae1ddf74ef7",
	"github.com/tendermint/tendermint":            "github.com/celestiaorg/celestia-core@v1.55.0-tm-v0.34.35",
	"nhooyr.io/websocket":                         "github.com/coder/websocket@v1.8.6",
	"github.com/ipfs/boxo":                        "github.com/celestiaorg/boxo@v0.29.0-fork-4",
	"github.com/ipfs/go-datastore":                "github.com/celestiaorg/go-datastore@v0.0.0-20250801131506-48a63ae531e4",
	"github.com/moby/term":                        "github.com/moby/term@v0.5.2",
	"github.com/docker/go-connections":            "github.com/docker/go-connections@v0.7.0",
	"github.com/bytedance/sonic":                  "github.com/bytedance/sonic@v1.15.0",
	"github.com/bytedance/sonic/loader":           "github.com/bytedance/sonic/loader@v0.5.0",
	"github.com/cloudwego/base64x":                "github.com/cloudwego/base64x@v0.1.6",
	"github.com/creack/pty":                       "github.com/creack/pty@v1.1.24",
}

// CheckBuild verifies that this binary was built with the pinned
// celestia-app version, the replace targets, and the version and h1 sum of
// every module the upstream fibre package links.
func CheckBuild() error {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return errors.New("fibrecommit: build info unavailable")
	}
	return checkBuildInfo(bi)
}

func checkBuildInfo(bi *debug.BuildInfo) error {
	if bi == nil {
		return errors.New("fibrecommit: build info unavailable")
	}
	pins := make(map[string]pinnedModule, len(pinnedModules))
	for _, p := range pinnedModules {
		pins[p.path] = p
	}
	var app *debug.Module
	seen := make(map[string]bool, len(pins))
	for _, d := range bi.Deps {
		if d == nil {
			continue
		}
		if d.Path == appModule {
			app = d
		}
		if p, ok := pins[d.Path]; ok {
			if err := checkPinned(d, p); err != nil {
				return err
			}
			seen[d.Path] = true
			continue
		}
		want, pinned := pinnedReplaces[d.Path]
		if !pinned {
			continue
		}
		if d.Replace == nil {
			return fmt.Errorf("fibrecommit: %s is not replaced, want %s", d.Path, want)
		}
		if got := d.Replace.Path + "@" + d.Replace.Version; got != want {
			return fmt.Errorf("fibrecommit: %s replaced by %s, want %s", d.Path, got, want)
		}
	}
	if app == nil {
		return fmt.Errorf("fibrecommit: %s is not in the build", appModule)
	}
	for _, p := range pinnedModules {
		if !seen[p.path] {
			return fmt.Errorf("fibrecommit: pinned module %s is not in the build", p.path)
		}
	}
	if app.Version != PinnedAppVersion || app.Replace != nil {
		return fmt.Errorf("fibrecommit: %s is %s, want %s", appModule, app.Version, PinnedAppVersion)
	}
	return nil
}

func checkPinned(d *debug.Module, p pinnedModule) error {
	eff := d
	if p.replacePath == "" {
		if d.Replace != nil {
			return fmt.Errorf("fibrecommit: %s is replaced by %s, want no replace", d.Path, d.Replace.Path)
		}
	} else {
		if d.Replace == nil {
			return fmt.Errorf("fibrecommit: %s is not replaced, want %s", d.Path, p.replacePath)
		}
		if d.Replace.Path != p.replacePath {
			return fmt.Errorf("fibrecommit: %s replaced by %s, want %s", d.Path, d.Replace.Path, p.replacePath)
		}
		eff = d.Replace
	}
	if eff.Version != p.version {
		return fmt.Errorf("fibrecommit: %s is %s, want %s", d.Path, eff.Version, p.version)
	}
	if eff.Sum == "" {
		return fmt.Errorf("fibrecommit: %s has no sum, want %s", d.Path, p.sum)
	}
	if eff.Sum != p.sum {
		return fmt.Errorf("fibrecommit: %s sum %s, want %s", d.Path, eff.Sum, p.sum)
	}
	return nil
}
