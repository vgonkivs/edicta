package fibrecommit

import (
	"encoding/hex"
	"errors"
	"fmt"
	"runtime/debug"

	"github.com/celestiaorg/celestia-app/v10/fibre"
)

// A payload anchored on Mocha and the commitment the chain recorded for it.
const (
	liveCommitmentHex = "0af738097b64a00bff6820c48a3ae26160b8054c9a9b79bd3cac2100d1833b2e"
	liveUploadSize    = 262144
)

// SelfTest recomputes the live Mocha vector and checks the encoder limits, so
// a drifted encoder is caught at startup instead of as mass rejections.
func SelfTest() error {
	got, err := Commitment([]byte{0x65})
	if err != nil {
		return fmt.Errorf("fibrecommit self-test: %w", err)
	}
	if h := hex.EncodeToString(got[:]); h != liveCommitmentHex {
		return fmt.Errorf("fibrecommit self-test: commitment %s, want %s", h, liveCommitmentHex)
	}
	up, err := UploadSize(1)
	if err != nil {
		return fmt.Errorf("fibrecommit self-test: %w", err)
	}
	if up != liveUploadSize {
		return fmt.Errorf("fibrecommit self-test: upload size %d, want %d", up, liveUploadSize)
	}
	if lim := fibre.DefaultBlobConfigV0().MaxDataSize; lim != MaxDataSize {
		return fmt.Errorf("fibrecommit self-test: encoder limit %d, want %d", lim, MaxDataSize)
	}
	return nil
}

const appModule = "github.com/celestiaorg/celestia-app/v10"

// pinnedReplaces are the replace targets the vectors were produced under.
// A module absent from the build is not checked.
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
// celestia-app version and the replace targets the vectors were produced
// under.
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
	var app *debug.Module
	for _, d := range bi.Deps {
		if d == nil {
			continue
		}
		if d.Path == appModule {
			app = d
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
	if app.Version != PinnedAppVersion || app.Replace != nil {
		return fmt.Errorf("fibrecommit: %s is %s, want %s", appModule, app.Version, PinnedAppVersion)
	}
	return nil
}
