module github.com/vgonkivs/edicta/services/signer

go 1.26.0

toolchain go1.26.6

require (
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.1
	github.com/pelletier/go-toml/v2 v2.4.3
	github.com/stretchr/testify v1.12.1
	github.com/vgonkivs/edicta v0.0.0
	go.etcd.io/bbolt v1.5.0
)

require (
	filippo.io/edwards25519 v1.1.1 // indirect
	github.com/celestiaorg/go-square/v4 v4.0.1 // indirect
	github.com/celestiaorg/nmt v0.24.5 // indirect
	github.com/fxamacker/cbor/v2 v2.9.4 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	go.yaml.in/yaml/v3 v3.0.5 // indirect
	golang.org/x/crypto v0.57.0 // indirect
	golang.org/x/exp v0.0.0-20250911091902-df9299821621 // indirect
	golang.org/x/sync v0.23.0 // indirect
	golang.org/x/sys v0.48.0 // indirect
	google.golang.org/protobuf v1.36.12 // indirect
)

replace github.com/vgonkivs/edicta => ../../
