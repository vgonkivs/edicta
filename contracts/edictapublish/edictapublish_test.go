package edictapublish

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type buildInfo struct {
	SolcVersion   string `json:"solc_version"`
	Optimizer     bool   `json:"optimizer"`
	OptimizerRuns int    `json:"optimizer_runs"`
	EVMVersion    string `json:"evm_version"`
	MetadataHash  string `json:"metadata_hash"`
	SourceSHA256  string `json:"source_sha256"`
	RuntimeSHA256 string `json:"runtime_sha256"`
	InitSHA256    string `json:"init_sha256"`
}

func fileSHA(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(name)
	require.NoError(t, err)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func TestArtifactsMatchBuildMetadata(t *testing.T) {
	raw, err := os.ReadFile("build.json")
	require.NoError(t, err)
	var bi buildInfo
	require.NoError(t, json.Unmarshal(raw, &bi))

	assert.Equal(t, "0.8.28", bi.SolcVersion)
	assert.True(t, bi.Optimizer)
	assert.Equal(t, 200, bi.OptimizerRuns)
	assert.Equal(t, "none", bi.MetadataHash)

	assert.Equal(t, bi.SourceSHA256, fileSHA(t, "EdictaPublish.sol"))
	assert.Equal(t, bi.RuntimeSHA256, fileSHA(t, "runtime.hex"))
	assert.Equal(t, bi.InitSHA256, fileSHA(t, "init.hex"))
}

func TestRuntimeCodeIsEmbeddedInInitCode(t *testing.T) {
	rt, ini := RuntimeCode(), InitCode()
	require.NotEmpty(t, rt)
	require.NotEmpty(t, ini)
	assert.True(t, bytes.HasSuffix(ini, rt), "init code must deploy exactly the runtime code")
}

func TestRuntimeCodeContainsInterface(t *testing.T) {
	rt := RuntimeCode()
	topic := EventTopic()
	assert.Contains(t, hex.EncodeToString(topic[:]), "3872ab07")
	assert.True(t, bytes.Contains(rt, PublishSelector[:]), "publish(bytes) selector")
	assert.True(t, bytes.Contains(rt, topic[:]), "event topic 0")
}

func TestPublishSelectorMatchesSignature(t *testing.T) {
	sum := keccak([]byte("publish(bytes)"))
	assert.Equal(t, PublishSelector[:], sum[:4])
}

func TestEventTopicKnownAnswer(t *testing.T) {
	topic := EventTopic()
	assert.Equal(t, "3872ab073608518956afa8f8a7a6934cbc646bbf48c2331bb933943e1c38eac1", hex.EncodeToString(topic[:]))
}

func TestPayloadTopicIsSHA256(t *testing.T) {
	// sha256("abc"), not keccak: the contract uses the sha256 precompile.
	got := PayloadTopic([]byte("abc"))
	assert.Equal(t, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", hex.EncodeToString(got[:]))
}

func TestABIHasOneFunctionOneEvent(t *testing.T) {
	raw, err := os.ReadFile("EdictaPublish.abi.json")
	require.NoError(t, err)
	var entries []struct {
		Type            string `json:"type"`
		Name            string `json:"name"`
		StateMutability string `json:"stateMutability"`
		Inputs          []struct {
			Type    string `json:"type"`
			Indexed bool   `json:"indexed"`
		} `json:"inputs"`
	}
	require.NoError(t, json.Unmarshal(raw, &entries))
	require.Len(t, entries, 2)

	byType := map[string]int{}
	for _, e := range entries {
		byType[e.Type]++
		switch e.Type {
		case "function":
			assert.Equal(t, "publish", e.Name)
			assert.Equal(t, "nonpayable", e.StateMutability)
			require.Len(t, e.Inputs, 1)
			assert.Equal(t, "bytes", e.Inputs[0].Type)
		case "event":
			assert.Equal(t, "EdictaPayload", e.Name)
			require.Len(t, e.Inputs, 1)
			assert.Equal(t, "bytes32", e.Inputs[0].Type)
			assert.True(t, e.Inputs[0].Indexed)
		}
	}
	assert.Equal(t, map[string]int{"function": 1, "event": 1}, byType)
}

func TestDeployCalldataLayout(t *testing.T) {
	data := DeployCalldata()
	salt := Salt()
	assert.Equal(t, salt[:], data[:32])
	assert.Equal(t, InitCode(), data[32:])
}

func TestCreate2AddressKnownAnswer(t *testing.T) {
	addr := Create2Address()
	assert.Equal(t, "dedc2b65d07a4c3506dbe6fe50a04373addcdb18", hex.EncodeToString(addr[:]))
}
