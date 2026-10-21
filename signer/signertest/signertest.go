// SPDX-License-Identifier: Apache-2.0

// Package signertest holds fixtures and fakes for tests of the signer: keys
// derived from labels, form T deposits, signed decisions with a gate
// Authorization, and a scripted Eden chain that is both the signer's RPC and
// a settlement source. Nothing here touches a network.
package signertest

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math/big"
	"time"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"

	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/edenescrow"
)

// GateID is the gate id of the fixtures.
const GateID = "gate1"

// Keys are the four signing roles of one test world, each its own key.
type Keys struct {
	Agent    ed25519.PrivateKey
	Gate     ed25519.PrivateKey
	Executor ed25519.PrivateKey
	// Payer is the payer's secp256k1 scalar.
	Payer []byte
}

func seed(label string) []byte {
	s := sha256.Sum256([]byte("edicta signertest " + label))
	return s[:]
}

// NewKeys derives the keys from a label. They are test keys only.
func NewKeys(label string) Keys {
	return Keys{
		Agent:    ed25519.NewKeyFromSeed(seed(label + "/agent")),
		Gate:     ed25519.NewKeyFromSeed(seed(label + "/gate")),
		Executor: ed25519.NewKeyFromSeed(seed(label + "/executor")),
		Payer:    seed(label + "/payer"),
	}
}

func pub(k ed25519.PrivateKey) ed25519.PublicKey { return ed25519.PublicKey(k[ed25519.SeedSize:]) }

// AgentPub, GatePub and ExecutorPub are the public keys.
func (k Keys) AgentPub() ed25519.PublicKey    { return pub(k.Agent) }
func (k Keys) GatePub() ed25519.PublicKey     { return pub(k.Gate) }
func (k Keys) ExecutorPub() ed25519.PublicKey { return pub(k.Executor) }

// PayerAddress is the payer key's address.
func (k Keys) PayerAddress() [20]byte {
	var s secp256k1.ModNScalar
	s.SetByteSlice(k.Payer)
	return edenescrow.Address(secp256k1.NewPrivateKey(&s).PubKey())
}

// Facilitator is the allowed facilitator of the fixtures.
var Facilitator = [20]byte{0xfa, 0xc1, 0x11, 0x7a, 0x70, 0x40}

// PayTo is the payee of the fixtures.
var PayTo = [20]byte{0x9a, 0x70}

// Deposit describes one form T deposit.
type Deposit struct {
	ChainID        uint64
	Nonce          uint64
	MaxPriorityFee uint64
	MaxFeePerGas   uint64
	GasLimit       uint64
	Value          *big.Int
	PaymentID      [32]byte
	PayTo          [20]byte
	Facilitator    [20]byte
	ExpiresAt      uint64
	RefundAfter    uint64
	Resource       string
	// Requirements is R, which the action binds; nil binds a mock document.
	Requirements []byte
}

// NewDeposit is a deposit on Eden mainnet that expires 5 minutes after now.
func NewDeposit(now time.Time) Deposit {
	exp := uint64(now.Unix()) + 300
	return Deposit{
		ChainID: 714, Nonce: 7, MaxPriorityFee: 1, MaxFeePerGas: 2299, GasLimit: 200_000,
		Value: big.NewInt(16_170_471_215_597_597), PaymentID: sha256.Sum256([]byte("payment")),
		PayTo: PayTo, Facilitator: Facilitator, ExpiresAt: exp, RefundAfter: exp + 3600,
		Resource: "https://api.example/v1/data",
	}
}

// Action is the canonical form T action of d. It fails when the strict
// decoder refuses the result.
func (d Deposit) Action() ([]byte, error) {
	row, ok := edenescrow.Lookup(d.ChainID)
	to := row.Escrow
	if !ok {
		to = [20]byte{0x01}
	}
	return d.ActionTo(to)
}

// ActionTo is Action with another escrow address.
func (d Deposit) ActionTo(to [20]byte) ([]byte, error) {
	data := make([]byte, 0, edenescrow.DepositCallSize)
	data = append(data, 0xb7, 0x07, 0xd8, 0x60)
	data = append(data, d.PaymentID[:]...)
	for _, a := range [][20]byte{d.PayTo, d.Facilitator} {
		data = append(data, make([]byte, 12)...)
		data = append(data, a[:]...)
	}
	for _, v := range []uint64{d.ExpiresAt, d.RefundAfter} {
		var w [32]byte
		binary.BigEndian.PutUint64(w[24:], v)
		data = append(data, w[:]...)
	}
	price := [32]byte{31: tiaPriceUSD}
	data = append(data, price[:]...)
	value := d.Value
	if value == nil {
		value = new(big.Int)
	}
	items := [][]byte{
		rlpUint(d.ChainID), rlpUint(d.Nonce), rlpUint(d.MaxPriorityFee), rlpUint(d.MaxFeePerGas),
		rlpUint(d.GasLimit), rlpString(to[:]), rlpString(value.Bytes()), rlpString(data), {0xc0},
	}
	unsigned := append([]byte{0x02}, rlpList(items...)...)
	r := d.Requirements
	if r == nil {
		r = []byte(`{"mock":true}`)
	}
	return edenescrow.EncodeTxAction(unsigned, d.Resource, edenescrow.RequirementsHash(r))
}

func rlpUint(v uint64) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	i := 0
	for i < 8 && b[i] == 0 {
		i++
	}
	return rlpString(b[i:])
}

func rlpString(b []byte) []byte {
	if len(b) == 1 && b[0] < 0x80 {
		return []byte{b[0]}
	}
	return append(rlpHead(0x80, len(b)), b...)
}

func rlpList(items ...[]byte) []byte {
	var p []byte
	for _, it := range items {
		p = append(p, it...)
	}
	return append(rlpHead(0xc0, len(p)), p...)
}

func rlpHead(base byte, n int) []byte {
	if n <= 55 {
		return []byte{base + byte(n)}
	}
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(n))
	i := 0
	for b[i] == 0 {
		i++
	}
	return append([]byte{base + 55 + byte(8-i)}, b[i:]...)
}

// Decision is one agent decision with the gate's Authorization.
type Decision struct {
	Envelope      []byte
	Action        []byte
	Salt          []byte
	Authorization []byte
	Hash          commitment.Hash
	Expires       uint64
}

// DecisionOpts change the defaults of NewDecision.
type DecisionOpts struct {
	// Label varies the commitment's nonce, so two decisions differ.
	Label string
	// Expires is the Authorization's expiry; zero is now + 600.
	Expires uint64
	// Strict asks for a strict-mode Authorization.
	Strict bool
	// GateKey signs the Authorization instead of the keys' gate key.
	GateKey ed25519.PrivateKey
	// AuthAction is the action the Authorization names, if not the
	// committed one.
	AuthAction []byte
	// AuthCommitment names another commitment in the Authorization.
	AuthCommitment *commitment.Hash
	// ActionType is the committed type, if not the form T type.
	ActionType string
	// ValidUntil is the commitment's valid_until, if not now + 900.
	ValidUntil uint64
	// ScopeGateID is the gate the commitment names, if not GateID.
	ScopeGateID string
}

// NewDecision builds the agent's signed commitment to action and the gate's
// Authorization for it, as of now.
func NewDecision(k Keys, action []byte, now time.Time, o DecisionOpts) (Decision, error) {
	t := uint64(now.Unix())
	salt := seed("salt/" + o.Label)
	typ := o.ActionType
	if typ == "" {
		typ = edenescrow.ActionType
	}
	ah, err := commitment.ActionHash(typ, salt, action)
	if err != nil {
		return Decision{}, err
	}
	ns := make([]byte, 29)
	ns[27] = 0x01
	sum := sha256.Sum256([]byte("payload/" + o.Label))
	issued, until, scope := t-10, t+900, GateID
	if o.ValidUntil != 0 {
		until = o.ValidUntil
		issued = min(issued, until-1)
	}
	if o.ScopeGateID != "" {
		scope = o.ScopeGateID
	}
	c := &commitment.Commitment{
		Version: 1, AgentID: "agent1", AgentPubKey: k.AgentPub(), Nonce: seed("nonce/" + o.Label)[:16],
		IssuedAt: issued, ValidUntil: until,
		Scope:  commitment.Scope{GateID: scope},
		Action: commitment.Action{Type: typ, Hash: ah[:]},
		PayloadRef: commitment.PayloadRef{
			DA: commitment.DACelestiaBlob, Namespace: ns, Commitment: sum[:], Height: 100, Signer: sum[:20],
		},
		CiphertextHash: sum[:], PlaintextHash: sum[:], PayloadSize: 64,
	}
	env, h, err := commitment.Sign(k.Agent, c)
	if err != nil {
		return Decision{}, err
	}
	envBytes, err := commitment.EncodeSigned(env)
	if err != nil {
		return Decision{}, err
	}
	exp := o.Expires
	if exp == 0 {
		exp = t + 600
	}
	authAction := action
	if o.AuthAction != nil {
		authAction = o.AuthAction
	}
	aah, err := commitment.ActionHash(typ, salt, authAction)
	if err != nil {
		return Decision{}, err
	}
	ch := h
	if o.AuthCommitment != nil {
		ch = *o.AuthCommitment
	}
	a := &commitment.Authorization{
		Version: 1, CommitmentHash: ch[:], ActionHash: aah[:], GateID: GateID, Expires: exp,
		Path: commitment.PathDA, Mode: commitment.ModeFast, AnchorDeadline: t + 120,
	}
	if o.Strict {
		a.Mode, a.AnchorDeadline = commitment.ModeStrict, 0
	}
	canon, err := commitment.EncodeAuthorization(a)
	if err != nil {
		return Decision{}, err
	}
	gk := k.Gate
	if o.GateKey != nil {
		gk = o.GateKey
	}
	sig := ed25519.Sign(gk, commitment.AuthorizationSigningMessage(commitment.HashAuthorization(canon)))
	auth, err := commitment.EncodeSignedAuthorization(&commitment.SignedAuthorization{Authorization: *a, Signature: sig})
	if err != nil {
		return Decision{}, fmt.Errorf("signertest: authorization: %w", err)
	}
	return Decision{Envelope: envBytes, Action: action, Salt: salt, Authorization: auth, Hash: h, Expires: exp}, nil
}
