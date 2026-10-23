// SPDX-License-Identifier: Apache-2.0

package edenescrow

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/engine/commitment"
	"github.com/vgonkivs/edicta/engine/policy"
	"github.com/vgonkivs/edicta/internal/evm"
	"github.com/vgonkivs/edicta/internal/testkit"
)

const vectorDir = "vectors/profiles/eden-escrow"

// profileRevision is the revision the profile document states today; every
// vector file must carry exactly it.
func profileRevision(t testing.TB) string {
	t.Helper()
	b, err := os.ReadFile(testkit.SpecPath(t, "profiles/eden-escrow-v1.md"))
	require.NoError(t, err)
	m := regexp.MustCompile("Status: revision `(eden-escrow-v1-draft\\.[0-9]+)`").FindSubmatch(b)
	require.NotNil(t, m, "profile document has no revision line")
	return string(m[1])
}

type header struct {
	Format   string `json:"format"`
	Profile  string `json:"profile"`
	Revision string `json:"revision"`
}

type depositFields struct {
	PaymentIDHex   string `json:"payment_id_hex"`
	PayTo          string `json:"pay_to"`
	Facilitator    string `json:"facilitator"`
	ExpiresAt      string `json:"expires_at"`
	RefundAfter    string `json:"refund_after"`
	TIAPriceUSDHex string `json:"tia_price_usd_hex"`
}

type depositCallFile struct {
	header
	SelectorHex string `json:"selector_hex"`
	Length      string `json:"length"`
	Cases       []struct {
		ID      string        `json:"id"`
		DataHex string        `json:"data_hex"`
		Fields  depositFields `json:"fields"`
	} `json:"cases"`
	Reject []struct {
		ID          string `json:"id"`
		DataHex     string `json:"data_hex"`
		ExpectError string `json:"expect_error"`
		Rule        string `json:"rule"`
	} `json:"reject"`
}

type vectorRow struct {
	ChainID  string `json:"chain_id"`
	Escrow   string `json:"escrow"`
	CodeHash string `json:"code_hash"`
}

type vectorFacts struct {
	Kind      string `json:"kind"`
	Asset     string `json:"asset"`
	Amount    string `json:"amount"`
	Scale     string `json:"scale"`
	Recipient string `json:"recipient"`
}

type actionCase struct {
	ID           string   `json:"id"`
	Build        string   `json:"build"`
	ExtractorIDs []string `json:"extractor_ids"`
	Input        struct {
		ChainID         string `json:"chain_id"`
		Nonce           string `json:"nonce"`
		MaxPriorityFee  string `json:"max_priority_fee_per_gas"`
		MaxFeePerGas    string `json:"max_fee_per_gas"`
		GasLimit        string `json:"gas_limit"`
		To              string `json:"to"`
		Value           string `json:"value"`
		DataRef         string `json:"data_ref"`
		Resource        string `json:"resource"`
		RequirementsHex string `json:"requirements_hex"`
	} `json:"input"`
	RequirementsHashHex  string       `json:"requirements_hash_hex"`
	TxHex                string       `json:"tx_hex"`
	SighashHex           string       `json:"sighash_hex"`
	CBORHex              string       `json:"cbor_hex"`
	ActionSaltHex        string       `json:"action_salt_hex"`
	ActionHashHex        string       `json:"action_hash_hex"`
	Facts                *vectorFacts `json:"facts"`
	FactsCBORHex         *string      `json:"facts_cbor_hex"`
	ExtractorExpectError *string      `json:"extractor_expect_error"`
	ExtractorRule        *string      `json:"extractor_rule"`
	ProfileFields        DepositView  `json:"profile_fields"`
}

type actionFile struct {
	header
	ActionType string `json:"action_type"`
	Extractors []struct {
		ID    string      `json:"id"`
		Build string      `json:"build"`
		Kind  string      `json:"kind"`
		Scale string      `json:"scale"`
		Rows  []vectorRow `json:"rows"`
	} `json:"extractors"`
	EscrowCode struct {
		RuntimeCodeHash string `json:"runtime_code_hash"`
		InitCodeHash    string `json:"init_code_hash"`
		Create          struct {
			Creator string `json:"creator"`
			Nonce   string `json:"nonce"`
			Address string `json:"address"`
		} `json:"create"`
		Create2 struct {
			Deployer string `json:"deployer"`
			SaltHex  string `json:"salt_hex"`
			Address  string `json:"address"`
		} `json:"create2"`
	} `json:"escrow_code"`
	RequirementsTag string `json:"requirements_tag"`
	Limits          struct {
		ActionMax   string `json:"action_max"`
		TxMax       string `json:"tx_max"`
		ResourceMax string `json:"resource_max"`
	} `json:"limits"`
	Cases  []actionCase `json:"cases"`
	Reject []struct {
		ID                   string `json:"id"`
		Build                string `json:"build"`
		ExtractorID          string `json:"extractor_id"`
		CBORHex              string `json:"cbor_hex"`
		ExpectError          string `json:"expect_error"`
		ExtractorExpectError string `json:"extractor_expect_error"`
		Rule                 string `json:"rule"`
	} `json:"reject"`
}

type signedFile struct {
	header
	Keys map[string]struct {
		PrivateKeyHex string `json:"private_key_hex"`
		Address       string `json:"address"`
	} `json:"keys"`
	NHex  string `json:"secp256k1_n_hex"`
	Cases []struct {
		ID         string `json:"id"`
		ActionRef  string `json:"action_ref"`
		Key        string `json:"key"`
		SighashHex string `json:"sighash_hex"`
		YParity    string `json:"y_parity"`
		RHex       string `json:"r_hex"`
		SHex       string `json:"s_hex"`
		SignedHex  string `json:"signed_hex"`
		RailRef    string `json:"rail_ref"`
		Payer      string `json:"payer"`
	} `json:"cases"`
	RailRef []struct {
		ID      string `json:"id"`
		RailRef string `json:"rail_ref"`
		Expect  string `json:"expect"`
	} `json:"rail_ref"`
	ExactTx []struct {
		ID        string `json:"id"`
		ActionRef string `json:"action_ref"`
		SignedHex string `json:"signed_hex"`
		RailRef   string `json:"rail_ref"`
		Expect    string `json:"expect"`
		Payer     string `json:"payer"`
	} `json:"exact_tx"`
}

func loadJSON[T any](t testing.TB, name string) T {
	t.Helper()
	b, err := os.ReadFile(testkit.SpecPath(t, vectorDir, name))
	require.NoError(t, err)
	var v T
	require.NoError(t, json.Unmarshal(b, &v))
	return v
}

func checkHeader(t *testing.T, h header) {
	t.Helper()
	require.Equal(t, "edicta-vectors/v0", h.Format)
	require.Equal(t, "eden-escrow", h.Profile)
	require.Equal(t, profileRevision(t), h.Revision)
}

func unhex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
	require.NoError(t, err)
	return b
}

func addr(t testing.TB, s string) [20]byte {
	t.Helper()
	var a [20]byte
	b := unhex(t, s)
	require.Len(t, b, 20)
	copy(a[:], b)
	return a
}

func u64(t testing.TB, s string) uint64 {
	t.Helper()
	v, err := strconv.ParseUint(s, 10, 64)
	require.NoError(t, err)
	return v
}

func minimal(t testing.TB, dec string) []byte {
	t.Helper()
	v, ok := new(big.Int).SetString(dec, 10)
	require.True(t, ok, dec)
	return v.Bytes()
}

var sentinels = map[string]error{
	"edenescrow.ErrMalformed":     ErrMalformed,
	"edenescrow.ErrUnknownDomain": ErrUnknownDomain,
}

func ruleOf(t testing.TB, err error) string {
	t.Helper()
	var re *ruleError
	require.True(t, errors.As(err, &re), "no rule in %v", err)
	return re.rule
}

func TestDepositCallVectors(t *testing.T) {
	v := loadJSON[depositCallFile](t, "deposit_call.json")
	checkHeader(t, v.header)
	require.Equal(t, hex.EncodeToString(depositSelector[:]), v.SelectorHex)
	require.Equal(t, strconv.Itoa(DepositCallSize), v.Length)
	require.Len(t, v.Cases, 3)
	require.Len(t, v.Reject, 16)
	for _, c := range v.Cases {
		t.Run(c.ID, func(t *testing.T) {
			d, err := DecodeDepositCall(unhex(t, c.DataHex))
			require.NoError(t, err)
			assert.Equal(t, c.Fields.PaymentIDHex, hex.EncodeToString(d.PaymentID[:]))
			assert.Equal(t, addr(t, c.Fields.PayTo), d.PayTo)
			assert.Equal(t, addr(t, c.Fields.Facilitator), d.Facilitator)
			assert.Equal(t, u64(t, c.Fields.ExpiresAt), d.ExpiresAt)
			assert.Equal(t, u64(t, c.Fields.RefundAfter), d.RefundAfter)
			assert.Equal(t, c.Fields.TIAPriceUSDHex, hex.EncodeToString(d.TIAPriceUSD[:]))
		})
	}
	for _, r := range v.Reject {
		t.Run(r.ID, func(t *testing.T) {
			_, err := DecodeDepositCall(unhex(t, r.DataHex))
			require.ErrorIs(t, err, sentinels[r.ExpectError])
			assert.Equal(t, r.Rule, ruleOf(t, err))
		})
	}
}

func TestEscrowTableVectors(t *testing.T) {
	v := loadJSON[actionFile](t, "action.json")
	checkHeader(t, v.header)
	require.Equal(t, ActionType, v.ActionType)
	require.Equal(t, RequirementsTag, v.RequirementsTag)
	require.Equal(t, strconv.Itoa(MaxActionSize), v.Limits.ActionMax)
	require.Equal(t, strconv.Itoa(MaxTxSize), v.Limits.TxMax)
	require.Equal(t, strconv.Itoa(MaxResourceSize), v.Limits.ResourceMax)
	require.Len(t, v.Extractors, 2)
	ids := map[string]string{"production": ExtractorID, "edictadev": DevExtractorID}
	for _, x := range v.Extractors {
		require.Equal(t, ids[x.Build], x.ID)
		require.Equal(t, Kind, x.Kind)
		require.Equal(t, strconv.Itoa(Scale), x.Scale)
		tbl, ok := tablesInBuild[x.ID]
		if !ok {
			assert.NotEqual(t, x.ID, RegisteredExtractorID())
			continue
		}
		require.Len(t, tbl.rows, len(x.Rows), x.ID)
		for i, r := range x.Rows {
			got := tbl.rows[i]
			assert.Equal(t, u64(t, r.ChainID), got.ChainID)
			assert.Equal(t, addr(t, r.Escrow), got.Escrow)
			assert.Equal(t, r.CodeHash, hex.EncodeToString(got.CodeHash[:]))
		}
	}
	assert.Equal(t, v.EscrowCode.RuntimeCodeHash, hex.EncodeToString(escrowCodeHash[:]))

	// The mainnet address is keccak256(rlp([creator, nonce]))[12:].
	creator := unhex(t, v.EscrowCode.Create.Creator)
	nonce := rlpString(minimal(t, v.EscrowCode.Create.Nonce))
	payload := append(rlpString(creator), nonce...)
	sum := evm.Keccak256(rlpListHeader(len(payload)), payload)
	assert.Equal(t, addr(t, v.EscrowCode.Create.Address), [20]byte(sum[12:]))
	assert.Equal(t, escrowMainnet, [20]byte(sum[12:]))

	// The copy's address is keccak256(0xff || deployer || salt || keccak256(init_code))[12:].
	sum = evm.Keccak256([]byte{0xff}, unhex(t, v.EscrowCode.Create2.Deployer), unhex(t, v.EscrowCode.Create2.SaltHex),
		unhex(t, v.EscrowCode.InitCodeHash))
	assert.Equal(t, addr(t, v.EscrowCode.Create2.Address), [20]byte(sum[12:]))
	assert.Equal(t, escrowCreate2, [20]byte(sum[12:]))
}

// Every table maps a chain to one escrow, and the built table is the one
// RegisteredExtractorID names.
func TestTablesHaveUniqueChains(t *testing.T) {
	for id, tbl := range tablesInBuild {
		assert.Equal(t, id, tbl.id)
		seen := map[uint64]bool{}
		for _, r := range tbl.rows {
			assert.False(t, seen[r.ChainID], "chain %d twice in %s", r.ChainID, id)
			seen[r.ChainID] = true
		}
	}
	assert.Equal(t, tablesInBuild[RegisteredExtractorID()].rows, builtTable.rows)
}

func caseByID(t testing.TB, v actionFile, id string) actionCase {
	t.Helper()
	i := slices.IndexFunc(v.Cases, func(c actionCase) bool { return c.ID == id })
	require.GreaterOrEqual(t, i, 0, id)
	return v.Cases[i]
}

// decodeAny decodes a case with the first table of this build that lists it.
func decodeAny(t testing.TB, c actionCase) (TxAction, bool) {
	t.Helper()
	for _, id := range c.ExtractorIDs {
		if tbl, ok := tablesInBuild[id]; ok {
			a, err := tbl.decode(unhex(t, c.CBORHex))
			require.NoError(t, err)
			return a, true
		}
	}
	return TxAction{}, false
}

func TestActionVectors(t *testing.T) {
	v := loadJSON[actionFile](t, "action.json")
	deposits := loadJSON[depositCallFile](t, "deposit_call.json")
	calls := map[string]string{}
	for _, c := range deposits.Cases {
		calls[c.ID] = c.DataHex
	}
	require.Len(t, v.Cases, 8)
	for _, c := range v.Cases {
		t.Run(c.ID, func(t *testing.T) {
			b := unhex(t, c.CBORHex)
			var reg *policy.Extractors
			for _, id := range c.ExtractorIDs {
				tbl, ok := tablesInBuild[id]
				if !ok {
					continue
				}
				a, err := tbl.decode(b)
				require.NoError(t, err, id)
				assert.Equal(t, u64(t, c.Input.ChainID), a.ChainID)
				assert.Equal(t, u64(t, c.Input.Nonce), a.Nonce)
				assert.Equal(t, minimal(t, c.Input.MaxPriorityFee), a.MaxPriorityFee)
				assert.Equal(t, minimal(t, c.Input.MaxFeePerGas), a.MaxFeePerGas)
				assert.Equal(t, u64(t, c.Input.GasLimit), a.GasLimit)
				assert.Equal(t, addr(t, c.Input.To), a.To)
				assert.Equal(t, minimal(t, c.Input.Value), a.Value)
				assert.Equal(t, c.Input.Resource, a.Resource)
				assert.Equal(t, c.TxHex, hex.EncodeToString(a.unsigned))
				assert.Equal(t, a.To, a.Row.Escrow)
				assert.Equal(t, a.ChainID, a.Row.ChainID)
				data, err := DecodeDepositCall(unhex(t, calls[c.Input.DataRef]))
				require.NoError(t, err)
				assert.Equal(t, data, a.Deposit)

				req := RequirementsHash(unhex(t, c.Input.RequirementsHex))
				assert.Equal(t, c.RequirementsHashHex, hex.EncodeToString(req[:]))
				assert.Equal(t, req, a.RequirementsHash)
				sh := a.SigHash()
				assert.Equal(t, c.SighashHex, hex.EncodeToString(sh[:]))

				ah, err := commitment.ActionHash(ActionType, unhex(t, c.ActionSaltHex), b)
				require.NoError(t, err)
				assert.Equal(t, c.ActionHashHex, hex.EncodeToString(ah[:]))

				assert.Equal(t, c.ProfileFields, a.DepositView())

				reg, err = policy.NewExtractors(txExtractor{t: tbl})
				require.NoError(t, err)
				f, ferr := a.Facts()
				gotID, rf, err := reg.Extract(ActionType, b)
				assert.Equal(t, id, gotID)
				if c.Facts == nil {
					require.NotNil(t, c.ExtractorExpectError)
					require.Equal(t, "ErrFactsInvalid", *c.ExtractorExpectError)
					require.NotNil(t, c.ExtractorRule)
					require.ErrorIs(t, ferr, policy.ErrFactsInvalid)
					assert.Equal(t, *c.ExtractorRule, ruleOf(t, ferr))
					require.ErrorIs(t, err, policy.ErrFactsInvalid)
					assert.Equal(t, *c.ExtractorRule, ruleOf(t, err))
					assert.Nil(t, c.FactsCBORHex)
					continue
				}
				require.Nil(t, c.ExtractorExpectError)
				require.Nil(t, c.ExtractorRule)
				require.NoError(t, ferr)
				assert.Equal(t, c.Facts.Kind, f.Kind)
				assert.Equal(t, c.Facts.Asset, f.Asset)
				assert.Equal(t, c.Facts.Amount, hex.EncodeToString(f.Amount))
				assert.Equal(t, c.Facts.Scale, strconv.FormatUint(f.Scale, 10))
				assert.Equal(t, c.Facts.Recipient, f.Recipient)
				wantAmount := new(big.Int).Add(new(big.Int).SetBytes(a.Value), a.FeeBound())
				assert.Equal(t, wantAmount.Bytes(), f.Amount, "amount is the value plus the fee bound")
				fc, err2 := policy.EncodeFacts(&f)
				require.NoError(t, err2)
				require.NotNil(t, c.FactsCBORHex)
				assert.Equal(t, *c.FactsCBORHex, hex.EncodeToString(fc))
				require.NoError(t, err)
				assert.Equal(t, f, rf)
			}

			a, err := DecodeTxAction(b)
			if !slices.Contains(c.ExtractorIDs, RegisteredExtractorID()) {
				require.ErrorIs(t, err, ErrUnknownDomain)
				assert.NotEqual(t, buildName, c.Build)
				return
			}
			require.NoError(t, err)
			enc, err := EncodeTxAction(a.unsigned, a.Resource, a.RequirementsHash)
			require.NoError(t, err)
			assert.Equal(t, b, enc)
		})
	}
}

func TestActionRejectVectors(t *testing.T) {
	v := loadJSON[actionFile](t, "action.json")
	require.Len(t, v.Reject, 66)
	for _, r := range v.Reject {
		t.Run(r.ID, func(t *testing.T) {
			want := sentinels[r.ExpectError]
			require.NotNil(t, want, r.ExpectError)
			require.Equal(t, "ErrFactsInvalid", r.ExtractorExpectError)
			b := unhex(t, r.CBORHex)
			tbl, ok := tablesInBuild[r.ExtractorID]
			if !ok {
				require.NotEqual(t, buildName, r.Build)
				_, err := DecodeTxAction(b)
				require.Error(t, err)
				return
			}
			_, err := tbl.decode(b)
			require.ErrorIs(t, err, want)
			assert.Equal(t, r.Rule, ruleOf(t, err))

			reg, err := policy.NewExtractors(txExtractor{t: tbl})
			require.NoError(t, err)
			id, _, err := reg.Extract(ActionType, b)
			require.ErrorIs(t, err, policy.ErrFactsInvalid)
			require.ErrorIs(t, err, want)
			assert.Equal(t, r.ExtractorID, id)

			if r.ExtractorID == RegisteredExtractorID() {
				_, err := DecodeTxAction(b)
				require.ErrorIs(t, err, want)
				_, err = New().Extract(b)
				require.ErrorIs(t, err, want)
			}
		})
	}
}

func TestSignedVectors(t *testing.T) {
	v := loadJSON[signedFile](t, "signed.json")
	checkHeader(t, v.header)
	actions := loadJSON[actionFile](t, "action.json")
	require.Equal(t, hex.EncodeToString(secp256k1.S256().N.Bytes()), v.NHex)
	require.Len(t, v.Cases, 8)
	for _, c := range v.Cases {
		t.Run(c.ID, func(t *testing.T) {
			a, ok := decodeAny(t, caseByID(t, actions, c.ActionRef))
			if !ok {
				t.Skipf("%s needs another build", c.ActionRef)
			}
			k := v.Keys[c.Key]
			priv := secp256k1.PrivKeyFromBytes(unhex(t, k.PrivateKeyHex))
			assert.Equal(t, addr(t, k.Address), Address(priv.PubKey()))

			sh := a.SigHash()
			require.Equal(t, c.SighashHex, hex.EncodeToString(sh[:]))
			sig, err := Sign(priv, sh)
			require.NoError(t, err)
			assert.Equal(t, c.YParity, strconv.Itoa(int(sig.YParity)))
			assert.Equal(t, c.RHex, hex.EncodeToString(sig.R[:]))
			assert.Equal(t, c.SHex, hex.EncodeToString(sig.S[:]))

			payer, err := RecoverPayer(sh, sig)
			require.NoError(t, err)
			assert.Equal(t, addr(t, c.Payer), payer)

			signed, err := a.Splice(sig, payer)
			require.NoError(t, err)
			assert.Equal(t, c.SignedHex, hex.EncodeToString(signed))
			assert.Equal(t, c.RailRef, RailRef(signed))
			viaSignTx, _, err := a.SignTx(priv)
			require.NoError(t, err)
			assert.Equal(t, signed, viaSignTx)

			got, gotPayer, err := ParseSigned(a, signed)
			require.NoError(t, err)
			assert.Equal(t, sig, got)
			assert.Equal(t, payer, gotPayer)
		})
	}
}

func TestRailRefVectors(t *testing.T) {
	v := loadJSON[signedFile](t, "signed.json")
	require.Len(t, v.RailRef, 8)
	for _, c := range v.RailRef {
		t.Run(c.ID, func(t *testing.T) {
			h, ok := ParseRailRef(c.RailRef)
			if c.Expect == "ok" {
				require.True(t, ok)
				assert.Equal(t, c.RailRef, hex.EncodeToString(h[:]))
				return
			}
			require.Equal(t, "malformed_rail_ref", c.Expect)
			assert.False(t, ok)
		})
	}
}

func TestExactTxVectors(t *testing.T) {
	v := loadJSON[signedFile](t, "signed.json")
	actions := loadJSON[actionFile](t, "action.json")
	require.Len(t, v.ExactTx, 29)
	for _, c := range v.ExactTx {
		t.Run(c.ID, func(t *testing.T) {
			a, ok := decodeAny(t, caseByID(t, actions, c.ActionRef))
			if !ok {
				t.Skipf("%s needs another build", c.ActionRef)
			}
			signed := unhex(t, c.SignedHex)
			require.Equal(t, c.RailRef, RailRef(signed))
			_, payer, err := ParseSigned(a, signed)
			if c.Expect == "pass" {
				require.NoError(t, err)
				assert.Equal(t, addr(t, c.Payer), payer)
				return
			}
			require.Equal(t, "wrong_tx", c.Expect)
			require.ErrorIs(t, err, ErrSignedMismatch)
		})
	}
}
