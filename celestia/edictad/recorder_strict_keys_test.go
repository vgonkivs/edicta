package edictad_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"testing"

	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/celestia/edictad"
	"github.com/vgonkivs/edicta/celestia/node"
	"github.com/vgonkivs/edicta/principalsig"
)

// keyedLanding is a strict-mode blob Submitter on a secp256k1 key that shows
// its public key, as the keyring submitter does.
type keyedLanding struct {
	*landing
	pub *secp256k1.PubKey
}

func (k keyedLanding) Signer(context.Context) ([]byte, error) { return k.pub.Address().Bytes(), nil }
func (k keyedLanding) PublicKey(context.Context) ([]byte, error) {
	return bytes.Clone(k.pub.Bytes()), nil
}

func keyedLandingFor(e *env, sk [32]byte) keyedLanding {
	return keyedLanding{landing: e.sub, pub: &secp256k1.PubKey{Key: (&secp256k1.PrivKey{Key: sk[:]}).PubKey().Bytes()}}
}

// addrLanding is a strict-mode blob Submitter that shows only its address.
type addrLanding struct {
	*landing
	addr []byte
}

func (a addrLanding) Signer(context.Context) ([]byte, error) { return bytes.Clone(a.addr), nil }

type keyedFibreSubmitter struct {
	node.FibreSubmitter
	pub []byte
}

func (k keyedFibreSubmitter) PublicKey(context.Context) ([]byte, error) {
	return bytes.Clone(k.pub), nil
}

// The strict-mode Recorder key is held apart from the mandate's principal just
// like the fast one: under ADR-036 and under EIP-712, whichever encoding of
// the same secp256k1 key the mandate names.
func TestRecorderStrictKeyEqualToThePrincipalIsRefused(t *testing.T) {
	recKey := sha256.Sum256([]byte("strict recorder and principal"))
	other := sha256.Sum256([]byte("another principal"))
	for name, tc := range map[string]struct {
		scheme    principalsig.Scheme
		principal [32]byte
		refused   bool
	}{
		"ADR-036 principal is the Recorder key": {principalsig.CosmosADR036, recKey, true},
		"ADR-036 principal is another key":      {principalsig.CosmosADR036, other, false},
		"EIP-712 principal is the Recorder key": {principalsig.EIP712, recKey, true},
		"EIP-712 principal is another key":      {principalsig.EIP712, other, false},
	} {
		t.Run(name, func(t *testing.T) {
			p := newPolicyEnv(t)
			p.signSecp(tc.scheme, tc.principal)
			p.deps.Submitter = keyedLandingFor(p.env, recKey)

			srv, err := edictad.Start(bg, p.cfg(p.edits()...), p.deps)
			if srv != nil {
				t.Cleanup(func() { _ = srv.Shutdown(bg) })
			}
			if !tc.refused {
				require.NoError(t, err)
				return
			}
			require.ErrorIs(t, err, edictad.ErrConfig, "the Recorder key is the mandate's principal")
			assert.Contains(t, err.Error(), tc.scheme.String()+" principal")
			assert.Zero(t, p.listens)
		})
	}
}

// A strict submitter that shows only its address is compared by address under
// ADR-036, where the address is the hash of the key, and refused outright
// against an EIP-712 principal, which its address cannot rule out.
func TestRecorderStrictSubmitterWithoutPublicKey(t *testing.T) {
	recKey := sha256.Sum256([]byte("strict recorder and principal"))
	recAccount := (&secp256k1.PrivKey{Key: recKey[:]}).PubKey().Address().Bytes()
	other := sha256.Sum256([]byte("another principal"))
	for name, tc := range map[string]struct {
		scheme    principalsig.Scheme
		principal [32]byte
		want      string
	}{
		"ADR-036 principal at its address": {principalsig.CosmosADR036, recKey, "cosmos-adr036 principal"},
		"ADR-036 principal elsewhere":      {principalsig.CosmosADR036, other, ""},
		"EIP-712 principal":                {principalsig.EIP712, other, "does not show its public key"},
	} {
		t.Run(name, func(t *testing.T) {
			p := newPolicyEnv(t)
			p.signSecp(tc.scheme, tc.principal)
			p.deps.Submitter = addrLanding{landing: p.sub, addr: recAccount}

			srv, err := edictad.Start(bg, p.cfg(p.edits()...), p.deps)
			if srv != nil {
				t.Cleanup(func() { _ = srv.Shutdown(bg) })
			}
			if tc.want == "" {
				require.NoError(t, err)
				return
			}
			require.ErrorIs(t, err, edictad.ErrConfig)
			assert.Contains(t, err.Error(), tc.want)
			assert.Zero(t, p.listens)
		})
	}
}

// A strict submitter that shows a key is held to it: the key must be the
// one of its account.
func TestRecorderStrictShownKeyMustBeTheAccountsKey(t *testing.T) {
	p := newPolicyEnv(t)
	p.signSecp(principalsig.CosmosADR036, sha256.Sum256([]byte("another principal")))
	k := keyedLandingFor(p.env, sha256.Sum256([]byte("strict recorder")))
	p.deps.Submitter = struct {
		addrLanding
		keyedPub
	}{addrLanding{landing: p.sub, addr: k.pub.Address().Bytes()}, keyedPub(secp256k1.GenPrivKey().PubKey().Bytes())}

	_, err := edictad.Start(bg, p.cfg(p.edits()...), p.deps)
	require.ErrorIs(t, err, edictad.ErrConfig)
	assert.Contains(t, err.Error(), "not the key of its account")
	assert.Zero(t, p.listens)
}

type keyedPub []byte

func (k keyedPub) PublicKey(context.Context) ([]byte, error) { return bytes.Clone(k), nil }

// A successor version adopted at a restart is checked like the first one in
// strict mode too.
func TestRecorderStrictSuccessorMandateWithTheRecorderKeyIsRefused(t *testing.T) {
	recKey := sha256.Sum256([]byte("strict recorder and principal"))
	p := newPolicyEnv(t)
	p.signSecp(principalsig.CosmosADR036, sha256.Sum256([]byte("another principal")))
	p.deps.Archive = p.real
	p.deps.Submitter = keyedLandingFor(p.env, recKey)
	require.NoError(t, p.start(p.edits()...).Shutdown(bg))
	listens := p.listens

	for _, scheme := range []principalsig.Scheme{principalsig.CosmosADR036, principalsig.EIP712} {
		t.Run(scheme.String(), func(t *testing.T) {
			p.mandate.Version = 2
			p.signSecp(scheme, recKey)
			srv, err := edictad.Start(bg, p.cfg(p.edits()...), p.deps)
			if srv != nil {
				t.Cleanup(func() { _ = srv.Shutdown(bg) })
			}
			require.ErrorIs(t, err, edictad.ErrConfig, "the successor's principal is the Recorder key")
			assert.Equal(t, listens, p.listens, "no listener")
		})
	}
}

// The da = fibre strict Recorder's submitter is checked as well.
func TestRecorderStrictFibreSubmitterKeyEqualToThePrincipalIsRefused(t *testing.T) {
	recKey := sha256.Sum256([]byte("strict fibre recorder and principal"))
	pub := (&secp256k1.PrivKey{Key: recKey[:]}).PubKey()
	for _, scheme := range []principalsig.Scheme{principalsig.CosmosADR036, principalsig.EIP712} {
		t.Run(scheme.String(), func(t *testing.T) {
			e, ff, rf := newFibreRecEnv(t)
			p := mandateFor(t, e)
			p.signSecp(scheme, recKey)
			rf.sub.Addr = pub.Address().Bytes()
			ff.deps.Submitter = keyedFibreSubmitter{FibreSubmitter: rf.sub, pub: pub.Bytes()}

			_, err := edictad.Start(bg, p.cfg(p.edits(fibreRecEdits()...)...), p.deps)
			require.ErrorIs(t, err, edictad.ErrConfig, "the Recorder key is the mandate's principal")
			assert.Contains(t, err.Error(), scheme.String()+" principal")
			assert.Zero(t, p.listens)
			assert.Zero(t, rf.builds.Load(), "the Recorder is never built")
		})
	}
}
