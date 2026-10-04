package sdk_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/sdk"
	"github.com/vgonkivs/edicta/sdk/blob"
	"github.com/vgonkivs/edicta/test/sdkfix"
)

// FuzzOpenPayload: arbitrary envelopes and blobs against a fixed key never
// panic and never succeed unless the blob is exactly the one the envelope
// commits to (the success path is covered by the vectors).
func FuzzOpenPayload(f *testing.F) {
	v := sdkfix.Load(f)
	c := v.Case0(f)
	key := v.Key(f, "gate-paper-1").OpenKey(true)
	f.Add(c.Envelope, c.Blob)
	f.Add(c.Envelope, []byte{})
	f.Add([]byte{}, c.Blob)
	f.Add(c.Blob, c.Envelope)
	for _, r := range v.Rejects {
		f.Add(c.Envelope, r.Blob)
	}
	f.Fuzz(func(t *testing.T, env, raw []byte) {
		o, err := sdk.OpenPayload(env, raw, key)
		if err != nil {
			require.Nil(t, o)
			return
		}
		s, derr := commitment.DecodeSigned(env)
		require.NoError(t, derr)
		require.NoError(t, commitment.CheckPayload(&s.Commitment, raw), "opened a blob the envelope does not commit to")
		_, berr := blob.Decode(raw)
		require.NoError(t, berr)
		require.NotNil(t, o.Payload)
	})
}

// FuzzChooseValidity: whatever the window, a decision never exceeds what was
// asked for, never reaches past the retention bound and always leaves the
// minimum validity.
func FuzzChooseValidity(f *testing.F) {
	f.Add(uint64(1_000_000), uint64(999_900), uint64(0), uint8(2), uint64(14400), uint64(14400), uint64(14400), uint64(30), uint64(900), uint64(60), uint64(0), false)
	f.Add(uint64(1_000_000), uint64(988_000), uint64(0), uint8(2), uint64(14400), uint64(14400), uint64(14400), uint64(30), uint64(3600), uint64(60), uint64(0), false)
	f.Add(uint64(1_000_000), uint64(999_990), uint64(999_800), uint8(1), uint64(14400), uint64(600), uint64(14400), uint64(30), uint64(900), uint64(60), uint64(0), false)
	f.Add(uint64(1_000_000), uint64(999_900), uint64(0), uint8(2), uint64(14400), uint64(14400), uint64(14400), uint64(30), uint64(900), uint64(60), uint64(1_000_600), true)
	f.Add(^uint64(0)-5, ^uint64(0)-10, uint64(0), uint8(2), ^uint64(0), ^uint64(0), ^uint64(0), uint64(30), ^uint64(0), uint64(60), ^uint64(0), true)
	f.Add(uint64(0), uint64(0), uint64(0), uint8(2), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), false)
	f.Fuzz(func(t *testing.T, nowS, blockTime, retStart uint64, da uint8, latest, atHeight, blobRet, skew, ttl, minV, deadline uint64, hasDeadline bool) {
		// Keep every sum below 2^64 so the properties themselves cannot overflow;
		// the saturating arithmetic has its own test.
		const m = 1<<62 - 1
		nowS, blockTime, retStart, latest, atHeight, blobRet, ttl, minV, deadline = nowS&m, blockTime&m, retStart&m,
			latest&m, atHeight&m, blobRet&m, ttl&m, minV&m, deadline&m
		skew &= 0xffff
		w := sdk.Window{
			Now: nowS, BlockTime: blockTime, RetentionStart: retStart, DA: commitment.DA(1 + da%2),
			FibreLatestS: latest, FibreAtHeightS: atHeight, BlobRetentionS: blobRet, SkewS: skew, TTLS: ttl, MinValidityS: minV,
		}
		if hasDeadline {
			w.Deadline = &deadline
		}
		var v sdk.Validity
		var err error
		require.NotPanics(t, func() { v, err = sdk.ChooseValidity(w) })
		if err != nil {
			require.Zero(t, v, "no partial result on error")
			return
		}
		require.LessOrEqual(t, v.ValidUntil, v.RequestedUntil, "valid_until is never above what was requested")
		require.Greater(t, v.ValidUntil, v.IssuedAt)
		require.Equal(t, max(w.Now, w.BlockTime), v.IssuedAt)
		require.GreaterOrEqual(t, v.Expiry, w.Now+w.MinValidityS)
		p := commitment.Params{FibreRetentionS: w.FibreLatestS, BlobRetentionS: w.BlobRetentionS, SkewS: w.SkewS}
		require.LessOrEqual(t, v.ValidUntil-v.IssuedAt, p.MaxTTL(w.DA), "within the maximum ttl")
		c := &commitment.Commitment{ValidUntil: v.ValidUntil}
		r, start := w.BlobRetentionS, w.BlockTime
		if w.DA == commitment.DAFibre {
			r, start = min(w.FibreLatestS, w.FibreAtHeightS), min(w.BlockTime, w.RetentionStart)
		}
		require.Truef(t, commitment.WithinRetention(c, start, r), "valid_until %d outside the retention window", v.ValidUntil)
	})
}

// Sums saturate: nothing near the top of the range panics, wraps or yields a
// decision that violates the properties.
func TestChooseValidityNearOverflow(t *testing.T) {
	const top = ^uint64(0)
	for _, w := range []sdk.Window{
		{Now: top - 5, BlockTime: top - 10, DA: commitment.DACelestiaBlob, BlobRetentionS: top, SkewS: 30, TTLS: top, MinValidityS: 60},
		{Now: top, BlockTime: top, DA: commitment.DACelestiaBlob, BlobRetentionS: top, SkewS: 300, TTLS: top, MinValidityS: top},
		{Now: 1, BlockTime: 1, DA: commitment.DAFibre, RetentionStart: 1, FibreLatestS: top, FibreAtHeightS: top, BlobRetentionS: 14400, SkewS: 0, TTLS: top, MinValidityS: 0},
		{Now: 1000, BlockTime: 900, DA: commitment.DACelestiaBlob, BlobRetentionS: 14400, SkewS: 30, TTLS: 900, MinValidityS: top},
		{Now: 1000, BlockTime: 900, DA: commitment.DACelestiaBlob, BlobRetentionS: 14400, SkewS: top, TTLS: 900, MinValidityS: 60},
		{Now: 1000, BlockTime: top, DA: commitment.DACelestiaBlob, BlobRetentionS: 14400, SkewS: top, TTLS: 900, MinValidityS: 60},
	} {
		var v sdk.Validity
		var err error
		require.NotPanics(t, func() { v, err = sdk.ChooseValidity(w) })
		if err == nil {
			require.LessOrEqual(t, v.ValidUntil, v.RequestedUntil)
			require.Greater(t, v.ValidUntil, v.IssuedAt)
		}
	}
}
