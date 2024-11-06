package vss

import (
	"crypto/elliptic"
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/test-go/testify/assert"
	"github.com/test-go/testify/require"
)

func TestSplitVerifyCombine(t *testing.T) {
	// Define elliptic curve, Q and secret to split
	curve := elliptic.P256()
	Q := curve.Params().N
	secret := new(big.Int).SetInt64(42)

	// Split the secret into 5 parts, with a threshold of 3 needed for reconstruction
	shares, commits, err := Split(curve, rand.Reader, Q, secret, 5, 3)
	require.NoError(t, err)

	// Combine the first 3 shares and check if they reconstruct the original secret
	combined, err := Combine(Q, shares[:3])
	require.NoError(t, err)
	assert.True(t, combined.Cmp(secret) == 0)

	// Verify each share against the generated commitments
	for _, share := range shares {
		v, err := share.Verify(curve, 3, commits)
		require.NoError(t, err)
		assert.True(t, v)
	}
}

func TestSplitWithBlindingVerifyCombine(t *testing.T) {
	// Define elliptic curve, Q and secret to split
	curve := elliptic.P256()
	Q := curve.Params().N
	secret := new(big.Int).SetInt64(42)

	// Split the secret into 5 parts, with a threshold of 3 needed for
	// reconstruction, using Pedersen
	shares, commits, err := Split(curve, rand.Reader, Q, secret, 5, 3, WithBlinding())
	require.NoError(t, err)

	// Combine the first 3 shares and check if they reconstruct the original secret
	combined, err := Combine(Q, shares[:3])
	require.NoError(t, err)
	assert.True(t, combined.Cmp(secret) == 0)

	// Verify each share against the generated commitments, using Pedersen
	for _, share := range shares {
		v, err := share.Verify(curve, 3, commits, WithBlinding())
		require.NoError(t, err)
		assert.True(t, v)
	}
}
