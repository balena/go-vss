package vss

import (
	"crypto/elliptic"
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/test-go/testify/require"
)

func SplitVerifyTest(t *testing.T) {
	curve := elliptic.P256()
	secret := new(big.Int).SetInt64(42)

	shares, commits, err := Split(curve, rand.Reader, secret, 5, 3)
	require.NoError(t, err)

	for _, share := range shares {
		v, err := share.Verify(curve, 3, commits)
		require.NoError(t, err)
		require.True(t, v)
	}
}
