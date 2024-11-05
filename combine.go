package vss

import (
	"crypto/elliptic"
	"errors"
	"math/big"
)

// Combine reconstructs the original secret by performing Lagrange
// interpolation over the provided shares. It requires an exact threshold of
// shares to successfully reconstruct the secret.
//
// This function is not typically called in a Distributed Key Generation (DKG)
// scheme, except at disaster recovery cases, and requires collaboration of a
// threshold of participants.
//
// Parameters:
// - curve: The elliptic curve used for calculations.
// - shares: The shares to combine, with x and y coordinates.
//
// Returns:
// - The reconstructed secret.
func Combine(curve elliptic.Curve, shares []*Share) (*big.Int, error) {
	secret := big.NewInt(0)
	q := curve.Params().N

	for i, si := range shares {
		xi, yi := si.X, si.Y
		basis := big.NewInt(1)
		for j, sj := range shares {
			if i == j {
				continue
			}
			xj := sj.X

			// Calculate xj / (xj - xi) mod q
			num := new(big.Int).Set(xj)
			denom := new(big.Int).Sub(xj, xi)
			denom.Mod(denom, q)

			// Find the modular inverse of denom
			denomInv := new(big.Int).ModInverse(denom, q)
			if denomInv == nil {
				return nil, errors.New("no modular inverse found")
			}

			term := new(big.Int).Mul(num, denomInv)
			term.Mod(term, q)

			basis.Mul(basis, term)
			basis.Mod(basis, q)
		}

		// Multiply yi by the basis and accumulate it in the secret
		group := new(big.Int).Mul(yi, basis)
		group.Mod(group, q)

		secret.Add(secret, group)
		secret.Mod(secret, q)
	}

	return secret, nil
}
