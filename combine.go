package vss

import (
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
// The parameter Q indicates the polynomial finite field order.
//
// Returns the reconstructed secret.
func Combine(Q *big.Int, shares []*Share) (*big.Int, error) {
	secret := big.NewInt(0)

	for i, si := range shares {
		xi, yi := si.X, si.Y
		basis := big.NewInt(1)
		for j, sj := range shares {
			if i == j {
				continue
			}
			xj := sj.X

			// Calculate xj / (xj - xi) mod Q
			num := new(big.Int).Set(xj)
			denom := new(big.Int).Sub(xj, xi)
			denom.Mod(denom, Q)

			// Find the modular inverse of denom
			denomInv := new(big.Int).ModInverse(denom, Q)
			if denomInv == nil {
				return nil, errors.New("no modular inverse found")
			}

			term := new(big.Int).Mul(num, denomInv)
			term.Mod(term, Q)

			basis.Mul(basis, term)
			basis.Mod(basis, Q)
		}

		// Multiply yi by the basis and accumulate it in the secret
		group := new(big.Int).Mul(yi, basis)
		group.Mod(group, Q)

		secret.Add(secret, group)
		secret.Mod(secret, Q)
	}

	return secret, nil
}
