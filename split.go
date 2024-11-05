package vss

import (
	"crypto/elliptic"
	cryptorand "crypto/rand"
	"errors"
	"fmt"
	"io"
	"math/big"
)

const (
	MaxParts     = 255
	MaxThreshold = 255
)

// ECPoint represents a point on an elliptic curve, with X and Y coordinates.
type ECPoint struct {
	X, Y *big.Int
}

// nonZeroInt generates a non-zero integer in the range [1, N) using the
// provided random source. It ensures that the integer is non-zero by retrying
// until a valid integer is found.
func nonZeroInt(rand io.Reader, N *big.Int) (i *big.Int, err error) {
	for {
		i, err = cryptorand.Int(rand, N)
		if err != nil {
			return nil, fmt.Errorf("error reading rand: %w", err)
		}
		// Discard coefficients == 0
		if i.Sign() == 0 {
			continue
		}
		break
	}
	return
}

// randomPolynomial constructs a polynomial of the specified degree with
// non-zero coefficients chosen at random in the finite field defined by N. The
// constant term of the polynomial is set to the secret.
func randomPolynomial(
	rand io.Reader,
	N *big.Int,
	secret *big.Int,
	degree int,
) (ais []*big.Int, err error) {
	ais = make([]*big.Int, degree+1)
	ais[0] = secret
	for i := 1; i <= degree; i++ {
		ais[i], err = nonZeroInt(rand, N)
		if err != nil {
			break
		}
	}
	return
}

// commit generates commitments for each coefficient of the polynomial on an
// elliptic curve. Each coefficient is multiplied by the curve's base point,
// and the resulting points serve as commitments for verifying shares.
func commit(curve elliptic.Curve, poly []*big.Int) []*ECPoint {
	commits := make([]*ECPoint, len(poly))
	for i, ai := range poly {
		var point ECPoint
		point.X, point.Y = curve.ScalarBaseMult(ai.Bytes())
		commits[i] = &point
	}
	return commits
}

// evaluatePolynomial calculates the value of the polynomial at a specific
// x-coordinate. The polynomial is defined by its coefficients, and the
// calculation is done modulo N.
func evaluatePolynomial(
	N *big.Int,
	poly []*big.Int,
	x *big.Int,
) (y *big.Int) {
	// Compute the polynomial value using Horner's method.
	y = new(big.Int).Set(poly[len(poly)-1])
	for i := len(poly) - 2; i >= 0; i-- {
		y.Mul(y, x)
		y.Mod(y, N)
		y.Add(y, poly[i])
		y.Mod(y, N)
	}
	return
}

// uniqueCoords generates unique x-coordinates for each participant, ensuring
// no two coordinates are identical.
func uniqueCoords(
	curve elliptic.Curve,
	rand io.Reader,
	n int,
) (result []*big.Int, err error) {
	result = make([]*big.Int, n)

	for i := range n {
		// Sort out unique x-coordinates for each participant
		var x *big.Int
	TryAgain:
		for {
			x, err = nonZeroInt(rand, curve.Params().N)
			if err != nil {
				return
			}
			for j := 0; j < i; j++ {
				if result[j].Cmp(x) == 0 {
					continue TryAgain
				}
			}
			break
		}
		result[i] = x
	}

	return
}

// Split divides a secret into multiple shares with a specified threshold and
// generates elliptic curve commitments for verification. Each share can be
// verified independently to ensure integrity.
//
// This function is typically executed from the dealer.
//
// Parameters:
// - curve: The elliptic curve to use for commitments and calculations.
// - rand: A random number generator.
// - secret: The secret to split.
// - parts: The total number of shares to generate.
// - threshold: The minimum number of shares required to reconstruct the secret.
//
// Returns:
// - A list of shares, each with an x and y coordinate.
// - A list of commitments for verifying shares.
// - Any error encountered during share generation.
func Split(
	curve elliptic.Curve,
	rand io.Reader,
	secret *big.Int,
	parts, threshold int,
) ([]*Share, []*ECPoint, error) {
	if threshold < 1 {
		return nil, nil, errors.New("threshold < 1")
	}
	if parts < threshold {
		return nil, nil, errors.New("parts cannot be less than threshold")
	}
	if parts > MaxParts {
		return nil, nil, fmt.Errorf("parts cannot exceed %d", MaxParts)
	}
	if threshold > MaxThreshold {
		return nil, nil, fmt.Errorf("threshold cannot exceed %d", MaxThreshold)
	}
	if secret == nil {
		return nil, nil, errors.New("secret cannot be nil")
	}

	poly, err := randomPolynomial(rand, curve.Params().N, secret, threshold-1)
	if err != nil {
		return nil, nil, err
	}

	xs, err := uniqueCoords(curve, rand, parts)
	if err != nil {
		return nil, nil, err
	}

	shares := make([]*Share, parts)
	for i, x := range xs {
		shares[i] = &Share{
			X: x,
			Y: evaluatePolynomial(curve.Params().N, poly, x),
		}
	}

	return shares, commit(curve, poly), nil
}
