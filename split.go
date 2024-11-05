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

type ECPoint struct {
	X, Y *big.Int
}

// nonZeroInt returns an integer in the range [1, N).
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

// randomPolynomial constructs a polynomial f(x) of degree threshold−1 where
// the constant term is the secret.
func randomPolynomial(
	rand io.Reader,
	N *big.Int,
	secret *big.Int,
	threshold int,
) (ais []*big.Int, err error) {
	ais = make([]*big.Int, threshold)
	ais[0] = secret
	for i := 1; i < threshold; i++ {
		ais[i], err = nonZeroInt(rand, N)
		if err != nil {
			break
		}
	}
	return
}

// commit the polynomial coefficients on the elliptic curve.
func commit(curve elliptic.Curve, poly []*big.Int) []*ECPoint {
	commits := make([]*ECPoint, len(poly))
	for i, ai := range poly {
		var point ECPoint
		point.X, point.Y = curve.ScalarBaseMult(ai.Bytes())
		commits[i] = &point
	}
	return commits
}

// evaluatePolynomial evaluates a polynomial for x given its coefficients. The
// N parameter is the finite field order.
func evaluatePolynomial(
	N *big.Int,
	poly []*big.Int,
	x *big.Int,
) (y *big.Int) {
	Xi := big.NewInt(int64(1))
	y = new(big.Int).Set(poly[0])

	for _, ai := range poly[1:] {
		Xi.Mul(Xi, x)
		Xi.Mod(Xi, N)

		aiXi := new(big.Int).Mul(ai, Xi)
		aiXi.Mod(aiXi, N)

		y.Add(y, aiXi)
		y.Mod(y, N)
	}

	return
}

// Split a secret into multiple parts given a threshold, returning also the
// commitments on an elliptic curve that can be independently used by
// participants to ensure their shares are sound.
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

	poly, err := randomPolynomial(rand, curve.Params().N, secret, threshold)
	if err != nil {
		return nil, nil, err
	}

	commits := commit(curve, poly)

	shares := make([]*Share, parts)
	for i := range parts {
		// Sort out unique x-coordinates for each participant
		var x *big.Int
	TryAgain:
		for {
			var err error
			x, err = nonZeroInt(rand, curve.Params().N)
			if err != nil {
				return nil, nil, err
			}
			for j := 0; j < i; j++ {
				if shares[j].X.Cmp(x) == 0 {
					continue TryAgain
				}
			}
			break
		}
		y := evaluatePolynomial(curve.Params().N, poly, x)
		shares[i] = &Share{X: x, Y: y}
	}

	return shares, commits, nil
}
