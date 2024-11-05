package vss

import (
	"crypto/elliptic"
	"errors"
	"math/big"
)

type Share struct {
	X, Y *big.Int
}

func (share *Share) Verify(curve elliptic.Curve, threshold int, commits []*ECPoint) (bool, error) {
	if commits == nil {
		return false, errors.New("commits cannot be nil")
	}
	if len(commits) != threshold+1 {
		return false, errors.New("commits length does not correspond to threshold+1")
	}
	if !curve.IsOnCurve(share.X, share.Y) {
		return false, errors.New("share is not on the curve")
	}

	acc := commits[0]
	tk := big.NewInt(1)

	for k := 1; k < threshold; k++ {
		tk.Mul(tk, share.X) // t^k
		tk.Mod(tk, curve.Params().N)

		cktkX, cktkY := curve.ScalarMult(commits[k].X, commits[k].Y, tk.Bytes()) // C_k * t^k
		acc.X, acc.Y = curve.Add(acc.X, acc.Y, cktkX, cktkY)                     // sum(C_k * t^k)
	}

	fiGx, fiGy := curve.ScalarBaseMult(share.Y.Bytes())
	return fiGx.Cmp(acc.X) == 0 && fiGy.Cmp(acc.Y) == 0, nil
}
