package util

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
)

type Account struct {
	A twistededwards.Point
	B twistededwards.Point
}

func CalculateTK(curve twistededwards.Curve, g *twistededwards.CurveParams, tk frontend.Variable) twistededwards.Point {
	G := twistededwards.Point{X: g.Base[0], Y: g.Base[1]}

	TK := curve.ScalarMul(G, tk)
	return TK
}

// acc=(g0*bal+(g1*delta0)+r*pk,r*h),bal=_
func EncryptAcc(curve twistededwards.Curve, plain twistededwards.Point, pk twistededwards.Point, r frontend.Variable, g *twistededwards.CurveParams) Account {
	rpk := curve.ScalarMul(pk, r)
	c1 := curve.Add(plain, rpk)
	H := twistededwards.Point{X: g.Base[0], Y: g.Base[1]}
	c2 := curve.ScalarMul(H, r)
	return Account{c1, c2}
}

func DecryptAcc(curve twistededwards.Curve, cipher Account, sk frontend.Variable, delta twistededwards.Point) twistededwards.Point {
	c2sk := curve.ScalarMul(cipher.B, sk)
	_c2sk := curve.Neg(c2sk)

	_plain := curve.Add(cipher.A, _c2sk)
	_delta := curve.Neg(delta)

	return curve.Add(_plain, _delta)
}

func EncryptTK(curve twistededwards.Curve, TK twistededwards.Point, pk twistededwards.Point, r frontend.Variable, g *twistededwards.CurveParams) []twistededwards.Point {
	rpk := curve.ScalarMul(pk, r)
	c1 := curve.Add(TK, rpk)

	h := twistededwards.Point{X: g.Base[0], Y: g.Base[1]}
	c2 := curve.ScalarMul(h, r)
	return []twistededwards.Point{c1, c2}
}
