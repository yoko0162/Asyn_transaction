package util

import (
	"crypto/rand"
	"math/big"

	curve "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	"github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
)

type Enroll struct {
	G2      curve.PointAffine
	Tracesk *big.Int
	Tracepk twistededwards.Point
	Seq     big.Int
	G1      curve.PointAffine
	H       curve.PointAffine
	Bal     big.Int
	Sk      *big.Int
	Pk      twistededwards.Point
	R       *big.Int
	Acc     Account
}

func (enroll Enroll) Init(params *twistededwards.CurveParams, hash hash.Hash) Enroll {
	tk, _ := rand.Int(rand.Reader, params.Order)
	enroll.G2.X.SetBigInt(params.Base[0])
	enroll.G2.Y.SetBigInt(params.Base[1])
	_TK := calculateTK(enroll.G2, tk)

	enroll.Tracesk = tk
	enroll.Tracepk = twistededwards.Point{X: _TK.X, Y: _TK.Y}

	modulus := params.Order
	var seq big.Int
	seq.Sub(modulus, big.NewInt(1))
	_data := tk.Bytes()
	data := append(_data, seq.Bytes()...)
	delta := calculatedelta(data, hash)

	enroll.Seq = seq

	var balance big.Int
	balance.SetString("0", 10)
	enroll.Bal = balance

	enroll.G1.X.SetBigInt(params.Base[0])
	enroll.G1.Y.SetBigInt(params.Base[1])

	sk, _ := rand.Int(rand.Reader, params.Order)
	enroll.Sk = sk
	enroll.H.X.SetBigInt(params.Base[0])
	enroll.H.Y.SetBigInt(params.Base[1])
	var pk curve.PointAffine
	pk.ScalarMultiplication(&enroll.H, sk)
	enroll.Pk = twistededwards.Point{X: pk.X, Y: pk.Y}
	r, _ := rand.Int(rand.Reader, params.Order)
	enroll.R = r

	var plain curve.PointAffine
	plain.ScalarMultiplication(&enroll.G1, &delta)

	acc := encryptacc(plain, pk, r, enroll.H)
	enroll.Acc = Account{
		A: twistededwards.Point{X: acc[0].X, Y: acc[0].Y},
		B: twistededwards.Point{X: acc[1].X, Y: acc[1].Y},
	}

	return enroll
}

func calculateTK(g curve.PointAffine, tk *big.Int) curve.PointAffine {
	var TK curve.PointAffine
	TK.ScalarMultiplication(&g, tk)
	return TK
}

func encryptacc(plain curve.PointAffine, pk curve.PointAffine, r *big.Int, h curve.PointAffine) []curve.PointAffine {
	var rpk curve.PointAffine
	rpk.ScalarMultiplication(&pk, r)

	var c1 curve.PointAffine
	c1.Add(&rpk, &plain)
	var c2 curve.PointAffine
	c2.ScalarMultiplication(&h, r)

	return []curve.PointAffine{c1, c2}
}

func calculatedelta(data []byte, hash hash.Hash) big.Int {
	hashfunc := hash.New()
	hashfunc.Write(data)
	_delta := hashfunc.Sum(nil)
	var delta big.Int
	delta.SetBytes(_delta)
	return delta
}
