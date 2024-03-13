package util

import (
	"math/big"

	curve "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	"github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark-crypto/signature"
)

type Publickey struct {
	Pk curve.PointAffine
}
type Privatekey struct {
	Sk *big.Int
}

func (pk Publickey) Encrypt(plain curve.PointAffine, r *big.Int, h curve.PointAffine) []curve.PointAffine {
	var rpk curve.PointAffine
	rpk.ScalarMultiplication(&pk.Pk, r)

	var c1 curve.PointAffine
	c1.Add(&rpk, &plain)
	var c2 curve.PointAffine
	c2.ScalarMultiplication(&h, r)

	return []curve.PointAffine{c1, c2}
}

func (sk Privatekey) Decryptacc(acc []curve.PointAffine, g1delta curve.PointAffine) curve.PointAffine {
	var c2sk curve.PointAffine
	c2sk.ScalarMultiplication(&acc[1], sk.Sk)
	var _c2sk curve.PointAffine
	_c2sk.Neg(&c2sk)
	var _complain curve.PointAffine
	_complain.Add(&acc[0], &_c2sk)
	var _g1delta curve.PointAffine
	_g1delta.Neg(&g1delta)
	var result curve.PointAffine
	result.Add(&_complain, &_g1delta)
	return result
}

func Calculate_TK(g curve.PointAffine, tk *big.Int) curve.PointAffine {
	var TK curve.PointAffine
	TK.ScalarMultiplication(&g, tk)
	return TK
}

func Calculate_delta(data []byte, hash hash.Hash) big.Int {
	hashfunc := hash.New()
	hashfunc.Write(data)
	_delta := hashfunc.Sum(nil)
	var delta big.Int
	delta.SetBytes(_delta)
	return delta
}

func SignAcc(sk signature.Signer, msg []byte, hashFunc hash.Hash) []byte {
	hFunc := hashFunc.New()

	signature, _ := sk.Sign(msg, hFunc)
	return signature

}
