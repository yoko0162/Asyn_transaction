package enroll

import (
	"Asyn_CBDC/util"
	"crypto/rand"
	"math/big"

	curve "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	"github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
)

type Enroll struct {
	G0      curve.PointAffine
	G2      curve.PointAffine
	Tracesk util.Privatekey
	Tracepk util.Publickey
	Seq     big.Int
	Delta   big.Int
	G1      curve.PointAffine
	H       curve.PointAffine
	Bal     big.Int
	Sk      util.Privatekey
	Pk      util.Publickey
	R       *big.Int
	Acc     []curve.PointAffine
}

func (enroll Enroll) Init(params *twistededwards.CurveParams, hash hash.Hash) Enroll {
	enroll.G0.X.SetBigInt(params.Base[0])
	enroll.G0.Y.SetBigInt(params.Base[1])

	tk, _ := rand.Int(rand.Reader, params.Order)
	enroll.G2.X.SetBigInt(params.Base[0])
	enroll.G2.Y.SetBigInt(params.Base[1])
	_TK := util.Calculate_TK(enroll.G2, tk)

	enroll.Tracesk = util.Privatekey{Sk: tk}
	enroll.Tracepk = util.Publickey{Pk: _TK}

	modulus := params.Order
	var seq big.Int
	seq.Sub(modulus, big.NewInt(1))
	_data := tk.Bytes()
	data := append(_data, seq.Bytes()...)
	delta := util.Calculate_delta(data, hash)
	enroll.Delta = delta

	enroll.Seq = seq

	var balance big.Int
	balance.SetString("0", 10)
	enroll.Bal = balance

	enroll.G1.X.SetBigInt(params.Base[0])
	enroll.G1.Y.SetBigInt(params.Base[1])

	_sk, _ := rand.Int(rand.Reader, params.Order)
	enroll.Sk = util.Privatekey{Sk: _sk}
	enroll.H.X.SetBigInt(params.Base[0])
	enroll.H.Y.SetBigInt(params.Base[1])
	var _pk curve.PointAffine
	_pk.ScalarMultiplication(&enroll.H, _sk)
	enroll.Pk = util.Publickey{Pk: _pk}
	r, _ := rand.Int(rand.Reader, params.Order)
	enroll.R = r

	var plain curve.PointAffine
	plain.ScalarMultiplication(&enroll.G1, &delta)

	pk := util.Publickey{Pk: _pk}

	acc := pk.Encrypt(plain, r, enroll.H)
	enroll.Acc = acc

	return enroll
}
