package offlinetx

import (
	"crypto/rand"
	"fmt"
	"math/big"

	bn254 "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	ecct "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
)

type elPublickey struct {
	pk bn254.PointAffine
}
type elPrivatekey struct {
	sk *big.Int
}
type accountCipher struct {
	A bn254.PointAffine
	B bn254.PointAffine
}

func (pk elPublickey) Encrypt(params *twistededwards.CurveParams, acc bn254.PointAffine, r *big.Int) accountCipher {
	var _h bn254.PointAffine
	_h.X.SetBigInt(params.Base[0])
	_h.Y.SetBigInt(params.Base[1])
	var _c1 bn254.PointAffine
	_c1.ScalarMultiplication(&pk.pk, r)
	var c1 bn254.PointAffine
	c1.Add(&_c1, &acc)
	var c2 bn254.PointAffine
	c2.ScalarMultiplication(&_h, r)
	result := accountCipher{
		c1,
		c2,
	}
	return result
}

func (sk elPrivatekey) Decrypt(acc accountCipher, g1delta bn254.PointAffine) bn254.PointAffine {
	var c2sk bn254.PointAffine
	c2sk.ScalarMultiplication(&acc.B, sk.sk)
	var _c2sk bn254.PointAffine
	_c2sk.Neg(&c2sk)
	var _complain bn254.PointAffine
	_complain.Add(&acc.A, &_c2sk)
	var _g1delta bn254.PointAffine
	_g1delta.Neg(&g1delta)
	var result bn254.PointAffine
	result.Add(&_complain, &_g1delta)
	return result
}

func Enc_dec() {
	params, _ := twistededwards.GetCurveParams(ecct.BN254)
	hashFunc := hash.MIMC_BN254

	_tacSk, _ := rand.Int(rand.Reader, params.Order)
	var balance big.Int
	balance.SetString("200", 10)
	_data := _tacSk.Bytes()
	data := append(_data, balance.Bytes()...)
	mimc := hashFunc.New()
	mimc.Write(data)
	_delta_0 := mimc.Sum(nil)
	var delta_0 big.Int
	delta_0.SetBytes(_delta_0)

	//acc=(g0*bal+(g1*delta0)+r*pk,r*h),bal=0
	var _g1 bn254.PointAffine
	_g1.X.SetBigInt(params.Base[0])
	_g1.Y.SetBigInt(params.Base[1])
	var _g0 bn254.PointAffine
	_g0.X.SetBigInt(params.Base[0])
	_g0.Y.SetBigInt(params.Base[1])

	var _g1delta bn254.PointAffine
	_g1delta.ScalarMultiplication(&_g1, &delta_0)
	var _g0bal bn254.PointAffine
	_g0bal.ScalarMultiplication(&_g0, &balance)
	var plaintext bn254.PointAffine
	plaintext.Add(&_g1delta, &_g0bal)

	_privatekey, _ := rand.Int(rand.Reader, params.Order)
	var _h bn254.PointAffine
	_h.X.SetBigInt(params.Base[0])
	_h.Y.SetBigInt(params.Base[1])
	var _publickey bn254.PointAffine
	_publickey.ScalarMultiplication(&_h, _privatekey)

	privatekey := elPrivatekey{_privatekey}
	publickey := elPublickey{_publickey}
	r, _ := rand.Int(rand.Reader, params.Order)
	acccipher := publickey.Encrypt(params, plaintext, r)

	g0bal := privatekey.Decrypt(acccipher, _g1delta)

	fmt.Println(g0bal.Equal(&_g0bal))
}
