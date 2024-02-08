package enroll

import (
	"crypto/rand"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	bn254 "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	ecct "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
)

func Enroll() {
	curve := ecct.BN254
	params, _ := twistededwards.GetCurveParams(curve)
	hashFunc := hash.MIMC_BN254

	var assignment enrollCircuit
	_tacSk, _ := rand.Int(rand.Reader, params.Order)
	assignment.TacSk = _tacSk

	//TK=g2*tk
	var _g2 bn254.PointAffine
	_g2.X.SetBigInt(params.Base[0])
	_g2.Y.SetBigInt(params.Base[1])
	var _tacPk bn254.PointAffine
	_tacPk.ScalarMultiplication(&_g2, _tacSk)
	tacPk := twistededwards.Point{X: _tacPk.X, Y: _tacPk.Y}
	assignment.ExpectedTacPk = tacPk

	//delta0=mimc(tk,seq)
	modulus := ecc.BN254.ScalarField()
	var seq big.Int
	seq.Sub(modulus, big.NewInt(1))
	assignment.Seq = seq
	_data := _tacSk.Bytes()
	data := append(_data, seq.Bytes()...)
	mimc := hashFunc.New()
	mimc.Write(data)
	_delta_0 := mimc.Sum(nil)
	var delta_0 big.Int
	delta_0.SetBytes(_delta_0)

	//acc=(g0*bal+(g1*delta0)+r*pk,r*h),bal=0
	var balance big.Int
	balance.SetString("0", 10)
	assignment.Balance = balance
	var _g1 bn254.PointAffine
	_g1.X.SetBigInt(params.Base[0])
	_g1.Y.SetBigInt(params.Base[1])
	var _plaintext bn254.PointAffine
	_plaintext.ScalarMultiplication(&_g1, &delta_0)
	privatekey, _ := rand.Int(rand.Reader, params.Order)
	var _h bn254.PointAffine
	_h.X.SetBigInt(params.Base[0])
	_h.Y.SetBigInt(params.Base[1])
	var _publickey bn254.PointAffine
	_publickey.ScalarMultiplication(&_h, privatekey)
	publickey := twistededwards.Point{X: _publickey.X, Y: _publickey.Y}
	assignment.PublicKey = publickey
	r, _ := rand.Int(rand.Reader, params.Order)
	assignment.Randomness = r
	var _c1 bn254.PointAffine
	_c1.ScalarMultiplication(&_publickey, r)
	var c1 bn254.PointAffine
	c1.Add(&_c1, &_plaintext)
	var c2 bn254.PointAffine
	c2.ScalarMultiplication(&_h, r)
	acc := accountWit{
		twistededwards.Point{X: c1.X, Y: c1.Y},
		twistededwards.Point{X: c2.X, Y: c2.Y},
	}
	assignment.ExpectedAcc = acc

	var circuit enrollCircuit

	r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)

	pk, vk, err := groth16.Setup(r1cs)

	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	publicWitness, err := witness.Public()
	proof, err := groth16.Prove(r1cs, pk, witness)

	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		// invalid proof
	}
	//2780
	//*
}
