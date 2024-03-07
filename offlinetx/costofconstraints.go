package offlinetx

import (
	"Asyn_CBDC/util"
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	bn254 "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	ecct "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark-crypto/signature/eddsa"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
)

func OfflineTx() {
	//=========================enroll ==============================
	params, _ := twistededwards.GetCurveParams(ecct.BN254)
	hashFunc := hash.MIMC_BN254

	//TK=g2*tk
	_tacSk, _ := rand.Int(rand.Reader, params.Order)
	var _g2 bn254.PointAffine
	_g2.X.SetBigInt(params.Base[0])
	_g2.Y.SetBigInt(params.Base[1])
	var _tacPk bn254.PointAffine
	_tacPk.ScalarMultiplication(&_g2, _tacSk)

	//delta_seq=mimc(tk,seq)
	modulus := ecc.BN254.ScalarField()
	var seq3 big.Int
	seq3.Sub(modulus, big.NewInt(3))
	_data3 := _tacSk.Bytes()
	data3 := append(_data3, seq3.Bytes()...)
	mimc3 := hashFunc.New()
	mimc3.Write(data3)
	_delta_3 := mimc3.Sum(nil)
	var delta_3 big.Int
	delta_3.SetBytes(_delta_3)

	//acc=(g0*bal+(g1*delta0)+r*pk,r*h)
	var balance big.Int
	balance.SetString("200", 10)

	var _g1 bn254.PointAffine
	_g1.X.SetBigInt(params.Base[0])
	_g1.Y.SetBigInt(params.Base[1])
	var _g0 bn254.PointAffine
	_g0.X.SetBigInt(params.Base[0])
	_g0.Y.SetBigInt(params.Base[1])

	var _g1delta3 bn254.PointAffine
	_g1delta3.ScalarMultiplication(&_g1, &delta_3)
	var _g0bal bn254.PointAffine
	_g0bal.ScalarMultiplication(&_g0, &balance)
	var plaintext bn254.PointAffine
	plaintext.Add(&_g1delta3, &_g0bal)

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

	g0bal := privatekey.Decrypt(acccipher, _g1delta3)

	fmt.Println("test encrypt and decrypt:", g0bal.Equal(&_g0bal))
	//=========================sign acc=============================
	_c1x := acccipher.A.X
	//_c2x := acccipher.B.X
	c1x := _c1x.Bytes()
	//c2x := _c2x.Bytes()
	var _msg []byte
	_msg = append(_msg, c1x[:]...)
	//var msg []byte
	//msg = append(msg, c2x[:]...)

	hFunc := hash.MIMC_BN254.New()

	sigprivateKey, _ := eddsa.New(ecct.BN254, rand.Reader)
	sigpublicKey := sigprivateKey.Public()

	signature, _ := sigprivateKey.Sign(_msg, hFunc)

	isValid, _ := sigpublicKey.Verify(signature, _msg, hFunc)
	if !isValid {
		fmt.Println("1. invalid signature")
	} else {
		fmt.Println("1. valid signature")
	}
	//==============================================================

	//======================== DAcc=================================
	//delta_seq+1=mimc(tk,seq+1)
	var seq4 big.Int
	seq4.Sub(modulus, big.NewInt(4))
	_data4 := _tacSk.Bytes()
	data4 := append(_data4, seq4.Bytes()...)
	mimc4 := hashFunc.New()
	mimc4.Write(data4)
	_delta_4 := mimc4.Sum(nil)
	var delta_4 big.Int
	delta_4.SetBytes(_delta_4)

	//dplaintext
	var _g1delta4 bn254.PointAffine
	_g1delta4.ScalarMultiplication(&_g1, &delta_4)
	var dplaintext bn254.PointAffine
	dplaintext.Add(&_g1delta4, &g0bal)

	//Dpk=alpha*pk (Dsk=alpha*sk)
	alpha, _ := rand.Int(rand.Reader, params.Order)
	var _dprivatekey big.Int
	_dprivatekey.Mul(alpha, _privatekey)
	dprivatekey := elPrivatekey{&_dprivatekey}
	var _dpublickey bn254.PointAffine
	_dpublickey.ScalarMultiplication(&_publickey, alpha)
	dpublickey := elPublickey{_dpublickey}

	dr, _ := rand.Int(rand.Reader, params.Order)
	dacccipher := dpublickey.Encrypt(params, dplaintext, dr)
	dg0bal := dprivatekey.Decrypt(dacccipher, _g1delta4)
	fmt.Println("test encrypt and decrypt:(DAcc)", dg0bal.Equal(&g0bal))
	//===================================================================

	//=========================== C_TK===================================
	_aprivatekey, _ := rand.Int(rand.Reader, params.Order)
	var _ah bn254.PointAffine
	_ah.X.SetBigInt(params.Base[0])
	_ah.Y.SetBigInt(params.Base[1])
	var _apublickey bn254.PointAffine
	_apublickey.ScalarMultiplication(&_ah, _aprivatekey)

	apublickey := elPublickey{_apublickey}
	ar, _ := rand.Int(rand.Reader, params.Order)
	cipherTK := apublickey.Encrypt(params, _tacPk, ar)

	var circuit offlineCircuit
	r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)

	// generating pk, vk
	pk, vk, err := groth16.Setup(r1cs)

	// declare the witness
	var assignment offlineCircuit

	// assign message value
	acc_c1 := acccipher.A
	acc_c2 := acccipher.B
	acc := util.Account{
		A: twistededwards.Point{X: acc_c1.X, Y: acc_c1.Y},
		B: twistededwards.Point{X: acc_c2.X, Y: acc_c2.Y},
	}
	assignment.Acc = acc
	assignment.TacSk = _tacSk
	assignment.Seq = seq3
	assignment.Seq1 = seq4
	assignment.ExpectedDelta = delta_3

	dacc_c1 := dacccipher.A
	dacc_c2 := dacccipher.B
	dacc := util.Account{
		A: twistededwards.Point{X: dacc_c1.X, Y: dacc_c1.Y},
		B: twistededwards.Point{X: dacc_c2.X, Y: dacc_c2.Y},
	}
	assignment.ExpectedDAcc = dacc
	_expectpk := twistededwards.Point{X: dpublickey.pk.X, Y: dpublickey.pk.Y}
	assignment.ExpectedDPublicKey = _expectpk
	assignment.PrivateKey = _privatekey
	assignment.PublicKey = twistededwards.Point{X: publickey.pk.X, Y: publickey.pk.Y}
	assignment.Alpha = alpha
	assignment.Randomness = dr
	var ctacpk [2]twistededwards.Point
	ctacpk[0] = twistededwards.Point{X: cipherTK.A.X, Y: cipherTK.A.Y}
	ctacpk[1] = twistededwards.Point{X: cipherTK.B.X, Y: cipherTK.B.Y}
	assignment.ExpectedCTacPk = ctacpk
	assignment.PublicKeyA = twistededwards.Point{X: apublickey.pk.X, Y: apublickey.pk.Y}
	assignment.RandomnessA = ar

	// public key bytes
	_sigpublicKey := sigpublicKey.Bytes()

	// assign public key values
	assignment.SigPublicKey.Assign(ecct.BN254, _sigpublicKey[:32])

	// assign signature values
	assignment.Signature.Assign(ecct.BN254, signature)

	// witness
	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	publicWitness, err := witness.Public()
	// generate the proof
	proof, err := groth16.Prove(r1cs, pk, witness)

	// verify the proof
	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		// invalid proof
	}
}
