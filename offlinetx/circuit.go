package offlinetx

import (
	ecct "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
	"github.com/consensys/gnark/std/hash/mimc"
	cir_eddsa "github.com/consensys/gnark/std/signature/eddsa"
)

type accountWit struct {
	A twistededwards.Point
	B twistededwards.Point
}

type offlineCircuit struct {
	SigPublicKey       cir_eddsa.PublicKey `gnark:",public"`
	Signature          cir_eddsa.Signature
	Acc                accountWit
	TacSk              frontend.Variable
	Seq                frontend.Variable
	Seq1               frontend.Variable
	ExpectedDelta      frontend.Variable    `gnark:",public"`
	ExpectedDAcc       accountWit           `gnark:",public"`
	ExpectedDPublicKey twistededwards.Point `gnark:",public"`
	PrivateKey         frontend.Variable
	PublicKey          twistededwards.Point
	Alpha              frontend.Variable
	Randomness         frontend.Variable
	ExpectedCTacPk     [2]twistededwards.Point `gnark:",public"`
	PublicKeyA         twistededwards.Point    `gnark:",public"`
	RandomnessA        frontend.Variable
}

func (circuit *offlineCircuit) Define(api frontend.API) error {
	curve, err := twistededwards.NewEdCurve(api, ecct.BN254)
	if err != nil {
		return err
	}

	hashf, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}

	msg := circuit.Acc.A.X

	// verify the signature in the cs
	result_sig := cir_eddsa.Verify(curve, circuit.Signature, msg, circuit.SigPublicKey, &hashf)
	if result_sig != nil {
		return err
	}

	//delta0=mimc(tk,seq)
	mimc0, _ := mimc.NewMiMC(api)
	mimc0.Write(circuit.TacSk, circuit.Seq)
	delta_0 := mimc0.Sum()
	api.AssertIsEqual(delta_0, circuit.ExpectedDelta)

	//g0bal,Dpk,delta1
	_g1, _ := twistededwards.GetCurveParams(ecct.BN254)
	g1 := twistededwards.Point{X: _g1.Base[0], Y: _g1.Base[1]}
	g1delta0 := curve.ScalarMul(g1, delta_0)

	var c2sk twistededwards.Point
	c2sk = curve.ScalarMul(circuit.Acc.B, circuit.PrivateKey)
	var _c2sk twistededwards.Point
	_c2sk = curve.Neg(c2sk)
	var _complain twistededwards.Point
	_complain = curve.Add(circuit.Acc.A, _c2sk)
	var _g1delta0 twistededwards.Point
	_g1delta0 = curve.Neg(g1delta0)
	var g0bal twistededwards.Point
	g0bal = curve.Add(_complain, _g1delta0)

	var dpublickey twistededwards.Point
	dpublickey = curve.ScalarMul(circuit.PublicKey, circuit.Alpha)
	api.AssertIsEqual(dpublickey.X, circuit.ExpectedDPublicKey.X)

	mimc1, _ := mimc.NewMiMC(api)
	mimc1.Write(circuit.TacSk, circuit.Seq1)
	delta_1 := mimc1.Sum()
	g1delta1 := curve.ScalarMul(g1, delta_1)

	plaintext := curve.Add(g0bal, g1delta1)

	rpk := curve.ScalarMul(dpublickey, circuit.Randomness)
	c1 := curve.Add(plaintext, rpk)
	_h, _ := twistededwards.GetCurveParams(ecct.BN254)
	h := twistededwards.Point{X: _h.Base[0], Y: _h.Base[1]}
	c2 := curve.ScalarMul(h, circuit.Randomness)
	api.AssertIsEqual(c1.X, circuit.ExpectedDAcc.A.X)
	api.AssertIsEqual(c2.X, circuit.ExpectedDAcc.B.X)

	//TK=g2*tk
	_g2, _ := twistededwards.GetCurveParams(ecct.BN254)
	g2 := twistededwards.Point{X: _g2.Base[0], Y: _g2.Base[1]}
	tacpk := curve.ScalarMul(g2, circuit.TacSk)

	//CTk
	arpk := curve.ScalarMul(circuit.PublicKeyA, circuit.RandomnessA)
	ac1 := curve.Add(tacpk, arpk)
	_ah, _ := twistededwards.GetCurveParams(ecct.BN254)
	ah := twistededwards.Point{X: _ah.Base[0], Y: _ah.Base[1]}
	ac2 := curve.ScalarMul(ah, circuit.RandomnessA)
	api.AssertIsEqual(ac1.X, circuit.ExpectedCTacPk[0].X)
	api.AssertIsEqual(ac2.X, circuit.ExpectedCTacPk[1].X)

	return nil
}
