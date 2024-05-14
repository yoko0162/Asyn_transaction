package offlinetx

import (
	"Asyn_CBDC/util"

	ecctedwards "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/std/math/cmp"
	cir_eddsa "github.com/consensys/gnark/std/signature/eddsa"
)

type nonRegulationCircuit struct {
	SigPublicKey       cir_eddsa.PublicKey `gnark:",public"`
	Signature          cir_eddsa.Signature
	Acc                util.Account
	Bal                frontend.Variable
	TacSk              frontend.Variable
	Seq                frontend.Variable
	Seq1               frontend.Variable
	ExpectedDelta      frontend.Variable    `gnark:",public"`
	ExpectedDAcc       util.Account         `gnark:",public"`
	ExpectedDPublicKey twistededwards.Point `gnark:",public"`
	PrivateKey         frontend.Variable
	PublicKey          twistededwards.Point
	Alpha              frontend.Variable
	Randomness         frontend.Variable
}

type nolimitRegulationCircuit struct {
	SigPublicKey       cir_eddsa.PublicKey `gnark:",public"`
	Signature          cir_eddsa.Signature
	Acc                util.Account
	Bal                frontend.Variable
	TacSk              frontend.Variable
	Seq                frontend.Variable
	Seq1               frontend.Variable
	ExpectedDelta      frontend.Variable    `gnark:",public"`
	ExpectedDAcc       util.Account         `gnark:",public"`
	ExpectedDPublicKey twistededwards.Point `gnark:",public"`
	PrivateKey         frontend.Variable
	PublicKey          twistededwards.Point
	Alpha              frontend.Variable
	Randomness         frontend.Variable
	ExpectedCPk        [2]twistededwards.Point `gnark:",public"`
	PublicKeyA         twistededwards.Point    `gnark:",public"`
	RandomnessA        frontend.Variable
}

type holdinglimitRegulationCircuit struct {
	SigPublicKey       cir_eddsa.PublicKey `gnark:",public"`
	Signature          cir_eddsa.Signature
	Acc                util.Account
	Bal                frontend.Variable
	TacSk              frontend.Variable
	Seq                frontend.Variable
	Seq1               frontend.Variable
	ExpectedDelta      frontend.Variable    `gnark:",public"`
	ExpectedDAcc       util.Account         `gnark:",public"`
	ExpectedDPublicKey twistededwards.Point `gnark:",public"`
	PrivateKey         frontend.Variable
	PublicKey          twistededwards.Point
	Alpha              frontend.Variable
	Randomness         frontend.Variable
	ExpectedCPk        [2]twistededwards.Point `gnark:",public"`
	PublicKeyA         twistededwards.Point    `gnark:",public"`
	RandomnessA        frontend.Variable
	A                  frontend.Variable
	ExpectedAux        twistededwards.Point `gnark:",public"`
}

type freqlimitRegulationCircuit struct {
	SigPublicKey       cir_eddsa.PublicKey `gnark:",public"`
	Signature          cir_eddsa.Signature
	Acc                util.Account
	Bal                frontend.Variable
	TacSk              frontend.Variable
	Seq                frontend.Variable
	Seq1               frontend.Variable
	ExpectedDelta      frontend.Variable    `gnark:",public"`
	ExpectedDAcc       util.Account         `gnark:",public"`
	ExpectedDPublicKey twistededwards.Point `gnark:",public"`
	PrivateKey         frontend.Variable
	PublicKey          twistededwards.Point
	Alpha              frontend.Variable
	Randomness         frontend.Variable
	ExpectedCPk        [2]twistededwards.Point `gnark:",public"`
	PublicKeyA         twistededwards.Point    `gnark:",public"`
	RandomnessA        frontend.Variable
	A                  frontend.Variable
	ExpectedAux        twistededwards.Point `gnark:",public"`
	Comment            twistededwards.Point `gnark:",public"`
	Date               frontend.Variable
	DateSignature      cir_eddsa.Signature
	Commentr           frontend.Variable
}

func (circuit *nonRegulationCircuit) Define(api frontend.API) error {
	//choose curve
	curvepara := ecctedwards.BN254

	curve, err := twistededwards.NewEdCurve(api, curvepara)
	if err != nil {
		return err
	}

	hashf1, err := mimc.NewMiMC(api)

	if err != nil {
		return err
	}

	msg := circuit.Acc.A.X

	// verify the signature in the cs
	result_sig := cir_eddsa.Verify(curve, circuit.Signature, msg, circuit.SigPublicKey, &hashf1)
	if result_sig != nil {
		return err
	}

	//delta0=mimc(tk,seq)
	mimc, _ := mimc.NewMiMC(api)
	mimc.Write(circuit.TacSk, circuit.Seq)
	delta_0 := mimc.Sum()
	api.AssertIsEqual(delta_0, circuit.ExpectedDelta)

	api.AssertIsEqual(cmp.IsLess(api, 0, circuit.Bal), 1)

	//g0bal,Dpk,delta1
	_g1, _ := twistededwards.GetCurveParams(curvepara)
	g1 := twistededwards.Point{X: _g1.Base[0], Y: _g1.Base[1]}
	g1delta0 := curve.ScalarMul(g1, delta_0)

	_g0, _ := twistededwards.GetCurveParams(curvepara)
	g0 := twistededwards.Point{X: _g0.Base[0], Y: _g0.Base[1]}
	g0bal := curve.ScalarMul(g0, circuit.Bal)

	expectedg0balg1delta0 := util.DecryptAcc(curve, circuit.Acc, circuit.PrivateKey)
	g0balg1delta0 := curve.Add(g1delta0, g0bal)
	api.AssertIsEqual(expectedg0balg1delta0.X, g0balg1delta0.X)

	_h, _ := twistededwards.GetCurveParams(curvepara)
	h := twistededwards.Point{X: _h.Base[0], Y: _h.Base[1]}
	_pk := curve.ScalarMul(h, circuit.PrivateKey)
	api.AssertIsEqual(_pk.X, circuit.PublicKey.X)

	var dpublickey twistededwards.Point
	dpublickey = curve.ScalarMul(circuit.PublicKey, circuit.Alpha)
	api.AssertIsEqual(dpublickey.X, circuit.ExpectedDPublicKey.X)

	mimc.Reset()
	mimc.Write(circuit.TacSk, circuit.Seq1)
	delta_1 := mimc.Sum()
	g1delta1 := curve.ScalarMul(g1, delta_1)

	plaintext := curve.Add(g0bal, g1delta1)

	acc := util.EncryptAcc(curve, plaintext, dpublickey, circuit.Randomness, _h)
	c1 := acc.A
	c2 := acc.B
	api.AssertIsEqual(c1.X, circuit.ExpectedDAcc.A.X)
	api.AssertIsEqual(c2.X, circuit.ExpectedDAcc.B.X)

	return nil
}

func (circuit *nolimitRegulationCircuit) Define(api frontend.API) error {
	//choose curve
	curvepara := ecctedwards.BN254

	curve, err := twistededwards.NewEdCurve(api, curvepara)
	if err != nil {
		return err
	}

	hashf1, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}

	msg := circuit.Acc.A.X

	// verify the signature in the cs
	result_sig := cir_eddsa.Verify(curve, circuit.Signature, msg, circuit.SigPublicKey, &hashf1)
	if result_sig != nil {
		return err
	}

	//delta0=mimc(tk,seq)
	mimc, _ := mimc.NewMiMC(api)
	mimc.Write(circuit.TacSk, circuit.Seq)
	delta_0 := mimc.Sum()
	api.AssertIsEqual(delta_0, circuit.ExpectedDelta)

	api.AssertIsEqual(cmp.IsLess(api, 0, circuit.Bal), 1)

	//g0bal,Dpk,delta1
	_g1, _ := twistededwards.GetCurveParams(curvepara)
	g1 := twistededwards.Point{X: _g1.Base[0], Y: _g1.Base[1]}
	g1delta0 := curve.ScalarMul(g1, delta_0)

	_g0, _ := twistededwards.GetCurveParams(curvepara)
	g0 := twistededwards.Point{X: _g0.Base[0], Y: _g0.Base[1]}
	g0bal := curve.ScalarMul(g0, circuit.Bal)

	expectedg0balg1delta0 := util.DecryptAcc(curve, circuit.Acc, circuit.PrivateKey)
	g0balg1delta0 := curve.Add(g1delta0, g0bal)
	api.AssertIsEqual(expectedg0balg1delta0.X, g0balg1delta0.X)

	_h, _ := twistededwards.GetCurveParams(curvepara)
	h := twistededwards.Point{X: _h.Base[0], Y: _h.Base[1]}
	_pk := curve.ScalarMul(h, circuit.PrivateKey)
	api.AssertIsEqual(_pk.X, circuit.PublicKey.X)

	var dpublickey twistededwards.Point
	dpublickey = curve.ScalarMul(circuit.PublicKey, circuit.Alpha)
	api.AssertIsEqual(dpublickey.X, circuit.ExpectedDPublicKey.X)

	mimc.Reset()
	mimc.Write(circuit.TacSk, circuit.Seq1)
	delta_1 := mimc.Sum()
	g1delta1 := curve.ScalarMul(g1, delta_1)

	plaintext := curve.Add(g0bal, g1delta1)

	acc := util.EncryptAcc(curve, plaintext, dpublickey, circuit.Randomness, _h)
	c1 := acc.A
	c2 := acc.B
	api.AssertIsEqual(c1.X, circuit.ExpectedDAcc.A.X)
	api.AssertIsEqual(c2.X, circuit.ExpectedDAcc.B.X)
	//32134

	//CPk
	_ah, _ := twistededwards.GetCurveParams(curvepara)

	cipher := util.EncryptPk(curve, circuit.PublicKey, circuit.PublicKeyA, circuit.RandomnessA, _ah)
	api.AssertIsEqual(cipher[0].X, circuit.ExpectedCPk[0].X)
	api.AssertIsEqual(cipher[1].X, circuit.ExpectedCPk[1].X)
	//38217+1278=39495

	return nil
}

func (circuit *holdinglimitRegulationCircuit) Define(api frontend.API) error {
	//choose curve
	curvepara := ecctedwards.BN254

	curve, err := twistededwards.NewEdCurve(api, curvepara)
	if err != nil {
		return err
	}

	hashf1, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}

	msg := circuit.Acc.A.X

	// verify the signature in the cs
	result_sig := cir_eddsa.Verify(curve, circuit.Signature, msg, circuit.SigPublicKey, &hashf1)
	if result_sig != nil {
		return err
	}

	//delta0=mimc(tk,seq)
	mimc, _ := mimc.NewMiMC(api)
	mimc.Write(circuit.TacSk, circuit.Seq)
	delta_0 := mimc.Sum()
	api.AssertIsEqual(delta_0, circuit.ExpectedDelta)

	api.AssertIsEqual(cmp.IsLess(api, 0, circuit.Bal), 1)

	//g0bal,Dpk,delta1
	_g1, _ := twistededwards.GetCurveParams(curvepara)
	g1 := twistededwards.Point{X: _g1.Base[0], Y: _g1.Base[1]}
	g1delta0 := curve.ScalarMul(g1, delta_0)

	_g0, _ := twistededwards.GetCurveParams(curvepara)
	g0 := twistededwards.Point{X: _g0.Base[0], Y: _g0.Base[1]}
	g0bal := curve.ScalarMul(g0, circuit.Bal)

	expectedg0balg1delta0 := util.DecryptAcc(curve, circuit.Acc, circuit.PrivateKey)
	g0balg1delta0 := curve.Add(g1delta0, g0bal)
	api.AssertIsEqual(expectedg0balg1delta0.X, g0balg1delta0.X)

	_h, _ := twistededwards.GetCurveParams(curvepara)
	h := twistededwards.Point{X: _h.Base[0], Y: _h.Base[1]}
	_pk := curve.ScalarMul(h, circuit.PrivateKey)
	api.AssertIsEqual(_pk.X, circuit.PublicKey.X)

	var dpublickey twistededwards.Point
	dpublickey = curve.ScalarMul(circuit.PublicKey, circuit.Alpha)
	api.AssertIsEqual(dpublickey.X, circuit.ExpectedDPublicKey.X)

	mimc.Reset()
	mimc.Write(circuit.TacSk, circuit.Seq1)
	delta_1 := mimc.Sum()
	g1delta1 := curve.ScalarMul(g1, delta_1)

	plaintext := curve.Add(g0bal, g1delta1)

	acc := util.EncryptAcc(curve, plaintext, dpublickey, circuit.Randomness, _h)
	c1 := acc.A
	c2 := acc.B
	api.AssertIsEqual(c1.X, circuit.ExpectedDAcc.A.X)
	api.AssertIsEqual(c2.X, circuit.ExpectedDAcc.B.X)
	//32134

	//CPk
	_ah, _ := twistededwards.GetCurveParams(curvepara)

	cipher := util.EncryptPk(curve, circuit.PublicKey, circuit.PublicKeyA, circuit.RandomnessA, _ah)

	reginfo, aux := util.RegulationTK(curve, _ah, cipher, circuit.A)

	api.AssertIsEqual(reginfo[0].X, circuit.ExpectedCPk[0].X)
	api.AssertIsEqual(reginfo[1].X, circuit.ExpectedCPk[1].X)
	api.AssertIsEqual(aux.X, circuit.ExpectedAux.X)
	//48868

	return nil
}

func (circuit *freqlimitRegulationCircuit) Define(api frontend.API) error {
	//choose curve
	curvepara := ecctedwards.BN254

	curve, err := twistededwards.NewEdCurve(api, curvepara)
	if err != nil {
		return err
	}

	hashf1, err := mimc.NewMiMC(api)
	hashf2, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}

	msg := circuit.Acc.A.X

	// verify the signature in the cs
	result_sig := cir_eddsa.Verify(curve, circuit.Signature, msg, circuit.SigPublicKey, &hashf1)
	if result_sig != nil {
		return err
	}
	msg = circuit.Date
	date_sig := cir_eddsa.Verify(curve, circuit.DateSignature, msg, circuit.SigPublicKey, &hashf2)
	if date_sig != nil {
		return err
	}

	//delta0=mimc(tk,seq)
	mimc, _ := mimc.NewMiMC(api)
	mimc.Write(circuit.TacSk, circuit.Seq)
	delta_0 := mimc.Sum()
	api.AssertIsEqual(delta_0, circuit.ExpectedDelta)

	api.AssertIsEqual(cmp.IsLess(api, 0, circuit.Bal), 1)

	//g0bal,Dpk,delta1
	_g1, _ := twistededwards.GetCurveParams(curvepara)
	g1 := twistededwards.Point{X: _g1.Base[0], Y: _g1.Base[1]}
	g1delta0 := curve.ScalarMul(g1, delta_0)

	_g0, _ := twistededwards.GetCurveParams(curvepara)
	g0 := twistededwards.Point{X: _g0.Base[0], Y: _g0.Base[1]}
	g0bal := curve.ScalarMul(g0, circuit.Bal)

	expectedg0balg1delta0 := util.DecryptAcc(curve, circuit.Acc, circuit.PrivateKey)
	g0balg1delta0 := curve.Add(g1delta0, g0bal)
	api.AssertIsEqual(expectedg0balg1delta0.X, g0balg1delta0.X)

	_h, _ := twistededwards.GetCurveParams(curvepara)
	h := twistededwards.Point{X: _h.Base[0], Y: _h.Base[1]}
	_pk := curve.ScalarMul(h, circuit.PrivateKey)
	api.AssertIsEqual(_pk.X, circuit.PublicKey.X)

	var dpublickey twistededwards.Point
	dpublickey = curve.ScalarMul(circuit.PublicKey, circuit.Alpha)
	api.AssertIsEqual(dpublickey.X, circuit.ExpectedDPublicKey.X)

	mimc.Reset()
	mimc.Write(circuit.TacSk, circuit.Seq1)
	delta_1 := mimc.Sum()
	g1delta1 := curve.ScalarMul(g1, delta_1)

	plaintext := curve.Add(g0bal, g1delta1)

	acc := util.EncryptAcc(curve, plaintext, dpublickey, circuit.Randomness, _h)
	c1 := acc.A
	c2 := acc.B
	api.AssertIsEqual(c1.X, circuit.ExpectedDAcc.A.X)
	api.AssertIsEqual(c2.X, circuit.ExpectedDAcc.B.X)
	//32134

	//CPk
	_ah, _ := twistededwards.GetCurveParams(curvepara)

	cipher := util.EncryptPk(curve, circuit.PublicKey, circuit.PublicKeyA, circuit.RandomnessA, _ah)

	reginfo, aux := util.RegulationTK(curve, _ah, cipher, circuit.A)

	api.AssertIsEqual(reginfo[0].X, circuit.ExpectedCPk[0].X)
	api.AssertIsEqual(reginfo[1].X, circuit.ExpectedCPk[1].X)
	api.AssertIsEqual(aux.X, circuit.ExpectedAux.X)
	//48868

	_G, _ := twistededwards.GetCurveParams(curvepara)
	_H, _ := twistededwards.GetCurveParams(curvepara)
	comm := util.Pedersen(curve, _G, _H, circuit.Date, circuit.Commentr)
	api.AssertIsEqual(comm.X, circuit.Comment.X)
	//61434

	return nil
}
