package enroll

import (
	ecct "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
	"github.com/consensys/gnark/std/hash/mimc"
)

type accountWit struct {
	A twistededwards.Point
	B twistededwards.Point
}

type enrollCircuit struct {
	ExpectedAcc   accountWit           `gnark:",public"`
	PublicKey     twistededwards.Point `gnark:",public"`
	Balance       frontend.Variable    `gnark:",public"`
	Randomness    frontend.Variable
	ExpectedTacPk twistededwards.Point `gnark:",public"`
	TacSk         frontend.Variable
	Seq           frontend.Variable
}

func (circuit *enrollCircuit) Define(api frontend.API) error {
	curve, err := twistededwards.NewEdCurve(api, ecct.BN254)
	mimc, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}

	//TK=g2*tk
	_g2, _ := twistededwards.GetCurveParams(ecct.BN254)
	g2 := twistededwards.Point{X: _g2.Base[0], Y: _g2.Base[1]}

	tacpk := curve.ScalarMul(g2, circuit.TacSk)
	api.AssertIsEqual(tacpk.X, circuit.ExpectedTacPk.X)

	//delta0=mimc(tk,seq)
	mimc.Write(circuit.TacSk, circuit.Seq)
	delta_0 := mimc.Sum()
	_g1, _ := twistededwards.GetCurveParams(ecct.BN254)
	g1 := twistededwards.Point{X: _g1.Base[0], Y: _g1.Base[1]}

	plaintext := curve.ScalarMul(g1, delta_0)

	//acc=(g0*bal+(g1*delta0)+r*pk,r*h),bal=0
	rpk := curve.ScalarMul(circuit.PublicKey, circuit.Randomness)
	c1 := curve.Add(plaintext, rpk)
	_h, _ := twistededwards.GetCurveParams(ecct.BN254)
	h := twistededwards.Point{X: _h.Base[0], Y: _h.Base[1]}
	c2 := curve.ScalarMul(h, circuit.Randomness)
	api.AssertIsEqual(c1.X, circuit.ExpectedAcc.A.X)
	api.AssertIsEqual(c2.X, circuit.ExpectedAcc.B.X)

	return nil
}
