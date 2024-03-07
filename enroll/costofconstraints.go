package enroll

import (
	"Asyn_CBDC/util"

	"github.com/consensys/gnark-crypto/ecc"
	ecctedwards "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
)

func Enroll() {
	params, _ := twistededwards.GetCurveParams(ecctedwards.BN254)
	hashFunc := hash.MIMC_BN254

	var enroll util.Enroll
	enroll = enroll.Init(params, hashFunc)

	var assignment enrollCircuit
	assignment.TacSk = enroll.Tracesk
	tacPk := enroll.Tracepk
	assignment.ExpectedTacPk = tacPk
	assignment.Seq = enroll.Seq
	assignment.Balance = enroll.Bal
	assignment.PublicKey = enroll.Pk
	assignment.Randomness = enroll.R
	assignment.ExpectedAcc = enroll.Acc

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
