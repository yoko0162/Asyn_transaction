package onlinetx

import (
	"Asyn_CBDC/onlinetx/bulletproof"
	"Asyn_CBDC/onlinetx/sigma"
	"fmt"
	"math/big"
	"time"

	eccfr "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	curve "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	ecctedwards "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
)

type transactionTX struct {
	A curve.PointAffine
	B curve.PointAffine
}

type sigmaProof struct {
	commit    []sigma.CommitMent
	commitenc [][]curve.PointAffine
	response  []sigma.Response
	challenge big.Int
}

type bulletProof struct {
	commitV  eccfr.G1Affine
	commitA  eccfr.G1Affine
	commitS  eccfr.G1Affine
	chall_y  big.Int
	chall_z  big.Int
	commitT1 eccfr.G1Affine
	commitT2 eccfr.G1Affine
	chall_x  big.Int
	rp_taux  *big.Int
	rp_miu   *big.Int
	rp_lx    []*big.Int
	rp_rx    []*big.Int
	rp_tx    *big.Int
	bpPara   bulletproof.BulletParams
}

func Verify() {
	curveid := ecctedwards.BN254
	params, _ := twistededwards.GetCurveParams(curveid)
	modulus := fr.Modulus()

	var s sender
	s, sigmaproof, bpv, bpbal := s.zkpProof(params, curveid, modulus)
	verifySigmaProtocol(s, sigmaproof)
	fmt.Println("bulletproof_transaction amount:")
	verifyBulletProof(bpv)
	fmt.Println("bulletproof_account balance:")
	verifyBulletProof(bpbal)
}

func verifySigmaProtocol(s sender, sigmaproof sigmaProof) {
	commit_s := sigmaproof.commit[0]
	commit_sh := sigmaproof.commit[1]
	commit_r := sigmaproof.commit[2]
	commit_rh := sigmaproof.commit[3]
	commit_bal := sigmaproof.commitenc[0]
	commit_v := sigmaproof.commitenc[1]

	rp_sr := sigmaproof.response[0]
	rp_rr := sigmaproof.response[1]
	rp_sv := sigmaproof.response[2]
	rp_rv := sigmaproof.response[3]
	rp_bal := sigmaproof.response[4]
	rp_bal_r := sigmaproof.response[5]
	rp_v := sigmaproof.response[6]
	rp_v_r := sigmaproof.response[7]

	challenge := sigmaproof.challenge

	/* */
	starttime := time.Now()

	var rp_sr_h curve.PointAffine
	rp_sr_h.ScalarMultiplication(&s.h, &rp_sr.Rp)
	var _commit_sh_chal_txsb curve.PointAffine
	_commit_sh_chal_txsb.ScalarMultiplication(&s.txs.B, &challenge)
	var commit_sh_chal_txsb curve.PointAffine
	commit_sh_chal_txsb.Add(&commit_sh.Commit, &_commit_sh_chal_txsb)

	var rp_sr_pk curve.PointAffine
	rp_sr_pk.ScalarMultiplication(&s.dacc.Keypair.DPk.Pk, &rp_sr.Rp)
	var rp_sv_g0 curve.PointAffine
	rp_sv_g0.ScalarMultiplication(&s.dacc.G0, &rp_sv.Rp)
	var rp_sr_pk_rp_sv_g0 curve.PointAffine
	rp_sr_pk_rp_sv_g0.Add(&rp_sr_pk, &rp_sv_g0)
	var _commit_s_chal_txsa curve.PointAffine
	_commit_s_chal_txsa.ScalarMultiplication(&s.txs.A, &challenge)
	var commit_s_chal_txsa curve.PointAffine
	commit_s_chal_txsa.Add(&_commit_s_chal_txsa, &commit_s.Commit)

	var rp_rr_h curve.PointAffine
	rp_rr_h.ScalarMultiplication(&s.h, &rp_rr.Rp)
	var _commit_rh_chal_txrb curve.PointAffine
	_commit_rh_chal_txrb.ScalarMultiplication(&s.txr.B, &challenge)
	var commit_rh_chal_txrb curve.PointAffine
	commit_rh_chal_txrb.Add(&commit_rh.Commit, &_commit_rh_chal_txrb)

	var rp_rr_pk curve.PointAffine
	rp_rr_pk.ScalarMultiplication(&s.r_derivepk.Pk, &rp_rr.Rp)
	var rp_rv_g0 curve.PointAffine
	rp_rv_g0.ScalarMultiplication(&s.dacc.G0, &rp_rv.Rp)
	var rp_rr_pk_rp_rv_g0 curve.PointAffine
	rp_rr_pk_rp_rv_g0.Add(&rp_rr_pk, &rp_rv_g0)
	var _commit_r_chal_txra curve.PointAffine
	_commit_r_chal_txra.ScalarMultiplication(&s.txr.A, &challenge)
	var commit_r_chal_txra curve.PointAffine
	commit_r_chal_txra.Add(&_commit_r_chal_txra, &commit_r.Commit)

	var plain_rp_bal curve.PointAffine
	plain_rp_bal.ScalarMultiplication(&s._trans, &rp_bal.Rp)
	cipher_rp_bal := s.apk.Encrypt(plain_rp_bal, &rp_bal_r.Rp, s.h)
	var _chal_bal1 curve.PointAffine
	_chal_bal1.ScalarMultiplication(&s.cipher_bal[0], &challenge)
	var commit_bal1_chal_bal1 curve.PointAffine
	commit_bal1_chal_bal1.Add(&commit_bal[0], &_chal_bal1)
	var _chal_bal2 curve.PointAffine
	_chal_bal2.ScalarMultiplication(&s.cipher_bal[1], &challenge)
	var commit_bal2_chal_bal2 curve.PointAffine
	commit_bal2_chal_bal2.Add(&commit_bal[1], &_chal_bal2)

	var plain_rp_v curve.PointAffine
	plain_rp_v.ScalarMultiplication(&s._trans, &rp_v.Rp)
	cipher_rp_v := s.apk.Encrypt(plain_rp_v, &rp_v_r.Rp, s.h)
	var _chal_v1 curve.PointAffine
	_chal_v1.ScalarMultiplication(&s.cipher_v[0], &challenge)
	var commit_v1_chal_v1 curve.PointAffine
	commit_v1_chal_v1.Add(&commit_v[0], &_chal_v1)
	var _chal_v2 curve.PointAffine
	_chal_v2.ScalarMultiplication(&s.cipher_v[1], &challenge)
	var commit_v2_chal_v2 curve.PointAffine
	commit_v2_chal_v2.Add(&commit_v[1], &_chal_v2)

	endtime := time.Now()

	/* debug */
	fmt.Println("sigma:")
	fmt.Println("rp_sr*h==commit_sh+challenge*txs.c2:", rp_sr_h.Equal(&commit_sh_chal_txsb))
	fmt.Println("rp_sr*pk+rp_sv*g0==commit_s+challenge*txs.c1:", rp_sr_pk_rp_sv_g0.Equal(&commit_s_chal_txsa))
	fmt.Println("rp_rr*h==commit_rh+challenge*txr.c2:", rp_rr_h.Equal(&commit_rh_chal_txrb))
	fmt.Println("rp_rr*pk+rp_rv*g0==commit_r+challenge*txr.c1:", rp_rr_pk_rp_rv_g0.Equal(&commit_r_chal_txra))
	fmt.Println("Enc(rp_bal)==commit_bal+challenge*cipher_bal:", (commit_bal1_chal_bal1.Equal(&cipher_rp_bal[0])) && (commit_bal2_chal_bal2.Equal(&cipher_rp_bal[1])))
	fmt.Println("Enc(rp_v)==commit_v+challenge*cipher_v:", (commit_v1_chal_v1.Equal(&cipher_rp_v[0])) && (commit_v2_chal_v2.Equal(&cipher_rp_v[1])))

	fmt.Println("verify:", endtime.Sub(starttime))
}

func verifyBulletProof(bpv bulletProof) {
	P := bpv.bpPara.P
	n := bpv.bpPara.N
	G := bpv.bpPara.G
	H := bpv.bpPara.H
	g := bpv.bpPara.Bg
	h := bpv.bpPara.Bh

	/* */
	starttime := time.Now()

	//know lx,rx,tx
	veritx := bulletproof.Calculate_tx(bpv.rp_lx, bpv.rp_rx)
	//know y,z calculate δ(y,z)
	veriyn := bulletproof.GenerateY(bpv.chall_y, n)
	veriz2 := big.NewInt(0)
	veriz2.Mul(&bpv.chall_z, &bpv.chall_z)
	veriz2.Mod(veriz2, P)
	veriz3 := big.NewInt(0)
	veriz3.Mul(veriz2, &bpv.chall_z)
	veriz3.Mod(veriz3, P)
	z_z2 := big.NewInt(0)
	z_z2.Sub(&bpv.chall_z, veriz2)
	z_z2.Mod(z_z2, P)
	y1n := bulletproof.Inner_produ(bulletproof.GenerateZ(*big.NewInt(1), n), veriyn)
	y2n1 := bulletproof.Inner_produ(bulletproof.GenerateZ(*big.NewInt(1), n), bulletproof.Generate2n(n))
	z_z2y1n := big.NewInt(0)
	z_z2y1n.Mul(z_z2, y1n)
	z_z2y1n.Mod(z_z2y1n, P)
	z3y2n1 := big.NewInt(0)
	z3y2n1.Mul(veriz3, y2n1)
	z3y2n1.Mod(z3y2n1, P)
	delta := big.NewInt(0)
	delta.Sub(z_z2y1n, z3y2n1)
	delta.Mod(delta, P)
	//know tx,taux,V,x,T1,T2,delta(calculated)
	verix2 := big.NewInt(0)
	verix2.Mul(&bpv.chall_x, &bpv.chall_x)
	verix2.Mod(verix2, P)
	commit0 := bulletproof.Commit(g, h, bpv.rp_tx, bpv.rp_taux)
	commitVg := bulletproof.Commit(bpv.commitV, g, veriz2, delta)
	commitT := bulletproof.Commit(bpv.commitT1, bpv.commitT2, &bpv.chall_x, verix2)
	var commitVgT eccfr.G1Affine
	commitVgT.Add(&commitVg, &commitT)
	//know A,S,x,z,y
	H1 := bulletproof.GenerateH1(H, bpv.chall_y, n, P)
	commitAS := bulletproof.Commit(bpv.commitA, bpv.commitS, big.NewInt(1), &bpv.chall_x)
	vec := bulletproof.CalVectorAdd(bulletproof.CalVectorTimes(veriyn, &bpv.chall_z), bulletproof.CalVectorTimes(bulletproof.Generate2n(n), veriz2))
	commitvec := bulletproof.CommitSingleVector(H1, vec)
	z1 := bulletproof.GenerateZ1(bpv.chall_z, n)
	commitz1 := bulletproof.CommitSingleVector(G, z1)
	var _commitP eccfr.G1Affine
	_commitP.Add(&commitAS, &commitz1)
	var commitP eccfr.G1Affine
	commitP.Add(&_commitP, &commitvec)
	//know miu,lx,rx
	commitmiu := bulletproof.CommitSingle(h, bpv.rp_miu)

	commitlr := bulletproof.CommitVectors(G, H1, bpv.rp_lx, bpv.rp_rx)
	var verip eccfr.G1Affine
	verip.Add(&commitmiu, &commitlr)

	endtime := time.Now()

	/* debug */
	fmt.Println("tx==<lx,rx>:(true is 0)", veritx.Cmp(bpv.rp_tx))
	fmt.Println("commit0==commitVgT:", commit0.Equal(&commitVgT))
	fmt.Println("veriP==commitP:", verip.Equal(&commitP))

	fmt.Println("verify:", endtime.Sub(starttime))
}
