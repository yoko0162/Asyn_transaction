package onlinetx

import (
	"Asyn_CBDC/offlinetx"
	"Asyn_CBDC/onlinetx/bulletproof"
	"Asyn_CBDC/onlinetx/sigma"
	"Asyn_CBDC/util"
	"crypto/rand"
	"fmt"
	"math/big"
	"time"

	eccfr "github.com/consensys/gnark-crypto/ecc/bn254"
	curve "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	ecctedwards "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
)

type sender struct {
	dacc       offlinetx.DeriveAccount
	r_derivepk util.Publickey
	v          big.Int  //witness,send to receiver
	beta       *big.Int //send to receiver
	r_txr      *big.Int //witness,send to receiver
	txr        transactionTX
	txs        transactionTX
	r_txs      *big.Int //witness
	bal        big.Int  //witness
	apk        util.Publickey
	r_bal      *big.Int
	r_v        *big.Int
	cipher_bal []curve.PointAffine
	cipher_v   []curve.PointAffine
	_trans     curve.PointAffine
	h          curve.PointAffine
}

func (s sender) execution(params *twistededwards.CurveParams, r_txr *big.Int, r_txs *big.Int, r_pk util.Publickey, v big.Int, o offlinetx.Offline) sender {
	s.v = v
	s.dacc = o.Deriveacc
	s.r_txr = r_txr
	s.r_txs = r_txs
	s.bal = o.Bal
	s.apk = o.Apk

	rb, _ := rand.Int(rand.Reader, params.Order)
	rv, _ := rand.Int(rand.Reader, params.Order)
	s.r_bal = rb
	s.r_v = rv

	var plain curve.PointAffine
	plain.ScalarMultiplication(&s.dacc.G0, &s.v)

	_txs := s.dacc.Keypair.DPk.Encrypt(plain, s.r_txs, s.dacc.H)
	s.txs = transactionTX{
		A: _txs[0],
		B: _txs[1],
	}

	beta, _ := rand.Int(rand.Reader, params.Order)
	s.beta = beta
	var _pkr curve.PointAffine
	_pkr.ScalarMultiplication(&r_pk.Pk, beta)
	s.r_derivepk = util.Publickey{Pk: _pkr}

	_txr := s.r_derivepk.Encrypt(plain, s.r_txr, s.dacc.H)
	s.txr = transactionTX{
		A: _txr[0],
		B: _txr[1],
	}

	var _trans curve.PointAffine
	_trans.X.SetBigInt(params.Base[0])
	_trans.Y.SetBigInt(params.Base[1])
	s._trans = _trans
	var aplain_bal curve.PointAffine
	aplain_bal.ScalarMultiplication(&_trans, &s.bal)
	var aplain_v curve.PointAffine
	aplain_v.ScalarMultiplication(&_trans, &s.v)
	var h curve.PointAffine
	h.X.SetBigInt(params.Base[0])
	h.Y.SetBigInt(params.Base[1])
	s.h = h
	s.cipher_bal = s.apk.Encrypt(aplain_bal, s.r_bal, s.h)
	s.cipher_v = s.apk.Encrypt(aplain_v, s.r_v, s.h)
	return s
}

func (s sender) sigmaprotocol(params *twistededwards.CurveParams, curveid ecctedwards.ID) (sigmaProof, sender) {
	//simulation receiver
	hashFunc := hash.MIMC_BN254
	var receiver_bal big.Int
	receiver_bal.SetString("200", 10)
	var receiver offlinetx.PrimitiveAccount
	receiver = receiver.GetAccount(params, hashFunc, receiver_bal, *big.NewInt(1))
	r_pk := receiver.Pk

	/* */
	var v big.Int
	v.SetString("100", 10)

	r_txr, _ := rand.Int(rand.Reader, params.Order)
	r_txs, _ := rand.Int(rand.Reader, params.Order)

	var o offlinetx.Offline
	o = o.Execution(params, hashFunc, curveid)

	s = s.execution(params, r_txr, r_txs, r_pk, v, o)

	/* */
	starttime := time.Now()

	var commit sigma.CommitMent
	para_sh := commit.ParamsGen(params)
	para_rh := commit.ParamsGen(params)
	para_s := commit.ParamsGen(params)
	para_r := commit.ParamsGen(params)

	para_bal := commit.ParamsGen(params)
	para_bal_r := commit.ParamsGen(params)
	para_v := commit.ParamsGen(params)
	para_v_r := commit.ParamsGen(params)

	commit_sh := commit.Commitmul(para_sh, s.dacc.H)
	commit_rh := commit.Commitmul(para_rh, s.dacc.H)
	commit_s := commit.Commitmuladd(para_sh, para_s, s.dacc.Keypair.DPk.Pk, s.dacc.G0)
	commit_r := commit.Commitmuladd(para_rh, para_r, s.r_derivepk.Pk, s.dacc.G0)

	commit_bal := commit.CommitencValid(para_bal, para_bal_r, s.apk, s.h, s._trans)
	commit_v := commit.CommitencValid(para_v, para_v_r, s.apk, s.h, s._trans)

	hash := hashFunc.New()

	var data []byte
	data = append(data, commit_sh.Commit.Marshal()...)
	data = append(data, commit_rh.Commit.Marshal()...)
	data = append(data, commit_s.Commit.Marshal()...)
	data = append(data, commit_r.Commit.Marshal()...)
	data = append(data, s.txs.A.Marshal()...)
	data = append(data, s.txs.B.Marshal()...)
	data = append(data, s.txr.A.Marshal()...)
	data = append(data, s.txr.B.Marshal()...)
	data = append(data, commit_bal[0].Marshal()...)
	data = append(data, commit_bal[1].Marshal()...)
	data = append(data, commit_v[0].Marshal()...)
	data = append(data, commit_v[1].Marshal()...)

	hash.Write(data)
	_challenge := hash.Sum(nil)
	var challenge big.Int
	challenge.SetBytes(_challenge)

	var rp_sr sigma.Response
	rp_sr = rp_sr.Response(para_sh, challenge, s.r_txs)
	var rp_rr sigma.Response
	rp_rr = rp_rr.Response(para_rh, challenge, s.r_txr)
	var rp_sv sigma.Response
	rp_sv = rp_sv.Response(para_s, challenge, &s.v)
	var rp_rv sigma.Response
	rp_rv = rp_rv.Response(para_r, challenge, &s.v)
	var rp_bal sigma.Response
	rp_bal = rp_bal.Response(para_bal, challenge, &s.bal)
	var rp_v sigma.Response
	rp_v = rp_v.Response(para_v, challenge, &s.v)
	var rp_bal_r sigma.Response
	rp_bal_r = rp_bal_r.Response(para_bal_r, challenge, s.r_bal)
	var rp_v_r sigma.Response
	rp_v_r = rp_v_r.Response(para_v_r, challenge, s.r_v)

	endtime := time.Now()

	fmt.Println("sigma----generate commitment,challenge,response cost:", endtime.Sub(starttime))

	return (sigmaProof{
		commit: []sigma.CommitMent{
			commit_s, commit_sh, commit_r, commit_rh,
		},
		commitenc: [][]curve.PointAffine{
			commit_bal,
			commit_v,
		},
		response: []sigma.Response{
			rp_sr, rp_rr, rp_sv, rp_rv, rp_bal, rp_bal_r, rp_v, rp_v_r,
		},
		challenge: challenge,
	}), s
}

func (bp bulletProof) rangeproof(num *big.Int, bpPara bulletproof.BulletParams) bulletProof {
	v := num

	n := bpPara.N
	P := bpPara.P
	G := bpPara.G
	H := bpPara.H
	g := bpPara.Bg
	h := bpPara.Bh
	bp.bpPara = bpPara

	gamma, _ := rand.Int(rand.Reader, P)

	commitV := bulletproof.Commit(g, h, v, gamma)
	bp.commitV = commitV

	/* */
	starttime := time.Now()

	//generate commitA
	alpha, _ := rand.Int(rand.Reader, P)
	aL, _ := bulletproof.Generate_a_L(v, n)
	aR := bulletproof.Generate_a_R(aL)
	_commitA := bulletproof.CommitVectors(G, H, aL, aR)
	_commitA1 := bulletproof.CommitSingle(h, alpha)
	var commitA eccfr.G1Affine
	commitA.Add(&_commitA, &_commitA1)
	bp.commitA = commitA

	//generate commitS
	rho, _ := rand.Int(rand.Reader, P)
	sL := bulletproof.Generate_s(n)
	sR := bulletproof.Generate_s(n)
	_commitS := bulletproof.CommitVectors(G, H, sL, sR)
	_commitS1 := bulletproof.CommitSingle(h, rho)
	var commitS eccfr.G1Affine
	commitS.Add(&_commitS, &_commitS1)
	bp.commitS = commitS

	//generate challenge y,z
	y := bulletproof.Challenge_yz(commitV, g, h, commitA, commitS, int64(1))
	z := bulletproof.Challenge_yz(commitV, g, h, commitA, commitS, int64(2))
	bp.chall_y = y
	bp.chall_z = z

	//generate commitT1,commitT2
	tau1, _ := rand.Int(rand.Reader, P)
	tau2, _ := rand.Int(rand.Reader, P)
	//t1,t2
	yn := bulletproof.GenerateY(y, n)
	srYn := bulletproof.CalHadamardVec(sR, yn)
	//t2
	t2 := bulletproof.Inner_produ(sL, srYn)
	//t1
	sum := big.NewInt(0)
	//t11
	y2n := bulletproof.Generate2n(n)
	sl2n := bulletproof.Inner_produ(sL, y2n)
	z2 := big.NewInt(0)
	z2.Mul(&z, &z)
	z2.Mod(z2, P)
	t11 := big.NewInt(0)
	t11.Mul(z2, sl2n)
	t11.Mod(t11, P)
	//t12
	t12 := bulletproof.Inner_produ(sL, bulletproof.CalHadamardVec(yn, aR))
	//t13
	t13 := bulletproof.Inner_produ(bulletproof.CalVectorTimes(sL, &z), yn)
	//t14
	t14 := bulletproof.Inner_produ(bulletproof.CalVectorSub(aL, bulletproof.GenerateZ(z, n)), bulletproof.CalHadamardVec(yn, sR))
	_sum := big.NewInt(0)
	_sum.Add(t11, t12)
	_sum.Mod(_sum, P)
	sum.Add(t13, t14)
	sum.Mod(sum, P)
	t1 := big.NewInt(0)
	t1.Add(sum, _sum)
	t1.Mod(t1, P)
	commitT1 := bulletproof.Commit(g, h, t1, tau1)
	commitT2 := bulletproof.Commit(g, h, t2, tau2)
	bp.commitT1 = commitT1
	bp.commitT2 = commitT2

	//generate challenge x
	x := bulletproof.Challenge_x(commitV, g, h, commitA, commitS, commitT1, commitT2)
	bp.chall_x = x

	//generate response
	taux := bulletproof.Calculate_taux(tau1, tau2, x, z, gamma)
	miu := bulletproof.Calculate_miu(alpha, rho, x)
	lx := bulletproof.Calculate_lx(aL, z, n, sL, x)
	rx := bulletproof.Calculate_rx(yn, aR, z, n, sR, x)
	tx := bulletproof.Calculate_tx(lx, rx)
	bp.rp_taux = taux
	bp.rp_miu = miu
	bp.rp_lx = lx
	bp.rp_rx = rx
	bp.rp_tx = tx

	endtime := time.Now()

	fmt.Println("bp----generate commitment,challenge,response cost:", endtime.Sub(starttime))

	return bp
}

func (_ sender) zkpProof(params *twistededwards.CurveParams, curveid ecctedwards.ID, frmodulus *big.Int) (sender, sigmaProof, bulletProof, bulletProof) {
	var s sender
	var sigmaproof sigmaProof
	sigmaproof, s = s.sigmaprotocol(params, curveid)
	v := s.v
	bal_v := s.bal.Sub(&s.bal, &s.v)

	var bpPara bulletproof.BulletParams
	bpPara = bpPara.ParamsGen()

	var bp1 bulletProof
	bp1 = bp1.rangeproof(&v, bpPara)
	var bp2 bulletProof
	bp2 = bp2.rangeproof(bal_v, bpPara)
	return s, sigmaproof, bp1, bp2
}
