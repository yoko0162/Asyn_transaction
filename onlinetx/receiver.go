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

	curve "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	ecctedwards "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
)

type receiver struct {
	pk          curve.PointAffine
	dacc        offlinetx.DeriveAccount
	v           big.Int       //from sender
	beta        *big.Int      //from sender
	r_txr       *big.Int      //from sender
	txr         transactionTX //from central bank
	bal         big.Int
	apk         util.Publickey
	r_bal       *big.Int
	cipher_bal  []curve.PointAffine
	_trans      curve.PointAffine
	h           curve.PointAffine
	dateg       curve.PointAffine
	dateh       curve.PointAffine
	commentdate curve.PointAffine
	commentr    *big.Int
	date        *big.Int
}

func accAggregation(tx transactionTX, dacc offlinetx.DeriveAccount) []curve.PointAffine {
	txc1 := tx.A
	txc2 := tx.B

	dacc1 := dacc.Acc[0]
	dacc2 := dacc.Acc[1]

	var c1 curve.PointAffine
	c1.Add(&txc1, &dacc1)
	var c2 curve.PointAffine
	c2.Add(&txc2, &dacc2)

	return []curve.PointAffine{c1, c2}
}

func (r receiver) execution(params *twistededwards.CurveParams, s sender, o offlinetx.Offline) receiver {
	r.pk = o.Pk.Pk
	r.v = s.v
	r.beta = s.beta
	r.r_txr = s.r_txr
	r.txr = s.txr
	r.dacc = o.Deriveacc
	r.bal = o.Bal
	r.dateg = o.CommentG
	r.dateh = o.CommentH
	r.commentdate = *o.Comment
	r.commentr = o.Commentr
	r.date = o.Date

	rb, _ := rand.Int(rand.Reader, params.Order)
	r.r_bal = rb

	var _trans curve.PointAffine
	_trans.X.SetBigInt(params.Base[0])
	_trans.Y.SetBigInt(params.Base[1])
	r._trans = _trans
	var aplain_bal curve.PointAffine
	aplain_bal.ScalarMultiplication(&_trans, &r.bal)
	var h curve.PointAffine
	h.X.SetBigInt(params.Base[0])
	h.Y.SetBigInt(params.Base[1])
	r.h = h
	r.cipher_bal = r.apk.Encrypt(&aplain_bal, r.r_bal, r.h)
	return r
}

func (r receiver) sigmaprotocol(params *twistededwards.CurveParams, curveid ecctedwards.ID, s sender) (sigmaProof, receiver) {
	hashFunc := hash.MIMC_BN254

	var o offlinetx.Offline
	o = o.Execution(params, hashFunc, curveid)

	r = r.execution(params, s, o)

	pk := r.pk
	bv := big.NewInt(1)
	bv.Add(&r.bal, &r.v)
	delta := o.Deriveacc.Delta
	_betar_gammar := big.NewInt(1)
	_betar_gammar = _betar_gammar.Mul(r.beta, r.r_txr)
	betar_gammar := big.NewInt(1)
	betar_gammar = betar_gammar.Mul(o.Deriveacc.Keypair.Deriver, o.Deriveacc.R)
	betar_gammar = betar_gammar.Add(betar_gammar, _betar_gammar)

	/* */
	starttime := time.Now()

	acc := accAggregation(r.txr, r.dacc)

	var commit sigma.CommitMent
	para_h := commit.ParamsGen(params)
	para_g0 := commit.ParamsGen(params)
	para_g1 := commit.ParamsGen(params)
	para_date := commit.ParamsGen(params)
	para_dater := commit.ParamsGen(params)

	para_bal := commit.ParamsGen(params)
	para_bal_r := commit.ParamsGen(params)

	commit_date := commit.Commitmuladd(para_date, para_dater, r.dateg, r.dateh)

	commit_h := commit.Commitmul(para_h, &r.dacc.H)
	commit_g0g1 := commit.Commitmuladd(para_g0, para_g1, r.dacc.G0, r.dacc.G1)
	commit_pk := commit.Commitmul(para_h, &pk)
	var _commit_g0g1pk curve.PointAffine
	_commit_g0g1pk.Add(&commit_g0g1.Commit, &commit_pk.Commit)
	commit_g0g1pk := sigma.CommitMent{Commit: _commit_g0g1pk}

	commit_bal := commit.CommitencValid(para_bal, para_bal_r, r.apk, r.h, r._trans)

	hash := hashFunc.New()

	var data []byte
	data = append(data, commit_h.Commit.Marshal()...)
	data = append(data, commit_g0g1.Commit.Marshal()...)
	data = append(data, commit_pk.Commit.Marshal()...)
	data = append(data, commit_bal[0].Marshal()...)
	data = append(data, commit_bal[1].Marshal()...)
	data = append(data, acc[0].Marshal()...)
	data = append(data, acc[1].Marshal()...)
	data = append(data, commit_date.Commit.Marshal()...)
	data = append(data, r.commentdate.Marshal()...)

	hash.Write(data)
	_challenge := hash.Sum(nil)
	var challenge big.Int
	challenge.SetBytes(_challenge)

	var rp_h sigma.Response
	rp_h = rp_h.Response(para_h, challenge, betar_gammar)
	var rp_g0 sigma.Response
	rp_g0 = rp_g0.Response(para_g0, challenge, bv)
	var rp_g1 sigma.Response
	rp_g1 = rp_g1.Response(para_g1, challenge, delta)
	var rp_bal sigma.Response
	rp_bal = rp_bal.Response(para_bal, challenge, &r.bal)
	var rp_bal_r sigma.Response
	rp_bal_r = rp_bal_r.Response(para_bal_r, challenge, r.r_bal)

	var rp_date sigma.Response
	rp_date = rp_date.Response(para_date, challenge, r.date)
	var rp_dater sigma.Response
	rp_dater = rp_dater.Response(para_dater, challenge, r.commentr)

	endtime := time.Now()

	fmt.Println("sigma----generate commitment,challenge,response cost:", endtime.Sub(starttime))

	return (sigmaProof{
		commit: []sigma.CommitMent{
			commit_g0g1pk, commit_h, commit_date,
		},
		commitenc: [][]curve.PointAffine{
			commit_bal,
		},
		response: []sigma.Response{
			rp_h, rp_g0, rp_g1, rp_bal, rp_bal_r, rp_date, rp_dater,
		},
		challenge: challenge,
	}), r
}

func (_ receiver) zkpProof(params *twistededwards.CurveParams, curveid ecctedwards.ID, frmodulus *big.Int, s sender) (receiver, sigmaProof, bulletProof) {
	var r receiver
	var sigmaproof sigmaProof
	sigmaproof, r = r.sigmaprotocol(params, curveid, s)
	bal := r.bal

	var bpPara bulletproof.BulletParams
	bpPara = bpPara.ParamsGen()

	var bp1 bulletProof
	bp1 = bp1.rangeproof(&bal, bpPara)

	return r, sigmaproof, bp1
}
