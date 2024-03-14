package onlinetx

import (
	"Asyn_CBDC/onlinetx/sigma"
	"fmt"
	"math/big"
	"time"

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

func Verify() {
	curveid := ecctedwards.BN254
	params, _ := twistededwards.GetCurveParams(curveid)

	var s sender
	sigmaproof, s := s.Sigmaprotocol(params, curveid)

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

	fmt.Println("rp_sr*h==commit_sh+challenge*txs.c2:", rp_sr_h.Equal(&commit_sh_chal_txsb))
	fmt.Println("rp_sr*pk+rp_sv*g0==commit_s+challenge*txs.c1:", rp_sr_pk_rp_sv_g0.Equal(&commit_s_chal_txsa))
	fmt.Println("rp_rr*h==commit_rh+challenge*txr.c2:", rp_rr_h.Equal(&commit_rh_chal_txrb))
	fmt.Println("rp_rr*pk+rp_rv*g0==commit_r+challenge*txr.c1:", rp_rr_pk_rp_rv_g0.Equal(&commit_r_chal_txra))
	fmt.Println("Enc(rp_bal)==commit_bal+challenge*cipher_bal:", (commit_bal1_chal_bal1.Equal(&cipher_rp_bal[0])) && (commit_bal2_chal_bal2.Equal(&cipher_rp_bal[1])))
	fmt.Println("Enc(rp_v)==commit_v+challenge*cipher_v:", (commit_v1_chal_v1.Equal(&cipher_rp_v[0])) && (commit_v2_chal_v2.Equal(&cipher_rp_v[1])))
	fmt.Println("verify:", endtime.Sub(starttime))

}
