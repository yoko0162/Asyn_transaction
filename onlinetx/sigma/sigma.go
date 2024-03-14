package sigma

import (
	"Asyn_CBDC/util"
	"crypto/rand"
	"math/big"

	curve "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
)

type CommitParams struct {
	r *big.Int
}

type CommitMent struct {
	Commit curve.PointAffine
}

type Response struct {
	Rp big.Int
}

func (c CommitMent) ParamsGen(params *twistededwards.CurveParams) CommitParams {
	r, _ := rand.Int(rand.Reader, params.Order)
	return CommitParams{r: r}
}
func (c CommitMent) Commitmul(params CommitParams, g curve.PointAffine) CommitMent {
	r := params.r
	var commit curve.PointAffine
	commit.ScalarMultiplication(&g, r)
	return CommitMent{Commit: commit}
}
func (c CommitMent) Commitmuladd(params1 CommitParams, params2 CommitParams, g1 curve.PointAffine, g2 curve.PointAffine) CommitMent {
	r1 := params1.r
	r2 := params2.r

	var commit curve.PointAffine
	var tmp1 curve.PointAffine
	tmp1.ScalarMultiplication(&g1, r1)
	var tmp2 curve.PointAffine
	tmp2.ScalarMultiplication(&g2, r2)
	commit.Add(&tmp1, &tmp2)

	return CommitMent{Commit: commit}
}
func (c CommitMent) CommitencValid(tb CommitParams, tr CommitParams, pk util.Publickey, h curve.PointAffine, g curve.PointAffine) []curve.PointAffine {
	var plain curve.PointAffine
	plain.ScalarMultiplication(&g, tb.r)
	Cipher := pk.Encrypt(plain, tr.r, h)
	return Cipher
}
func (r Response) Response(params CommitParams, challenge big.Int, witness *big.Int) Response {
	var _res big.Int
	_res.Mul(&challenge, witness)
	var res big.Int
	res.Add(params.r, &_res)
	return Response{Rp: res}
}
