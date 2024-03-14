package offlinetx

import (
	"Asyn_CBDC/enroll"
	"Asyn_CBDC/util"
	"crypto/rand"
	"math/big"

	curve "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	ecctedwards "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark-crypto/signature"
	"github.com/consensys/gnark-crypto/signature/eddsa"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
)

type PrimitiveAccount struct {
	G0      curve.PointAffine
	Tracesk util.Privatekey
	Tracepk util.Publickey
	Delta   big.Int
	G1      curve.PointAffine
	H       curve.PointAffine
	Bal     big.Int
	Sk      util.Privatekey
	Pk      util.Publickey
	R       *big.Int
	Acc     []curve.PointAffine
}

type DeriveKeypair struct {
	DPk     util.Publickey
	DSk     util.Privatekey
	Deriver *big.Int
}

type DeriveAccount struct {
	G0      curve.PointAffine
	G1      curve.PointAffine
	H       curve.PointAffine
	Delta   big.Int
	Bal     big.Int
	Keypair DeriveKeypair
	R       *big.Int
	Acc     []curve.PointAffine
}

type Offline struct {
	Signature []byte
	Sigpk     signature.PublicKey
	Oldseq    big.Int
	Newseq    big.Int
	G0        curve.PointAffine
	Bal       big.Int
	Tracesk   util.Privatekey
	Tracepk   util.Publickey
	Delta     big.Int
	G1        curve.PointAffine
	H         curve.PointAffine
	Sk        util.Privatekey
	Pk        util.Publickey
	OldAcc    []curve.PointAffine
	Deriveacc DeriveAccount
	Ar        *big.Int
	Apk       util.Publickey
	CipherTk  []curve.PointAffine
}

func (o Offline) Execution(params *twistededwards.CurveParams, hash hash.Hash, curveid ecctedwards.ID) Offline {
	//=========================primitive acc ==============================
	modulus := params.Order
	var oldseq big.Int
	oldseq.Sub(modulus, big.NewInt(3))
	o.Oldseq = oldseq

	var balance big.Int
	balance.SetString("200", 10)

	var testacc PrimitiveAccount
	testacc = testacc.GetAccount(params, hash, balance, oldseq)
	o.Delta = testacc.Delta

	o.Tracepk = testacc.Tracepk
	o.Tracesk = testacc.Tracesk

	o.Sk = testacc.Sk
	o.Pk = testacc.Pk
	oldacc := testacc.Acc
	//=====================================================================

	o.OldAcc = oldacc
	//sign
	_c1x := oldacc[0].X
	//_c2x := acccipher.B.X
	c1x := _c1x.Bytes()
	//c2x := _c2x.Bytes()
	var _msg []byte
	_msg = append(_msg, c1x[:]...)
	//var msg []byte
	//msg = append(msg, c2x[:]...)
	sigprivateKey, _ := eddsa.New(curveid, rand.Reader)
	sigpublicKey := sigprivateKey.Public()
	o.Sigpk = sigpublicKey
	signature := util.SignAcc(sigprivateKey, _msg, hash)
	o.Signature = signature

	//DAcc
	var newseq big.Int
	newseq.Sub(modulus, big.NewInt(4))
	o.Newseq = newseq
	var Dacc DeriveAccount
	Dacc = Dacc.DaccountGen(params, hash, newseq, testacc)
	o.Deriveacc = Dacc
	o.Bal = Dacc.Bal

	o.G0 = Dacc.G0
	o.G1 = Dacc.G1
	o.H = Dacc.H

	//C_TK
	_aprivatekey, _ := rand.Int(rand.Reader, params.Order)
	var _ah curve.PointAffine
	_ah.X.SetBigInt(params.Base[0])
	_ah.Y.SetBigInt(params.Base[1])
	var _apublickey curve.PointAffine
	_apublickey.ScalarMultiplication(&_ah, _aprivatekey)
	o.Apk = util.Publickey{Pk: _apublickey}

	ar, _ := rand.Int(rand.Reader, params.Order)
	o.Ar = ar
	cipherTK := o.Apk.Encrypt(testacc.Tracepk.Pk, ar, _ah)
	o.CipherTk = cipherTK
	return o
}

func (t PrimitiveAccount) GetAccount(params *twistededwards.CurveParams, hashFunc hash.Hash, balance big.Int, seq big.Int) PrimitiveAccount {
	t.Bal = balance

	var enroll enroll.Enroll
	enroll = enroll.Init(params, hashFunc)

	t.Tracesk = enroll.Tracesk
	t.Tracepk = enroll.Tracepk

	_tacSk := t.Tracesk.Sk
	_data3 := _tacSk.Bytes()
	data3 := append(_data3, seq.Bytes()...)
	var delta_3 big.Int
	delta_3 = util.Calculate_delta(data3, hashFunc)

	t.Delta = delta_3
	t.Bal = balance
	t.G1 = enroll.G1
	_g1 := t.G1
	t.G0 = enroll.G0
	_g0 := t.G0

	var _g1delta3 curve.PointAffine
	_g1delta3.ScalarMultiplication(&_g1, &t.Delta)
	var _g0bal curve.PointAffine
	_g0bal.ScalarMultiplication(&_g0, &balance)
	var plaintext curve.PointAffine
	plaintext.Add(&_g1delta3, &_g0bal)

	t.H = enroll.H
	t.Sk = enroll.Sk
	t.Pk = enroll.Pk
	t.R = enroll.R

	_publickey := t.Pk.Pk
	_h := t.H
	r := t.R

	publickey := util.Publickey{Pk: _publickey}

	t.Acc = publickey.Encrypt(plaintext, r, _h)

	return t
}

func (d DeriveKeypair) DkeypairGen(order *big.Int, pk util.Publickey, sk util.Privatekey) DeriveKeypair {
	d.Deriver, _ = rand.Int(rand.Reader, order)

	var dsk big.Int
	dsk.Mul(d.Deriver, sk.Sk)
	d.DSk = util.Privatekey{Sk: &dsk}

	var dpk curve.PointAffine
	dpk.ScalarMultiplication(&pk.Pk, d.Deriver)
	d.DPk = util.Publickey{Pk: dpk}

	return d
}

func (d DeriveAccount) DaccountGen(params *twistededwards.CurveParams, hashFunc hash.Hash, seq big.Int, priacc PrimitiveAccount) DeriveAccount {
	_data4 := priacc.Tracesk.Sk.Bytes()
	data4 := append(_data4, seq.Bytes()...)
	var delta_4 big.Int
	delta_4 = util.Calculate_delta(data4, hashFunc)

	d.Delta = delta_4

	var derivekey DeriveKeypair
	derivekey = derivekey.DkeypairGen(params.Order, priacc.Pk, priacc.Sk)

	d.Keypair = derivekey

	d.Bal = priacc.Bal

	dr, _ := rand.Int(rand.Reader, params.Order)
	d.R = dr

	var _g1delta4 curve.PointAffine
	_g1delta4.ScalarMultiplication(&priacc.G1, &delta_4)
	var _g1delta3 curve.PointAffine
	_g1delta3.ScalarMultiplication(&priacc.G1, &priacc.Delta)
	g0bal := priacc.Sk.Decryptacc(priacc.Acc, _g1delta3)
	var dplaintext curve.PointAffine
	dplaintext.Add(&_g1delta4, &g0bal)

	dacccipher := derivekey.DPk.Encrypt(dplaintext, dr, priacc.H)
	d.Acc = dacccipher

	d.G0 = priacc.G0
	d.G1 = priacc.G1
	d.H = priacc.H
	return d
}
