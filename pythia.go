package pythia

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"math/big"

	"golang.org/x/crypto/bn256"
)

func BilinearPairing(x *big.Int, y *big.Int) *bn256.GT {
	g1 := new(bn256.G1).ScalarBaseMult(x)
	g2 := new(bn256.G2).ScalarBaseMult(y)
	gt := bn256.Pair(g1, g2)
	return gt
}

func GenKw(w string, msk string) []byte {
	h := hmac.New(sha256.New, []byte(msk))
	h.Write([]byte(w))
	return h.Sum(nil)
}

func Eval(w string, t string, x []byte, msk string) *bn256.GT {
	tHash := sha256.Sum256([]byte(t))
	kw := GenKw(w, msk)

	xInt := new(big.Int)
	xInt.SetBytes(x)

	k1 := new(big.Int)
	k1.SetBytes(kw)

	k1.Mul(k1, xInt)

	k2 := new(big.Int)
	k2.SetBytes(tHash[:])

	k1.Mod(k1, bn256.Order)
	k2.Mod(k2, bn256.Order)

	return BilinearPairing(k1, k2)

}

func HashBlind(x string) ([]byte, *big.Int) {
	xHash := sha256.Sum256([]byte(x))
	xHashInt := new(big.Int)
	xHashInt.SetBytes(xHash[:])

	r, _ := rand.Int(rand.Reader, bn256.Order)
	rInv := new(big.Int)

	for ret := rInv.ModInverse(r, bn256.Order); ret == nil; {
		r, _ = rand.Int(rand.Reader, bn256.Order)
	}

	xHashInt.Mul(xHashInt, r)

	return xHashInt.Bytes(), rInv

}

func UnblindGT(gt *bn256.GT, rInv *big.Int) []byte {
	gt.ScalarMult(gt, rInv)
	return gt.Marshal()
}

func GenUpdateToken(w string, wPrime string, msk string) *big.Int {
	token := new(big.Int)
	temp := new(big.Int)

	kw := GenKw(w, msk)
	kwPrime := GenKw(wPrime, msk)

	token.SetBytes(kwPrime)
	temp.SetBytes(kw)
	temp.ModInverse(temp, bn256.Order)

	token.Mul(token, temp)

	return token
}

func ApplyUpdateToken(xHash []byte, updateToken *big.Int) []byte {
	gt := new(bn256.GT)
	gt.Unmarshal(xHash)

	gt.ScalarMult(gt, updateToken)

	return gt.Marshal()

}

func GenerateProof(blindHash []byte, saltHash []byte, kw []byte, blindResult []byte) ([]byte, *big.Int, *big.Int) {
	k1 := new(big.Int).SetBytes(blindHash)
	k2 := new(big.Int).SetBytes(saltHash)

	kwInt := new(big.Int).SetBytes(kw)

	beta := BilinearPairing(k1, k2)

	pQ := new(bn256.G1).ScalarBaseMult(kwInt)
	p := pQ.Marshal()

	v, _ := rand.Int(rand.Reader, bn256.Order)

	t1Q := new(bn256.G1).ScalarBaseMult(v)
	t1 := t1Q.Marshal()

	t2Gt := BilinearPairing(k1, k2)
	t2Gt.ScalarMult(t2Gt, v)
	t2 := t2Gt.Marshal()

	hash := sha256.New()
	hash.Write(p)
	hash.Write(beta.Marshal())
	hash.Write(blindResult)
	hash.Write(t1)
	hash.Write(t2)

	c := hash.Sum(nil)

	cInt := new(big.Int).SetBytes(c)

	u := new(big.Int)
	u.Mul(cInt, kwInt)
	u.Sub(v, u)
	u.Mod(u, bn256.Order)

	return p, cInt, u

}

func VerifyProof(blindHash []byte, salt string, blindResult []byte, p []byte, c *big.Int, u *big.Int) bool {
	k1 := new(big.Int).SetBytes(blindHash)

	saltHash := sha256.Sum256([]byte(salt))
	k2 := new(big.Int).SetBytes(saltHash[:])

	beta := BilinearPairing(k1, k2)

	uQ := new(bn256.G1).ScalarBaseMult(u)
	pc := new(bn256.G1)
	pc.Unmarshal(p)
	pc.ScalarMult(pc, c)

	t1 := new(bn256.G1).Add(uQ, pc).Marshal()

	betau := BilinearPairing(k1, k2)
	betau.ScalarMult(betau, u)
	yc := new(bn256.GT)
	yc.Unmarshal(blindResult)
	yc.ScalarMult(yc, c)

	t2 := new(bn256.GT).Add(betau, yc).Marshal()

	hash := sha256.New()
	hash.Write(p)
	hash.Write(beta.Marshal())
	hash.Write(blindResult)
	hash.Write(t1)
	hash.Write(t2)

	cPrime := hash.Sum(nil)
	cPrimeInt := new(big.Int).SetBytes(cPrime)

	return c.Cmp(cPrimeInt) == 0
}
