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

func GenUpdateToken(w string, wPrime string) *big.Int {
	token := new(big.Int)
	temp := new(big.Int)

	kw := GenKw(w, "msk")
	kwPrime := GenKw(wPrime, "msk")

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
