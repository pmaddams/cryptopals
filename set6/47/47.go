package main

import (
	"crypto/rsa"
	"math/big"
)

var (
	one   = big.NewInt(1)
	two   = big.NewInt(2)
	three = big.NewInt(3)
)

func rsaPaddingOracle(priv *rsa.PrivateKey) func([]byte) error {
	return func(ciphertext []byte) error {
		_, err := rsa.DecryptPKCS1v15(nil, priv, ciphertext)
		return err
	}
}

type interval struct {
	lo *big.Int
	hi *big.Int
}

type rsaBreaker struct {
	rsa.PublicKey
	oracle func([]byte) error
	b      *big.Int
	c      *big.Int
	s      *big.Int
	m      []interval
}

// size returns the size of an arbitrary-precision integer in bytes.
func size(z *big.Int) int {
	return (z.BitLen() + 7) / 8
}

func newRSABreaker(pub *rsa.PublicKey, oracle func([]byte) error, ciphertext []byte) *rsaBreaker {
	z := big.NewInt(int64(8 * (size(pub.N) - 2)))
	b := z.Exp(two, z, nil)

	lo := new(big.Int).Mul(two, b)
	hi := new(big.Int).Mul(three, b)
	hi.Sub(hi, one)

	return &rsaBreaker{
		PublicKey: *pub,
		oracle:    oracle,
		b:         b,
		c:         new(big.Int).SetBytes(ciphertext),
		s:         new(big.Int),
		m:         []interval{interval{lo, hi}},
	}
}

func main() {
}
