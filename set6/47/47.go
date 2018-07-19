package main

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"math/big"
)

var _ = fmt.Sprintf("")

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
		m:         []interval{interval{lo, hi}},
	}
}

func (x *rsaBreaker) findFirstS() {
	x.s = new(big.Int).Mul(x.b, three)
	x.s.Div(x.N, x.s)
	e := big.NewInt(int64(x.E))

	cPrime := new(big.Int)
	for {
		cPrime.Exp(x.s, e, x.N)
		cPrime.Mul(cPrime, x.c)
		cPrime.Mod(cPrime, x.N)
		if err := x.oracle(cPrime.Bytes()); err != nil {
			break
		}
		x.s.Add(x.s, one)
	}
}

func main() {
	priv, err := rsa.GenerateKey(rand.Reader, 256)
	if err != nil {
		panic(err)
	}
	oracle := rsaPaddingOracle(priv)
	pub := &priv.PublicKey
	ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, pub, []byte("hello world"))
	if err != nil {
		panic(err)
	}
	x := newRSABreaker(pub, oracle, ciphertext)
	x.findFirstS()
}
