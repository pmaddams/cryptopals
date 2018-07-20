package main

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"math/big"
)

var _ = fmt.Sprintf("")

var (
	zero  = big.NewInt(0)
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
	c      *big.Int
	b      *big.Int
	s      *big.Int
	ivals  []interval
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
		c:         new(big.Int).SetBytes(ciphertext),
		b:         b,
		ivals:     []interval{interval{lo, hi}},
	}
}

func (x *rsaBreaker) searchFirst() {
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

func (x *rsaBreaker) searchNext() {
	switch len(x.ivals) {
	case 0:
		panic("searchNext: no search space")
	case 1:
		x.searchOne()
	default:
		x.searchMany()
	}
}

func (x *rsaBreaker) searchMany() {
	x.s.Add(x.s, one)

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

func (x *rsaBreaker) searchOne() {
	rValues := func(hi *big.Int) <-chan *big.Int {
		ch := make(chan *big.Int)
		go func() {
			r := new(big.Int).Mul(hi, x.s)
			z := new(big.Int).Mul(two, x.b)
			r.Sub(r, z)
			r.Mul(two, r)
			r.DivMod(r, x.N, z)
			if !equal(z, zero) {
				r.Add(r, one) // Ceiling division?
			}
			for {
				ch <- new(big.Int).Set(r)
				r.Add(r, one)
			}
		}
		return ch
	}
}

// equal returns true if two arbitrary-precision integers are equal.
func equal(z1, z2 *big.Int) bool {
	return z1.Cmp(z2) == 0
}

func (x *rsaBreaker) generateIntervals() {
	rValues := func(m interval) <-chan *big.Int {
		ch := make(chan *big.Int)
		go func() {
			r := new(big.Int).Mul(m.lo, x.s)
			z := new(big.Int).Mul(three, x.b)
			r.Sub(r, z)
			r.Add(r, one)
			r.DivMod(r, x.N, z)
			if !equal(z, zero) {
				r.Add(r, one) // Ceiling division?
			}
			rmax := new(big.Int).Mul(m.hi, x.s)
			z.Mul(x.b, two)
			rmax.Sub(rmax, z)
			rmax.Div(rmax, x.N)
			for !equal(r, rmax) {
				ch <- new(big.Int).Set(r)
				r.Add(r, one)
			}
			close(ch)
		}()
		return ch
	}
	ivals := []interval{}
	z := new(big.Int)
	for _, m := range x.ivals {
		for r := range rValues(m) {
			lo := new(big.Int).Mul(two, x.b)
			z.Mul(r, x.N)
			lo.Add(lo, z)
			// Perform ceiling, not floor division.
			lo.DivMod(lo, x.s, z)
			if !equal(z, zero) {
				lo.Add(lo, one)
			}
			if lo.Cmp(m.lo) < 0 {
				lo = m.lo
			}
			hi := new(big.Int).Mul(three, x.b)
			hi.Sub(hi, one)
			z.Mul(r, x.N)
			hi.Add(hi, z)
			hi.Div(hi, x.s)
			if hi.Cmp(m.hi) > 0 {
				hi = m.hi
			}
			ivals = append(ivals, interval{lo, hi})
		}
	}
	x.ivals = ivals
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
	x.searchFirst()
}
