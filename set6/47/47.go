package main

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"io"
	"math/big"
	"os"
)

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
	twoB   *big.Int
	threeB *big.Int
	c      *big.Int
	e      *big.Int
	s      *big.Int
	ivals  []interval
}

// size returns the size of an arbitrary-precision integer in bytes.
func size(z *big.Int) int {
	return (z.BitLen() + 7) / 8
}

func newRSABreaker(pub *rsa.PublicKey, oracle func([]byte) error, ciphertext []byte) *rsaBreaker {
	x := new(rsaBreaker)
	x.PublicKey = *pub
	x.oracle = oracle

	z := big.NewInt(int64(8 * (size(pub.N) - 2)))
	z.Exp(two, z, nil)
	x.twoB = new(big.Int).Mul(two, z)
	x.threeB = new(big.Int).Mul(three, z)

	x.c = z.SetBytes(ciphertext)
	x.e = big.NewInt(int64(pub.E))
	x.s = z.Div(pub.N, x.threeB)
	cPrime := new(big.Int)
	for {
		cPrime.Exp(x.s, x.e, x.N)
		cPrime.Mul(cPrime, x.c)
		cPrime.Mod(cPrime, x.N)
		if err := x.oracle(cPrime.Bytes()); err != nil {
			break
		}
		x.s.Add(x.s, one)
	}
	x.ivals = []interval{
		interval{
			new(big.Int).Set(x.twoB),
			new(big.Int).Set(x.threeB),
		},
	}
	return x
}

// equal returns true if two arbitrary-precision integers are equal.
func equal(z1, z2 *big.Int) bool {
	return z1.Cmp(z2) == 0
}

// Values returns a channel that yields successive values in [lo, hi].
func Values(lo, hi *big.Int) <-chan *big.Int {
	z1 := new(big.Int).Set(lo)
	z2 := new(big.Int).Set(hi)

	ch := make(chan *big.Int)
	go func() {
		lo, hi := z1, z2
		for {
			if lo.Cmp(hi) > 0 {
				break
			}
			ch <- new(big.Int).Set(lo)
			lo.Add(lo, one)
		}
		close(ch)
	}()
	return ch
}

func (x *rsaBreaker) intervalRValues(m interval) <-chan *big.Int {
	lo := new(big.Int).Mul(m.lo, x.s)
	lo.Sub(lo, x.threeB)
	lo.Add(lo, one)
	lo.Div(lo, x.N) // Ceiling division?

	hi := new(big.Int).Mul(m.hi, x.s)
	hi.Sub(hi, x.twoB)
	hi.Div(hi, x.N)

	return Values(lo, hi)
}

func (x *rsaBreaker) generateIntervals() {
	ivals := []interval{}
	z := new(big.Int)
	for _, m := range x.ivals {
		for r := range x.intervalRValues(m) {
			lo := new(big.Int).Mul(r, x.N)
			lo.Add(lo, x.twoB)
			// Perform ceiling, not floor division.
			lo.DivMod(lo, x.s, z)
			if !equal(z, zero) {
				lo.Add(lo, one)
			}
			if lo.Cmp(m.lo) < 0 {
				lo = m.lo
			}
			hi := new(big.Int).Mul(r, x.N)
			hi.Add(hi, x.threeB)
			hi.Sub(hi, one)
			hi.Div(hi, x.s)
			if hi.Cmp(m.hi) > 0 {
				hi = m.hi
			}
			ivals = append(ivals, interval{lo, hi})
		}
	}
	x.ivals = ivals
}

func (x *rsaBreaker) searchOneRValues(hi *big.Int) <-chan *big.Int {
	lo := new(big.Int).Mul(hi, x.s)
	lo.Sub(lo, x.twoB)
	lo.Mul(two, lo)
	lo.Div(lo, x.N) // Ceiling division?

	return Values(lo, nil)
}

func (x *rsaBreaker) searchOne() {
	m := x.ivals[0]
	cPrime := new(big.Int)
	for r := range x.searchOneRValues(m.hi) {
		lo := new(big.Int).Mul(r, x.N)
		lo.Add(lo, x.twoB)
		lo.Div(lo, m.hi) // Ceiling division?

		hi := new(big.Int).Mul(r, x.N)
		hi.Add(hi, x.threeB)
		hi.Div(hi, m.lo) // Ceiling division?

		for x.s = range Values(lo, hi) {
			cPrime.Exp(x.s, x.e, x.N)
			cPrime.Mul(cPrime, x.c)
			cPrime.Mod(cPrime, x.N)
			if err := x.oracle(cPrime.Bytes()); err != nil {
				break
			}
		}
	}
}

func (x *rsaBreaker) searchMany() {
	x.s.Add(x.s, one)

	cPrime := new(big.Int)
	for {
		cPrime.Exp(x.s, x.e, x.N)
		cPrime.Mul(cPrime, x.c)
		cPrime.Mod(cPrime, x.N)
		if err := x.oracle(cPrime.Bytes()); err != nil {
			break
		}
		x.s.Add(x.s, one)
	}
}

func (x *rsaBreaker) breakOracle() []byte {
	for {
		if len(x.ivals) == 1 {
			if m := x.ivals[0]; equal(m.lo, m.hi) {
				return m.lo.Bytes()
			}
			x.searchOne()
		}
		x.searchMany()
	}
}

func breakRSA(in io.Reader, pub *rsa.PublicKey, oracle func([]byte) error) error {
	input := bufio.NewScanner(in)
	for input.Scan() {
		ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, pub, input.Bytes())
		if err != nil {
			return err
		}
		x := newRSABreaker(pub, oracle, ciphertext)
		plaintext := x.breakOracle()

		fmt.Println(string(plaintext))
	}
	return input.Err()
}

func main() {
	priv, err := rsa.GenerateKey(rand.Reader, 256)
	if err != nil {
		panic(err)
	}
	pub := &priv.PublicKey
	oracle := rsaPaddingOracle(priv)

	files := os.Args[1:]
	// If no files are specified, read from standard input.
	if len(files) == 0 {
		if err := breakRSA(os.Stdin, pub, oracle); err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
		return
	}
	for _, name := range files {
		f, err := os.Open(name)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			continue
		}
		if err := breakRSA(f, pub, oracle); err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
		f.Close()
	}
}
