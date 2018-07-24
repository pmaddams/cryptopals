package main

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"errors"
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

// size returns the size of an arbitrary-precision integer in bytes.
func size(z *big.Int) int {
	return (z.BitLen() + 7) / 8
}

// copyRight copies a source buffer to the right side of a destination buffer.
func copyRight(dst, src []byte) {
	dst = dst[len(dst)-len(src):]
	copy(dst, src)
}

func rsaPaddingOracle(priv *rsa.PrivateKey) func([]byte) error {
	return func(buf []byte) error {
		c := new(big.Int).SetBytes(buf)
		p := c.Exp(c, priv.D, priv.N)

		res := make([]byte, size(priv.N))
		copyRight(res, p.Bytes())

		if res[0] != 0x00 || res[1] != 0x02 {
			return errors.New("invalid padding")
		}
		return nil
	}
}

type interval struct {
	lo *big.Int
	hi *big.Int
}

func makeInterval(lo, hi *big.Int) interval {
	return interval{
		new(big.Int).Set(lo),
		new(big.Int).Set(hi),
	}
}

type rsaBreaker struct {
	oracle func([]byte) error
	e      *big.Int
	n      *big.Int
	twoB   *big.Int
	threeB *big.Int
	c      *big.Int
	s      *big.Int
	ivals  []interval
}

func newRSABreaker(pub *rsa.PublicKey, oracle func([]byte) error, ciphertext []byte) *rsaBreaker {
	x := new(rsaBreaker)
	x.oracle = oracle
	x.e = big.NewInt(int64(pub.E))
	x.n = new(big.Int).Set(pub.N)

	z := big.NewInt(int64(8 * (size(x.n) - 2)))
	b := z.Exp(two, z, nil)
	x.twoB = new(big.Int).Mul(two, b)
	x.threeB = new(big.Int).Mul(three, b)

	fmt.Printf("twoB:\n%x\nthreeB:\n%x\n", x.twoB, x.threeB)

	x.c = new(big.Int).SetBytes(ciphertext)
	x.s, z = new(big.Int).DivMod(x.n, x.threeB, z)
	if !equal(z, zero) {
		x.s.Add(x.s, one)
	}
	for {
		cPrime := z.Exp(x.s, x.e, x.n)
		cPrime.Mul(cPrime, x.c)
		cPrime.Mod(cPrime, x.n)
		if err := x.oracle(cPrime.Bytes()); err == nil {
			break
		}
		x.s.Add(x.s, one)
		fmt.Printf("s: %x\n", x.s)
	}
	x.ivals = []interval{
		interval{
			new(big.Int).Set(x.twoB),
			new(big.Int).Sub(x.threeB, one),
		},
	}
	return x
}

// equal returns true if two arbitrary-precision integers are equal.
func equal(z1, z2 *big.Int) bool {
	return z1.Cmp(z2) == 0
}

// Values returns a channel that iterates over successive values in [lo, hi].
func Values(lo, hi *big.Int) <-chan *big.Int {
	ch := make(chan *big.Int)
	go func() {
		z := new(big.Int).Set(lo)
		for {
			if z.Cmp(hi) > 0 {
				break
			}
			ch <- z
			z.Add(z, one)
		}
		close(ch)
	}()
	return ch
}

func (x *rsaBreaker) intervalRValues(m interval) <-chan *big.Int {
	lo := new(big.Int).Mul(m.lo, x.s)
	lo.Sub(lo, x.threeB)
	lo.Add(lo, one)
	z := new(big.Int)
	lo.DivMod(lo, x.n, z)
	if !equal(z, zero) {
		lo.Add(lo, one)
	}
	hi := new(big.Int).Mul(m.hi, x.s)
	hi.Sub(hi, x.twoB)
	hi.Div(hi, x.n)

	fmt.Printf("minR: %x\nmaxR: %x\n", lo, hi)
	if !equal(lo, hi) {
		panic("fail")
	}

	return Values(lo, hi)
}

func (x *rsaBreaker) generateIntervals() {
	ivals := []interval{}
	lo, hi, z := new(big.Int), new(big.Int), new(big.Int)
	for _, m := range x.ivals {
		for r := range x.intervalRValues(m) {
			fmt.Printf("twoB:\n%x\nthreeB:\n%x\n", x.twoB, x.threeB)
			fmt.Printf("n:\n%x\n", x.n)
			fmt.Printf("current r value:\n%x\n", r)
			fmt.Printf("current s value:\n%x\n", x.s)
			lo.Mul(r, x.n)
			lo.Add(lo, x.twoB)
			fmt.Printf("lo before:\n%x\n", lo)
			lo.DivMod(lo, x.s, z)
			if !equal(z, zero) {
				lo.Add(lo, one)
			}
			fmt.Printf("lo after:\n%x\n", lo)
			if lo.Cmp(m.lo) < 0 {
				lo.Set(m.lo)
			}
			fmt.Printf("lo final:\n%x\n", lo)
			hi.Mul(r, x.n)
			hi.Add(hi, x.threeB)
			fmt.Printf("hi before:\n%x\n", hi)
			hi.Sub(hi, one)
			hi.Div(hi, x.s)
			fmt.Printf("hi after:\n%x\n", hi)
			if hi.Cmp(m.hi) > 0 {
				hi.Set(m.hi)
			}
			fmt.Printf("hi final:\n%x\n", hi)
			fmt.Printf("interval r values in range [%x, %x]\n", lo, hi)
			if lo.Cmp(hi) > 0 {
				panic("lo can't be greater than hi")
			}
			ivals = append(ivals, makeInterval(lo, hi))
		}
	}
	x.ivals = ivals
}

func (x *rsaBreaker) searchOneRValues(hi *big.Int) <-chan *big.Int {
	lo := new(big.Int).Mul(hi, x.s)
	lo.Sub(lo, x.twoB)
	lo.Mul(two, lo)
	z := new(big.Int)
	lo.DivMod(lo, x.n, z)
	if !equal(z, zero) {
		lo.Add(lo, one)
	}
	return Values(lo, x.n)
}

func (x *rsaBreaker) searchOne() {
	panic("shouldn't get here")
	m := x.ivals[0]
	lo, hi, z := new(big.Int), new(big.Int), new(big.Int)
	for r := range x.searchOneRValues(m.hi) {
		lo.Mul(r, x.n)
		lo.Add(lo, x.twoB)
		lo.DivMod(lo, m.hi, z)
		if !equal(z, zero) {
			lo.Add(lo, one)
		}
		hi.Mul(r, x.n)
		hi.Add(hi, x.threeB)
		hi.Div(hi, m.lo)

		fmt.Printf("searching in range [%x, %x]\n", lo, hi)
		if lo.Cmp(hi) > 0 {
			panic("lo can't be higher than hi")
		}

		for x.s = range Values(lo, hi) {
			cPrime := z.Exp(x.s, x.e, x.n)
			cPrime.Mul(cPrime, x.c)
			cPrime.Mod(cPrime, x.n)
			if err := x.oracle(cPrime.Bytes()); err == nil {
				break
			}
		}
	}
}

func (x *rsaBreaker) searchMany() {
	cPrime := new(big.Int)
	for {
		x.s.Add(x.s, one)
		cPrime.Exp(x.s, x.e, x.n)
		cPrime.Mul(cPrime, x.c)
		cPrime.Mod(cPrime, x.n)
		if err := x.oracle(cPrime.Bytes()); err == nil {
			break
		}
	}
}

func (x *rsaBreaker) breakOracle() []byte {
	for i := 1; ; i++ {
		fmt.Println("loop", i)
		x.generateIntervals()
		if len(x.ivals) == 1 {
			if m := x.ivals[0]; equal(m.lo, m.hi) {
				return m.lo.Bytes()
			} else {
				fmt.Printf("lo: %x\nhi: %x\n", m.lo, m.hi)
			}
			x.searchOne()
		}
		panic("multiple intervals")
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
