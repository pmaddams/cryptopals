// 47. Bleichenbacher's PKCS 1.5 Padding Oracle (Simple Case)

package main

import (
	"bufio"
	"crypto/rand"
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

// RSAPublicKey represents the public part of an RSA key pair.
type RSAPublicKey struct {
	n *big.Int
	e *big.Int
}

// RSAPrivateKey represents an RSA key pair.
type RSAPrivateKey struct {
	RSAPublicKey
	d *big.Int
}

// equal returns true if two arbitrary-precision integers are equal.
func equal(z1, z2 *big.Int) bool {
	return z1.Cmp(z2) == 0
}

// RSAGenerateKey generates a private key.
func RSAGenerateKey(exponent, bits int) (*RSAPrivateKey, error) {
	e := big.NewInt(int64(exponent))
	if exponent < 3 || !e.ProbablyPrime(0) {
		return nil, errors.New("RSAGenerateKey: invalid exponent")
	}
Retry:
	p, err := rand.Prime(rand.Reader, bits/2)
	if err != nil {
		return nil, err
	}
	q, err := rand.Prime(rand.Reader, bits/2)
	if err != nil {
		return nil, err
	}
	if equal(p, q) {
		goto Retry
	}
	pMinusOne := new(big.Int).Sub(p, one)
	qMinusOne := new(big.Int).Sub(q, one)
	totient := pMinusOne.Mul(pMinusOne, qMinusOne)
	d := new(big.Int)
	if gcd := new(big.Int).GCD(d, nil, e, totient); !equal(gcd, one) {
		goto Retry
	}
	if d.Sign() < 0 {
		d.Add(d, totient)
	}
	return &RSAPrivateKey{
		RSAPublicKey{
			n: p.Mul(p, q),
			e: e,
		},
		d,
	}, nil
}

// Public returns a public key.
func (priv *RSAPrivateKey) Public() *RSAPublicKey {
	return &priv.RSAPublicKey
}

// size returns the size of an arbitrary-precision integer in bytes.
func size(z *big.Int) int {
	return (z.BitLen() + 7) / 8
}

// copyR copies a source buffer to the right of a destination buffer.
func copyR(dst, src []byte) int {
	return copy(dst[len(dst)-len(src):], src)
}

// RSAEncrypt takes a public key and plaintext, and returns ciphertext.
func RSAEncrypt(pub *RSAPublicKey, buf []byte) ([]byte, error) {
	z := new(big.Int).SetBytes(buf)
	if z.Cmp(pub.n) > 0 {
		return nil, errors.New("RSAEncrypt: buffer too large")
	}
	z.Exp(z, pub.e, pub.n)

	res := make([]byte, size(pub.n))
	copyR(res, z.Bytes())

	return res, nil
}

// RSADecrypt takes a private key and ciphertext, and returns plaintext.
func RSADecrypt(priv *RSAPrivateKey, buf []byte) ([]byte, error) {
	z := new(big.Int).SetBytes(buf)
	if z.Cmp(priv.n) > 0 {
		return nil, errors.New("RSADecrypt: buffer too large")
	}
	z.Exp(z, priv.d, priv.n)

	res := make([]byte, size(priv.n))
	copyR(res, z.Bytes())

	return res, nil
}

// RandomBytes returns a random buffer of the desired length.
func RandomBytes(n int) []byte {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		panic(err)
	}
	return buf
}

// randomNonzeroBytes returns a random buffer of the desired length containing no zero bytes.
func randomNonzeroBytes(n int) []byte {
	buf := RandomBytes(n)
	for i := range buf {
		for buf[i] == 0 {
			buf[i] = RandomBytes(1)[0]
		}
	}
	return buf
}

// PKCS1v15CryptPad returns a checksum with PKCS #1 v1.5 encryption padding added.
func PKCS1v15CryptPad(buf []byte, size int) ([]byte, error) {
	if len(buf)+11 > size {
		return nil, errors.New("PKCS1v15CryptPad: buffer too large")
	}
	n := size - len(buf) - 3

	buf = append([]byte{0x00}, buf...)
	buf = append(randomNonzeroBytes(n), buf...)
	buf = append([]byte{0x00, 0x02}, buf...)

	return buf, nil
}

// PKCS1v15CryptUnpad returns a checksum with PKCS #1 v1.5 encryption padding removed.
func PKCS1v15CryptUnpad(buf []byte) ([]byte, error) {
	errInvalidPadding := errors.New("PKCS1v15CryptUnpad: invalid padding")
	if buf[0] != 0x00 {
		return nil, errInvalidPadding
	}
	buf = buf[1:]
	if buf[0] != 0x02 {
		return nil, errInvalidPadding
	}
	for len(buf) > 0 && buf[0] != 0x00 {
		buf = buf[1:]
	}
	if len(buf) == 0 {
		return nil, errInvalidPadding
	}
	buf = buf[1:]

	return buf, nil
}

// RSAEncryptPKCS1v15 takes a public key and plaintext, and returns PKCS #1 v1.5 padded ciphertext.
func RSAEncryptPKCS1v15(pub *RSAPublicKey, buf []byte) ([]byte, error) {
	buf, err := PKCS1v15CryptPad(buf, size(pub.n))
	if err != nil {
		return nil, err
	}
	return RSAEncrypt(pub, buf)
}

// RSADecryptPKCS1v15 takes a private key and PKCS #1 v1.5 padded ciphertext, and returns plaintext.
func RSADecryptPKCS1v15(priv *RSAPrivateKey, buf []byte) ([]byte, error) {
	buf, err := RSADecrypt(priv, buf)
	if err != nil {
		return nil, err
	}
	return PKCS1v15CryptUnpad(buf)
}

// rsaPaddingOracle returns an RSA padding oracle.
func rsaPaddingOracle(priv *RSAPrivateKey) func([]byte) bool {
	return func(ciphertext []byte) bool {
		buf, err := RSADecrypt(priv, ciphertext)
		if err != nil {
			panic(err)
		}
		return buf[0] == 0x00 && buf[1] == 0x02
	}
}

// interval represents an range of possible plaintexts.
type interval struct {
	lo *big.Int
	hi *big.Int
}

// rsaBreaker contains data necessary to attack the PKCS #1 v1.5 padding oracle.
type rsaBreaker struct {
	oracle func([]byte) bool
	e      *big.Int
	n      *big.Int
	c      *big.Int
	twoB   *big.Int
	threeB *big.Int
	s      *big.Int
	ivals  []interval
}

// newRSABreaker takes a public key, oracle, and ciphertext, and returns a breaker.
func newRSABreaker(pub *RSAPublicKey, oracle func([]byte) bool, ciphertext []byte) (*rsaBreaker, error) {
	x := new(rsaBreaker)
	x.oracle = oracle

	x.e = new(big.Int).Set(pub.e)
	x.n = new(big.Int).Set(pub.n)
	x.c = new(big.Int).SetBytes(ciphertext)

	z := big.NewInt(int64(8 * (size(x.n) - 2)))
	b := z.Exp(two, z, nil)
	x.twoB = new(big.Int).Mul(two, b)
	x.threeB = new(big.Int).Mul(three, b)

	sMin := z.Div(x.n, x.threeB)
	s, err := x.findS(sMin, x.n)
	if err != nil {
		return nil, err
	} else if s == nil {
		return nil, errors.New("newRSABreaker: nothing found")
	}
	x.s = s
	x.ivals = append(x.ivals, interval{
		new(big.Int).Set(x.twoB),
		new(big.Int).Sub(x.threeB, one),
	})
	return x, nil
}

// findS finds the smallest multiple of the ciphertext that generates valid padding.
func (x *rsaBreaker) findS(sMin, sMax *big.Int) (*big.Int, error) {
	if sMin.Cmp(sMax) > 0 {
		return nil, errors.New("findS: invalid range")
	}
	s := new(big.Int).Set(sMin)
	cPrime := new(big.Int)
	for {
		if s.Cmp(sMax) > 0 {
			return nil, nil
		}
		cPrime.Exp(s, x.e, x.n)
		cPrime.Mul(cPrime, x.c)
		cPrime.Mod(cPrime, x.n)
		if x.oracle(cPrime.Bytes()) {
			return s, nil
		}
		s.Add(s, one)
	}
}

// ceilingDiv performs ceiling division of z1 by z2.
func ceilingDiv(res, z1, z2 *big.Int) *big.Int {
	tmp := new(big.Int)
	res.DivMod(z1, z2, tmp)
	if !equal(tmp, zero) {
		res.Add(res, one)
	}
	return res
}

// intervalRValues returns the bounds for generating the next set of intervals.
func (x *rsaBreaker) intervalRValues(m interval) (*big.Int, *big.Int) {
	r := new(big.Int).Mul(m.lo, x.s)
	r.Sub(r, x.threeB)
	r.Add(r, one)
	ceilingDiv(r, r, x.n)

	rMax := new(big.Int).Mul(m.hi, x.s)
	rMax.Sub(rMax, x.twoB)
	rMax.Div(rMax, x.n)

	return r, rMax
}

// generateIntervals generates the next set of intervals.
func (x *rsaBreaker) generateIntervals() {
	var ivals []interval
	for _, m := range x.ivals {
		for r, rMax := x.intervalRValues(m); r.Cmp(rMax) <= 0; r.Add(r, one) {
			lo, hi := new(big.Int), new(big.Int)

			lo.Mul(r, x.n)
			lo.Add(lo, x.twoB)
			ceilingDiv(lo, lo, x.s)
			if lo.Cmp(m.lo) < 0 {
				lo.Set(m.lo)
			}
			hi.Mul(r, x.n)
			hi.Add(hi, x.threeB)
			hi.Sub(hi, one)
			hi.Div(hi, x.s)
			if hi.Cmp(m.hi) > 0 {
				hi.Set(m.hi)
			}
			ivals = append(ivals, interval{lo, hi})
		}
	}
	x.ivals = ivals
}

// searchOne searches for the next "s" value for a single interval.
func (x *rsaBreaker) searchOne(m interval) error {
	r := new(big.Int).Mul(m.hi, x.s)
	r.Sub(r, x.twoB)
	r.Mul(two, r)
	r.Div(r, x.n)

	sMin, sMax := new(big.Int), new(big.Int)
	for {
		sMin.Mul(r, x.n)
		sMin.Add(sMin, x.twoB)
		sMin.Div(sMin, m.hi)

		sMax.Mul(r, x.n)
		sMax.Add(sMax, x.threeB)
		sMax.Div(sMax, m.lo)

		s, err := x.findS(sMin, sMax)
		if err != nil {
			return err
		} else if s != nil {
			x.s = s
			return nil
		}
		r.Add(r, one)
	}
}

// searchMany searches for the next "s" value for multiple intervals.
func (x *rsaBreaker) searchMany() error {
	sMin := new(big.Int).Add(x.s, one)
	s, err := x.findS(sMin, x.n)
	if err != nil {
		return err
	} else if s == nil {
		return errors.New("searchMany: nothing found")
	}
	x.s = s
	return nil
}

// breakOracle breaks the padding oracle and returns the plaintext.
func (x *rsaBreaker) breakOracle() ([]byte, error) {
	for {
		x.generateIntervals()
		switch len(x.ivals) {
		case 0:
			return nil, errors.New("breakOracle: no intervals")
		case 1:
			m := x.ivals[0]
			if equal(m.lo, m.hi) {
				buf := make([]byte, size(x.n))
				copyR(buf, m.lo.Bytes())

				plaintext, err := PKCS1v15CryptUnpad(buf)
				if err != nil {
					return nil, err
				}
				return plaintext, nil
			}
			x.searchOne(m)
		default:
			x.searchMany()
		}
	}
}

// decryptRSA reads lines of text, encrypts them, and prints the decrypted plaintext.
func decryptRSA(in io.Reader, pub *RSAPublicKey, oracle func([]byte) bool) error {
	input := bufio.NewScanner(in)
	for input.Scan() {
		ciphertext, err := RSAEncryptPKCS1v15(pub, input.Bytes())
		if err != nil {
			return err
		}
		x, err := newRSABreaker(pub, oracle, ciphertext)
		if err != nil {
			return err
		}
		plaintext, err := x.breakOracle()
		if err != nil {
			return err
		}
		fmt.Println(string(plaintext))
	}
	return input.Err()
}

func main() {
	priv, err := RSAGenerateKey(3, 256)
	if err != nil {
		panic(err)
	}
	pub := &priv.RSAPublicKey
	oracle := rsaPaddingOracle(priv)

	files := os.Args[1:]
	// If no files are specified, read from standard input.
	if len(files) == 0 {
		if err := decryptRSA(os.Stdin, pub, oracle); err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
		return
	}
	for _, file := range files {
		f, err := os.Open(file)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			continue
		}
		if err := decryptRSA(f, pub, oracle); err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
		f.Close()
	}
}
