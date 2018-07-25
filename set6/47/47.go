package main

import (
	"crypto/rand"
	"errors"
	"fmt"
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

// copyRight copies a source buffer to the right side of a destination buffer.
func copyRight(dst, src []byte) {
	dst = dst[len(dst)-len(src):]
	copy(dst, src)
}

// RSAEncrypt takes a public key and plaintext, and returns ciphertext.
func RSAEncrypt(pub *RSAPublicKey, buf []byte) ([]byte, error) {
	z := new(big.Int).SetBytes(buf)
	if z.Cmp(pub.n) > 0 {
		return nil, errors.New("RSAEncrypt: buffer too large")
	}
	z.Exp(z, pub.e, pub.n)

	res := make([]byte, size(pub.n))
	copyRight(res, z.Bytes())

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
	copyRight(res, z.Bytes())

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

// RandomNonzeroBytes returns a random buffer of the desired length containing no zero bytes.
func RandomNonzeroBytes(n int) []byte {
	buf := RandomBytes(n)
	for i, b := range buf {
		if b == 0 {
			buf[i]++
		}
	}
	return buf
}

// PKCS1v15CryptPad returns a checksum with PKCS #1 v1.5 signature padding added.
func PKCS1v15CryptPad(buf []byte, size int) ([]byte, error) {
	if len(buf)+11 > size {
		return nil, errors.New("PKCS1v15CryptPad: buffer too large")
	}
	n := size - len(buf) - 3

	buf = append([]byte{0x00}, buf...)
	buf = append(RandomNonzeroBytes(n), buf...)
	buf = append([]byte{0x00, 0x02}, buf...)

	return buf, nil
}

// PKCS1v15CryptUnpad returns a checksum with PKCS #1 v1.5 signature padding removed.
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

func rsaPaddingOracle(priv *RSAPrivateKey) func([]byte) bool {
	return func(ciphertext []byte) bool {
		_, err := RSADecryptPKCS1v15(priv, ciphertext)
		if err != nil {
			return false
		}
		return true
	}
}

type interval struct {
	lo *big.Int
	hi *big.Int
}

type rsaBreaker struct {
	oracle func([]byte) bool
	e      *big.Int
	n      *big.Int
	c      *big.Int
	twoB   *big.Int
	threeB *big.Int
	s      *big.Int
	m      interval
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

	sMin := ceilingDiv(z, x.n, x.threeB)
	s, err := x.findS(sMin, x.n)
	if err != nil {
		return nil, err
	} else if s == nil {
		return nil, errors.New("newRSABreaker: nothing found")
	}
	x.s = s
	x.m = interval{
		new(big.Int).Set(x.twoB),
		new(big.Int).Sub(x.threeB, one),
	}
	return x, nil
}

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

// Values returns a channel that yields successive values in [lo, hi].
func Values(lo, hi *big.Int) <-chan *big.Int {
	ch := make(chan *big.Int)
	z1 := new(big.Int).Set(lo)
	z2 := new(big.Int).Set(hi)
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

func (x *rsaBreaker) intervalRValue(m interval) *big.Int {
	rMin := new(big.Int).Mul(m.lo, x.s)
	rMin.Sub(rMin, x.threeB)
	rMin.Add(rMin, one)
	ceilingDiv(rMin, rMin, x.n)

	rMax := new(big.Int).Mul(m.hi, x.s)
	rMax.Sub(rMax, x.twoB)
	rMax.Div(rMax, x.n)

	if !equal(rMin, rMax) {
		panic("intervalRValue: multiple r values")
	}
	return rMin
}

func (x *rsaBreaker) generateInterval() {
	r := x.intervalRValue(x.m)
	lo, hi := new(big.Int), new(big.Int)

	lo.Mul(r, x.n)
	lo.Add(lo, x.twoB)
	ceilingDiv(lo, lo, x.s)
	if lo.Cmp(x.m.lo) < 0 {
		lo.Set(x.m.lo)
	}
	hi.Mul(r, x.n)
	hi.Add(hi, x.threeB)
	hi.Sub(hi, one)
	hi.Div(hi, x.s)
	if hi.Cmp(x.m.hi) > 0 {
		hi.Set(x.m.hi)
	}
	x.m = interval{
		new(big.Int).Set(lo),
		new(big.Int).Set(hi),
	}
}

func (x *rsaBreaker) searchOneRValues(hi *big.Int) <-chan *big.Int {
	lo := new(big.Int).Mul(hi, x.s)
	lo.Sub(lo, x.twoB)
	lo.Mul(two, lo)
	ceilingDiv(lo, lo, x.n)

	return Values(lo, x.n)
}

func (x *rsaBreaker) searchOne() error {
	lo, hi := new(big.Int), new(big.Int)
	for r := range x.searchOneRValues(x.m.hi) {
		lo.Mul(r, x.n)
		lo.Add(lo, x.twoB)
		ceilingDiv(lo, lo, x.m.hi)

		hi.Mul(r, x.n)
		hi.Add(hi, x.threeB)
		hi.Div(hi, x.m.lo)

		s, err := x.findS(lo, hi)
		if err != nil {
			return err
		} else if s != nil {
			x.s = s
			return nil
		}
	}
	return errors.New("searchOne: nothing found")
}

func (x *rsaBreaker) breakOracle() []byte {
	for {
		x.generateInterval()
		if equal(x.m.lo, x.m.hi) {
			return x.m.lo.Bytes()
		}
		x.searchOne()
	}
}

func main() {
	priv, err := RSAGenerateKey(3, 256)
	if err != nil {
		panic(err)
	}
	oracle := rsaPaddingOracle(priv)
	pub := &priv.RSAPublicKey

	ciphertext, err := RSAEncryptPKCS1v15(pub, []byte("kick it, CC"))
	if err != nil {
		panic(err)
	}
	x, err := newRSABreaker(pub, oracle, ciphertext)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	plaintext := x.breakOracle()

	fmt.Println(string(plaintext))
}
