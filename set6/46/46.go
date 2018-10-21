package main

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"unicode"
)

const rsaExponent = 65537

var (
	one = big.NewInt(1)
	two = big.NewInt(2)
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

// trailingZero returns true if the buffer has a trailing zero bit.
func trailingZero(buf []byte) bool {
	return buf[len(buf)-1]&1 == 0
}

// parityOracle takes an RSA private key and returns a parity oracle.
func parityOracle(priv *RSAPrivateKey) func([]byte) (bool, error) {
	return func(ciphertext []byte) (bool, error) {
		plaintext, err := RSADecrypt(priv, ciphertext)
		if err != nil {
			return false, err
		}
		return trailingZero(plaintext), nil
	}
}

// parityBreaker contains data necessary to attack the parity oracle.
type parityBreaker struct {
	*RSAPublicKey
	oracle func([]byte) (bool, error)
}

// newParityBreaker takes a public key and parity oracle, and returns a breaker.
func newParityBreaker(pub *RSAPublicKey, oracle func([]byte) (bool, error)) *parityBreaker {
	return &parityBreaker{pub, oracle}
}

// printRunes prints printable runes in a buffer.
func printRunes(buf []byte) {
	for _, r := range string(buf) {
		if unicode.IsPrint(r) {
			fmt.Print(string(r))
		}
	}
	fmt.Println()
}

// breakOracle breaks the parity oracle and returns the plaintext.
func (x *parityBreaker) breakOracle(ciphertext []byte) ([]byte, error) {
	c := new(big.Int).SetBytes(ciphertext)
	p := new(big.Int)
	encryptedTwo := new(big.Int).Exp(two, x.e, x.n)

	lo, hi := big.NewInt(0), new(big.Int).Sub(x.n, one)
	for !equal(lo, hi) {
		c.Mul(c, encryptedTwo)
		c.Mod(c, x.n)
		even, err := x.oracle(c.Bytes())
		if err != nil {
			return nil, err
		}
		p.Add(lo, hi)
		p.Div(p, two)
		if even {
			hi.Set(p)
		} else {
			lo.Add(p, one)
		}
		printRunes(p.Bytes())
	}
	return p.Bytes(), nil
}

// decryptHollywoodStyle reads lines of base64-encoded input, encrypts them, and prints them "Hollywood style".
func decryptHollywoodStyle(in io.Reader, x *parityBreaker) error {
	input := bufio.NewScanner(in)
	for input.Scan() {
		buf, err := base64.StdEncoding.DecodeString(input.Text())
		if err != nil {
			return err
		}
		ciphertext, err := RSAEncrypt(x.RSAPublicKey, buf)
		if err != nil {
			return err
		}
		plaintext, err := x.breakOracle(ciphertext)
		if err != nil {
			return err
		}
		printRunes(plaintext)
	}
	return input.Err()
}

func main() {
	fmt.Print("generating RSA key...")
	priv, err := RSAGenerateKey(rsaExponent, 1024)
	if err != nil {
		panic(err)
	}
	fmt.Println("done.")
	oracle := parityOracle(priv)
	x := newParityBreaker(priv.Public(), oracle)

	files := os.Args[1:]
	// If no files are specified, read from standard input.
	if len(files) == 0 {
		if err := decryptHollywoodStyle(os.Stdin, x); err != nil {
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
		if err := decryptHollywoodStyle(f, x); err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
		f.Close()
	}
}
