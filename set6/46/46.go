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
)

const rsaDefaultE = 65537

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

// copyRight copies a source buffer to the right side of a destination buffer.
func copyRight(dst, src []byte) {
	dst = dst[len(dst)-len(src):]
	copy(dst, src)
}

// RSAEncrypt takes an encrypted buffer and returns a decrypted buffer.
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

// RSADecrypt takes a decrypted buffer and returns an encrypted buffer.
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

// parityOracleBreaker contains data necessary to attack the parity oracle.
type parityOracleBreaker struct {
	*RSAPublicKey
	oracle func([]byte) (bool, error)
}

// newParityOracleBreaker takes a public key and parity oracle, and returns a breaker.
func newParityOracleBreaker(pub *RSAPublicKey, oracle func([]byte) (bool, error)) *parityOracleBreaker {
	return &parityOracleBreaker{pub, oracle}
}

// breakOracle breaks the parity oracle and returns the plaintext.
func (x *parityOracleBreaker) breakOracle(ciphertext []byte) ([]byte, error) {
	c := new(big.Int).SetBytes(ciphertext)
	buf, err := RSAEncrypt(x.RSAPublicKey, []byte{2})
	if err != nil {
		return nil, err
	}
	encryptedTwo := new(big.Int).SetBytes(buf)
	lower := big.NewInt(0)
	upper := new(big.Int).Set(x.n)
	for z := new(big.Int); !equal(lower, upper); {
		z.Add(lower, upper)
		z.Div(z, two)
		if equal(z, lower) {
			break
		}
		c.Mul(c, encryptedTwo)
		c.Mod(c, x.n)
		even, err := x.oracle(c.Bytes())
		if err != nil {
			return nil, err
		}
		if even {
			upper.Set(z)
			upper.Add(upper, one)
		} else {
			lower.Set(z)
		}
		fmt.Println(string(upper.Bytes()))
	}
	return upper.Bytes(), nil
}

// printHollywoodStyle reads lines of base64-encoded input, encrypts them, and prints them "Hollywood style".
func printHollywoodStyle(in io.Reader, x *parityOracleBreaker) error {
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
		fmt.Println(string(plaintext))
	}
	return input.Err()
}

func main() {
	fmt.Print("generating RSA key...")
	priv, err := RSAGenerateKey(rsaDefaultE, 1024)
	if err != nil {
		panic(err)
	}
	fmt.Println("done.")
	oracle := parityOracle(priv)
	x := newParityOracleBreaker(priv.Public(), oracle)

	files := os.Args[1:]
	// If no files are specified, read from standard input.
	if len(files) == 0 {
		if err := printHollywoodStyle(os.Stdin, x); err != nil {
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
		if err := printHollywoodStyle(f, x); err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
		f.Close()
	}
}
