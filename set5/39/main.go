// 39. Implement RSA

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

const rsaExponent = 65537

var one = big.NewInt(1)

func main() {
	fmt.Print("generating RSA key...")
	priv, err := RSAGenerateKey(rsaExponent, 1024)
	if err != nil {
		panic(err)
	}
	fmt.Println("done.")
	files := os.Args[1:]
	if len(files) == 0 {
		if err := printRSA(os.Stdin, priv); err != nil {
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
		if err := printRSA(f, priv); err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
		f.Close()
	}
}

// printRSA reads lines of text and prints the results of RSA encryption and decryption.
func printRSA(in io.Reader, priv *RSAPrivateKey) error {
	input := bufio.NewScanner(in)
	for input.Scan() {
		ciphertext, err := RSAEncrypt(priv.Public(), input.Bytes())
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			continue
		}
		plaintext, err := RSADecrypt(priv, ciphertext)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			continue
		}
		fmt.Printf("ciphertext: %x\nplaintext: %s\n",
			ciphertext, plaintext)
	}
	return input.Err()
}

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

// copyR copies a source buffer to the right of a destination buffer.
func copyR(dst, src []byte) int {
	// Panic if dst is smaller than src.
	return copy(dst[len(dst)-len(src):], src)
}

// size returns the size of an arbitrary-precision integer in bytes.
func size(z *big.Int) int {
	return (z.BitLen() + 7) / 8
}

// equal returns true if two arbitrary-precision integers are equal.
func equal(z1, z2 *big.Int) bool {
	return z1.Cmp(z2) == 0
}
