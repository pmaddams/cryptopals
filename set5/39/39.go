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

const defaultExponent = 65537

var one = big.NewInt(1)

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
	p, err := rand.Prime(rand.Reader, bits)
	if err != nil {
		return nil, err
	}
	q, err := rand.Prime(rand.Reader, bits)
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

// RSAEncrypt takes an encrypted buffer and returns a decrypted buffer.
func RSAEncrypt(pub *RSAPublicKey, buf []byte) ([]byte, error) {
	if len(buf) > pub.n.BitLen()/8 {
		return nil, errors.New("RSAEncrypt: buffer too large")
	}
	z := new(big.Int).SetBytes(buf)
	z = z.Exp(z, pub.e, pub.n)
	return z.Bytes(), nil
}

// RSADecrypt takes a decrypted buffer and returns an encrypted buffer.
func RSADecrypt(priv *RSAPrivateKey, buf []byte) ([]byte, error) {
	if len(buf) > priv.n.BitLen()/8 {
		return nil, errors.New("RSADecrypt: buffer too large")
	}
	z := new(big.Int).SetBytes(buf)
	z = z.Exp(z, priv.d, priv.n)
	return z.Bytes(), nil
}

// printRSA reads lines of input and prints the results of RSA encryption and decryption.
func printRSA(in io.Reader, priv *RSAPrivateKey) error {
	input := bufio.NewScanner(in)
	for input.Scan() {
		ciphertext, err := RSAEncrypt(&priv.RSAPublicKey, input.Bytes())
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

func main() {
	fmt.Print("generating RSA key...")
	priv, err := RSAGenerateKey(defaultExponent, 1024)
	if err != nil {
		panic(err)
	}
	fmt.Println("done.")
	files := os.Args[1:]
	// If no files are specified, read from standard input.
	if len(files) == 0 {
		if err := printRSA(os.Stdin, priv); err != nil {
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
		if err := printRSA(f, priv); err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
		f.Close()
	}
}
