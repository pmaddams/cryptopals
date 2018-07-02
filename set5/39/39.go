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

// RSAGenerateKey generates a private key.
func RSAGenerateKey(exponent, bits int) (*RSAPrivateKey, error) {
Retry:
	p, err := rand.Prime(rand.Reader, bits)
	if err != nil {
		return nil, err
	}
	q, err := rand.Prime(rand.Reader, bits)
	if err != nil {
		return nil, err
	}
	if q.Cmp(p) == 0 {
		goto Retry
	}
	pMinusOne := new(big.Int).Sub(p, one)
	qMinusOne := new(big.Int).Sub(q, one)
	totient := pMinusOne.Mul(pMinusOne, qMinusOne)
	e := big.NewInt(int64(exponent))
	d := new(big.Int)
	if gcd := new(big.Int).GCD(d, nil, e, totient); gcd.Cmp(one) != 0 {
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
	m := new(big.Int).SetBytes(buf)
	if m.Cmp(pub.n) >= 0 {
		return nil, errors.New("RSAEncrypt: buffer too large")
	}
	c := m.Exp(m, pub.e, pub.n)
	return c.Bytes(), nil
}

// RSADecrypt takes a decrypted buffer and returns an encrypted buffer.
func RSADecrypt(priv *RSAPrivateKey, buf []byte) ([]byte, error) {
	c := new(big.Int).SetBytes(buf)
	if c.Cmp(priv.n) >= 0 {
		return nil, errors.New("RSADecrypt: buffer too large")
	}
	m := c.Exp(c, priv.d, priv.n)
	return m.Bytes(), nil
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
		// If encryption worked, decryption should work as well.
		if err != nil {
			panic(err)
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
