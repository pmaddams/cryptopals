// 41. Implement unpadded message recovery oracle

package main

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"sync"
	"time"
)

const rsaExponent = 65537

var (
	errInvalidMessage = errors.New("invalid message")

	one = big.NewInt(1)
	two = big.NewInt(2)
)

func main() {
	priv, err := RSAGenerateKey(rsaExponent, 1024)
	if err != nil {
		panic(err)
	}
	oracle := unpaddedRSAOracle(priv)
	x := newUnpaddedRSABreaker(priv.Public(), oracle)

	files := os.Args[1:]
	if len(files) == 0 {
		if err := decrypt(os.Stdin, x); err != nil {
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
		if err := decrypt(f, x); err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
		f.Close()
	}
}

// decrypt reads lines of text, encrypts them, and prints the decrypted plaintext.
func decrypt(in io.Reader, x *unpaddedRSABreaker) error {
	input := bufio.NewScanner(in)
	for input.Scan() {
		ciphertext, err := RSAEncrypt(x.RSAPublicKey, input.Bytes())
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			continue
		}
		plaintext, err := x.breakOracle(ciphertext)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			continue
		}
		fmt.Printf("ciphertext: %x\nplaintext: %s\n",
			ciphertext, plaintext)
	}
	return input.Err()
}

// unpaddedRSAOracle takes an RSA private key and returns an unpadded message recovery oracle.
func unpaddedRSAOracle(priv *RSAPrivateKey) func([]byte) ([]byte, error) {
	var cache sync.Map
	return func(ciphertext []byte) ([]byte, error) {
		checksum := fmt.Sprintf("%x", sha256.Sum256(ciphertext))
		if _, ok := cache.Load(checksum); ok {
			return nil, errInvalidMessage
		}
		cache.Store(checksum, time.Now().Unix())
		plaintext, err := RSADecrypt(priv, ciphertext)
		if err != nil {
			return nil, err
		}
		return plaintext, nil
	}
}

// unpaddedRSABreaker contains state for attacking the unpadded RSA oracle.
type unpaddedRSABreaker struct {
	*RSAPublicKey
	oracle func([]byte) ([]byte, error)
}

// newUnpaddedRSABreaker takes a public key and unpadded RSA oracle, and returns a breaker.
func newUnpaddedRSABreaker(pub *RSAPublicKey, oracle func([]byte) ([]byte, error)) *unpaddedRSABreaker {
	return &unpaddedRSABreaker{pub, oracle}
}

// breakOracle breaks the unpadded RSA oracle and returns the plaintext.
func (x *unpaddedRSABreaker) breakOracle(ciphertext []byte) ([]byte, error) {
	if _, err := x.oracle(ciphertext); err != nil {
		return nil, err
	}
	if _, err := x.oracle(ciphertext); err != errInvalidMessage {
		if err != nil {
			return nil, err
		}
		return nil, errors.New("breakOracle: message not previously sent")
	}
	z := new(big.Int).Div(x.n, two)
	c := new(big.Int).SetBytes(ciphertext)
	cPrime := new(big.Int).Exp(z, x.e, x.n)
	cPrime.Mul(cPrime, c)
	cPrime.Mod(cPrime, x.n)

	plaintextPrime, err := x.oracle(cPrime.Bytes())
	if err != nil {
		return nil, err
	}
	zInv := z.ModInverse(z, x.n)
	pPrime := new(big.Int).SetBytes(plaintextPrime)
	pPrime.Mul(pPrime, zInv)
	p := pPrime.Mod(pPrime, x.n)

	return p.Bytes(), nil
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
		return nil, errors.New("RSAEncrypt: too much data")
	}
	z.Exp(z, pub.e, pub.n)

	res := make([]byte, size(pub.n))
	CopyRight(res, z.Bytes())

	return res, nil
}

// RSADecrypt takes a private key and ciphertext, and returns plaintext.
func RSADecrypt(priv *RSAPrivateKey, buf []byte) ([]byte, error) {
	z := new(big.Int).SetBytes(buf)
	if z.Cmp(priv.n) > 0 {
		return nil, errors.New("RSADecrypt: too much data")
	}
	z.Exp(z, priv.d, priv.n)

	res := make([]byte, size(priv.n))
	CopyRight(res, z.Bytes())

	return res, nil
}

// CopyRight copies a source buffer to the right of a destination buffer.
func CopyRight(dst, src []byte) int {
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
