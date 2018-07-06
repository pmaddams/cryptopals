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

const defaultExponent = 65537

var (
	one = big.NewInt(1)
	two = big.NewInt(2)
)

var errDuplicateMessage = errors.New("duplicate message")

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
	z.Exp(z, pub.e, pub.n)
	return z.Bytes(), nil
}

// RSADecrypt takes a decrypted buffer and returns an encrypted buffer.
func RSADecrypt(priv *RSAPrivateKey, buf []byte) ([]byte, error) {
	if len(buf) > priv.n.BitLen()/8 {
		return nil, errors.New("RSADecrypt: buffer too large")
	}
	z := new(big.Int).SetBytes(buf)
	z.Exp(z, priv.d, priv.n)
	return z.Bytes(), nil
}

// unpaddedRSAOracle takes an RSA private key and returns an unpadded message recovery oracle.
func unpaddedRSAOracle(priv *RSAPrivateKey) func([]byte) ([]byte, error) {
	var cache sync.Map
	return func(ciphertext []byte) ([]byte, error) {
		checksum := fmt.Sprintf("%x", sha256.Sum256(ciphertext))
		if _, ok := cache.Load(checksum); ok {
			return nil, errDuplicateMessage
		}
		cache.Store(checksum, time.Now().Unix())
		plaintext, err := RSADecrypt(priv, ciphertext)
		if err != nil {
			return nil, err
		}
		return plaintext, nil
	}
}

// unpaddedRSABreaker contains data necessary to attack the unpadded RSA oracle.
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
	if _, err := x.oracle(ciphertext); err != errDuplicateMessage {
		if err != nil {
			return nil, err
		}
		return nil, errors.New("breakOracle: not a duplicate message")
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

// printUnpaddedRSA reads lines of text, encrypts them, and prints the decrypted plaintext.
func printUnpaddedRSA(in io.Reader, x *unpaddedRSABreaker) error {
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

func main() {
	fmt.Print("generating RSA key...")
	priv, err := RSAGenerateKey(defaultExponent, 1024)
	if err != nil {
		panic(err)
	}
	fmt.Println("done.")
	oracle := unpaddedRSAOracle(priv)
	x := newUnpaddedRSABreaker(&priv.RSAPublicKey, oracle)

	files := os.Args[1:]
	// If no files are specified, read from standard input.
	if len(files) == 0 {
		if err := printUnpaddedRSA(os.Stdin, x); err != nil {
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
		if err := printUnpaddedRSA(f, x); err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
		f.Close()
	}
}
