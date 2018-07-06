package main

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"time"
)

const defaultExponent = 65537

var one = big.NewInt(1)

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

// unpaddedRSAOracle takes an RSA private key returns an unpadded message recovery oracle.
func unpaddedRSAOracle(priv *RSAPrivateKey) func([]byte) ([]byte, error) {
	var cache sync.Map
	return func(buf []byte) ([]byte, error) {
		sum := fmt.Sprintf("%x", sha256.Sum256(buf))
		if _, ok := cache.Load(sum); ok {
			return nil, errDuplicateMessage
		}
		cache.Store(sum, time.Now().Unix())
		res, err := RSADecrypt(priv, buf)
		if err != nil {
			return nil, err
		}
		return res, nil
	}
}

type unpaddedRSABreaker struct {
	*RSAPublicKey
	oracle func([]byte) ([]byte, error)
}

func newUnpaddedRSABreaker(pub *RSAPublicKey, oracle func([]byte) ([]byte, error)) *unpaddedRSABreaker {
	return &unpaddedRSABreaker{pub, oracle}
}

func (x *unpaddedRSABreaker) breakOracle(s string) (string, error) {
	ciphertext, err := RSAEncrypt(x.RSAPublicKey, []byte(s))
	if err != nil {
		return "", err
	}
/*
	if plaintext, err := x.oracle(ciphertext); err != nil {
		if err != nil {
			return nil, err
		} else {
			return nil, errors.New("breakOracle: not a duplicate message")
		}
	}
	if _, err := x.oracle(ciphertext); err != errDuplicateMessage {
		if err != nil {
			return nil, err
		} else {
			return nil, errors.New("breakOracle: not a duplicate message")
		}
	}
	c := new(big.Int).SetBytes(ciphertext)
	s := new(big.Int).Div(x.n)
	cPrime := new(big.Int).Exp(s, x.e, x.n)
	plaintextPrime, err := x.oracle(cPrime.Bytes())
	pPrime := new(big.Int).SetBytes(plaintextPrime)
	sInv := new(big.Int).ModInverse(s, x.n)
	p := new(big.Int).Mul(pPrime, sInv)

	return p.Bytes(), nil
*/
}

func main() {
}
