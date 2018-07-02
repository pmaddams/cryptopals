package main

import (
	"crypto/rand"
	"errors"
	"math/big"
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
func RSAGenerateKey(bits int) (*RSAPrivateKey, error) {
	if bits < 1024 {
		return nil, errors.New("RSAGenerateKey: key size too small")
	}
	randPrime := func() *big.Int {
		n, err := rand.Prime(rand.Reader, bits)
		if err != nil {
			panic(err)
		}
		return n
	}
	p, q := randPrime(), randPrime()
	for q.Cmp(p) == 0 {
		q = randPrime()
	}
	n := new(big.Int).Mul(p, q)
	e := big.NewInt(defaultExponent)

	pMinusOne := new(big.Int).Sub(p, one)
	qMinusOne := new(big.Int).Sub(q, one)
	totient := pMinusOne.Mul(pMinusOne, qMinusOne)
	d := new(big.Int).ModInverse(e, totient)

	return &RSAPrivateKey{RSAPublicKey{n, e}, d}, nil
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

func main() {
}
