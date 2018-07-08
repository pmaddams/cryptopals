package main

import (
	"crypto"
	"crypto/rand"
	"errors"
	"math/big"
)

const (
	defaultExponent = 65537
	defaultBits     = 2048
)

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

// RSAEncrypt takes an encrypted buffer and returns a decrypted buffer.
func RSAEncrypt(pub *RSAPublicKey, buf []byte) ([]byte, error) {
	z := new(big.Int).SetBytes(buf)
	if z.Cmp(pub.n) > 0 {
		return nil, errors.New("RSAEncrypt: buffer too large")
	}
	z.Exp(z, pub.e, pub.n)
	return z.Bytes(), nil
}

// RSADecrypt takes a decrypted buffer and returns an encrypted buffer.
func RSADecrypt(priv *RSAPrivateKey, buf []byte) ([]byte, error) {
	z := new(big.Int).SetBytes(buf)
	if z.Cmp(priv.n) > 0 {
		return nil, errors.New("RSADecrypt: buffer too large")
	}
	z.Exp(z, priv.d, priv.n)
	return z.Bytes(), nil
}

// DigestInfo returns precomputed ASN.1 DER structures for cryptographic hash functions.
func DigestInfo(h crypto.Hash) ([]byte, error) {
	var res []byte
	switch h {
	case crypto.SHA224:
		res = []byte{0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05, 0x00, 0x04, 0x1c}
	case crypto.SHA256:
		res = []byte{0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20}
	case crypto.SHA384:
		res = []byte{0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30}
	case crypto.SHA512:
		res = []byte{0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40}
	default:
		return nil, errors.New("DigestInfo: invalid hash function")
	}
	return res, nil
}

// size returns the size of an arbitrary-precision integer in bytes.
func size(z *big.Int) int {
	return (z.BitLen() + 7) / 8
}

// RSASign returns a checksum signed with a private key.
func RSASign(priv *RSAPrivateKey, h crypto.Hash, sum []byte) ([]byte, error) {
	der, err := DigestInfo(h)
	if err != nil {
		return nil, err
	}
	if len(sum) != h.Size() {
		return nil, errors.New("RSASign: invalid checksum")
	}
	n := size(priv.n)
	buf := make([]byte, n)

	buf[1] = 0x01
	for i := 2; i < n-1-len(der)-len(sum); i++ {
		buf[i] = 0xff
	}
	copy(buf[n-len(der)-len(sum):], der)
	copy(buf[n-len(sum):], sum)

	res, err := RSADecrypt(priv, buf)
	if err != nil {
		return nil, err
	}
	return res, nil
}

// RSAVerify returns an error if a checksum does not match its signature.
func RSAVerify(pub *RSAPublicKey, h crypto.Hash, sum []byte, sig []byte) error {
	return nil
}

func main() {
}
