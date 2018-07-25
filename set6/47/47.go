package main

import (
	"crypto/rand"
	"errors"
	"math/big"
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

// size returns the size of an arbitrary-precision integer in bytes.
func size(z *big.Int) int {
	return (z.BitLen() + 7) / 8
}

// copyRight copies a source buffer to the right side of a destination buffer.
func copyRight(dst, src []byte) {
	dst = dst[len(dst)-len(src):]
	copy(dst, src)
}

// RSAEncrypt takes a public key and plaintext, and returns ciphertext.
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

// RSADecrypt takes a private key and ciphertext, and returns plaintext.
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

// RandomBytes returns a random buffer of the desired length.
func RandomBytes(n int) []byte {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		panic(err)
	}
	return buf
}

// RandomNonzeroBytes returns a random buffer of the desired length containing no zero bytes.
func RandomNonzeroBytes(n int) []byte {
	buf := RandomBytes(n)
	for i, b := range buf {
		if b == 0 {
			buf[i]++
		}
	}
	return buf
}

// PKCS1v15CryptPad returns a checksum with PKCS #1 v1.5 signature padding added.
func PKCS1v15CryptPad(buf []byte, size int) ([]byte, error) {
	if len(buf)+11 > size {
		return nil, errors.New("PKCS1v15CryptPad: buffer too large")
	}
	n := size - len(buf) - 3

	buf = append([]byte{0x00}, buf...)
	buf = append(RandomNonzeroBytes(n), buf...)
	buf = append([]byte{0x00, 0x02}, buf...)

	return buf, nil
}

// PKCS1v15CryptUnpad returns a checksum with PKCS #1 v1.5 signature padding removed.
func PKCS1v15CryptUnpad(buf []byte) ([]byte, error) {
	errInvalidPadding := errors.New("PKCS1v15CryptUnpad: invalid padding")
	if buf[0] != 0x00 {
		return nil, errInvalidPadding
	}
	buf = buf[1:]
	if buf[0] != 0x02 {
		return nil, errInvalidPadding
	}
	for len(buf) > 0 && buf[0] != 0x00 {
		buf = buf[1:]
	}
	if len(buf) == 0 {
		return nil, errInvalidPadding
	}
	buf = buf[1:]

	return buf, nil
}

// RSAEncryptPKCS1v15 takes a public key and plaintext, and returns PKCS #1 v1.5 padded ciphertext.
func RSAEncryptPKCS1v15(pub *RSAPublicKey, buf []byte) ([]byte, error) {
	buf, err := PKCS1v15CryptPad(buf, size(pub.n))
	if err != nil {
		return nil, err
	}
	return RSAEncrypt(pub, buf)
}

// RSADecryptPKCS1v15 takes a private key and PKCS #1 v1.5 padded ciphertext, and returns plaintext.
func RSADecryptPKCS1v15(priv *RSAPrivateKey, buf []byte) ([]byte, error) {
	buf, err := RSADecrypt(priv, buf)
	if err != nil {
		return nil, err
	}
	return PKCS1v15CryptUnpad(buf)
}

func main() {
}
