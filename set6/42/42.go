package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"errors"
	"math/big"
)

const (
	defaultExponent = 65537
	defaultBits     = 2048
)

var (
	one   = big.NewInt(1)
	two   = big.NewInt(2)
	three = big.NewInt(3)
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
	var buf []byte
	switch h {
	case crypto.SHA224:
		buf = []byte{0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05, 0x00, 0x04, 0x1c}
	case crypto.SHA256:
		buf = []byte{0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20}
	case crypto.SHA384:
		buf = []byte{0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30}
	case crypto.SHA512:
		buf = []byte{0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40}
	default:
		return nil, errors.New("DigestInfo: invalid hash function")
	}
	return buf, nil
}

// PKCS1v15Pad returns a buffer containing a checksum with PKCS #1 v1.5 padding.
func PKCS1v15Pad(h crypto.Hash, sum []byte, size int) ([]byte, error) {
	der, err := DigestInfo(h)
	if err != nil {
		return nil, err
	}
	if len(sum) != h.Size() {
		return nil, errors.New("PKCS1v15Pad: invalid checksum")
	}
	if size < 3+len(der)+len(sum) {
		return nil, errors.New("PKCS1v15Pad: insufficient modulus")
	}
	buf := make([]byte, size)
	buf[1] = 0x01
	for i := 2; i < size-1-len(der)-len(sum); i++ {
		buf[i] = 0xff
	}
	copy(buf[size-len(der)-len(sum):], der)
	copy(buf[size-len(sum):], sum)

	return buf, nil
}

// size returns the size of an arbitrary-precision integer in bytes.
func size(z *big.Int) int {
	return (z.BitLen() + 7) / 8
}

// RSASign returns a checksum signed with a private key.
func RSASign(priv *RSAPrivateKey, h crypto.Hash, sum []byte) ([]byte, error) {
	buf, err := PKCS1v15Pad(h, sum, size(priv.n))
	if err != nil {
		return nil, err
	}
	buf, err = RSADecrypt(priv, buf)
	if err != nil {
		return nil, err
	}
	return buf, nil
}

// RSAVerify returns an error if a checksum does not match its signature.
func RSAVerify(pub *RSAPublicKey, h crypto.Hash, sum []byte, sig []byte) error {
	b1, err := PKCS1v15Pad(h, sum, size(pub.n))
	if err != nil {
		return err
	}
	b2, err := RSAEncrypt(pub, sig)
	if err != nil {
		return err
	}
	b2 = append([]byte{0}, b2...)
	if !bytes.Equal(b1, b2) {
		return errors.New("RSAVerify: invalid signature")
	}
	return nil
}

// RSAVerifyWeak returns an error if a checksum does not match its signature.
// It is vulnerable to forgery because it parses the signature incorrectly.
func RSAVerifyWeak(pub *RSAPublicKey, h crypto.Hash, sum []byte, sig []byte) error {
	errInvalidSignature := errors.New("RSAVerifyWeak: invalid signature")
	buf, err := RSAEncrypt(pub, sig)
	if err != nil {
		return err
	}
	if len(buf) == 0 || buf[0] != 0x01 {
		return errInvalidSignature
	}
	buf = buf[1:]
	for len(buf) > 0 && buf[0] == 0xff {
		buf = buf[1:]
	}
	if len(buf) == 0 || buf[0] != 0x00 {
		return errInvalidSignature
	}
	buf = buf[1:]

	der, err := DigestInfo(h)
	if len(buf) < len(der) || !bytes.Equal(buf[:len(der)], der) {
		return errInvalidSignature
	}
	buf = buf[len(der):]

	var n int
	switch h {
	case crypto.SHA224:
		n = 224 / 8
	case crypto.SHA256:
		n = 256 / 8
	case crypto.SHA384:
		n = 384 / 8
	case crypto.SHA512:
		n = 512 / 8
	default:
		return errInvalidSignature
	}
	if len(buf) < n || !bytes.Equal(buf[:n], sum) {
		return errInvalidSignature
	}
	return nil
}

// Cbrt returns the cube root of the given integer using successive approximations.
func Cbrt(z *big.Int) *big.Int {
	prev := new(big.Int)
	guess := new(big.Int).Set(z)
	for !equal(prev, guess) {
		prev.Set(guess)
		guess.Mul(guess, guess)
		guess.Div(z, guess)
		guess.Add(guess, prev)
		guess.Add(guess, prev)
		guess.Div(guess, three)

		// Average the new and previous guesses to prevent oscillation.
		guess.Add(guess, prev)
		guess.Div(guess, two)
	}
	return guess
}

func main() {
}
