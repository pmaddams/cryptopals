// 42. Bleichenbacher's e=3 RSA Attack

package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	_ "crypto/sha256"
	"errors"
	"fmt"
	"math/big"
	"os"
)

var (
	one   = big.NewInt(1)
	two   = big.NewInt(2)
	three = big.NewInt(3)
)

func main() {
	priv, err := RSAGenerateKey(3, 2048)
	if err != nil {
		panic(err)
	}
	pub := priv.Public()
	sum, sig, err := forge([]byte("hi mom"), pub, crypto.SHA256)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	if err := RSAVerifyWeak(pub, crypto.SHA256, sum, sig); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	fmt.Println("success")
}

// forge creates a fake signature for arbitrary data using RSA public exponent 3.
func forge(buf []byte, pub *RSAPublicKey, id crypto.Hash) ([]byte, []byte, error) {
	der, err := digestInfo(id)
	if err != nil {
		return nil, nil, err
	}
	n := size(pub.n)
	if n < 3+len(der)+id.Size() {
		return nil, nil, errors.New("forge: insufficient modulus")
	}
	h := id.New()
	h.Write(buf)
	sum := h.Sum([]byte{})

	tmp := make([]byte, size(pub.n))
	tmp[1] = 0x01
	copy(tmp[3:], der)
	copy(tmp[3+len(der):], sum)
	for i := 3 + len(der) + len(sum); i < len(tmp); i++ {
		tmp[i] = 0xff
	}
	sig := Cbrt(new(big.Int).SetBytes(tmp)).Bytes()

	return sum, sig, nil
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

// RSASign returns a PKCS #1 v1.5 signature for a checksum.
func RSASign(priv *RSAPrivateKey, h crypto.Hash, sum []byte) ([]byte, error) {
	buf, err := PKCS1v15SignaturePad(h, sum, size(priv.n))
	if err != nil {
		return nil, err
	}
	if buf, err = RSADecrypt(priv, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// RSAVerify returns an error if a checksum does not match its signature.
func RSAVerify(pub *RSAPublicKey, h crypto.Hash, sum []byte, sig []byte) error {
	b1, err := PKCS1v15SignaturePad(h, sum, size(pub.n))
	if err != nil {
		return err
	}
	b2, err := RSAEncrypt(pub, sig)
	if err != nil {
		return err
	}
	if !bytes.Equal(b1, b2) {
		return errors.New("RSAVerify: invalid signature")
	}
	return nil
}

// RSAVerifyWeak returns an error if a checksum does not match its signature.
// It is vulnerable to forgery because it parses the signature incorrectly.
func RSAVerifyWeak(pub *RSAPublicKey, h crypto.Hash, sum []byte, sig []byte) error {
	buf, err := RSAEncrypt(pub, sig)
	if err != nil {
		return err
	}
	if buf, err = PKCS1v15SignatureUnpad(h, buf); err != nil {
		return err
	}
	if len(buf) < len(sum) || !bytes.Equal(buf[:len(sum)], sum) {
		return errors.New("RSAVerifyWeak: invalid signature")
	}
	return nil
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

// PKCS1v15SignaturePad returns a checksum with PKCS #1 v1.5 signature padding added.
func PKCS1v15SignaturePad(h crypto.Hash, sum []byte, size int) ([]byte, error) {
	der, err := digestInfo(h)
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

// PKCS1v15SignatureUnpad returns a checksum with PKCS #1 v1.5 signature padding removed.
func PKCS1v15SignatureUnpad(h crypto.Hash, buf []byte) ([]byte, error) {
	errInvalidPadding := errors.New("PKCS1v15Unpad: invalid padding")
	if len(buf) == 0 || buf[0] != 0x00 {
		return nil, errInvalidPadding
	}
	buf = buf[1:]
	if len(buf) == 0 || buf[0] != 0x01 {
		return nil, errInvalidPadding
	}
	buf = buf[1:]
	for len(buf) > 0 && buf[0] == 0xff {
		buf = buf[1:]
	}
	if len(buf) == 0 || buf[0] != 0x00 {
		return nil, errInvalidPadding
	}
	buf = buf[1:]
	der, err := digestInfo(h)
	if err != nil {
		return nil, err
	}
	if len(buf) < len(der) || !bytes.Equal(buf[:len(der)], der) {
		return nil, errInvalidPadding
	}
	buf = buf[len(der):]

	return buf, nil
}

// digestInfo returns precomputed ASN.1 DER structures for cryptographic hash functions.
func digestInfo(h crypto.Hash) ([]byte, error) {
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
		return nil, errors.New("digestInfo: invalid hash function")
	}
	return buf, nil
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
