package main

import (
	"crypto/rand"
	"crypto/sha1"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

const (
	dsaDefaultP = `800000000000000089e1855218a0e7dac38136ffafa72eda7
859f2171e25e65eac698c1702578b07dc2a1076da241c76c6
2d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebe
ac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2
b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc87
1a584471bb1`
	dsaDefaultQ = `f4f47f05794b256174bba6e9b396a7707e563c5b`
	dsaDefaultG = `5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119
458fef538b8fa4046c8db53039db620c094c9fa077ef389b5
322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a047
0f5b64c36b625a097f1651fe775323556fe00b3608c887892
878480e99041be601a62166ca6894bdd41a7054ec89f756ba
9fc95302291`
)

var (
	zero = big.NewInt(0)
	one  = big.NewInt(1)
)

// DSAPublicKey represents the public part of a DSA key pair.
type DSAPublicKey struct {
	p *big.Int
	q *big.Int
	g *big.Int
	y *big.Int
}

// DSAPrivateKey represents a DSA key pair.
type DSAPrivateKey struct {
	DSAPublicKey
	x *big.Int
}

// equal returns true if two arbitrary-precision integers are equal.
func equal(z1, z2 *big.Int) bool {
	return z1.Cmp(z2) == 0
}

// DSAGenerateKey generates a private key.
func DSAGenerateKey(p, q, g *big.Int) *DSAPrivateKey {
	x, err := rand.Int(rand.Reader, q)
	if err != nil {
		panic(err)
	}
	y := new(big.Int).Exp(g, x, p)

	return &DSAPrivateKey{DSAPublicKey{p, q, g, y}, x}
}

// Public returns a public key.
func (priv *DSAPrivateKey) Public() *DSAPublicKey {
	return &priv.DSAPublicKey
}

// DSASign returns a signature for a checksum.
func DSASign(priv *DSAPrivateKey, sum []byte) (*big.Int, *big.Int) {
Retry:
	k := new(big.Int)
	for k.Cmp(one) <= 0 {
		var err error
		if k, err = rand.Int(rand.Reader, priv.q); err != nil {
			panic(err)
		}
	}
	r := new(big.Int).Exp(priv.g, k, priv.p)
	r.Mod(r, priv.q)
	if equal(r, zero) {
		goto Retry
	}
	z1 := new(big.Int).SetBytes(sum)
	z2 := new(big.Int).Mul(priv.x, r)
	z1.Add(z1, z2)
	z2.ModInverse(k, priv.q)

	s := z1.Mul(z1, z2)
	s.Mod(s, priv.q)
	if equal(s, zero) {
		goto Retry
	}
	return r, s
}

// DSAVerify returns false if a checksum does not match its signature.
func DSAVerify(pub *DSAPublicKey, sum []byte, r, s *big.Int) bool {
	if r.Sign() <= 0 || r.Cmp(pub.q) >= 0 {
		return false
	}
	if s.Sign() <= 0 || s.Cmp(pub.q) >= 0 {
		return false
	}
	w := new(big.Int).ModInverse(s, pub.q)

	u1 := new(big.Int).SetBytes(sum)
	u1.Mul(u1, w)
	u1.Mod(u1, pub.q)
	u1.Exp(pub.g, u1, pub.p)

	u2 := new(big.Int).Mul(r, w)
	u2.Mod(u2, pub.q)
	u2.Exp(pub.y, u2, pub.p)

	v := u1.Mul(u1, u2)
	v.Mod(v, pub.p)
	v.Mod(v, pub.q)

	return equal(v, r)
}

// breakDSA returns the private key used to sign a checksum.
func breakDSA(pub *DSAPublicKey, sum []byte, r, s, k *big.Int) *DSAPrivateKey {
	z1 := new(big.Int).Mul(s, k)
	z2 := new(big.Int).SetBytes(sum)
	z1.Sub(z1, z2)
	z2.ModInverse(r, pub.q)

	x := z1.Mul(z1, z2)
	x.Mod(x, pub.q)

	return &DSAPrivateKey{*pub, x}
}

// parseBigInt converts a string to an arbitrary-precision integer.
func parseBigInt(s string, base int) (*big.Int, error) {
	if base < 0 || base > 16 {
		return nil, errors.New("parseBigInt: invalid base")
	}
	s = strings.Replace(s, "\n", "", -1)
	z, ok := new(big.Int).SetString(s, base)
	if !ok {
		return nil, errors.New("parseBigInt: invalid string")
	}
	return z, nil
}

func main() {
	p, err := parseBigInt(dsaDefaultP, 16)
	if err != nil {
		panic(err)
	}
	q, err := parseBigInt(dsaDefaultQ, 16)
	if err != nil {
		panic(err)
	}
	g, err := parseBigInt(dsaDefaultG, 16)
	if err != nil {
		panic(err)
	}
	y, err := parseBigInt(`84ad4719d044495496a3201c8ff484feb45b962e7302e56a392aee4
abab3e4bdebf2955b4736012f21a08084056b19bcd7fee56048e004
e44984e2f411788efdc837a0d2e5abb7b555039fd243ac01f0fb2ed
1dec568280ce678e931868d23eb095fde9d3779191b8c0299d6e07b
bb283e6633451e535c45513b2d33c99ea17`, 16)
	if err != nil {
		panic(err)
	}
	pub := &DSAPublicKey{p, q, g, y}

	r, err := parseBigInt("548099063082341131477253921760299949438196259240", 10)
	if err != nil {
		panic(err)
	}
	s, err := parseBigInt("857042759984254168557880549501802188789837994940", 10)
	if err != nil {
		panic(err)
	}
	h := sha1.New()
	h.Write([]byte("For those that envy a MC it can be hazardous to your health\n"))
	h.Write([]byte("So be friendly, a matter of life and death, just like a etch-a-sketch\n"))
	sum := h.Sum([]byte{})

	k := new(big.Int)
	for i := 0; i < 65536; i++ {
		k.SetInt64(int64(i))
		priv := breakDSA(pub, sum, r, s, k)
		newY := k.Exp(priv.g, priv.x, priv.p)
		if equal(y, newY) {
			fmt.Println("success")
			return
		}
	}
}
