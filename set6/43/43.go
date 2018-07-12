package main

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"strings"
)

const (
	defaultP = `800000000000000089e1855218a0e7dac38136ffafa72eda7
859f2171e25e65eac698c1702578b07dc2a1076da241c76c6
2d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebe
ac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2
b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc87
1a584471bb1`
	defaultQ = `f4f47f05794b256174bba6e9b396a7707e563c5b`
	defaultG = `5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119
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
	x := new(big.Int)
	for equal(x, zero) {
		var err error
		if x, err = rand.Int(rand.Reader, q); err != nil {
			panic(err)
		}
	}
	y := new(big.Int).Exp(g, x, p)

	return &DSAPrivateKey{DSAPublicKey{p, q, g, y}, x}
}

// DSASign returns a DSA signature for a checksum.
func DSASign(priv *DSAPrivateKey, sum []byte) (*big.Int, *big.Int) {
Retry:
	k := new(big.Int)
	for k.Cmp(one) < 0 {
		var err error
		if k, err = rand.Int(rand.Reader, priv.q); err != nil {
			panic(err)
		}
	}
	r := new(big.Int).Exp(priv.g, k, priv.q)
	if equal(r, zero) {
		goto Retry
	}
	z1 := new(big.Int).SetBytes(sum)
	z2 := new(big.Int).Mul(priv.x, r)
	z1.Add(z1, z2)
	s := z2.ModInverse(k, priv.q)
	s.Mul(s, z1)
	s.Mod(s, priv.q)
	if equal(s, zero) {
		goto Retry
	}
	return r, s
}

// DSAVerify returns false if a checksum does not match its signature.
func DSAVerify(pub *DSAPublicKey, sum []byte, r, s *big.Int) bool {
	if r.Cmp(zero) <= 0 || r.Cmp(pub.q) >= 0 {
		return false
	}
	if s.Cmp(zero) <= 0 || s.Cmp(pub.q) >= 0 {
		return false
	}
	w := new(big.Int).ModInverse(s, pub.q)

	u1 := new(big.Int).SetBytes(sum)
	u1.Mul(u1, w)
	u1.Mod(u1, pub.q)

	u2 := new(big.Int).Mul(r, w)
	u2.Mod(u2, pub.q)

	z1 := new(big.Int).Exp(pub.g, u1, pub.p)
	z2 := new(big.Int).Exp(pub.y, u2, pub.p)
	v := z1.Mul(z1, z2)
	v.Mod(v, pub.p)
	v.Mod(v, pub.q)

	return equal(v, r)
}

func main() {
	p, ok := new(big.Int).SetString(strings.Replace(defaultP, "\n", "", -1), 16)
	if !ok {
		panic("invalid p")
	}
	q, ok := new(big.Int).SetString(defaultQ, 16)
	if !ok {
		panic("invalid q")
	}
	g, ok := new(big.Int).SetString(strings.Replace(defaultG, "\n", "", -1), 16)
	if !ok {
		panic("invalid g")
	}
	priv := DSAGenerateKey(p, q, g)
	fmt.Println(priv)
}
