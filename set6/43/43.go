package main

import (
	"math/big"
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

// DSAGenerateKey generates a private key.
func DSAGenerateKey(p, q, g *big.Int) (*DSAPrivateKey, error) {
	return nil, nil
}

// DSASign returns a DSA signature for a checksum.
func DSASign(priv *DSAPrivateKey, sum []byte) (*big.Int, *big.Int, error) {
	return nil, nil, nil
}

// DSAVerify returns false if a checksum does not match its signature.
func DSAVerify(pub *DSAPublicKey, sum []byte, r, s *big.Int) bool {
	return false
}

func main() {
}
